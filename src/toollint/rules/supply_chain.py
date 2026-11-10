"""TL3xx: how servers are installed and reached."""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import lru_cache
from importlib import resources
from urllib.parse import urlsplit

from toollint.commands import PackageRef, analyze
from toollint.document import Document
from toollint.model import Category, Finding, Severity
from toollint.normalize import safe_display
from toollint.rules.base import Rule, ScanContext, register

# --------------------------------------------------------------------------------------
# TL301
# --------------------------------------------------------------------------------------


def _pin_hint(ref: PackageRef) -> str:
    if ref.ecosystem == "npm":
        return f"Pin an exact version, e.g. {ref.name}@1.2.3 (check the registry for the current release)."
    if ref.ecosystem == "pypi":
        return f"Pin an exact version, e.g. {ref.name}==1.2.3."
    if ref.ecosystem == "docker":
        return f"Pin a digest, e.g. {ref.name}@sha256:<digest>, or at least a version tag."
    return "Pin the reference to a full 40-character commit SHA."


@register
class UnpinnedPackage(Rule):
    """
    ## What it does

    Flags servers launched from a package registry without an exact version:
    `npx` / `bunx` / `pnpm dlx` / `npm exec` packages without `@x.y.z` (`@latest`
    counts as unpinned), `uvx` / `pipx run` / `uv tool run` packages without
    `==x.y.z`, `docker run` images with no tag or a moving tag (`latest`, `main`)
    and no digest, and git references that are not a full commit SHA.

    ## Why is this bad?

    `npx -y some-server` downloads and runs whatever was published most recently,
    every time the client starts. A hijacked maintainer account, or a malicious
    update, runs on your machine with no review. Pinning makes changes explicit
    and reviewable.

    ## Example

    ```json
    {"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}
    ```

    ## Fix

    Pin exact versions (`@modelcontextprotocol/server-github@2025.4.8`,
    `mcp-server-fetch==2025.4.7`) or image digests (`mcp/fetch@sha256:…`), and
    update on purpose.
    """

    id = "TL301"
    name = "unpinned-package"
    category = Category.SUPPLY_CHAIN
    severity = Severity.MEDIUM
    summary = "npx/uvx/pipx/docker refs without a version or digest"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            sname = safe_display(server.name, 60)
            for ref in analyze(server).packages:
                if ref.pinned:
                    continue
                state = f"floating version {ref.version!r}" if ref.version else "no version"
                kind = {"docker": "image", "git": "git reference"}.get(ref.ecosystem, "package")
                yield self.report(
                    doc,
                    ref.path,
                    f"Server '{sname}' runs {kind} {safe_display(ref.spec, 80)!r} via {ref.launcher} with {state}",
                    fix=_pin_hint(ref),
                    key=ref.spec,
                )


# --------------------------------------------------------------------------------------
# TL302
# --------------------------------------------------------------------------------------


@lru_cache(maxsize=1)
def bundled_popular_packages() -> frozenset[tuple[str, str]]:
    text = resources.files("toollint.data").joinpath("popular_packages.txt").read_text(encoding="utf-8")
    out: set[tuple[str, str]] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        eco, name = line.split(":", 1)
        out.add((eco.strip(), name.strip().lower()))
    return frozenset(out)


def _scope_and_bare(name: str) -> tuple[str | None, str]:
    if name.startswith("@") and "/" in name:
        scope, bare = name.split("/", 1)
        return scope, bare
    return None, name


def typosquat_candidates(eco: str, name: str, popular: frozenset[tuple[str, str]]) -> str | None:
    """Return the popular package ``name`` imitates, or ``None``."""
    from rapidfuzz.distance import Levenshtein

    lname = name.lower()
    if (eco, lname) in popular:
        return None
    pool = [p for e, p in popular if e == eco or (eco == "pypi" and e == "npm") or (eco == "npm" and e == "pypi")]
    if lname in pool:
        return None
    scope, bare = _scope_and_bare(lname)
    best: tuple[int, str] | None = None
    for cand in pool:
        if cand == lname:
            return None
        if len(cand) < 5:
            continue  # too short to fuzzy-match without false positives
        dist = Levenshtein.distance(lname, cand, score_cutoff=3)
        # Very short names only tolerate a single edit.
        limit = 1 if len(cand) < 10 else 2
        if dist <= limit and (best is None or dist < best[0]):
            best = (dist, cand)
    # Scope impersonation: an unknown scope, a near copy of a popular one, with a popular bare name.
    if best is None and scope:
        for cand in pool:
            cscope, cbare = _scope_and_bare(cand)
            if cscope and cscope != scope and cbare == bare and Levenshtein.distance(scope, cscope) <= 3:
                best = (Levenshtein.distance(scope, cscope), cand)
                break
    return best[1] if best else None


@register
class Typosquat(Rule):
    """
    ## What it does

    Compares every npm, PyPI and Docker package a server is launched from with a
    bundled list of popular MCP packages (`toollint/data/popular_packages.txt`).
    Names within a small edit distance (`@modelcontextprotocol/server-filesytem`)
    and popular names under a look-alike scope (`@modelcontextprotocoI/…`) are
    flagged. Exact matches are never flagged. Matching is fully offline.

    Add your own trusted packages with `extra-popular-packages` in the config.

    ## Why is this bad?

    Typosquatting is the most common way malicious packages get installed. Config
    snippets are copied from blog posts and chat messages, where one wrong
    character is easy to miss and the package runs with your full user rights.

    ## Example

    ```json
    {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesytem@1.0.0", "/tmp/x"]}}}
    ```

    ## Fix

    Correct the name and check the package's publisher and repository before you
    run it.
    """

    id = "TL302"
    name = "possible-typosquat"
    category = Category.SUPPLY_CHAIN
    severity = Severity.HIGH
    summary = "Package names that look like popular MCP packages"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        popular = bundled_popular_packages()
        extra = ctx.options.get("extra_popular_packages") or []
        if extra:
            popular = popular | frozenset(_parse_extra(extra))
        for server in doc.servers:
            for ref in analyze(server).packages:
                if ref.ecosystem not in ("npm", "pypi", "docker"):
                    continue
                target = typosquat_candidates(ref.ecosystem, ref.name, popular)
                if target:
                    yield self.report(
                        doc,
                        ref.path,
                        f"Package {safe_display(ref.name, 80)!r} looks like a typosquat of popular package {target!r}",
                        fix=f"Did you mean {target!r}? Verify the publisher before running it.",
                        key=ref.name,
                    )


def _parse_extra(extra: list[str]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for item in extra:
        if ":" in item and item.split(":", 1)[0] in ("npm", "pypi", "docker"):
            eco, name = item.split(":", 1)
            out.add((eco, name.lower()))
        else:
            for eco in ("npm", "pypi", "docker"):
                out.add((eco, item.lower()))
    return out


# --------------------------------------------------------------------------------------
# TL303
# --------------------------------------------------------------------------------------

_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|fetch)\b[^|;&]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python[0-9.]*|node|perl|ruby|iex|invoke-expression|pwsh|powershell)\b",
    re.I,
)
_SUBSHELL_FETCH_RE = re.compile(r"(?:\$\(|<\(|`)\s*(?:curl|wget)\b", re.I)
_IEX_RE = re.compile(
    r"\b(?:iex|invoke-expression)\b\s*\(?\s*(?:\(?\s*(?:new-object\s+net\.webclient\)?\.downloadstring|irm|iwr|invoke-webrequest|invoke-restmethod))",
    re.I,
)
_REMOTE_SCRIPT_RE = re.compile(r"^https?://\S+\.(?:sh|bash|ps1|py|js|mjs|ts|rb|pl)(?:\?\S*)?$", re.I)
_INTERPRETERS = {
    "sh",
    "bash",
    "zsh",
    "python",
    "python3",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "pwsh",
    "powershell",
    "tsx",
    "ts-node",
}


@register
class RemoteScriptExecution(Rule):
    """
    ## What it does

    Flags servers whose launch command downloads code and runs it at once:
    `curl … | sh`, `bash -c "$(curl …)"`, `bash <(wget …)`, PowerShell
    `iex (irm …)`, and interpreters pointed at a remote URL
    (`deno run https://…/server.ts`, `python https://…/x.py`).

    ## Why is this bad?

    The server is whatever that URL returns at launch time, with no pinning, no
    integrity check and no review, and it runs every time the client starts. The
    host or anyone on the network path can replace it.

    ## Example

    ```json
    {"mcpServers": {"helper": {"command": "bash", "args": ["-c", "curl -fsSL https://get.helper.example/install.sh | sh && helper-mcp"]}}}
    ```

    ## Fix

    Download the script once, review it, verify its checksum, and install a
    pinned release. Then point `command` at the installed binary.
    """

    id = "TL303"
    name = "remote-script-execution"
    category = Category.SUPPLY_CHAIN
    severity = Severity.CRITICAL
    summary = "curl | sh and other download-and-run commands"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            sname = safe_display(server.name, 60)
            ex = analyze(server)
            joined = " ".join(t.text for t in ex.tokens)
            hit = _PIPE_TO_SHELL_RE.search(joined) or _SUBSHELL_FETCH_RE.search(joined) or _IEX_RE.search(joined)
            if hit:
                path = next((t.path for t in ex.tokens if hit.group(0)[:8] in t.text), server.path)
                yield self.report(
                    doc,
                    path,
                    f"Server '{sname}' downloads and executes a remote script: \"{safe_display(hit.group(0), 100)}\"",
                    fix="Install a pinned, checksum-verified release and point 'command' at the installed binary.",
                    key="pipe",
                )
                continue
            if ex.launcher in _INTERPRETERS:
                for tok in ex.server_args:
                    if _REMOTE_SCRIPT_RE.match(tok.text) or (
                        ex.launcher == "deno" and tok.text.startswith(("http://", "https://"))
                    ):
                        yield self.report(
                            doc,
                            tok.path,
                            f"Server '{sname}' runs a script straight from a URL with {ex.launcher}: {safe_display(tok.text, 80)!r}",
                            fix="Vendor the script locally (reviewed and pinned) instead of executing it from a URL.",
                            key=f"url:{tok.text}",
                        )
                        break


# --------------------------------------------------------------------------------------
# TL304
# --------------------------------------------------------------------------------------

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]", "host.docker.internal"}
_URL_IN_ARG_RE = re.compile(r"http://[^\s\"']+", re.I)


def _hostname(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _is_local(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower().strip("[]")
    return h in _LOCAL_HOSTS or h.endswith(".localhost") or h.startswith("127.")


@register
class PlainHttpRemote(Rule):
    """
    ## What it does

    Flags remote MCP servers reached over plain `http://`: the `url` /
    `serverUrl` of HTTP and SSE servers, and URLs passed to bridges such as
    `mcp-remote` or `supergateway`. Loopback addresses (`localhost`,
    `127.0.0.1`, `::1`, `*.localhost`) are allowed. Severity is raised to high
    when the server also sends credentials in `headers`.

    ## Why is this bad?

    Without TLS, anyone on the network path (public Wi-Fi, a compromised router)
    can read the session, steal bearer tokens, and, worst of all, rewrite tool
    descriptions and results in transit to inject instructions.

    ## Example

    ```json
    {"mcpServers": {"crm": {"url": "http://mcp.crm.example/sse", "headers": {"Authorization": "Bearer ${CRM_TOKEN}"}}}}
    ```

    ## Fix

    Use `https://`. For local development, bind to `localhost`.
    """

    id = "TL304"
    name = "plain-http-remote"
    category = Category.SUPPLY_CHAIN
    severity = Severity.MEDIUM
    summary = "Remote MCP servers over unencrypted HTTP"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            sname = safe_display(server.name, 60)
            has_auth = any(
                k.lower() in ("authorization", "x-api-key", "api-key", "cookie") for k in server.headers
            ) or any("--header" in a or a.lower().startswith("authorization") for a in server.args)
            sev = Severity.HIGH if has_auth else self.severity
            if (
                server.url
                and server.url_key
                and server.url.lower().startswith("http://")
                and not _is_local(_hostname(server.url))
            ):
                yield self.report(
                    doc,
                    server.path + (server.url_key,),
                    f"Server '{sname}' connects over plain HTTP: {safe_display(server.url, 80)!r}"
                    + (" while sending credentials" if has_auth else ""),
                    severity=sev,
                    fix="Use an https:// URL.",
                    key="url",
                )
            for i, arg in enumerate(server.args):
                for m in _URL_IN_ARG_RE.finditer(arg):
                    if not _is_local(_hostname(m.group(0))):
                        yield self.report(
                            doc,
                            server.arg_path(i),
                            f"Server '{sname}' passes a plain-HTTP URL to its launcher: {safe_display(m.group(0), 80)!r}",
                            severity=sev,
                            fix="Use an https:// URL.",
                            key=f"arg:{m.group(0)}",
                        )
                        break


# --------------------------------------------------------------------------------------
# TL305
# --------------------------------------------------------------------------------------

_TLS_ENV = {
    "NODE_TLS_REJECT_UNAUTHORIZED": {"0", "false"},
    "PYTHONHTTPSVERIFY": {"0", "false"},
    "CURL_INSECURE": {"1", "true"},
    "GIT_SSL_NO_VERIFY": {"1", "true"},
    "REQUESTS_CA_BUNDLE": {""},
    "NPM_CONFIG_STRICT_SSL": {"false", "0"},
    "UV_INSECURE_HOST": None,
    "PIP_TRUSTED_HOST": None,
}
_TLS_ARGS_RE = re.compile(
    r"^(?:--insecure|--no-verify-ssl|--no-check-certificate|--allow-insecure|--skip-tls-verify|--tls-skip-verify|"
    r"--ignore-certificate-errors|--strict-ssl=false|--trusted-host(?:=.*)?|--allow-insecure-host(?:=.*)?|--insecure-host(?:=.*)?)$",
    re.I,
)


@register
class TlsVerificationDisabled(Rule):
    """
    ## What it does

    Flags servers that turn off TLS certificate checks, through environment
    variables (`NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0`,
    `GIT_SSL_NO_VERIFY=1`, `NPM_CONFIG_STRICT_SSL=false`, `PIP_TRUSTED_HOST`,
    `UV_INSECURE_HOST`) or launcher flags (`--insecure`, `--trusted-host`,
    `--allow-insecure-host`, `--no-check-certificate`, `--ignore-certificate-errors`).

    ## Why is this bad?

    With verification off, `https://` gives no protection: anyone on the network
    path can serve a different package at install time, or rewrite tool
    descriptions and results at run time. These settings are often pasted in to
    "fix" a proxy error and then forgotten.

    ## Example

    ```json
    {"mcpServers": {"jira": {"command": "npx", "args": ["-y", "jira-mcp@1.4.0"], "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}}}}
    ```

    ## Fix

    Remove the override. Behind a TLS-inspecting proxy, add the proxy's CA
    instead (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`).
    """

    id = "TL305"
    name = "tls-verification-disabled"
    category = Category.SUPPLY_CHAIN
    severity = Severity.HIGH
    summary = "TLS certificate verification turned off"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            sname = safe_display(server.name, 60)
            for k, v in server.env.items():
                bad = _TLS_ENV.get(k.upper(), ...)
                if bad is ... or (bad is not None and v.strip().lower() not in bad):
                    continue
                yield self.report(
                    doc,
                    server.env_path(k),
                    f"Server '{sname}' disables TLS verification ({safe_display(k, 40)}={safe_display(v, 20)})",
                    fix="Remove the override; trust a corporate proxy with NODE_EXTRA_CA_CERTS / SSL_CERT_FILE instead.",
                    key=f"env:{k}",
                )
            for i, arg in enumerate(server.args):
                if _TLS_ARGS_RE.match(arg.strip()):
                    yield self.report(
                        doc,
                        server.arg_path(i),
                        f"Server '{sname}' is launched with {safe_display(arg, 40)!r}, which disables certificate checks",
                        fix="Remove the flag and fix certificate trust properly.",
                        key=f"arg:{arg}",
                    )
