"""TL4xx: credentials committed in configs and manifests."""

from __future__ import annotations

import re
from collections.abc import Iterator

from toollint.document import Document
from toollint.model import Category, Finding, JsonPath, Server, Severity
from toollint.normalize import safe_display, shannon_entropy
from toollint.rules.base import Rule, ScanContext, iter_strings, register
from toollint.secrets_patterns import find_known_secrets, redact

# Values that are references or placeholders, not secrets.
_REFERENCE_RE = re.compile(
    r"^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^}]+\}\}|<[^>]+>|op://\S+|"
    r"(?:Bearer|Basic|Token)\s+(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>|\{\{[^}]+\}\}))$"
)
_PLACEHOLDER_RE = re.compile(
    r"^(?:|x+|\*+|\.\.\.|changeme|change[-_ ]?me|todo|tbd|none|null|test|example|placeholder|redacted|dummy|"
    r"(?:your|my|insert|enter|replace|put)[-_ ]?.*|.*[-_ ](?:here|goes[-_ ]here)|.*example.*|.*placeholder.*|sk-\.\.\.|xxx.*)$",
    re.I,
)
_SECRET_KEY_RE = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|apikey|token|access[_-]?token|auth[_-]?token|secret|client[_-]?secret|password|passwd|pwd|"
    r"private[_-]?key|credentials?|auth|pat|session|cookie|signing[_-]?key|webhook[_-]?secret)(?:$|[_-])|^authorization$|^x-api-key$|^api-key$",
    re.I,
)
_NON_SECRET_KEY_RE = re.compile(
    r"(?:_|^)(?:url|uri|endpoint|host|path|file|dir|region|model|id|name|user(?:name)?|email|type|mode|header|ttl|expiry|expires)$",
    re.I,
)
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9+/=_\-.:~]{20,}$")
_ARG_SECRET_RE = re.compile(
    r"^--?(?:api[-_]?key|token|access[-_]?token|auth[-_]?token|secret|client[-_]?secret|password|pat)(?:=(.+))?$", re.I
)


def is_reference(value: str) -> bool:
    return bool(_REFERENCE_RE.match(value.strip()))


def is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(value.strip()))


def strip_auth_scheme(value: str) -> tuple[str, str]:
    m = re.match(r"^(Bearer|Basic|Token|Bot)\s+(.+)$", value.strip(), re.I)
    return (m.group(1) + " ", m.group(2)) if m else ("", value.strip())


def secret_slots(server: Server) -> Iterator[tuple[JsonPath, str, str]]:
    """Yield ``(path, key, value)`` for every env and header value of a server."""
    for k, v in server.env.items():
        yield server.env_path(k), k, v
    for k, v in server.headers.items():
        yield server.path + ("headers", k), k, v


@register
class KnownSecretFormat(Rule):
    """
    ## What it does

    Matches well-known credential formats anywhere in a config or tool manifest:
    AWS access key IDs, GitHub tokens (`ghp_`, `gho_`, `github_pat_`), Slack tokens
    and webhooks, OpenAI-style (`sk-…`) and Anthropic-style (`sk-ant-…`) keys,
    Stripe, Google, npm and Hugging Face tokens, JWTs, and PEM private-key blocks.

    Detection uses patterns only. ToolLint never contacts a provider to check a
    key, and matches are **always printed redacted**.

    ## Why is this bad?

    MCP configs get pasted into issues, dotfile repos, screenshots and support
    chats. A committed key is a leaked key: rotate it, because it may already be
    in git history.

    ## Example

    ```json
    {"mcpServers": {"github": {"command": "github-mcp", "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_…"}}}}
    ```

    ## Fix

    Rotate the credential, then load it from the environment or a secret manager
    (`"${env:GITHUB_PERSONAL_ACCESS_TOKEN}"`). `toollint scan --fix` rewrites
    literal values in `env` and `headers` into references and writes a
    `.env.example`.
    """

    id = "TL401"
    name = "known-secret-format"
    category = Category.SECRETS
    severity = Severity.HIGH
    summary = "Recognized API key / token / private key formats"
    fixable = True

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        slot_paths = {p for s in doc.servers for p, _, _ in secret_slots(s)}
        for path, text, is_key in iter_strings(doc.data):
            if is_key:
                continue
            for m in find_known_secrets(text):
                yield self.report(
                    doc,
                    path,
                    f"{m.pattern.label} found ({redact(m.value)})",
                    fix="Rotate this credential and load it from the environment instead of the file.",
                    fixable=path in slot_paths,
                    key=m.pattern.id,
                )


@register
class HighEntropyValue(Rule):
    """
    ## What it does

    Flags random-looking strings (Shannon entropy ≥ 4.0 bits per character, at
    least 20 characters, mixed letters and digits) in server `env` and `headers`
    values that do not match a known format (TL401 covers those) and are not
    references like `${env:NAME}`.

    ## Why is this bad?

    Most leaked credentials are custom-format tokens for internal or smaller
    services, which no pattern list covers. Literal random strings in `env` are
    almost always secrets.

    ## Example

    ```json
    {"mcpServers": {"crm": {"command": "crm-mcp", "env": {"CRM_SESSION": "q8Zr2Lx9TfW4mKp7Vn3Hy6Bc1Jd5Gs0E"}}}}
    ```

    ## Fix

    Move the value into the environment or a secret manager and reference it.
    Fixable with `--fix`.
    """

    id = "TL402"
    name = "high-entropy-value"
    category = Category.SECRETS
    severity = Severity.MEDIUM
    summary = "High-entropy strings in env/headers values"
    fixable = True

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        threshold = float(ctx.options.get("entropy_threshold", 4.0))
        for server in doc.servers:
            for path, key, value in secret_slots(server):
                _, token = strip_auth_scheme(value)
                if is_reference(value) or is_placeholder(token) or find_known_secrets(value):
                    continue
                if _SECRET_KEY_RE.search(key) and not _NON_SECRET_KEY_RE.search(key):
                    continue  # TL403 reports literal values under secret-looking keys
                if not _TOKENISH_RE.match(token) or token.startswith(("http://", "https://", "/", "~", ".")):
                    continue
                if not (re.search(r"[A-Za-z]", token) and re.search(r"\d", token)):
                    continue
                ent = shannon_entropy(token)
                if ent >= threshold:
                    yield self.report(
                        doc,
                        path,
                        f"Server '{safe_display(server.name, 60)}' {safe_display(key, 40)} holds a high-entropy literal "
                        f"({redact(token)}, {ent:.1f} bits/char) that is probably a credential",
                        fix="Move the value to the environment and reference it, e.g. ${env:NAME}.",
                        key=key,
                    )


@register
class LiteralSecretValue(Rule):
    """
    ## What it does

    Flags literal values for settings whose name says they hold a credential
    (`*_API_KEY`, `*_TOKEN`, `*_SECRET`, `PASSWORD`, `Authorization`,
    `X-API-Key`…) in server `env` and `headers`, and literal `--token=…` /
    `--api-key …` arguments. References such as `${VAR}`, `${env:VAR}`,
    `${input:id}` and `op://…`, and obvious placeholders (`<your-key>`,
    `YOUR_API_KEY`), are fine.

    ## Why is this bad?

    Even when a value does not match a known format, a literal password in a
    shared config file is a leaked password. Arguments are also visible to every
    local user through the process list.

    ## Example

    ```json
    {"servers": {"db": {"type": "stdio", "command": "db-mcp", "env": {"DB_PASSWORD": "hunter2-but-longer"}}}}
    ```

    ## Fix

    Use a reference: `"DB_PASSWORD": "${env:DB_PASSWORD}"` (VS Code and Cursor),
    `"${DB_PASSWORD}"` (Claude Code), or a VS Code `${input:…}` prompt. `--fix`
    rewrites `env` and `headers` values automatically.
    """

    id = "TL403"
    name = "literal-secret-value"
    category = Category.SECRETS
    severity = Severity.HIGH
    summary = "Secret-looking settings with literal values instead of ${ENV} refs"
    fixable = True

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            sname = safe_display(server.name, 60)
            for path, key, value in secret_slots(server):
                if not _SECRET_KEY_RE.search(key) or _NON_SECRET_KEY_RE.search(key):
                    continue
                _, token = strip_auth_scheme(value)
                if not value.strip() or is_reference(value) or is_placeholder(token) or find_known_secrets(value):
                    continue
                if value.strip().lower() in ("true", "false", "0", "1", "yes", "no") or len(token) < 6:
                    continue
                yield self.report(
                    doc,
                    path,
                    f"Server '{sname}' sets {safe_display(key, 40)} to a literal value ({redact(token)}); use an environment reference",
                    fix="Replace the literal with a reference such as ${env:" + _var_hint(key) + "}.",
                    key=key,
                )
            for i, arg in enumerate(server.args):
                m = _ARG_SECRET_RE.match(arg)
                if not m:
                    continue
                # --token=VALUE, or --token VALUE (report the value's position)
                at = i if m.group(1) else i + 1
                if at >= len(server.args):
                    continue
                arg_value = m.group(1) or server.args[at]
                if (
                    is_reference(arg_value)
                    or is_placeholder(arg_value)
                    or find_known_secrets(arg_value)
                    or len(arg_value) < 6
                    or arg_value.startswith("-")
                ):
                    continue
                yield self.report(
                    doc,
                    server.arg_path(at),
                    f"Server '{sname}' passes a literal credential on the command line ({redact(arg_value)})",
                    fixable=False,
                    fix="Pass credentials through env references, not arguments (arguments show up in the process list).",
                    key=f"arg:{at}",
                )


def _var_hint(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", key).strip("_").upper() or "SECRET"


__all__ = [
    "HighEntropyValue",
    "KnownSecretFormat",
    "LiteralSecretValue",
    "is_placeholder",
    "is_reference",
    "iter_strings",
]


# --------------------------------------------------------------------------------------
# TL404
# --------------------------------------------------------------------------------------

_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.I)
_SECRET_QUERY_RE = re.compile(
    r"^(?:api[_-]?key|apikey|key|token|access[_-]?token|auth|auth[_-]?token|secret|client[_-]?secret|password|pwd|sig|signature|session|code)$",
    re.I,
)


def credentials_in_url(url: str) -> list[str]:
    """Names of credential parts found in ``url`` (``userinfo`` / query parameter names)."""
    from urllib.parse import parse_qsl, urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return []
    found: list[str] = []
    if parts.password and not is_reference(parts.password) and not is_placeholder(parts.password):
        found.append("password in userinfo")
    for name, value in parse_qsl(parts.query, keep_blank_values=False):
        if (
            _SECRET_QUERY_RE.match(name)
            and value
            and not is_reference(value)
            and not is_placeholder(value)
            and len(value) >= 8
        ):
            found.append(f"query parameter '{name}'")
    return found


@register
class CredentialInUrl(Rule):
    """
    ## What it does

    Flags credentials embedded in URLs: `https://user:password@host/…` and query
    parameters such as `?api_key=…`, `?token=…` or `?secret=…`, in server URLs and
    launcher arguments (for example `mcp-remote https://mcp.example/sse?token=…`).
    References such as `?token=${env:TOKEN}` are fine.

    ## Why is this bad?

    URLs end up everywhere: client logs, proxy logs, browser history, error
    messages and screenshots. Many remote MCP servers accept a key in the URL for
    convenience, which turns every one of those places into a leak.

    ## Example

    ```json
    {"mcpServers": {"search": {"url": "https://mcp.search.example/sse?api_key=live_4f9c2d7e1b8a"}}}
    ```

    ## Fix

    Send the credential in a header (`"headers": {"Authorization": "Bearer ${env:SEARCH_TOKEN}"}`)
    and rotate the leaked value.
    """

    id = "TL404"
    name = "credential-in-url"
    category = Category.SECRETS
    severity = Severity.HIGH
    summary = "Passwords or API keys embedded in URLs"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            sname = safe_display(server.name, 60)
            slots: list[tuple[JsonPath, str]] = []
            if server.url and server.url_key:
                slots.append((server.path + (server.url_key,), server.url))
            slots.extend((server.arg_path(i), a) for i, a in enumerate(server.args))
            for path, text in slots:
                for m in _URL_RE.finditer(text):
                    found = credentials_in_url(m.group(0))
                    if found:
                        yield self.report(
                            doc,
                            path,
                            f"Server '{sname}' URL embeds a credential ({', '.join(found)})",
                            fix="Move the credential into a header that references an environment variable, then rotate it.",
                            key=str(path),
                        )
                        break
