"""Understand how an MCP server is launched: which launcher, which packages, which args.

This is a static reading of ``command`` + ``args``. Nothing is executed.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from toollint.model import JsonPath, Server

_SEMVER_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
_PEP440_EXACT_RE = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PY_SPEC_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(?P<op>===|==|@|>=|<=|~=|>|<|!=)\s*(?P<ver>.+))?$"
)


@dataclass(frozen=True)
class Token:
    text: str
    path: JsonPath
    #: True if the token came from splitting a ``sh -c "..."`` string.
    from_shell: bool = False


@dataclass(frozen=True)
class PackageRef:
    ecosystem: str  # "npm" | "pypi" | "docker" | "git" | "url"
    spec: str
    name: str
    version: str | None
    pinned: bool
    launcher: str
    path: JsonPath


@dataclass
class DockerRun:
    image: Token | None = None
    volumes: list[Token] = field(default_factory=list)
    env_flags: list[Token] = field(default_factory=list)
    privileged: bool = False
    privileged_token: Token | None = None
    network_host: bool = False


@dataclass
class ServerExec:
    launcher: str | None
    tokens: list[Token]
    packages: list[PackageRef] = field(default_factory=list)
    #: Arguments passed to the server itself (after the package / script).
    server_args: list[Token] = field(default_factory=list)
    docker: DockerRun | None = None
    shell_string: Token | None = None


def _base(cmd: str) -> str:
    name = re.split(r"[\\/]", cmd)[-1].lower()
    for ext in (".cmd", ".exe", ".bat", ".ps1"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    return name


def server_tokens(server: Server) -> list[Token]:
    toks: list[Token] = []
    if server.command:
        # Some configs put a whole command line in "command".
        parts = _split(server.command) if " " in server.command.strip() and not server.args else [server.command]
        toks.extend(Token(p, server.command_path, from_shell=len(parts) > 1) for p in parts)
    toks.extend(Token(a, server.arg_path(i)) for i, a in enumerate(server.args))
    return toks


def _split(s: str) -> list[str]:
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


_SHELLS = {"sh", "bash", "zsh", "dash", "ash", "fish", "cmd", "powershell", "pwsh"}


def analyze(server: Server) -> ServerExec:
    tokens = server_tokens(server)
    return analyze_tokens(tokens)


def analyze_tokens(tokens: list[Token], depth: int = 0) -> ServerExec:
    if not tokens:
        return ServerExec(None, tokens)
    head = _base(tokens[0].text)
    rest = tokens[1:]

    # Unwrap shells and Windows wrappers: `cmd /c npx ...`, `bash -c "npx ..."`, `env FOO=1 npx ...`
    if head in _SHELLS and depth < 3:
        for i, t in enumerate(rest):
            if t.text.lower() in ("-c", "/c", "-command", "/k", "-lc", "-ic"):
                remaining = rest[i + 1 :]
                if len(remaining) == 1 and (" " in remaining[0].text):
                    inner = [Token(p, remaining[0].path, True) for p in _split(remaining[0].text)]
                    ex = analyze_tokens(inner, depth + 1)
                    ex.shell_string = remaining[0]
                    ex.tokens = tokens
                    return ex
                ex = analyze_tokens(remaining, depth + 1)
                ex.tokens = tokens
                return ex
        return ServerExec(head, tokens, server_args=rest)
    if head == "env" and depth < 3:
        i = 0
        while i < len(rest) and ("=" in rest[i].text or rest[i].text.startswith("-")):
            i += 1
        ex = analyze_tokens(rest[i:], depth + 1)
        ex.tokens = tokens
        return ex

    if head in ("npx", "bunx"):
        return _npm_like(head, tokens, rest)
    if head in ("pnpm", "yarn", "bun") and rest and rest[0].text in ("dlx", "x"):
        return _npm_like(f"{head} {rest[0].text}", tokens, rest[1:])
    if head == "npm" and rest and rest[0].text in ("exec", "x"):
        return _npm_like("npm exec", tokens, rest[1:])
    if head == "uvx":
        return _py_like("uvx", tokens, rest)
    if head == "uv" and len(rest) >= 2 and rest[0].text == "tool" and rest[1].text == "run":
        return _py_like("uv tool run", tokens, rest[2:])
    if head == "pipx" and rest and rest[0].text == "run":
        return _py_like("pipx run", tokens, rest[1:])
    if head in ("docker", "podman", "nerdctl") and rest and rest[0].text in ("run", "container"):
        start = 2 if rest[0].text == "container" and len(rest) > 1 and rest[1].text == "run" else 1
        return _docker(head, tokens, rest[start:])
    return ServerExec(head, tokens, server_args=rest)


# --------------------------------------------------------------------------------------


def parse_npm_spec(spec: str) -> tuple[str, str | None]:
    s = spec[4:] if spec.startswith("npm:") else spec
    if s.startswith("@"):
        at = s.find("@", 1)
    else:
        at = s.find("@")
    if at <= 0:
        return s, None
    return s[:at], s[at + 1 :] or None


def _is_remote(spec: str) -> bool:
    return bool(re.match(r"^(?:https?://|git\+|git://|github:|gitlab:|bitbucket:|ssh://)", spec)) or (
        "/" in spec and not spec.startswith("@") and re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", spec) is not None
    )


def _git_ref(spec: str, launcher: str, path: JsonPath, ecosystem_hint: str) -> PackageRef:
    ref = None
    m = re.search(r"[#@]([^#@/]+)$", spec)
    if m:
        ref = m.group(1)
    pinned = bool(ref and _GIT_SHA_RE.match(ref))
    return PackageRef("git", spec, spec.split("#")[0], ref, pinned, launcher, path)


_NPX_VALUE_OPTS = {"-p", "--package", "-c", "--call", "--registry", "--cache", "--userconfig", "--node-options"}


def _npm_like(launcher: str, tokens: list[Token], rest: list[Token]) -> ServerExec:
    ex = ServerExec(launcher, tokens)
    explicit: list[Token] = []
    i = 0
    first_positional: int | None = None
    while i < len(rest):
        t = rest[i].text
        if t == "--":
            first_positional = i + 1 if i + 1 < len(rest) else None
            break
        if t.startswith("--package="):
            explicit.append(Token(t.split("=", 1)[1], rest[i].path, rest[i].from_shell))
        elif t in ("-p", "--package") and i + 1 < len(rest):
            explicit.append(rest[i + 1])
            i += 1
        elif t in _NPX_VALUE_OPTS and i + 1 < len(rest):
            i += 1
        elif t.startswith("-"):
            pass
        else:
            first_positional = i
            break
        i += 1
    pkg_tokens = list(explicit)
    if first_positional is not None:
        if not explicit:
            pkg_tokens.append(rest[first_positional])
        ex.server_args = rest[first_positional + 1 :]
    for tok in pkg_tokens:
        spec = tok.text
        if _is_remote(spec):
            ex.packages.append(_git_ref(spec, launcher, tok.path, "npm"))
            continue
        if spec.startswith((".", "/", "file:")):
            continue
        name, version = parse_npm_spec(spec)
        pinned = bool(version and _SEMVER_RE.match(version))
        ex.packages.append(PackageRef("npm", spec, name, version, pinned, launcher, tok.path))
    return ex


_UVX_VALUE_OPTS = {
    "--from", "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index-url", "-i",
    "--extra-index-url", "--index", "--default-index", "--constraint", "-c", "--override", "--spec",
    "--find-links", "-f", "--cache-dir", "--python-preference", "--resolution", "--prerelease",
    "--allow-insecure-host", "--trusted-host", "--keyring-provider", "--exclude-newer", "--refresh-package",
    "--reinstall-package", "--upgrade-package", "--index-strategy", "--config-setting", "-C", "--link-mode",
    "--python-platform", "--env-file", "--directory", "--project", "--config-file",
}  # fmt: skip


def parse_py_spec(spec: str) -> tuple[str, str | None, bool]:
    s = spec.strip()
    m = _PY_SPEC_RE.match(s)
    if not m:
        return s, None, False
    op, ver = m.group("op"), m.group("ver")
    if op is None:
        return m.group("name"), None, False
    ver = ver.strip()
    pinned = op in ("==", "===", "@") and bool(_PEP440_EXACT_RE.match(ver) or _SEMVER_RE.match(ver)) and "," not in ver
    return m.group("name"), f"{op}{ver}", pinned


def _py_like(launcher: str, tokens: list[Token], rest: list[Token]) -> ServerExec:
    ex = ServerExec(launcher, tokens)
    from_tok: Token | None = None
    withs: list[Token] = []
    first_positional: int | None = None
    i = 0
    while i < len(rest):
        t = rest[i].text
        opt, eq, val = t.partition("=")
        if opt in ("--from", "--spec") and eq:
            from_tok = Token(val, rest[i].path, rest[i].from_shell)
        elif opt == "--with" and eq:
            withs.append(Token(val, rest[i].path, rest[i].from_shell))
        elif t in ("--from", "--spec") and i + 1 < len(rest):
            from_tok = rest[i + 1]
            i += 1
        elif t == "--with" and i + 1 < len(rest):
            withs.append(rest[i + 1])
            i += 1
        elif t in _UVX_VALUE_OPTS and i + 1 < len(rest):
            i += 1
        elif t.startswith("-"):
            pass
        else:
            first_positional = i
            break
        i += 1
    pkg_tokens = [from_tok] if from_tok else []
    if first_positional is not None:
        if from_tok is None:
            pkg_tokens.append(rest[first_positional])
        ex.server_args = rest[first_positional + 1 :]
    pkg_tokens.extend(withs)
    for tok in pkg_tokens:
        spec = tok.text
        if _is_remote(spec) or spec.startswith("git+"):
            ex.packages.append(_git_ref(spec, launcher, tok.path, "pypi"))
            continue
        if spec.startswith((".", "/")):
            continue
        name, version, pinned = parse_py_spec(spec)
        ex.packages.append(PackageRef("pypi", spec, name, version, pinned, launcher, tok.path))
    return ex


_DOCKER_VALUE_OPTS = {
    "-e", "--env", "-v", "--volume", "--mount", "--name", "-p", "--publish", "--network", "--net", "-w",
    "--workdir", "--env-file", "-u", "--user", "--entrypoint", "--platform", "-l", "--label", "--cpus",
    "--memory", "-m", "--add-host", "--cap-add", "--cap-drop", "--security-opt", "--hostname", "-h",
    "--pull", "--restart", "--ulimit", "--device", "--tmpfs", "--log-driver", "--log-opt", "--pid",
    "--ipc", "--runtime", "--gpus", "--dns", "--expose", "--label-file", "--shm-size", "--stop-signal",
}  # fmt: skip


def parse_image(ref: str) -> tuple[str, str | None, bool]:
    """Return ``(name, tag_or_digest, pinned)``. A digest or an explicit non-latest tag counts as pinned."""
    if "@sha256:" in ref:
        name, digest = ref.split("@", 1)
        return name, digest, True
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
        return name, tag, tag.lower() not in ("latest", "main", "master", "edge", "nightly", "dev")
    return ref, None, False


def _docker(head: str, tokens: list[Token], rest: list[Token]) -> ServerExec:
    ex = ServerExec(head, tokens)
    d = DockerRun()
    ex.docker = d
    i = 0
    while i < len(rest):
        tok = rest[i]
        t = tok.text
        opt, eq, val = t.partition("=")
        if t.startswith("--") and eq:
            if opt in ("--volume", "--mount"):
                d.volumes.append(Token(val, tok.path, tok.from_shell))
            elif opt == "--env":
                d.env_flags.append(Token(val, tok.path, tok.from_shell))
            elif opt in ("--network", "--net") and val == "host":
                d.network_host = True
            elif opt == "--privileged" and val.lower() != "false":
                d.privileged, d.privileged_token = True, tok
        elif t in _DOCKER_VALUE_OPTS and i + 1 < len(rest):
            nxt = rest[i + 1]
            if t in ("-v", "--volume", "--mount"):
                d.volumes.append(nxt)
            elif t in ("-e", "--env"):
                d.env_flags.append(nxt)
            elif t in ("--network", "--net") and nxt.text == "host":
                d.network_host = True
            i += 1
        elif t == "--privileged":
            d.privileged, d.privileged_token = True, tok
        elif t.startswith("-"):
            pass
        else:
            d.image = tok
            ex.server_args = rest[i + 1 :]
            name, tag, pinned = parse_image(t)
            ex.packages.append(PackageRef("docker", t, name, tag, pinned, head, tok.path))
            break
        i += 1
    return ex
