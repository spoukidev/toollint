"""TL2xx: permission scope of servers and tools."""

from __future__ import annotations

import re
from collections.abc import Iterator

from toollint.commands import Token, analyze
from toollint.document import Document
from toollint.model import Category, Finding, Server, Severity, Tool
from toollint.normalize import safe_display, split_identifier
from toollint.rules.base import Rule, ScanContext, register

# --------------------------------------------------------------------------------------
# TL201
# --------------------------------------------------------------------------------------

_HOME_RE = re.compile(
    r"""^(?:
        /|~|~/|\$HOME/?|\$\{HOME\}/?|\$\{env:HOME\}/?|\$\{userHome\}/?|%USERPROFILE%\\?|%HOMEPATH%\\?|
        /root/?|/home/?|/Users/?|/home/[^/]+/?|/Users/[^/]+/?|
        [A-Za-z]:\\?|[A-Za-z]:/|[A-Za-z]:\\Users\\[^\\]+\\?|[A-Za-z]:/Users/[^/]+/?
    )$""",
    re.VERBOSE,
)
_FS_PACKAGE_RE = re.compile(
    r"(?:^|[/@_-])(?:server-)?(?:filesystem|file-system|fs)(?:-mcp|-server|$|@)|mcp-server-filesystem|filesystem-mcp",
    re.I,
)
_DOCKER_SOCK_RE = re.compile(r"(?:^|[=,:])/var/run/docker\.sock|(?:^|[=,:])/run/docker\.sock")


def is_broad_root(path: str) -> bool:
    return bool(_HOME_RE.match(path.strip().strip('"').strip("'")))


def _mount_source(spec: str) -> str | None:
    """``/src:/dst[:ro]`` or ``type=bind,src=/,dst=/x`` -> source."""
    if "=" in spec and ("src=" in spec or "source=" in spec):
        for part in spec.split(","):
            k, _, v = part.partition("=")
            if k in ("src", "source"):
                return v
        return None
    # Windows drive letters: C:\Users\me:/data
    m = re.match(r"^([A-Za-z]:[\\/][^:]*|[^:]+):", spec)
    return m.group(1) if m else None


def _is_filesystem_server(server: Server, names: list[str]) -> bool:
    return any(_FS_PACKAGE_RE.search(n) for n in names) or server.name.lower() in ("filesystem", "fs", "files")


@register
class BroadFilesystemRoot(Rule):
    """
    ## What it does

    Flags filesystem access rooted at `/`, a drive root, `~`, `$HOME`, or a whole
    home directory (`/Users/alice`, `/home/alice`, `C:\\Users\\alice`). It checks
    the allowed directories passed to filesystem MCP servers and bind mounts
    passed to `docker run -v`. A root or home path given to any other server is
    reported at medium severity.

    ## Why is this bad?

    A home directory holds SSH keys, cloud credentials, browser profiles, shell
    history and every other project. One prompt injection anywhere in the agent's
    context can then read or overwrite all of it.

    ## Example

    ```json
    {"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.7.29", "/Users/alice"]}}}
    ```

    ## Fix

    Grant only the project directories the agent needs, for example
    `/Users/alice/code/my-app`. Use read-only mounts (`:ro`) for Docker.
    """

    id = "TL201"
    name = "broad-filesystem-root"
    category = Category.PERMISSIONS
    severity = Severity.HIGH
    summary = "Filesystem access rooted at /, ~ or a home directory"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            ex = analyze(server)
            names = [p.name for p in ex.packages] + ([ex.launcher] if ex.launcher else [])
            sname = safe_display(server.name, 60)
            if ex.docker:
                for vol in ex.docker.volumes:
                    src = _mount_source(vol.text)
                    if src and is_broad_root(src):
                        yield self.report(
                            doc,
                            vol.path,
                            f"Server '{sname}' mounts {safe_display(src, 60)!r} into its container",
                            fix="Mount only the directories the server needs, read-only where possible (-v /path/project:/data:ro).",
                            key=f"mount:{vol.text}",
                        )
                continue
            fs = _is_filesystem_server(server, names)
            for tok in ex.server_args:
                if tok.text.startswith("-"):
                    value = tok.text.partition("=")[2]
                    if not value:
                        continue
                else:
                    value = tok.text
                if is_broad_root(value):
                    yield self.report(
                        doc,
                        tok.path,
                        f"Server '{sname}' is given access to {safe_display(value, 60)!r}"
                        + (" (filesystem server)" if fs else ""),
                        severity=Severity.HIGH if fs else Severity.MEDIUM,
                        fix="Pass specific project directories instead of a root or home directory.",
                        key=f"root:{tok.text}",
                    )


# --------------------------------------------------------------------------------------
# TL202
# --------------------------------------------------------------------------------------

_SHELL_PACKAGE_RE = re.compile(
    r"(?:shell|terminal|desktop-commander|server-commands|command-runner|cmd-mcp|exec-mcp|mcp-exec|run-command|bash-mcp|mcp-bash|powershell)",
    re.I,
)
_ALLOWLIST_RE = re.compile(r"allow|whitelist|permit|restrict|sandbox", re.I)
_SHELLISH_TOKENS = {"shell", "bash", "zsh", "terminal", "powershell", "pwsh", "subprocess"}
_EXEC_VERBS = {"exec", "execute", "run", "eval", "spawn"}
_EXEC_OBJ_TOKENS = {"command", "commands", "cmd", "script", "process", "code"}
_CMD_PARAM_NAMES = {"command", "cmd", "script", "shell_command", "commandline", "command_line", "bash_command", "code"}


@register
class UnrestrictedShell(Rule):
    """
    ## What it does

    Flags arbitrary command execution with no allowlist:

    * shell/terminal MCP servers (`mcp-shell`, `desktop-commander`, …) whose args and
      env contain no allowlist setting (`--allowed-commands`, `ALLOWED_COMMANDS`, …)
    * tool definitions such as `run_command(command: string)` whose command
      parameter has no `enum` or `pattern` constraint
    * Docker servers started with `--privileged` or with the Docker socket
      mounted, which is root on the host

    ## Why is this bad?

    A shell tool turns any prompt injection, from a web page, an issue comment or
    a poisoned tool, into code execution on your machine.

    ## Example

    ```json
    {"name": "run_command", "description": "Run a shell command.",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}}
    ```

    ## Fix

    Configure an allowlist of commands, constrain the parameter with `enum` or
    `pattern`, run the server in a sandbox without the Docker socket, and require
    the user to confirm each call.
    """

    id = "TL202"
    name = "unrestricted-shell"
    category = Category.PERMISSIONS
    severity = Severity.HIGH
    summary = "Shell/exec access with no allowlist"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            yield from self._check_server(doc, server)
        for tool in doc.tools:
            yield from self._check_tool(doc, tool)

    def _check_server(self, doc: Document, server: Server) -> Iterator[Finding]:
        ex = analyze(server)
        sname = safe_display(server.name, 60)
        if ex.docker:
            if ex.docker.privileged and ex.docker.privileged_token:
                yield self.report(
                    doc,
                    ex.docker.privileged_token.path,
                    f"Server '{sname}' runs a privileged container (equivalent to root on the host)",
                    fix="Drop --privileged; add only the specific capabilities the server needs.",
                    key="privileged",
                )
            for vol in ex.docker.volumes:
                if _DOCKER_SOCK_RE.search(vol.text):
                    yield self.report(
                        doc,
                        vol.path,
                        f"Server '{sname}' mounts the Docker socket, which gives root-equivalent control of the host",
                        fix="Do not mount /var/run/docker.sock into MCP servers.",
                        key="docker-sock",
                    )
        names = [p.name for p in ex.packages]
        if not any(_SHELL_PACKAGE_RE.search(n) for n in names) and not _SHELL_PACKAGE_RE.search(server.name):
            return
        haystack = " ".join([*server.args, *server.env.keys(), *server.env.values()])
        if _ALLOWLIST_RE.search(haystack):
            return
        target = ex.packages[0].path if ex.packages else server.path
        yield self.report(
            doc,
            target,
            f"Server '{sname}' exposes shell command execution with no allowlist configured",
            fix="Configure the server's command allowlist (for example --allowed-commands or ALLOWED_COMMANDS) and require confirmation.",
            key="shell-server",
        )

    def _check_tool(self, doc: Document, tool: Tool) -> Iterator[Finding]:
        parts = split_identifier(tool.name)
        if not parts or parts[0] in _SAFE_PREFIX:
            return
        tokens = set(parts)
        shellish = bool(tokens & _SHELLISH_TOKENS)
        exec_verb = bool(tokens & _EXEC_VERBS)
        name_is_exec = shellish or (exec_verb and bool(tokens & _EXEC_OBJ_TOKENS))
        cmd_params = [p for p in tool.params if p.name.lower() in _CMD_PARAM_NAMES and p.type in (None, "string")]
        if not name_is_exec and not (cmd_params and (exec_verb or shellish)):
            return
        if tool.extensions.get("x-allowed-commands") or tool.annotations.get("allowedCommands"):
            return
        candidates = cmd_params or [p for p in tool.params if p.type in (None, "string") and "." not in p.name]
        if not candidates:
            return
        unconstrained = [p for p in candidates if not (p.has_enum or p.has_pattern)]
        if not unconstrained:
            return
        yield self.report(
            doc,
            unconstrained[0].path,
            f"Tool '{safe_display(tool.name, 60)}' executes arbitrary commands via unconstrained parameter "
            f"'{safe_display(unconstrained[0].name, 40)}'",
            fix="Constrain the command with an enum/pattern allowlist, or replace it with narrow, purpose-built tools.",
            key="shell-tool",
        )


# --------------------------------------------------------------------------------------
# TL203
# --------------------------------------------------------------------------------------

_DESTRUCTIVE = {
    "delete", "remove", "rm", "drop", "destroy", "purge", "wipe", "erase", "truncate", "send", "pay", "transfer",
    "withdraw", "refund", "charge", "purchase", "buy", "publish", "deploy", "kill", "terminate", "revoke", "format",
    "shutdown", "reboot", "uninstall", "overwrite", "nuke", "ban", "unpublish",
}  # fmt: skip
_SAFE_PREFIX = {
    "get",
    "list",
    "read",
    "search",
    "find",
    "fetch",
    "describe",
    "show",
    "preview",
    "estimate",
    "draft",
    "validate",
    "check",
    "query",
    "count",
}
_CONFIRM_PARAMS = {
    "confirm",
    "confirmed",
    "confirmation",
    "dry_run",
    "dryrun",
    "require_confirmation",
    "preview",
    "force",
}
_CONFIRM_TEXT_RE = re.compile(
    r"requires? (?:explicit )?(?:user )?(?:confirmation|approval)|asks? the user to confirm|after the user confirms",
    re.I,
)


@register
class DestructiveWithoutConfirmation(Rule):
    """
    ## What it does

    Flags tools whose name says they do something irreversible or external
    (delete, drop, send, pay, transfer, deploy, revoke…) when the definition gives
    the client no way to tell: no MCP `destructiveHint: true` annotation, no
    `confirm` / `dry_run` parameter, and no `x-requires-confirmation` extension.

    It is **high** severity when such a tool claims `readOnlyHint: true`, because
    that tells clients they can skip asking the user.

    ## Why is this bad?

    Clients use annotations to decide when to ask the user before a call. A
    `delete_repository` tool that looks harmless can be called automatically,
    so one injected instruction is enough to destroy data or move money.

    ## Example

    ```json
    {"name": "transfer_funds", "description": "Transfer money between accounts.", "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}}}}
    ```

    ## Fix

    Add `"annotations": {"destructiveHint": true}` (MCP), a required `confirm`
    parameter, or `"x-requires-confirmation": true`, and turn on
    per-call approval in your client.
    """

    id = "TL203"
    name = "destructive-without-confirmation"
    category = Category.PERMISSIONS
    severity = Severity.MEDIUM
    summary = "Destructive tools with no confirmation or honest annotations"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for tool in doc.tools:
            tokens = split_identifier(tool.name)
            if not tokens or tokens[0] in _SAFE_PREFIX:
                continue
            verbs = [t for t in tokens if t in _DESTRUCTIVE]
            if not verbs:
                continue
            ann = tool.annotations
            tname = safe_display(tool.name, 60)
            if ann.get("readOnlyHint") is True:
                yield self.report(
                    doc,
                    tool.path + ("annotations", "readOnlyHint"),
                    f"Tool '{tname}' looks destructive ('{verbs[0]}') but declares readOnlyHint: true, so clients may run it without asking",
                    severity=Severity.HIGH,
                    fix="Set readOnlyHint to false and destructiveHint to true.",
                    key="readonly-lie",
                )
                continue
            if ann.get("destructiveHint") is True:
                continue
            if tool.extensions.get("x-requires-confirmation") is True or tool.extensions.get("x-confirm") is True:
                continue
            if any(p.name.lower().split(".")[-1] in _CONFIRM_PARAMS for p in tool.params):
                continue
            if _CONFIRM_TEXT_RE.search(tool.description):
                continue
            yield self.report(
                doc,
                tool.path + ("name",),
                f"Tool '{tname}' performs a destructive action ('{verbs[0]}') with no confirmation parameter or destructiveHint annotation",
                fix='Add "annotations": {"destructiveHint": true} or a required "confirm" parameter.',
                key="destructive",
            )


# --------------------------------------------------------------------------------------
# TL204
# --------------------------------------------------------------------------------------

_CLOUD_ROOT_VARS = re.compile(
    r"^(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_ACCESS_KEY_ID|AWS_PROFILE|GOOGLE_APPLICATION_CREDENTIALS|"
    r"AZURE_CLIENT_SECRET|AZURE_CREDENTIALS|ARM_CLIENT_SECRET|KUBECONFIG|SSH_AUTH_SOCK|NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_TOKEN|"
    r"TWINE_PASSWORD|DOCKER_AUTH_CONFIG|VAULT_TOKEN|CI_JOB_TOKEN)$"
)
_GH_TOKEN_VARS = re.compile(r"^(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GH_ENTERPRISE_TOKEN)$")
_REF_RE = re.compile(
    r"^\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_*]*)\}$|^\$([A-Za-z_][A-Za-z0-9_*]*)$|^%([A-Za-z_][A-Za-z0-9_*]*)%$"
)
_PASSTHROUGH_KEYS = ("envPassthrough", "env_passthrough", "passEnv", "inheritEnv", "inherit_env", "envAllowlist")


def _referenced_var(value: str) -> str | None:
    m = _REF_RE.match(value.strip())
    return next((g for g in m.groups() if g), None) if m else None


@register
class BroadEnvPassthrough(Rule):
    """
    ## What it does

    Flags servers that receive broad or high-value environment variables:

    * wildcards (`"*"`, `AWS_*`) in `env`, in pass-through settings
      (`envPassthrough`, `inheritEnv: true`), or in `docker run -e`
    * cloud root credentials (`AWS_SECRET_ACCESS_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`,
      `KUBECONFIG`, `SSH_AUTH_SOCK`, `NPM_TOKEN`, …) passed through by reference
    * `GITHUB_TOKEN` / `GH_TOKEN` handed to a server that is not a GitHub server

    ## Why is this bad?

    Every variable a server receives can leak through a bug, a log line or a
    poisoned tool. Ambient credentials such as CI tokens and cloud keys usually
    carry far more access than the server needs.

    ## Example

    ```json
    {"mcpServers": {"notes": {"command": "notes-mcp", "env": {"AWS_SECRET_ACCESS_KEY": "${env:AWS_SECRET_ACCESS_KEY}", "*": "inherit"}}}}
    ```

    ## Fix

    Pass only the variables the server needs. Prefer a dedicated, narrowly scoped
    token per server.
    """

    id = "TL204"
    name = "broad-env-passthrough"
    category = Category.PERMISSIONS
    severity = Severity.MEDIUM
    summary = "Wildcard or high-value environment variables passed to a server"

    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        for server in doc.servers:
            sname = safe_display(server.name, 60)
            raw = doc.get(server.path) or {}
            is_github = "github" in (server.name + " " + " ".join(server.args) + " " + (server.command or "")).lower()
            for key in _PASSTHROUGH_KEYS:
                val = raw.get(key) if isinstance(raw, dict) else None
                if (
                    val is True
                    or (isinstance(val, list) and any(isinstance(v, str) and "*" in v for v in val))
                    or val == "*"
                ):
                    yield self.report(
                        doc,
                        server.path + (key,),
                        f"Server '{sname}' inherits the whole environment ({key}={safe_display(str(val), 40)})",
                        severity=Severity.HIGH,
                        fix="List the specific variables the server needs instead of inheriting everything.",
                        key=f"passthrough:{key}",
                    )
            for k, v in server.env.items():
                path = server.env_path(k)
                ref = _referenced_var(v)
                if "*" in k or (ref and "*" in ref):
                    yield self.report(
                        doc,
                        path,
                        f"Server '{sname}' passes a wildcard environment variable ({safe_display(k, 40)})",
                        severity=Severity.HIGH,
                        fix="Replace the wildcard with the specific variables the server needs.",
                        key=f"wild:{k}",
                    )
                    continue
                var = ref or k
                if ref and _CLOUD_ROOT_VARS.match(var):
                    yield self.report(
                        doc,
                        path,
                        f"Server '{sname}' receives the ambient credential {var}",
                        fix="Create a narrowly scoped credential for this server instead of passing your main one.",
                        key=f"cloud:{k}",
                    )
                elif ref and _GH_TOKEN_VARS.match(var) and not is_github:
                    yield self.report(
                        doc,
                        path,
                        f"Server '{sname}' is not a GitHub server but receives {var}",
                        fix="Do not hand your GitHub token to unrelated servers.",
                        key=f"gh:{k}",
                    )
            ex = analyze(server)
            if ex.docker:
                for tok in ex.docker.env_flags:
                    yield from self._docker_env(doc, sname, tok)

    def _docker_env(self, doc: Document, sname: str, tok: Token) -> Iterator[Finding]:
        name = tok.text.split("=", 1)[0]
        if "*" in name:
            yield self.report(
                doc,
                tok.path,
                f"Server '{sname}' passes a wildcard environment variable into its container ({safe_display(name, 40)})",
                severity=Severity.HIGH,
                fix="Pass specific variables with -e NAME.",
                key=f"docker-wild:{name}",
            )
        elif "=" not in tok.text and _CLOUD_ROOT_VARS.match(name):
            yield self.report(
                doc,
                tok.path,
                f"Server '{sname}' passes the ambient credential {name} into its container",
                fix="Create a narrowly scoped credential for this server instead of passing your main one.",
                key=f"docker-cloud:{name}",
            )
