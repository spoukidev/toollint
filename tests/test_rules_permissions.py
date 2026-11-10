from __future__ import annotations

import pytest

from tests.conftest import codes, lint, server, tool

FS = "@modelcontextprotocol/server-filesystem@2025.8.21"

# ---------------------------------------------------------------- TL201


@pytest.mark.parametrize(
    "root",
    [
        "/",
        "~",
        "~/",
        "$HOME",
        "${HOME}",
        "${userHome}",
        "/Users/alice",
        "/home/bob/",
        "C:\\",
        "C:\\Users\\carol",
        "/root",
    ],
)
def test_tl201_filesystem_roots(root: str) -> None:
    f = lint(server(command="npx", args=["-y", FS, root]), select=["TL201"])
    assert f and f[0].severity.value == "high"
    assert f[0].location.json_path == "$.mcpServers.srv.args[2]"


@pytest.mark.parametrize(
    "root", ["/Users/alice/code/app", "/home/bob/projects", "~/projects/site", "/tmp/scratch", "./data"]
)
def test_tl201_specific_dirs_are_fine(root: str) -> None:
    assert lint(server(command="npx", args=["-y", FS, root]), select=["TL201"]) == []


def test_tl201_other_server_with_home_is_medium() -> None:
    f = lint(server(command="uvx", args=["mcp-server-git==2025.7.1", "--repository", "~"]), select=["TL201"])
    assert f and f[0].severity.value == "medium"


@pytest.mark.parametrize("mount", ["/:/host", "/Users/alice:/data", "type=bind,src=/home/bob,dst=/x"])
def test_tl201_docker_mounts(mount: str) -> None:
    flag = "--mount" if mount.startswith("type=") else "-v"
    f = lint(
        server(command="docker", args=["run", "-i", "--rm", flag, mount, "mcp/filesystem:1.0.0", "/x"]),
        select=["TL201"],
    )
    assert "TL201" in codes(f)


def test_tl201_docker_narrow_mount_is_fine() -> None:
    args = ["run", "-i", "--rm", "-v", "/Users/alice/code/app:/data:ro", "mcp/filesystem:1.0.0", "/data"]
    assert lint(server(command="docker", args=args), select=["TL201"]) == []


# ---------------------------------------------------------------- TL202


def test_tl202_shell_server_without_allowlist() -> None:
    assert "TL202" in codes(
        lint(server(command="npx", args=["-y", "@wonderwhy-er/desktop-commander@0.2.3"]), select=["TL202"])
    )


def test_tl202_shell_server_with_allowlist() -> None:
    srv = server(command="uvx", args=["mcp-shell-server==1.0.3"], env={"ALLOW_COMMANDS": "ls,cat"})
    assert lint(srv, select=["TL202"]) == []


def test_tl202_privileged_and_docker_socket() -> None:
    args = ["run", "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock", "acme/tool:1.0.0"]
    f = lint(server(command="docker", args=args), select=["TL202"])
    assert len(f) == 2


@pytest.mark.parametrize(
    ("name", "props"),
    [
        ("run_command", {"command": {"type": "string"}}),
        ("execute_shell", {"cmd": {"type": "string"}}),
        ("bash", {"script": {"type": "string"}}),
        ("terminal_exec", {"input": {"type": "string"}}),
    ],
)
def test_tl202_exec_tools(name: str, props: dict[str, object]) -> None:
    assert "TL202" in codes(lint(tool(name=name, properties=props), select=["TL202"]))


@pytest.mark.parametrize(
    ("name", "props"),
    [
        ("run_command", {"command": {"type": "string", "enum": ["test", "lint"]}}),
        ("run_command", {"command": {"type": "string", "pattern": "^git (status|diff)$"}}),
        ("execute_sql", {"sql": {"type": "string"}}),
        ("get_shell_history", {"limit": {"type": "number"}}),
        ("run_tests", {"path": {"type": "string"}}),
    ],
)
def test_tl202_exec_tool_negatives(name: str, props: dict[str, object]) -> None:
    assert lint(tool(name=name, properties=props), select=["TL202"]) == []


# ---------------------------------------------------------------- TL203


@pytest.mark.parametrize("name", ["delete_repository", "transferFunds", "send-payment", "drop_table", "deploy_service"])
def test_tl203_destructive_without_confirmation(name: str) -> None:
    f = lint(tool(name=name), select=["TL203"])
    assert f and f[0].severity.value == "medium"


def test_tl203_readonly_lie_is_high() -> None:
    f = lint(tool(name="delete_user", annotations={"readOnlyHint": True}), select=["TL203"])
    assert f and f[0].severity.value == "high"


@pytest.mark.parametrize(
    "extra",
    [
        {"annotations": {"destructiveHint": True}},
        {"x-requires-confirmation": True},
        {"description": "Deletes a user. Requires user confirmation."},
    ],
)
def test_tl203_confirmation_signals(extra: dict[str, object]) -> None:
    assert lint(tool(name="delete_user", **extra), select=["TL203"]) == []


def test_tl203_confirm_param() -> None:
    assert lint(tool(name="delete_user", properties={"confirm": {"type": "boolean"}}), select=["TL203"]) == []


@pytest.mark.parametrize(
    "name", ["list_deleted_items", "get_payment_status", "read_file", "create_issue", "preview_deploy"]
)
def test_tl203_negatives(name: str) -> None:
    assert lint(tool(name=name), select=["TL203"]) == []


# ---------------------------------------------------------------- TL204


def test_tl204_wildcards() -> None:
    f = lint(server(command="x", env={"*": "inherit", "AWS_*": "${AWS_*}"}), select=["TL204"])
    assert len(f) == 2 and all(x.severity.value == "high" for x in f)


def test_tl204_inherit_env() -> None:
    assert lint(server(command="x", inheritEnv=True), select=["TL204"])


def test_tl204_cloud_credentials_by_reference() -> None:
    f = lint(server(command="x", env={"AWS_SECRET_ACCESS_KEY": "${env:AWS_SECRET_ACCESS_KEY}"}), select=["TL204"])
    assert f and f[0].severity.value == "medium"


def test_tl204_github_token_to_non_github_server() -> None:
    assert lint(server(command="notes-mcp", env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"}), select=["TL204"])
    gh = {"mcpServers": {"github": {"command": "github-mcp", "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}
    assert lint(gh, select=["TL204"]) == []


def test_tl204_docker_env_flags() -> None:
    args = ["run", "-e", "AWS_SESSION_TOKEN", "-e", "LOG_LEVEL=debug", "acme/x:1.0.0"]
    f = lint(server(command="docker", args=args), select=["TL204"])
    assert len(f) == 1


def test_tl204_negative() -> None:
    assert (
        lint(server(command="x", env={"LOG_LEVEL": "info", "API_URL": "https://api.example"}), select=["TL204"]) == []
    )
