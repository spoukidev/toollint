from __future__ import annotations

import pytest

from tests.conftest import FAKE, codes, lint, server, tool

# ---------------------------------------------------------------- TL401


@pytest.mark.parametrize("kind", sorted(FAKE))
def test_tl401_known_formats_in_env(kind: str) -> None:
    f = lint(server(command="x", env={"VALUE": FAKE[kind]}), select=["TL401"])
    assert f, kind
    assert FAKE[kind] not in f[0].message
    assert f[0].fixable


def test_tl401_anywhere_in_document() -> None:
    f = lint(tool(description=f"Use key {FAKE['openai']} to call the API."), select=["TL401"])
    assert f and not f[0].fixable
    f = lint(server(command="x", args=["--key", FAKE["stripe"]]), select=["TL401"])
    assert f


def test_tl401_anthropic_is_not_reported_as_openai() -> None:
    f = lint(server(command="x", env={"K": FAKE["anthropic"]}), select=["TL401"])
    assert len(f) == 1 and "Anthropic" in f[0].message


@pytest.mark.parametrize("value", ["${env:GITHUB_TOKEN}", "sk-...", "ghp_short", "AKIA-not-a-key", "eyJhbGciOi"])
def test_tl401_negatives(value: str) -> None:
    assert lint(server(command="x", env={"VALUE": value}), select=["TL401"]) == []


# ---------------------------------------------------------------- TL402


def test_tl402_high_entropy_literal() -> None:
    f = lint(server(command="x", env={"CRM_LICENSE": "q8Zr2Lx9TfW4mKp7Vn3Hy6Bc1Jd5Gs0E"}), select=["TL402"])
    assert f and f[0].fixable


def test_tl402_headers() -> None:
    doc = {"mcpServers": {"x": {"url": "https://x.example", "headers": {"X-Custom": "Zq81Lm02Xp93Kv74Hb65Tc46Nd37"}}}}
    assert lint(doc, select=["TL402"])


@pytest.mark.parametrize(
    "value",
    [
        "${env:CRM_LICENSE}",
        "/Users/alice/projects/app/data/catalog.db",
        "https://api.example/v1/very/long/path",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "production-eu-west-1-cluster",
        "0123456789012345678901234",
    ],
)
def test_tl402_negatives(value: str) -> None:
    assert lint(server(command="x", env={"SETTING": value}), select=["TL402"]) == []


# ---------------------------------------------------------------- TL403


@pytest.mark.parametrize("key", ["DB_PASSWORD", "OPENWEATHER_API_KEY", "SERVICE_TOKEN", "CLIENT_SECRET", "apiKey"])
def test_tl403_literal_values(key: str) -> None:
    f = lint(server(command="x", env={key: "hunter2-but-longer"}), select=["TL403"])
    assert f and f[0].fixable
    assert "hunter2-but-longer" not in f[0].message


def test_tl403_authorization_header() -> None:
    doc = {"mcpServers": {"x": {"url": "https://x.example", "headers": {"Authorization": "Bearer abcdef123456"}}}}
    assert lint(doc, select=["TL403"])


def test_tl403_command_line_argument() -> None:
    f = lint(server(command="x", args=["--api-key", "abcdef123456"]), select=["TL403"])
    assert f and not f[0].fixable
    assert lint(server(command="x", args=["--token=abcdef123456"]), select=["TL403"])


@pytest.mark.parametrize(
    "value",
    [
        "${env:DB_PASSWORD}",
        "${DB_PASSWORD}",
        "${input:db-password}",
        "$DB_PASSWORD",
        "%DB_PASSWORD%",
        "<your-password>",
        "YOUR_API_KEY_HERE",
        "op://vault/item/password",
        "Bearer ${TOKEN}",
        "",
        "true",
    ],
)
def test_tl403_references_and_placeholders(value: str) -> None:
    assert lint(server(command="x", env={"DB_PASSWORD": value}), select=["TL403"]) == []


@pytest.mark.parametrize("key", ["TOKEN_URL", "AUTH_TYPE", "SECRET_FILE_PATH", "PATH"])
def test_tl403_non_secret_keys(key: str) -> None:
    assert lint(server(command="x", env={key: "some-literal-value"}), select=["TL403"]) == []


# ---------------------------------------------------------------- TL404


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example/sse?api_key=live_4f9c2d7e1b8a",
        "https://mcp.example/sse?x=1&token=abcdef0123456789",
        "https://user:Sup3rS3cret@mcp.example/mcp",
    ],
)
def test_tl404_positives(url: str) -> None:
    assert "TL404" in codes(lint({"mcpServers": {"x": {"url": url}}}, select=["TL404"]))


def test_tl404_in_args() -> None:
    assert lint(
        server(command="npx", args=["-y", "mcp-remote@0.1.29", "https://u:p4ssw0rd!@x.example/sse"]), select=["TL404"]
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example/sse",
        "https://mcp.example/sse?token=${env:TOKEN}",
        "https://mcp.example/sse?page=2&limit=50",
        "https://user@mcp.example/sse",
        "https://mcp.example/sse?key=short",
    ],
)
def test_tl404_negatives(url: str) -> None:
    assert lint({"mcpServers": {"x": {"url": url}}}, select=["TL404"]) == []
