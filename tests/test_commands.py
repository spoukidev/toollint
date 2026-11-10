from __future__ import annotations

import pytest

from toollint.commands import analyze, parse_image, parse_npm_spec, parse_py_spec
from toollint.model import Server


def ex(command: str, args: list[str]):
    return analyze(Server(name="s", command=command, args=args, path=("mcpServers", "s")))


def test_npx_package_and_server_args() -> None:
    e = ex("npx", ["-y", "@scope/pkg@1.2.3", "/data", "--flag"])
    assert [p.name for p in e.packages] == ["@scope/pkg"]
    assert e.packages[0].pinned
    assert [t.text for t in e.server_args] == ["/data", "--flag"]


def test_windows_cmd_wrapper() -> None:
    e = ex("cmd", ["/c", "npx", "-y", "pkg@1.0.0"])
    assert e.launcher == "npx" and e.packages[0].pinned


def test_shell_string_is_split() -> None:
    e = ex("bash", ["-c", "npx -y pkg@1.0.0 /tmp"])
    assert e.packages[0].name == "pkg"
    assert e.packages[0].path == ("mcpServers", "s", "args", 1)


def test_env_wrapper() -> None:
    e = ex("env", ["FOO=1", "uvx", "mcp-server-time==1.0.0"])
    assert e.launcher == "uvx" and e.packages[0].pinned


def test_docker_parsing() -> None:
    e = ex("docker", ["run", "-i", "--rm", "-e", "A", "-v", "/x:/y", "--network=host", "img:1.0", "serve"])
    assert e.docker is not None
    assert e.docker.image is not None and e.docker.image.text == "img:1.0"
    assert [v.text for v in e.docker.volumes] == ["/x:/y"]
    assert e.docker.network_host
    assert [t.text for t in e.server_args] == ["serve"]


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("pkg", ("pkg", None)),
        ("pkg@1.0.0", ("pkg", "1.0.0")),
        ("@s/p", ("@s/p", None)),
        ("@s/p@latest", ("@s/p", "latest")),
        ("npm:pkg@2.0.0", ("pkg", "2.0.0")),
    ],
)
def test_parse_npm_spec(spec: str, expected: tuple[str, str | None]) -> None:
    assert parse_npm_spec(spec) == expected


@pytest.mark.parametrize(
    ("spec", "pinned"),
    [
        ("pkg", False),
        ("pkg==1.0", True),
        ("pkg===1.0", True),
        ("pkg>=1.0", False),
        ("pkg[extra]==2.1.0", True),
        ("pkg==1.0,<2", False),
        ("pkg@0.3.1", True),
    ],
)
def test_parse_py_spec(spec: str, pinned: bool) -> None:
    assert parse_py_spec(spec)[2] is pinned


@pytest.mark.parametrize(
    ("ref", "pinned"),
    [
        ("img", False),
        ("img:latest", False),
        ("img:1.2", True),
        ("ghcr.io/a/b:v1", True),
        ("localhost:5000/img", False),
        ("img@sha256:" + "a" * 64, True),
    ],
)
def test_parse_image(ref: str, pinned: bool) -> None:
    assert parse_image(ref)[2] is pinned
