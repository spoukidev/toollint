"""ToolLint must not touch the network unless --online is passed."""

from __future__ import annotations

import socket
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from tests.conftest import FIXTURES, ROOT
from toollint.cli import app


class NetworkBlocked(OSError):
    pass


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def guard(*args: object, **kwargs: object) -> None:
        raise NetworkBlocked("network access attempted")

    monkeypatch.setattr(socket, "socket", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)


def test_scan_works_with_sockets_blocked(no_network: None) -> None:
    for fmt in ("text", "json", "sarif", "github"):
        result = CliRunner().invoke(app, ["scan", str(FIXTURES), "--format", fmt, "--isolated", "--exit-zero"])
        assert result.exit_code == 0, result.output
        assert not isinstance(result.exception, NetworkBlocked)


def test_online_mode_is_the_only_network_path(no_network: None) -> None:
    # A config with a remote server: without --online nothing is fetched.
    result = CliRunner().invoke(app, ["scan", str(FIXTURES / "clean" / "cursor_mcp.json"), "--isolated"])
    assert result.exit_code == 0
    # With --online the socket guard trips (proving the guard is effective),
    # and the failure is reported as a scan error rather than a crash.
    result = CliRunner().invoke(app, ["scan", str(FIXTURES / "clean" / "cursor_mcp.json"), "--isolated", "--online"])
    assert result.exit_code == 2
    assert "--online" in result.output


def test_httpx_is_not_imported_by_default() -> None:
    code = (
        "import sys; from toollint.cli import app; from typer.testing import CliRunner;"
        f"CliRunner().invoke(app, ['scan', {str(FIXTURES)!r}, '--isolated', '--exit-zero']);"
        "assert 'httpx' not in sys.modules, 'httpx imported'; print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, check=False)
    assert out.returncode == 0, out.stderr
    assert "ok" in out.stdout
