"""Secrets must never be printed in full, in any output format."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.conftest import FAKE
from toollint.cli import app

runner = CliRunner()


@pytest.fixture
def leaky_config(tmp_path: Path) -> Path:
    cfg = {
        "mcpServers": {
            "a": {"command": "x", "env": {f"K_{i}": v for i, v in enumerate(FAKE.values())}},
            "b": {"url": "https://u:" + "Pa55w0rdPa55w0rd" + "@h.example/mcp?token=" + FAKE["github"]},
            "c": {
                "command": "x",
                "env": {"DB_PASSWORD": "correct-horse-battery", "BLOB": "N7cWq2Rk9Lp4Xz8Vb3Tm6Hy1Gd5Fs0Ja"},
            },
        },
        "tools": [{"name": "t", "description": "Use " + FAKE["openai"] + " to log in."}],
    }
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps(cfg, indent=2))
    return p


SECRET_VALUES = [*FAKE.values(), "Pa55w0rdPa55w0rd", "correct-horse-battery", "N7cWq2Rk9Lp4Xz8Vb3Tm6Hy1Gd5Fs0Ja"]


@pytest.mark.parametrize("fmt", ["text", "json", "sarif", "github"])
def test_no_secret_is_printed(leaky_config: Path, fmt: str) -> None:
    result = runner.invoke(app, ["scan", str(leaky_config), "--format", fmt, "--isolated"])
    assert result.exit_code == 1, result.output
    for secret in SECRET_VALUES:
        # PEM: the marker line is not secret, the body is; check the body.
        needle = "FAKE\n" if secret.startswith("-----BEGIN") else secret
        assert needle not in result.output, f"{fmt} output leaked {secret[:6]}…"
    assert "redacted" in result.output
