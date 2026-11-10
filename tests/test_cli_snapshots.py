"""Snapshot tests for terminal and JSON output.

Regenerate after an intentional output change with:

    TOOLLINT_UPDATE_SNAPSHOTS=1 pytest tests/test_cli_snapshots.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.conftest import ROOT
from toollint.cli import app

SNAPSHOTS = Path(__file__).parent / "snapshots"
UPDATE = os.environ.get("TOOLLINT_UPDATE_SNAPSHOTS") == "1"

CASES = {
    "poisoned_tool_text": ["scan", "fixtures/malicious/TL101_poisoned_add_tool.json", "--isolated", "--no-color"],
    "secrets_text": ["scan", "fixtures/malicious/TL401_hardcoded_tokens.json", "--isolated", "--no-color"],
    "supply_chain_quiet": [
        "scan",
        "fixtures/malicious/TL301_unpinned_packages.json",
        "fixtures/malicious/TL303_curl_pipe_sh.json",
        "--isolated",
        "--no-color",
        "-q",
    ],
    "clean_text": ["scan", "fixtures/clean", "--isolated", "--no-color"],
    "shadowing_json": ["scan", "fixtures/malicious/TL104_shadowing_send_email.json", "--isolated", "--format", "json"],
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_snapshot(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("TOOLLINT_WIDTH", "200")
    monkeypatch.setenv("NO_COLOR", "1")
    out = CliRunner().invoke(app, CASES[name]).output
    out = out.replace(f'"version": "{__import__("toollint").__version__}"', '"version": "<version>"')
    path = SNAPSHOTS / f"{name}.txt"
    if UPDATE or not path.exists():
        if not UPDATE:
            pytest.fail(f"missing snapshot {path.name}; run with TOOLLINT_UPDATE_SNAPSHOTS=1")
        path.parent.mkdir(exist_ok=True)
        path.write_text(out)
    assert out == path.read_text()
