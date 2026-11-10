from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from toollint.config import Config
from toollint.engine import scan_documents
from toollint.loaders import load_text
from toollint.model import Finding

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def lint(
    data: Any, *, suffix: str = ".json", select: list[str] | None = None, config: Config | None = None
) -> list[Finding]:
    """Lint an in-memory document (dict/list is serialized as JSON; str is used verbatim)."""
    text = data if isinstance(data, str) else json.dumps(data, indent=2)
    doc = load_text(text, Path(f"input{suffix}"), f"input{suffix}")
    if doc is None:
        return []
    cfg = config or Config()
    if select is not None:
        cfg.select = select
    findings, _ = scan_documents([doc], cfg)
    return findings


def lint_many(docs: list[tuple[str, Any]], select: list[str] | None = None) -> list[Finding]:
    loaded = []
    for name, data in docs:
        doc = load_text(json.dumps(data), Path(name), name)
        assert doc is not None
        loaded.append(doc)
    cfg = Config()
    if select is not None:
        cfg.select = select
    findings, _ = scan_documents(loaded, cfg)
    return findings


def codes(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings}


def server(**kwargs: Any) -> dict[str, Any]:
    """A Claude-Desktop-style config with a single server named 'srv'."""
    return {"mcpServers": {"srv": kwargs}}


def tool(
    name: str = "my_tool", description: str = "Does a thing.", properties: dict[str, Any] | None = None, **extra: Any
) -> dict[str, Any]:
    """An MCP tools/list document with one tool."""
    t: dict[str, Any] = {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties or {}},
    }
    t.update(extra)
    return {"tools": [t]}


# Fake credentials are assembled at runtime so that no complete token-shaped
# string is committed to the repository (keeps secret scanners and push
# protection quiet). None of these are real.
FAKE = {
    "aws": "AKIA" + "Z" * 4 + "FAKEFAKEFAKE",
    "github": "ghp_" + "0" * 4 + "FAKE" * 8,
    "github_pat": "github_pat_" + "FAKE0" * 6,
    "slack": "xoxb-" + "0000-FAKE-NOT-REAL",
    "openai": "sk-" + "proj-" + "FAKEFAKEFAKE" * 3,
    "anthropic": "sk-ant-" + "api03-" + "FAKE-FAKE-FAKE-FAKE-FAKE",
    "stripe": "sk_" + "test_" + "FAKE" * 6,
    "google": "AIza" + "F" * 35,
    "pem": "-----BEGIN " + "RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----",
}


@pytest.fixture
def fake() -> dict[str, str]:
    return dict(FAKE)
