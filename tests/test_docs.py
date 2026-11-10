from __future__ import annotations

import subprocess
import sys

from tests.conftest import ROOT
from toollint.rules import all_rules


def test_rule_docs_are_generated_and_current() -> None:
    out = subprocess.run(
        [sys.executable, "scripts/gen_docs.py", "--check"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert out.returncode == 0, out.stderr


def test_every_rule_documents_the_essentials() -> None:
    for rule in all_rules():
        doc = rule.docs()
        for heading in ("## What it does", "## Why is this bad?", "## Example", "## Fix"):
            assert heading in doc, f"{rule.id} docs missing {heading!r}"
        assert rule.id.startswith("TL") and len(rule.id) == 5
        assert rule.name == rule.name.lower() and " " not in rule.name


def test_readme_rule_table_lists_every_rule() -> None:
    readme = (ROOT / "README.md").read_text()
    for rule in all_rules():
        assert f"`{rule.id}`" in readme, f"README is missing {rule.id}"
