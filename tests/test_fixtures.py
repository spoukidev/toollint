"""Corpus tests: every rule catches its malicious fixture; clean configs stay clean."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import FIXTURES, ROOT
from toollint.config import Config
from toollint.engine import scan
from toollint.model import Severity
from toollint.rules import all_rules

MALICIOUS = sorted((FIXTURES / "malicious").iterdir())
CLEAN = sorted(p for p in (FIXTURES / "clean").iterdir() if p.is_file())
_EXPECT_RE = re.compile(r"^(TL\d{3})_")


def _expected(path: Path) -> str:
    m = _EXPECT_RE.match(path.name)
    assert m, f"malicious fixture {path.name} must be named <RULE>_<description>.<ext>"
    return m.group(1)


@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.name)
def test_malicious_fixture_is_caught_by_its_rule(path: Path) -> None:
    rule = _expected(path)
    result = scan([str(path)], Config(), root=ROOT)
    assert not result.errors, result.errors
    found = {f.rule_id for f in result.findings}
    assert rule in found, f"{path.name}: expected {rule}, got {sorted(found)}"


def test_every_rule_has_a_malicious_fixture_and_docs() -> None:
    covered = {_expected(p) for p in MALICIOUS}
    for rule in all_rules():
        assert rule.id in covered, f"no malicious fixture for {rule.id}"
        assert (ROOT / "docs" / "rules" / f"{rule.id}.md").is_file(), f"no docs page for {rule.id}"


def test_at_least_18_rules() -> None:
    assert len(all_rules()) >= 18


def test_clean_corpus_size() -> None:
    assert len(CLEAN) >= 20


@pytest.mark.parametrize("path", CLEAN, ids=lambda p: p.name)
def test_clean_fixture_has_no_high_severity_findings(path: Path) -> None:
    result = scan([str(path)], Config(), root=ROOT)
    assert not result.errors
    assert result.documents, f"{path.name} was not recognized"
    high = [f for f in result.findings if f.severity >= Severity.HIGH]
    assert high == [], [f"{f.rule_id}: {f.message}" for f in high]


def test_false_positive_rate() -> None:
    """Track the false-positive rate on the clean corpus (scanned together, as a user would).

    Target from the project brief: zero high-severity findings. We currently hold
    the stricter line of zero findings of any severity; loosen the second bound
    deliberately, never silently.
    """
    result = scan([str(FIXTURES / "clean")], Config(), root=ROOT)
    files_with_high = {f.location.file for f in result.findings if f.severity >= Severity.HIGH}
    files_with_any = {f.location.file for f in result.findings}
    fpr_high = len(files_with_high) / len(CLEAN)
    fpr_any = len(files_with_any) / len(CLEAN)
    print(f"\nclean corpus: {len(CLEAN)} files, FPR(high)={fpr_high:.1%}, FPR(any)={fpr_any:.1%}")
    assert fpr_high == 0.0
    assert fpr_any <= 0.05


def test_malicious_detection_rate() -> None:
    result = scan([str(FIXTURES / "malicious")], Config(), root=ROOT)
    flagged = {f.location.file for f in result.findings}
    assert len(flagged) == len(MALICIOUS)
    # Everything except the warn-only heuristic (TL106) is flagged at medium or above.
    serious = {f.location.file for f in result.findings if f.severity >= Severity.MEDIUM}
    assert len(serious) == len(MALICIOUS) - 1


def test_whole_fixture_set_scans_fast() -> None:
    import time

    start = time.perf_counter()
    scan([str(FIXTURES)], Config(), root=ROOT)
    assert time.perf_counter() - start < 1.0
