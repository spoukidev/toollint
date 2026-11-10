from __future__ import annotations

import json

import jsonschema
import pytest

from tests.conftest import FIXTURES, ROOT
from toollint.config import Config
from toollint.engine import scan
from toollint.report.sarif import build_sarif
from toollint.rules import all_rules

SCHEMA = json.loads((ROOT / "tests" / "data" / "sarif-schema-2.1.0.json").read_text())


@pytest.fixture(scope="module")
def sarif() -> dict:
    return build_sarif(scan([str(FIXTURES)], Config(), root=ROOT))


def test_validates_against_sarif_2_1_0_schema(sarif: dict) -> None:
    jsonschema.Draft4Validator.check_schema(SCHEMA)
    jsonschema.Draft4Validator(SCHEMA).validate(sarif)


def test_empty_run_validates() -> None:
    from toollint.engine import ScanResult

    jsonschema.Draft4Validator(SCHEMA).validate(build_sarif(ScanResult()))


def test_rules_and_results_are_consistent(sarif: dict) -> None:
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == [r.id for r in all_rules()]
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        region = res["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1 and region["startColumn"] >= 1
        assert not res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("/")
        assert res["partialFingerprints"]["toollint/v1"]


def test_github_security_severity_present(sarif: dict) -> None:
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        assert float(rule["properties"]["security-severity"]) > 0
