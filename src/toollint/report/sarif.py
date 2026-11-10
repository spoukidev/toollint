"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import json
from typing import Any

from toollint import __version__
from toollint.engine import ScanResult
from toollint.model import Severity
from toollint.rules import all_rules

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
#: GitHub code scanning maps this property to critical/high/medium/low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule_descriptor(rule: Any) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": "".join(p.capitalize() for p in rule.name.split("-")),
        "shortDescription": {"text": rule.summary},
        "fullDescription": {"text": rule.summary},
        "help": {"text": rule.docs(), "markdown": rule.docs()},
        "defaultConfiguration": {"level": _LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", rule.category.value],
            "security-severity": _SECURITY_SEVERITY[rule.severity],
            "precision": "medium" if rule.severity <= Severity.LOW else "high",
        },
    }


def build_sarif(result: ScanResult) -> dict[str, Any]:
    rules = all_rules()
    index = {r.id: i for i, r in enumerate(rules)}
    results = []
    for f in result.findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": index[f.rule_id],
                "level": _LEVEL[f.severity],
                "message": {"text": f.message + (f"\nFix: {f.fix}" if f.fix else "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location.file, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": f.location.line, "startColumn": f.location.column},
                        },
                        "logicalLocations": [{"fullyQualifiedName": f.location.json_path, "kind": "member"}],
                    }
                ],
                "partialFingerprints": {"toollint/v1": f.fingerprint},
                "properties": {
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                },
            }
        )
    notifications = [
        {
            "level": "error",
            "message": {"text": e.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": e.file}}}],
        }
        for e in result.errors
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ToolLint",
                        "semanticVersion": __version__,
                        "version": __version__,
                        "rules": [_rule_descriptor(r) for r in rules],
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The directory toollint was run from."}}},
                "invocations": [
                    {"executionSuccessful": not result.errors, "toolExecutionNotifications": notifications}
                ],
                "results": results,
            }
        ],
    }


def render_sarif(result: ScanResult) -> str:
    return json.dumps(build_sarif(result), indent=2, ensure_ascii=False) + "\n"
