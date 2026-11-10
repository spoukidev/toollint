from __future__ import annotations

import json

from toollint import __version__
from toollint.engine import ScanResult
from toollint.report.summary import summary


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": "toollint",
        "version": __version__,
        "summary": summary(result),
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "category": f.category.value,
                "message": f.message,
                "file": f.location.file,
                "line": f.location.line,
                "column": f.location.column,
                "json_path": f.location.json_path,
                "snippet": f.snippet,
                "fix": f.fix,
                "fixable": f.fixable,
                "fingerprint": f.fingerprint,
            }
            for f in result.findings
        ],
        "errors": [e.model_dump() for e in result.errors],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
