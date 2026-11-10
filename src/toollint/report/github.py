"""GitHub Actions workflow commands (``::error file=…``), shown inline on PR diffs."""

from __future__ import annotations

from toollint.engine import ScanResult
from toollint.model import Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def _escape_data(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(s: str) -> str:
    return _escape_data(s).replace(":", "%3A").replace(",", "%2C")


def render_github(result: ScanResult) -> str:
    lines = []
    for f in result.findings:
        loc = f.location
        title = _escape_prop(f"{f.rule_id} {f.rule_name}")
        lines.append(
            f"::{_LEVEL[f.severity]} file={_escape_prop(loc.file)},line={loc.line},col={loc.column},title={title}::"
            f"{_escape_data(f'[{f.severity.value}] {f.message}')}"
        )
    for e in result.errors:
        lines.append(f"::error file={_escape_prop(e.file)}::{_escape_data(e.message)}")
    return "\n".join(lines) + ("\n" if lines else "")
