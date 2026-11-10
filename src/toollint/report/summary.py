from __future__ import annotations

from collections import Counter
from typing import Any

from toollint.engine import ScanResult
from toollint.model import Severity


def summary(result: ScanResult) -> dict[str, Any]:
    by_sev = Counter(f.severity.value for f in result.findings)
    return {
        "files_scanned": len(result.documents),
        "files_considered": result.files_considered,
        "findings": len(result.findings),
        "by_severity": {s.value: by_sev.get(s.value, 0) for s in reversed(Severity)},
        "fixable": sum(1 for f in result.findings if f.fixable),
        "suppressed": result.suppressed,
        "baselined": result.baselined,
        "errors": len(result.errors),
    }
