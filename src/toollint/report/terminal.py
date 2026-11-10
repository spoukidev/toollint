"""Human-readable terminal output (ruff-style), rendered with Rich.

All attacker-controlled text is already escaped by the rules (see
:func:`toollint.normalize.safe_display`) and is rendered as Rich ``Text`` objects,
never as markup, so a hostile description cannot inject terminal escapes or
Rich markup into the report.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from toollint.engine import ScanResult
from toollint.model import Severity
from toollint.normalize import safe_display

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_text(result: ScanResult, console: Console, *, show_fix: bool = True, quiet: bool = False) -> None:
    for f in result.findings:
        line = Text()
        line.append(safe_display(f.location.file, limit=300), style="bold")
        line.append(f":{f.location.line}:{f.location.column}: ", style="dim")
        line.append(f.rule_id, style="bold magenta")
        line.append(" ")
        line.append(f"[{f.severity.value}]", style=SEVERITY_STYLE[f.severity])
        line.append(" ")
        line.append(safe_display(f.message, limit=2000))
        console.print(line, soft_wrap=True, highlight=False)
        if quiet:
            continue
        detail = Text("  │ ", style="dim")
        detail.append(f.location.json_path, style="dim")
        if f.snippet:
            detail.append("  ")
            detail.append(safe_display(f.snippet, limit=400), style="italic dim")
        console.print(detail, soft_wrap=True, highlight=False)
        if show_fix and f.fix:
            fix = Text("  = ", style="dim")
            fix.append("help", style="bold green")
            fix.append(": " + f.fix)
            if f.fixable:
                fix.append("  [fixable with --fix]", style="green")
            console.print(fix, soft_wrap=True, highlight=False)

    for e in result.errors:
        err = Text()
        err.append(e.file, style="bold")
        err.append(": ")
        err.append("error", style="bold red")
        err.append(f": {e.message}")
        console.print(err, soft_wrap=True, highlight=False)
    for s in result.skipped:
        console.print(
            Text(f"{s}: skipped (not a recognized MCP config or tool definition file)", style="dim"), soft_wrap=True
        )

    n = len(result.findings)
    files = len(result.documents)
    if n == 0:
        msg = Text("All checks passed! ", style="bold green")
        msg.append(f"({files} file{'s' if files != 1 else ''} scanned)", style="dim")
        console.print(msg)
        return
    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in reversed(Severity)}
    out = Text("\nFound ", style="bold")
    out.append(f"{n} issue{'s' if n != 1 else ''}", style="bold")
    out.append(f" in {files} file{'s' if files != 1 else ''} (")
    parts = [(f"{c} {s.value}", SEVERITY_STYLE[s]) for s, c in counts.items() if c]
    for i, (label, style) in enumerate(parts):
        if i:
            out.append(", ")
        out.append(label, style=style)
    out.append(").")
    fixable = sum(1 for f in result.findings if f.fixable)
    if fixable:
        out.append(f" {fixable} fixable with --fix.", style="green")
    if result.suppressed or result.baselined:
        out.append(f" ({result.suppressed} suppressed, {result.baselined} in baseline)", style="dim")
    console.print(out)
