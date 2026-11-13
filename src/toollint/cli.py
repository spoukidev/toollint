"""Command-line interface: ``toollint scan``, ``toollint rules``, ``toollint explain``."""

from __future__ import annotations

import os
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.text import Text

from toollint import __version__
from toollint.config import Config, ConfigError, find_config, load_config_file
from toollint.model import Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

app = typer.Typer(
    name="toollint",
    help="Offline security linter for MCP server configs and LLM tool definitions.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)


class OutputFormat(str, Enum):
    text = "text"
    json = "json"
    sarif = "sarif"
    github = "github"


class SeverityOpt(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def _console(no_color: bool, file: object = None) -> Console:
    color = not no_color and "NO_COLOR" not in os.environ
    width = int(os.environ.get("TOOLLINT_WIDTH", "0") or 0) or None
    # legacy_windows=False keeps box-drawing (│) and ellipsis (…) intact on
    # Windows consoles, which otherwise replace them with U+FFFD.
    return Console(
        file=file,  # type: ignore[arg-type]
        highlight=False,
        no_color=not color,
        width=width,
        height=50 if width else None,
        legacy_windows=False,
    )


def _err(message: str) -> None:
    Console(stderr=True, highlight=False).print(Text("error: ", style="bold red") + Text(message))


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"toollint {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool, typer.Option("--version", "-V", callback=_version_callback, is_eager=True, help="Show version and exit.")
    ] = False,
) -> None:
    """Offline security linter for MCP server configs and LLM tool definitions."""


def _split_codes(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or []:
        out.extend(p.strip() for p in v.split(",") if p.strip())
    return out


def _load_config(config_path: Path | None, isolated: bool, first_target: str | None) -> Config:
    if isolated:
        return Config()
    if config_path is not None:
        return load_config_file(config_path)
    start = Path(first_target).expanduser() if first_target else Path.cwd()
    if not start.exists():
        start = Path.cwd()
    found = find_config(start) or find_config(Path.cwd())
    return load_config_file(found) if found else Config()


def scan_command(
    paths: Annotated[
        list[str] | None,
        typer.Argument(
            help="Files, directories or globs to scan. Defaults to the current directory.", show_default=False
        ),
    ] = None,
    discover: Annotated[
        bool, typer.Option("--discover", help="Also scan well-known MCP config locations on this machine (read-only).")
    ] = False,
    output_format: Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")] = OutputFormat.text,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file instead of stdout.")
    ] = None,
    select: Annotated[
        list[str] | None,
        typer.Option("--select", help="Rules to enable: codes, prefixes (TL1) or ALL. Comma-separated or repeated."),
    ] = None,
    extend_select: Annotated[
        list[str] | None, typer.Option("--extend-select", help="Rules to add on top of the configured selection.")
    ] = None,
    ignore: Annotated[list[str] | None, typer.Option("--ignore", help="Rules to disable: codes or prefixes.")] = None,
    fail_on: Annotated[
        SeverityOpt | None,
        typer.Option("--fail-on", help="Exit 1 if any finding is at or above this severity. [default: medium]"),
    ] = None,
    min_severity: Annotated[
        SeverityOpt, typer.Option("--min-severity", help="Only report findings at or above this severity.")
    ] = SeverityOpt.info,
    fix: Annotated[
        bool,
        typer.Option("--fix", help="Apply safe autofixes (move literal secrets in env/headers to ${VAR} references)."),
    ] = False,
    config_path: Annotated[
        Path | None,
        typer.Option("--config", help="Path to toollint.toml or pyproject.toml.", exists=True, dir_okay=False),
    ] = None,
    isolated: Annotated[bool, typer.Option("--isolated", help="Ignore all configuration files.")] = False,
    baseline: Annotated[
        Path | None, typer.Option("--baseline", help="Hide findings recorded in this baseline file.")
    ] = None,
    write_baseline: Annotated[
        Path | None, typer.Option("--write-baseline", help="Record current findings as accepted and exit 0.")
    ] = None,
    exit_zero: Annotated[
        bool, typer.Option("--exit-zero", help="Always exit 0 when the scan completes, even with findings.")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="One line per finding; no help text.")] = False,
    online: Annotated[
        bool,
        typer.Option(
            "--online", help="Also fetch tools/list from remote (HTTP) servers and lint them. Uses the network."
        ),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colored output.")] = False,
) -> None:
    """Scan MCP configs and tool definitions for security issues."""
    from toollint.config import resolve_rules
    from toollint.engine import scan
    from toollint.engine import write_baseline as _write_baseline
    from toollint.report import render_github, render_json, render_sarif, render_text
    from toollint.rules import all_rules

    targets = list(paths or [])
    console_err = Console(stderr=True, highlight=False, soft_wrap=True, no_color=no_color or "NO_COLOR" in os.environ)
    if discover:
        from toollint.discover import discover as _discover

        found = _discover()
        if not found:
            console_err.print(Text("--discover: no MCP config files found in the usual locations.", style="dim"))
        for client, p in found:
            console_err.print(Text(f"--discover: {client}: {p}", style="dim"))
            targets.append(str(p))
        if not targets:
            raise typer.Exit(EXIT_OK)
    if not targets:
        targets = ["."]

    try:
        cfg = _load_config(config_path, isolated, targets[0] if paths else None)
        if select:
            cfg.select = _split_codes(select)
        if extend_select:
            cfg.extend_select = cfg.extend_select + _split_codes(extend_select)
        if ignore:
            cfg.ignore = cfg.ignore + _split_codes(ignore)
        if fail_on is not None:
            cfg.fail_on = Severity(fail_on.value)
        codes = [r.id for r in all_rules()]
        resolve_rules(cfg.select + cfg.extend_select, cfg.ignore, codes, {r.name: r.id for r in all_rules()})
    except ConfigError as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_ERROR) from exc

    result = scan(targets, cfg, baseline=baseline, online=online)

    if fix:
        from toollint.fix import apply_fixes

        applied = 0
        for doc in result.documents:
            fr = apply_fixes(doc, result.findings)
            if fr:
                applied += fr.applied
                msg = f"Fixed {fr.applied} secret(s) in {fr.file} -> {', '.join(fr.variables)}"
                if fr.env_example:
                    msg += f" (names added to {fr.env_example.as_posix()})"
                console_err.print(Text(msg, style="green"))
        if applied:
            result = scan(targets, cfg, baseline=baseline, online=online)
        else:
            console_err.print(Text("--fix: nothing to fix.", style="dim"))

    if write_baseline is not None:
        _write_baseline(write_baseline, result.findings)
        console_err.print(Text(f"Wrote {len(result.findings)} finding(s) to baseline {write_baseline}", style="green"))
        raise typer.Exit(EXIT_OK if not result.errors else EXIT_ERROR)

    threshold = Severity(min_severity.value)
    result.findings = [f for f in result.findings if f.severity >= threshold]

    fh = output.open("w", encoding="utf-8") if output else None
    try:
        if output_format is OutputFormat.text:
            render_text(result, _console(no_color or fh is not None, fh or sys.stdout), quiet=quiet)
        else:
            rendered = {
                OutputFormat.json: render_json,
                OutputFormat.sarif: render_sarif,
                OutputFormat.github: render_github,
            }[output_format](result)
            (fh or sys.stdout).write(rendered)
    finally:
        if fh:
            fh.close()

    if result.errors:
        raise typer.Exit(EXIT_ERROR)
    if not exit_zero and any(f.severity >= cfg.fail_on for f in result.findings):
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_OK)


app.command("scan")(scan_command)
app.command("check", hidden=True, help="Alias for scan.")(scan_command)


@app.command("rules")
def rules_command(
    output_format: Annotated[OutputFormat, typer.Option("--format", "-f", help="text or json.")] = OutputFormat.text,
) -> None:
    """List every rule with its code, severity and category."""
    import json

    from toollint.rules import all_rules

    rules = all_rules()
    if output_format is OutputFormat.json:
        typer.echo(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "name": r.name,
                        "category": r.category.value,
                        "severity": r.severity.value,
                        "fixable": r.fixable,
                        "summary": r.summary,
                    }
                    for r in rules
                ],
                indent=2,
            )
        )
        return
    from toollint.report.terminal import SEVERITY_STYLE

    table = Table(title=f"ToolLint rules ({len(rules)})", title_justify="left")
    table.add_column("Code", style="bold magenta", no_wrap=True)
    table.add_column("Name", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Fix", justify="center", no_wrap=True)
    table.add_column("Summary", ratio=1)
    current = None
    for r in rules:
        if r.category != current:
            if current is not None:
                table.add_section()
            current = r.category
            table.add_row("", Text(r.category.value, style="bold underline"), "", "", "")
        table.add_row(
            r.id,
            r.name,
            Text(r.severity.value, style=SEVERITY_STYLE[r.severity]),
            "yes" if r.fixable else "",
            r.summary,
        )
    _console(False).print(table)


@app.command("explain")
def explain_command(rule: Annotated[str, typer.Argument(help="Rule code (TL104) or name (tool-shadowing).")]) -> None:
    """Show the documentation for a rule."""
    from toollint.docs import render_rule_markdown
    from toollint.rules import get_rule

    cls = get_rule(rule)
    if cls is None:
        _err(f"unknown rule {rule!r}. Run 'toollint rules' to list them.")
        raise typer.Exit(EXIT_ERROR)
    console = _console(False)
    console.print(Markdown(render_rule_markdown(cls)))


def main() -> None:
    app()
