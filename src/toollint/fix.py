"""Safe autofixes: move literal secrets out of ``env`` / ``headers`` into references.

Only edits that cannot change what a server *does* are applied: the literal value
is replaced by an environment reference, and the variable name is written to a
``.env.example`` file next to the config (names only, never values). Everything
else in the file, including comments and formatting, is preserved byte-for-byte
because edits are applied to the exact source span of each value.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from toollint.document import Document
from toollint.model import Finding
from toollint.rules.secrets import strip_auth_scheme

FIXABLE_RULES = {"TL401", "TL402", "TL403"}


@dataclass
class FixResult:
    file: str
    variables: list[str]
    env_example: Path | None
    applied: int


def reference_style(doc: Document) -> str:
    """``${env:NAME}`` for VS Code and Cursor, ``${NAME}`` elsewhere (Claude Code, generic)."""
    p = doc.path.as_posix().lower()
    if doc.config_flavor == "servers" or "/.cursor/" in p or "/.vscode/" in p or p.startswith((".cursor/", ".vscode/")):
        return "${env:%s}"
    return "${%s}"


def _var_name(doc: Document, f: Finding) -> str:
    path = f.path
    # (... server, "env"|"headers", key)
    key = str(path[-1]) if path else "SECRET"
    section = str(path[-2]) if len(path) >= 2 else ""
    server = str(path[-3]) if len(path) >= 3 else ""
    if section == "headers":
        base = f"{server}_{key}"
        if key.lower() == "authorization":
            base = f"{server}_TOKEN"
    else:
        base = key
    name = re.sub(r"[^A-Za-z0-9]+", "_", base).strip("_").upper()
    if not name or name[0].isdigit():
        name = f"SECRET_{name}"
    return name


def plan_fixes(doc: Document, findings: list[Finding]) -> list[tuple[int, int, str, str]]:
    """Return ``(start, end, replacement, var)`` edits for fixable findings in ``doc``."""
    edits: dict[tuple[str | int, ...], tuple[int, int, str, str]] = {}
    style = reference_style(doc)
    for f in findings:
        if f.rule_id not in FIXABLE_RULES or not f.fixable or f.location.file != doc.display_path:
            continue
        if len(f.path) < 2 or f.path[-2] not in ("env", "headers") or f.path in edits:
            continue
        span = doc.locator.values.get(f.path)
        value = doc.get(f.path)
        if span is None or not isinstance(value, str):
            continue
        original = doc.text[span.start : span.end]
        if not original or (doc.fmt == "json" and original[0] not in "\"'"):
            continue
        var = _var_name(doc, f)
        prefix, _ = strip_auth_scheme(value)
        new_value = prefix + (style % var)
        if doc.fmt == "yaml":
            replacement = json.dumps(new_value)
        elif original[0] == "'":
            replacement = "'" + new_value + "'"
        else:
            replacement = json.dumps(new_value)
        edits[f.path] = (span.start, span.end, replacement, var)
    return sorted(edits.values(), key=lambda e: e[0], reverse=True)


def apply_fixes(doc: Document, findings: list[Finding], *, write_env_example: bool = True) -> FixResult | None:
    edits = plan_fixes(doc, findings)
    if not edits:
        return None
    text = doc.text
    for start, end, replacement, _ in edits:
        text = text[:start] + replacement + text[end:]
    doc.path.write_text(text, encoding="utf-8")
    variables = sorted({e[3] for e in edits})
    env_path: Path | None = None
    if write_env_example:
        env_path = doc.path.parent / ".env.example"
        existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
        have = {line.split("=", 1)[0].strip() for line in existing.splitlines() if "=" in line}
        missing = [v for v in variables if v not in have]
        if missing:
            header = (
                ""
                if existing
                else "# Variables referenced by your MCP config. Fill in real values locally; never commit them.\n"
            )
            sep = "" if not existing or existing.endswith("\n") else "\n"
            env_path.write_text(existing + sep + header + "".join(f"{v}=\n" for v in missing), encoding="utf-8")
    return FixResult(doc.display_path, variables, env_path, len(edits))
