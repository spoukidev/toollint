"""Scan orchestration: file discovery, loading, rule execution and suppressions."""

from __future__ import annotations

import fnmatch
import glob
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from toollint.config import Config, resolve_rules
from toollint.document import Document
from toollint.loaders import SUPPORTED_SUFFIXES, LoadError, load_document
from toollint.model import FileError, Finding
from toollint.rules import REGISTRY, ScanContext, all_rules

DEFAULT_EXCLUDES = (
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".nox", "dist", "build",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "site-packages",
)  # fmt: skip


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[FileError] = field(default_factory=list)
    documents: list[Document] = field(default_factory=list)
    files_considered: int = 0
    suppressed: int = 0
    baselined: int = 0
    rules_run: list[str] = field(default_factory=list)
    #: Explicitly named files that parsed but are not a recognized shape.
    skipped: list[str] = field(default_factory=list)


def _display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _excluded(display: str, patterns: Iterable[str]) -> bool:
    parts = display.split("/")
    return any(fnmatch.fnmatch(display, pat) or any(fnmatch.fnmatch(p, pat) for p in parts) for pat in patterns)


def collect_files(
    targets: list[str], exclude: list[str], root: Path
) -> tuple[list[tuple[Path, bool]], list[FileError]]:
    """Expand paths, directories and globs. Returns ``(path, explicit)`` pairs."""
    out: list[tuple[Path, bool]] = []
    errors: list[FileError] = []
    seen: set[Path] = set()
    patterns = list(DEFAULT_EXCLUDES) + list(exclude)

    def add(p: Path, explicit: bool) -> None:
        key = p.resolve()
        if key not in seen:
            seen.add(key)
            out.append((p, explicit))

    for target in targets:
        p = Path(os.path.expanduser(target))
        if any(ch in target for ch in "*?[") and not p.exists():
            matches = sorted(glob.glob(os.path.expanduser(target), recursive=True))
            if not matches:
                errors.append(FileError(file=target, message="glob matched no files"))
            for m in matches:
                mp = Path(m)
                if mp.is_file() and not _excluded(_display(mp, root), exclude):
                    add(mp, True)
            continue
        if p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = sorted(d for d in dirnames if not _excluded(d, patterns))
                for fn in sorted(filenames):
                    fp = Path(dirpath) / fn
                    if fp.suffix.lower() in SUPPORTED_SUFFIXES and not _excluded(_display(fp, root), patterns):
                        add(fp, False)
        elif p.is_file():
            add(p, True)
        else:
            errors.append(FileError(file=target, message="no such file or directory"))
    return out, errors


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
        return {str(x) for x in data["fingerprints"]}
    return set()


def write_baseline(path: Path, findings: list[Finding]) -> None:
    payload = {
        "tool": "toollint",
        "comment": "Findings accepted as of this baseline. Regenerate with --write-baseline.",
        "fingerprints": sorted({f.fingerprint for f in findings}),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _suppressed(f: Finding, doc: Document, per_file: dict[str, list[str]]) -> bool:
    codes = doc.inline_ignores(f.path)
    line_codes = doc.line_ignores.get(f.location.line, set())
    codes = codes | line_codes
    for pattern, ignored in per_file.items():
        if fnmatch.fnmatch(doc.display_path, pattern):
            codes |= {c.upper() for c in ignored}
    return "*" in codes or "ALL" in codes or any(f.rule_id.startswith(c) for c in codes if c)


def scan_documents(docs: list[Document], config: Config, selected: set[str] | None = None) -> tuple[list[Finding], int]:
    if selected is None:
        codes = [r.id for r in all_rules()]
        names = {r.name: r.id for r in all_rules()}
        selected = resolve_rules(config.select + config.extend_select, config.ignore, codes, names)
    ctx = ScanContext(documents=docs, options=config.rule_options())
    rules = [REGISTRY[c]() for c in sorted(selected)]
    findings: list[Finding] = []
    suppressed = 0
    for doc in docs:
        seen: set[str] = set()
        for rule in rules:
            for f in rule.check(doc, ctx):
                if f.fingerprint in seen:
                    continue
                seen.add(f.fingerprint)
                if _suppressed(f, doc, config.per_file_ignores):
                    suppressed += 1
                    continue
                findings.append(f)
    findings.sort(key=Finding.sort_key)
    return findings, suppressed


def scan(
    targets: list[str],
    config: Config,
    root: Path | None = None,
    baseline: Path | None = None,
    *,
    online: bool = False,
) -> ScanResult:
    root = root or Path.cwd()
    result = ScanResult()
    files, errors = collect_files(targets, config.exclude, root)
    result.errors.extend(errors)
    result.files_considered = len(files)
    for path, explicit in files:
        display = _display(path, root)
        try:
            doc = load_document(path, display)
        except LoadError as exc:
            result.errors.append(FileError(file=display, message=str(exc)))
            continue
        if doc is None:
            if explicit:
                result.skipped.append(display)
            continue
        result.documents.append(doc)
    if online:
        from toollint.online import fetch_online_documents

        extra, online_errors = fetch_online_documents(result.documents)
        result.documents.extend(extra)
        result.errors.extend(FileError(file=f, message=m) for f, m in online_errors)
    codes = [r.id for r in all_rules()]
    names = {r.name: r.id for r in all_rules()}
    selected = resolve_rules(config.select + config.extend_select, config.ignore, codes, names)
    result.rules_run = sorted(selected)
    findings, suppressed = scan_documents(result.documents, config, selected)
    result.suppressed = suppressed
    bl_path = baseline or (Path(config.baseline) if config.baseline else None)
    if bl_path is not None and config.source is not None and not bl_path.is_absolute() and baseline is None:
        bl_path = config.source.parent / bl_path
    if bl_path is not None and bl_path.exists():
        accepted = load_baseline(bl_path)
        kept = [f for f in findings if f.fingerprint not in accepted]
        result.baselined = len(findings) - len(kept)
        findings = kept
    result.findings = findings
    return result
