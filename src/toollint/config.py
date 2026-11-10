"""Configuration from ``toollint.toml``, ``.toollint.toml`` or ``[tool.toollint]`` in ``pyproject.toml``.

Keys (kebab-case, as in ruff)::

    select = ["ALL"]                # rule codes or prefixes: "TL1", "TL301", "ALL"
    ignore = ["TL106"]
    fail-on = "medium"              # info | low | medium | high | critical
    exclude = ["vendor/**"]
    per-file-ignores = { "examples/*.json" = ["TL301"] }
    baseline = "toollint-baseline.json"
    max-description-length = 1000
    entropy-threshold = 4.0
    extra-popular-packages = ["npm:@acme/mcp-server-internal"]
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from toollint.model import Severity

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import-not-found,unused-ignore]

CONFIG_FILES = ("toollint.toml", ".toollint.toml", "pyproject.toml")


class ConfigError(Exception):
    pass


@dataclass
class Config:
    select: list[str] = field(default_factory=lambda: ["ALL"])
    ignore: list[str] = field(default_factory=list)
    extend_select: list[str] = field(default_factory=list)
    fail_on: Severity = Severity.MEDIUM
    exclude: list[str] = field(default_factory=list)
    per_file_ignores: dict[str, list[str]] = field(default_factory=dict)
    baseline: str | None = None
    max_description_length: int = 1000
    entropy_threshold: float = 4.0
    extra_popular_packages: list[str] = field(default_factory=list)
    source: Path | None = None

    def rule_options(self) -> dict[str, Any]:
        return {
            "max_description_length": self.max_description_length,
            "entropy_threshold": self.entropy_threshold,
            "extra_popular_packages": self.extra_popular_packages,
        }


_KNOWN = {
    "select", "ignore", "extend-select", "fail-on", "exclude", "per-file-ignores", "baseline",
    "max-description-length", "entropy-threshold", "extra-popular-packages",
}  # fmt: skip


def _str_list(value: Any, key: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    raise ConfigError(f"'{key}' must be a list of strings")


def parse_config(table: dict[str, Any], source: Path | None = None) -> Config:
    unknown = set(table) - _KNOWN
    if unknown:
        raise ConfigError(f"unknown config key(s): {', '.join(sorted(unknown))}")
    cfg = Config(source=source)
    if "select" in table:
        cfg.select = _str_list(table["select"], "select")
    if "extend-select" in table:
        cfg.extend_select = _str_list(table["extend-select"], "extend-select")
    if "ignore" in table:
        cfg.ignore = _str_list(table["ignore"], "ignore")
    if "fail-on" in table:
        try:
            cfg.fail_on = Severity(str(table["fail-on"]).lower())
        except ValueError as exc:
            raise ConfigError(f"invalid fail-on: {table['fail-on']!r}") from exc
    if "exclude" in table:
        cfg.exclude = _str_list(table["exclude"], "exclude")
    if "per-file-ignores" in table:
        pfi = table["per-file-ignores"]
        if not isinstance(pfi, dict):
            raise ConfigError("'per-file-ignores' must be a table of glob -> [codes]")
        cfg.per_file_ignores = {str(k): _str_list(v, f"per-file-ignores.{k}") for k, v in pfi.items()}
    if "baseline" in table:
        cfg.baseline = str(table["baseline"])
    if "max-description-length" in table:
        cfg.max_description_length = int(table["max-description-length"])
    if "entropy-threshold" in table:
        cfg.entropy_threshold = float(table["entropy-threshold"])
    if "extra-popular-packages" in table:
        cfg.extra_popular_packages = _str_list(table["extra-popular-packages"], "extra-popular-packages")
    return cfg


def load_config_file(path: Path) -> Config:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if path.name == "pyproject.toml":
        table = data.get("tool", {}).get("toollint", {})
    else:
        table = data.get("tool", {}).get("toollint", data)
    return parse_config(table, source=path)


def find_config(start: Path) -> Path | None:
    """Walk up from ``start`` looking for a config file (pyproject only if it has [tool.toollint])."""
    here = start.resolve()
    if here.is_file():
        here = here.parent
    for directory in (here, *here.parents):
        for name in CONFIG_FILES:
            candidate = directory / name
            if not candidate.is_file():
                continue
            if name == "pyproject.toml":
                try:
                    data = tomllib.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, tomllib.TOMLDecodeError):
                    continue
                if "toollint" not in data.get("tool", {}):
                    continue
            return candidate
    return None


def resolve_rules(select: list[str], ignore: list[str], all_codes: list[str], names: dict[str, str]) -> set[str]:
    """Ruff-style selection: codes, prefixes (``TL1``), rule names, or ``ALL``."""

    def expand(items: list[str], key: str) -> set[str]:
        out: set[str] = set()
        for raw in items:
            item = raw.strip()
            if not item:
                continue
            if item.upper() == "ALL":
                out |= set(all_codes)
                continue
            if item.lower() in names:
                out.add(names[item.lower()])
                continue
            matched = {c for c in all_codes if c.startswith(item.upper())}
            if not matched:
                raise ConfigError(f"unknown rule selector in {key}: {item!r}")
            out |= matched
        return out

    return expand(select, "select") - expand(ignore, "ignore")
