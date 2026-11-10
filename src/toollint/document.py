"""A parsed input file plus everything rules need to report precise locations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

from toollint.locate import Locator
from toollint.model import JsonPath, Location, Server, Tool, format_path

IGNORE_KEY = "x-toollint-ignore"

#: ``// toollint: ignore[TL301, TL401]`` or ``# toollint: ignore`` (all rules) on a line.
_LINE_IGNORE_RE = re.compile(r"toollint:\s*ignore(?:\[([A-Za-z0-9_,\s-]*)\])?", re.IGNORECASE)


@dataclass
class Document:
    path: Path
    display_path: str
    fmt: str  # "json" | "yaml"
    text: str
    data: Any
    locator: Locator
    servers: list[Server] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
    #: "mcpServers" (Claude/Cursor/Windsurf), "servers" (VS Code), "context_servers" (Zed)
    config_flavor: str | None = None

    def location(self, path: JsonPath) -> Location:
        span = self.locator.find(path)
        if span is None:
            return Location(file=self.display_path, json_path=format_path(path))
        return Location(file=self.display_path, line=span.line, column=span.column, json_path=format_path(path))

    def get(self, path: JsonPath) -> Any:
        node = self.data
        for part in path:
            try:
                node = node[part]
            except (KeyError, IndexError, TypeError):
                return None
        return node

    def inline_ignores(self, path: JsonPath) -> set[str]:
        """Rule codes suppressed by ``x-toollint-ignore`` on ``path`` or any ancestor."""
        codes: set[str] = set()
        node = self.data
        for depth in range(len(path) + 1):
            if isinstance(node, dict):
                codes |= _as_codes(node.get(IGNORE_KEY))
            if depth == len(path):
                break
            try:
                node = node[path[depth]]
            except (KeyError, IndexError, TypeError):
                break
        return codes

    @cached_property
    def line_ignores(self) -> dict[int, set[str]]:
        """Line number -> suppressed codes (``{"*"}`` means every rule)."""
        out: dict[int, set[str]] = {}
        if "toollint" not in self.text.lower():
            return out
        for lineno, line in enumerate(self.text.splitlines(), start=1):
            m = _LINE_IGNORE_RE.search(line)
            if not m:
                continue
            if m.group(1) is None or not m.group(1).strip():
                out[lineno] = {"*"}
            else:
                out[lineno] = {c.strip().upper() for c in m.group(1).split(",") if c.strip()}
        return out


def _as_codes(value: Any) -> set[str]:
    if isinstance(value, str):
        return {"*"} if value.strip().lower() in ("*", "all") else {value.strip().upper()}
    if isinstance(value, list):
        out: set[str] = set()
        for v in value:
            if isinstance(v, str):
                out |= _as_codes(v)
        return out
    return set()
