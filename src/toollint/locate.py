"""Map JSON paths back to line/column positions in the source text.

Neither ``json`` nor ``json5`` reports positions, so this module runs a small,
tolerant scanner over JSON / JSONC / JSON5 text that records the span of every key
and value. YAML positions come from PyYAML's node marks. If the scanner gives up
on odd input, callers fall back to line 1, so a position problem never hides a
finding.
"""

from __future__ import annotations

import bisect
import contextlib
import json
from dataclasses import dataclass, field

from toollint.model import JsonPath


@dataclass(frozen=True)
class Span:
    line: int
    column: int
    start: int
    end: int


@dataclass
class Locator:
    text: str
    values: dict[JsonPath, Span] = field(default_factory=dict)
    keys: dict[JsonPath, Span] = field(default_factory=dict)

    def find(self, path: JsonPath) -> Span | None:
        """Best span for ``path``: the value, else the key, else the nearest ancestor."""
        probe = tuple(path)
        while True:
            span = self.values.get(probe) or self.keys.get(probe)
            if span is not None:
                return span
            if not probe:
                return None
            probe = probe[:-1]

    def line_text(self, line: int) -> str:
        lines = self.text.splitlines()
        return lines[line - 1] if 0 < line <= len(lines) else ""


class _LineIndex:
    def __init__(self, text: str) -> None:
        self.starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self.starts.append(i + 1)

    def pos(self, offset: int) -> tuple[int, int]:
        idx = bisect.bisect_right(self.starts, offset) - 1
        return idx + 1, offset - self.starts[idx] + 1


class _ScanError(Exception):
    pass


_MAX_DEPTH = 128


class _JsonScanner:
    def __init__(self, text: str, loc: Locator) -> None:
        self.s = text
        self.i = 0
        self.loc = loc
        self.lines = _LineIndex(text)

    def span(self, start: int, end: int) -> Span:
        line, col = self.lines.pos(start)
        return Span(line, col, start, end)

    def ws(self) -> None:
        s, n = self.s, len(self.s)
        while self.i < n:
            c = s[self.i]
            if c in " \t\r\n\ufeff\u00a0\u2028\u2029":
                self.i += 1
            elif s.startswith("//", self.i) or c == "#":
                nl = s.find("\n", self.i)
                self.i = n if nl == -1 else nl + 1
            elif s.startswith("/*", self.i):
                end = s.find("*/", self.i + 2)
                self.i = n if end == -1 else end + 2
            else:
                return

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def value(self, path: JsonPath, depth: int = 0) -> None:
        if depth > _MAX_DEPTH:
            raise _ScanError("too deep")
        self.ws()
        start = self.i
        c = self.peek()
        if c == "{":
            self.obj(path, depth)
        elif c == "[":
            self.arr(path, depth)
        elif c in "\"'":
            self.string()
        elif c == "":
            raise _ScanError("eof")
        else:
            self.literal()
        self.loc.values[path] = self.span(start, self.i)

    def string(self) -> str:
        quote = self.s[self.i]
        start = self.i
        self.i += 1
        n = len(self.s)
        while self.i < n:
            c = self.s[self.i]
            if c == "\\":
                self.i += 2
                continue
            if c == quote:
                self.i += 1
                raw = self.s[start + 1 : self.i - 1]
                if quote == '"':
                    try:
                        return str(json.loads(f'"{raw}"'))
                    except ValueError:
                        return raw
                return raw.replace("\\'", "'")
            self.i += 1
        raise _ScanError("unterminated string")

    def literal(self) -> None:
        n = len(self.s)
        start = self.i
        while self.i < n and self.s[self.i] not in ",:]}\n\r\t /":
            self.i += 1
        if self.i == start:
            raise _ScanError(f"unexpected character {self.s[self.i]!r}")

    def ident(self) -> str:
        start = self.i
        n = len(self.s)
        while self.i < n and (self.s[self.i].isalnum() or self.s[self.i] in "_$-"):
            self.i += 1
        if self.i == start:
            raise _ScanError("expected key")
        return self.s[start : self.i]

    def obj(self, path: JsonPath, depth: int) -> None:
        self.i += 1
        while True:
            self.ws()
            c = self.peek()
            if c == "}":
                self.i += 1
                return
            if c == ",":
                self.i += 1
                continue
            kstart = self.i
            key = self.string() if c in "\"'" else self.ident()
            self.loc.keys[path + (key,)] = self.span(kstart, self.i)
            self.ws()
            if self.peek() != ":":
                raise _ScanError("expected ':'")
            self.i += 1
            self.value(path + (key,), depth + 1)

    def arr(self, path: JsonPath, depth: int) -> None:
        self.i += 1
        idx = 0
        while True:
            self.ws()
            c = self.peek()
            if c == "]":
                self.i += 1
                return
            if c == ",":
                self.i += 1
                continue
            self.value(path + (idx,), depth + 1)
            idx += 1


def locate_json(text: str) -> Locator:
    loc = Locator(text)
    with contextlib.suppress(_ScanError, IndexError, RecursionError):
        _JsonScanner(text, loc).value(())  # on failure, keep whatever was collected
    return loc


def locate_yaml(text: str) -> Locator:
    import yaml

    loc = Locator(text)
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return loc
    if root is None:
        return loc

    seen: set[int] = set()

    def walk(node: yaml.Node, path: JsonPath, depth: int) -> None:
        if depth > _MAX_DEPTH or id(node) in seen:
            return
        seen.add(id(node))
        loc.values[path] = Span(
            node.start_mark.line + 1, node.start_mark.column + 1, node.start_mark.index, node.end_mark.index
        )
        if isinstance(node, yaml.MappingNode):
            for knode, vnode in node.value:
                key = str(knode.value)
                loc.keys[path + (key,)] = Span(
                    knode.start_mark.line + 1,
                    knode.start_mark.column + 1,
                    knode.start_mark.index,
                    knode.end_mark.index,
                )
                walk(vnode, path + (key,), depth + 1)
        elif isinstance(node, yaml.SequenceNode):
            for i, child in enumerate(node.value):
                walk(child, path + (i,), depth + 1)

    walk(root, (), 0)
    return loc
