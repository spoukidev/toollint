"""Rule interface, registry and shared helpers.

A rule is a small class with a stable ``id`` (``TL<category><nn>``), a kebab-case
``name``, a default severity and a ``check`` generator. The class docstring is the
rule's documentation: ``toollint explain`` prints it and ``docs/rules/<id>.md`` is
generated from it, so docs cannot drift from code.
"""

from __future__ import annotations

import hashlib
import inspect
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, ClassVar

from toollint.document import IGNORE_KEY, Document
from toollint.model import Category, Finding, JsonPath, Severity, Tool
from toollint.secrets_patterns import redact_known_secrets


@dataclass
class ScanContext:
    """Run-wide information shared by all rules (for example, every tool name seen)."""

    documents: list[Document] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    def tool_index(self) -> dict[str, list[tuple[Document, Tool]]]:
        cached = self.options.get("_tool_index")
        if cached is None:
            cached = {}
            for doc in self.documents:
                for tool in doc.tools:
                    cached.setdefault(tool.name, []).append((doc, tool))
            self.options["_tool_index"] = cached
        return cached  # type: ignore[no-any-return,unused-ignore]


class Rule(ABC):
    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[Category]
    severity: ClassVar[Severity]
    summary: ClassVar[str]
    fixable: ClassVar[bool] = False

    @abstractmethod
    def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
        """Yield findings for one document."""

    @classmethod
    def docs(cls) -> str:
        return inspect.cleandoc(cls.__doc__ or "")

    def report(
        self,
        doc: Document,
        path: JsonPath,
        message: str,
        *,
        severity: Severity | None = None,
        fix: str | None = None,
        snippet: str | None = None,
        fixable: bool | None = None,
        key: str = "",
    ) -> Finding:
        """Build a finding. Messages and snippets are passed through secret redaction."""
        location = doc.location(path)
        fp_src = f"{self.id}|{doc.display_path}|{location.json_path}|{key}"
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=severity or self.severity,
            category=self.category,
            message=redact_known_secrets(message),
            location=location,
            snippet=redact_known_secrets(snippet) if snippet else None,
            fix=fix,
            fixable=self.fixable if fixable is None else fixable,
            fingerprint=hashlib.sha256(fp_src.encode()).hexdigest()[:16],
            path=path,
        )


REGISTRY: dict[str, type[Rule]] = {}


def register(cls: type[Rule]) -> type[Rule]:
    if cls.id in REGISTRY:
        raise ValueError(f"duplicate rule id {cls.id}")
    REGISTRY[cls.id] = cls
    return cls


# --------------------------------------------------------------------------------------
# Text helpers shared by several rules
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TextField:
    """One piece of model-visible text: a tool description, title or parameter doc."""

    tool: Tool
    path: JsonPath
    text: str
    label: str  # e.g. "description", "parameter 'path' description"


def tool_text_fields(tool: Tool) -> Iterator[TextField]:
    if tool.description:
        yield TextField(tool, tool.path + ("description",), tool.description, "description")
    if tool.title:
        yield TextField(tool, tool.path + ("title",), tool.title, "title")
    for p in tool.params:
        if p.description:
            yield TextField(tool, p.path + ("description",), p.description, f"parameter '{p.name}' description")


def iter_strings(
    node: Any, path: JsonPath = (), depth: int = 0, seen: set[int] | None = None
) -> Iterator[tuple[JsonPath, str, bool]]:
    """Yield ``(path, string, is_key)`` for every string key and value in ``node``.

    Shared containers (YAML aliases) are visited once, which keeps alias bombs linear.
    """
    if seen is None:
        seen = set()
    if depth > 64:
        return
    if isinstance(node, dict):
        if id(node) in seen:
            return
        seen.add(id(node))
        for k, v in node.items():
            if k == IGNORE_KEY:
                continue
            if isinstance(k, str):
                yield path + (k,), k, True
            yield from iter_strings(v, path + (str(k),), depth + 1, seen)
    elif isinstance(node, list):
        if id(node) in seen:
            return
        seen.add(id(node))
        for i, v in enumerate(node):
            yield from iter_strings(v, path + (i,), depth + 1, seen)
    elif isinstance(node, str):
        yield path, node, False


def excerpt(text: str, start: int, end: int, width: int = 40) -> str:
    """A short window of ``text`` around ``[start, end)`` for messages."""
    from toollint.normalize import safe_display

    lo = max(0, start - width)
    hi = min(len(text), end + width)
    out = text[lo:hi]
    return (
        ("…" if lo > 0 else "")
        + safe_display(out, limit=2 * width + (end - start) + 2)
        + ("…" if hi < len(text) else "")
    )
