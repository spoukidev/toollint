"""Core data model: what loaders produce and what rules report."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

#: A JSON-style path into a parsed document, e.g. ``("mcpServers", "github", "env", "TOKEN")``.
JsonPath = tuple[str | int, ...]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Category(str, Enum):
    HIDDEN_INSTRUCTIONS = "hidden-instructions"
    PERMISSIONS = "permissions"
    SUPPLY_CHAIN = "supply-chain"
    SECRETS = "secrets"


def format_path(path: JsonPath) -> str:
    """Render a path as a JSONPath-like string: ``$.mcpServers.github.args[2]``."""
    out = "$"
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        elif part.isidentifier():
            out += f".{part}"
        else:
            escaped = part.replace("\\", "\\\\").replace("'", "\\'")
            out += f"['{escaped}']"
    return out


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Location(_Base):
    file: str
    line: int = 1
    column: int = 1
    json_path: str = "$"


class Param(_Base):
    """One (possibly nested) parameter of a tool's input schema."""

    name: str
    description: str | None = None
    type: str | None = None
    has_enum: bool = False
    has_pattern: bool = False
    path: JsonPath = ()


class Tool(_Base):
    """A tool/function definition, normalized across OpenAI, Anthropic and MCP shapes."""

    name: str
    description: str = ""
    title: str | None = None
    params: list[Param] = Field(default_factory=list)
    annotations: dict[str, Any] = Field(default_factory=dict)
    extensions: dict[str, Any] = Field(default_factory=dict)
    #: Where the tool came from: the file plus server/group name if known.
    source: str = ""
    flavor: str = "generic"
    path: JsonPath = ()


class Server(_Base):
    """One MCP server entry from a client config file."""

    name: str
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    url_key: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    transport: str | None = None
    path: JsonPath = ()
    #: Sub-path (relative to ``path``) where ``command``/``args``/``env`` live.
    #: Zed nests them under ``command``; everything else keeps them at the top.
    exec_path: JsonPath = ()

    @property
    def argv(self) -> list[str]:
        return ([self.command] if self.command else []) + list(self.args)

    def arg_path(self, index: int) -> JsonPath:
        return self.path + self.exec_path + ("args", index)

    def env_path(self, key: str) -> JsonPath:
        return self.path + self.exec_path + ("env", key)

    @property
    def command_path(self) -> JsonPath:
        if self.exec_path:
            return self.path + self.exec_path + ("path",)
        return self.path + ("command",)


class Finding(_Base):
    rule_id: str
    rule_name: str
    severity: Severity
    category: Category
    message: str
    location: Location
    snippet: str | None = None
    fix: str | None = None
    fixable: bool = False
    fingerprint: str = ""
    #: Internal: the raw path, used for suppressions and autofix.
    path: JsonPath = ()

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.location.file, self.location.line, self.location.column, self.rule_id)


class FileError(_Base):
    file: str
    message: str
