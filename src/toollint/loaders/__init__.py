"""Turn files on disk into :class:`~toollint.document.Document` objects.

File type is auto-detected from content, not the file name: anything with an
``mcpServers`` / ``servers`` / ``context_servers`` map is an MCP client config, and
anything with tool definitions (OpenAI, Anthropic or MCP ``tools/list`` shapes) is a
tool manifest. A file can be both.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toollint.document import Document
from toollint.loaders.generic import extract_tools
from toollint.loaders.mcp_config import extract_servers
from toollint.locate import locate_json, locate_yaml

MAX_FILE_BYTES = 5 * 1024 * 1024
SUPPORTED_SUFFIXES = {".json", ".jsonc", ".json5", ".yaml", ".yml"}


class LoadError(Exception):
    """The file exists but cannot be read or parsed."""


def parse_text(text: str, suffix: str) -> tuple[Any, str]:
    if suffix in (".yaml", ".yml"):
        import yaml

        try:
            return yaml.safe_load(text), "yaml"
        except yaml.YAMLError as exc:
            raise LoadError(f"invalid YAML: {exc}") from exc
    try:
        return json.loads(text), "json"
    except RecursionError as exc:
        raise LoadError("document is nested too deeply") from exc
    except ValueError:
        pass
    import json5

    try:
        return json5.loads(text), "json"
    except RecursionError as exc:
        raise LoadError("document is nested too deeply") from exc
    except ValueError as exc:
        raise LoadError(f"invalid JSON/JSON5: {exc}") from exc


def load_document(path: Path, display_path: str | None = None) -> Document | None:
    """Load ``path``. Returns ``None`` when the file is valid but not a recognized shape."""
    display = display_path or path.as_posix()
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise LoadError(f"file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB; skipped")
        raw = path.read_bytes()
    except OSError as exc:
        raise LoadError(f"cannot read file: {exc.strerror or exc}") from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LoadError("file is not valid UTF-8") from exc
    return load_text(text, path, display)


def load_text(text: str, path: Path, display_path: str) -> Document | None:
    suffix = path.suffix.lower()
    data, fmt = parse_text(text, suffix)
    servers, flavor = extract_servers(data, source=display_path)
    tools = extract_tools(data, source=display_path)
    if not servers and not tools:
        return None
    locator = locate_yaml(text) if fmt == "yaml" else locate_json(text)
    kinds = []
    if servers:
        kinds.append("mcp-config")
    if tools:
        kinds.append("tool-definitions")
    return Document(
        path=path,
        display_path=display_path,
        fmt=fmt,
        text=text,
        data=data,
        locator=locator,
        servers=servers,
        tools=tools,
        kinds=kinds,
        config_flavor=flavor,
    )
