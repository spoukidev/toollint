"""MCP client config shapes.

Supported layouts:

* Claude Desktop, Cursor, Windsurf, Claude Code (``.mcp.json``), Gemini CLI::

      {"mcpServers": {"name": {"command": "...", "args": [...], "env": {...}}}}
      {"mcpServers": {"name": {"url": "https://...", "headers": {...}}}}

  ``mcpServers`` maps are also found nested (``~/.claude.json`` keeps one per project).

* VS Code ``mcp.json`` (``{"servers": {...}}``) and ``settings.json``
  (``{"mcp": {"servers": {...}}}``), including ``type: stdio|http|sse``.

* Continue ``config.yaml`` (``mcpServers`` as a list of ``{name, command, args, env}``).

* Zed ``context_servers`` (both the flat shape and ``{"command": {"path", "args", "env"}}``).
"""

from __future__ import annotations

from typing import Any

from toollint.document import IGNORE_KEY
from toollint.model import JsonPath, Server

_URL_KEYS = ("url", "serverUrl", "httpUrl", "endpoint")
_MAX_SEARCH_DEPTH = 4


def _looks_like_server(value: Any) -> bool:
    return isinstance(value, dict) and any(
        k in value for k in ("command", "args", "url", "serverUrl", "httpUrl", "type")
    )


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [v if isinstance(v, str) else str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def _str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): (v if isinstance(v, str) else str(v)) for k, v in value.items() if k != IGNORE_KEY}


def _server_from(name: str, raw: dict[str, Any], path: JsonPath) -> Server:
    exec_raw: dict[str, Any] = raw
    exec_path: JsonPath = ()
    command_val = raw.get("command")
    if isinstance(command_val, dict):  # Zed: {"command": {"path": ..., "args": ..., "env": ...}}
        exec_raw = command_val
        exec_path = ("command",)
        command_val = command_val.get("path")
    url_key = next((k for k in _URL_KEYS if isinstance(raw.get(k), str)), None)
    return Server(
        name=name,
        command=command_val if isinstance(command_val, str) else None,
        args=_str_list(exec_raw.get("args")),
        env=_str_map(exec_raw.get("env")),
        url=raw.get(url_key) if url_key else None,
        url_key=url_key,
        headers=_str_map(raw.get("headers")),
        transport=raw.get("type") if isinstance(raw.get("type"), str) else raw.get("transport"),
        path=path,
        exec_path=exec_path,
    )


def _collect(mapping: Any, base: JsonPath, out: list[Server]) -> None:
    if isinstance(mapping, list):  # Continue: mcpServers: [{name: ..., command: ...}]
        for i, raw in enumerate(mapping):
            if isinstance(raw, dict) and _looks_like_server(raw):
                raw_name = raw.get("name")
                name = raw_name if isinstance(raw_name, str) else f"server[{i}]"
                out.append(_server_from(name, raw, base + (i,)))
        return
    if not isinstance(mapping, dict):
        return
    for name, raw in mapping.items():
        if name == IGNORE_KEY or not isinstance(raw, dict):
            continue
        out.append(_server_from(str(name), raw, base + (str(name),)))


def extract_servers(data: Any, source: str = "") -> tuple[list[Server], str | None]:
    """Return ``(servers, flavor)`` where flavor names the top-level layout found."""
    servers: list[Server] = []
    flavor: str | None = None
    if not isinstance(data, dict):
        return servers, flavor

    # VS Code mcp.json
    vs = data.get("servers")
    if isinstance(vs, dict) and any(_looks_like_server(v) for v in vs.values()):
        _collect(vs, ("servers",), servers)
        flavor = "servers"
    # VS Code settings.json
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        _collect(mcp["servers"], ("mcp", "servers"), servers)
        flavor = flavor or "servers"
    # Zed
    if isinstance(data.get("context_servers"), dict):
        _collect(data["context_servers"], ("context_servers",), servers)
        flavor = flavor or "context_servers"

    # mcpServers anywhere (bounded depth), e.g. ~/.claude.json projects.*.mcpServers
    def search(node: Any, path: JsonPath, depth: int) -> None:
        nonlocal flavor
        if depth > _MAX_SEARCH_DEPTH or not isinstance(node, dict):
            return
        for key, value in node.items():
            if key == "mcpServers" and isinstance(value, (dict, list)):
                _collect(value, path + ("mcpServers",), servers)
                flavor = flavor or "mcpServers"
            elif isinstance(value, dict):
                search(value, path + (str(key),), depth + 1)

    search(data, (), 0)
    return servers, flavor
