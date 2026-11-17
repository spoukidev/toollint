"""Optional ``--online`` mode: fetch ``tools/list`` from remote (HTTP) MCP servers.

Off by default. This is the only module that touches the network, and it is only
imported when ``--online`` is passed. It needs the ``online`` extra
(``pip install 'toollint[online]'``).

Only servers with a ``url`` (Streamable HTTP or SSE-over-POST) are queried. ToolLint
never launches stdio servers: that would mean running untrusted code, which is
exactly what it exists to check before you do.
"""

from __future__ import annotations

import json
from typing import Any

from toollint.model import Server

PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 20


class OnlineError(Exception):
    pass


def _parse_body(resp: Any) -> dict[str, Any]:
    ctype = resp.headers.get("content-type", "")
    text = resp.text
    if "text/event-stream" in ctype:
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    msg = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(msg, dict) and ("result" in msg or "error" in msg):
                    return msg
        raise OnlineError("no JSON-RPC response in event stream")
    try:
        msg = json.loads(text)
    except ValueError as exc:
        raise OnlineError("server did not return JSON") from exc
    if not isinstance(msg, dict):
        raise OnlineError("unexpected JSON-RPC response")
    return msg


def list_tools(server: Server, *, timeout: float = 10.0, client: Any = None) -> list[dict[str, Any]]:
    """Run ``initialize`` + ``tools/list`` against ``server.url`` and return raw tool dicts."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise OnlineError("--online needs httpx: pip install 'toollint[online]'") from exc
    if not server.url:
        raise OnlineError("server has no url")
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
    }
    headers.update({k: v for k, v in server.headers.items() if "${" not in v})
    own = client is None
    http = client or httpx.Client(timeout=timeout, follow_redirects=False)
    try:
        init = http.post(
            server.url,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "toollint", "version": "0.1.0"},
                },
            },
        )
        init.raise_for_status()
        msg = _parse_body(init)
        if "error" in msg:
            raise OnlineError(f"initialize failed: {msg['error']}")
        session = init.headers.get("mcp-session-id")
        if session:
            headers["Mcp-Session-Id"] = session
        http.post(server.url, headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for page in range(MAX_PAGES):
            params: dict[str, Any] = {"cursor": cursor} if cursor else {}
            resp = http.post(
                server.url,
                headers=headers,
                json={"jsonrpc": "2.0", "id": 2 + page, "method": "tools/list", "params": params},
            )
            resp.raise_for_status()
            msg = _parse_body(resp)
            if "error" in msg:
                raise OnlineError(f"tools/list failed: {msg['error']}")
            result = msg.get("result") or {}
            if not isinstance(result, dict):
                raise OnlineError("tools/list returned a non-object result")
            page_tools = result.get("tools", [])
            if not isinstance(page_tools, list):
                raise OnlineError("tools/list result has a non-list 'tools' field")
            tools.extend(t for t in page_tools if isinstance(t, dict))
            next_cursor = result.get("nextCursor")
            # A hostile or buggy server can repeat a cursor forever; stop instead of re-fetching.
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
                break
            cursor = next_cursor
        return tools
    except (httpx.HTTPError, OSError) as exc:
        raise OnlineError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        if own:
            http.close()


def fetch_online_documents(docs: list[Any]) -> tuple[list[Any], list[tuple[str, str]]]:
    """Query every remote server in ``docs``; return ``(documents, errors)``."""
    from pathlib import Path

    from toollint.loaders import load_text

    out: list[Any] = []
    errors: list[tuple[str, str]] = []
    for doc in docs:
        for server in doc.servers:
            if not server.url or not server.url.startswith(("http://", "https://")):
                continue
            label = f"{doc.display_path}#{server.name}"
            try:
                tools = list_tools(server)
            except OnlineError as exc:
                errors.append((label, f"--online: {exc}"))
                continue
            text = json.dumps({"tools": tools}, indent=2, ensure_ascii=False)
            new = load_text(text, Path(f"{server.name}.tools.json"), f"{label} (online tools/list)")
            if new is not None:
                out.append(new)
    return out, errors
