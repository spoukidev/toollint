"""OpenAI function-calling shapes.

* Chat Completions: ``{"type": "function", "function": {"name", "description", "parameters"}}``
* Responses API / Realtime: ``{"type": "function", "name", "description", "parameters"}``
* Legacy ``functions=[{"name", "description", "parameters"}]``
"""

from __future__ import annotations

from typing import Any

from toollint.model import JsonPath


def unwrap_openai(item: dict[str, Any], path: JsonPath) -> tuple[dict[str, Any], JsonPath, str] | None:
    """Return ``(tool_dict, tool_path, flavor)`` for an OpenAI-style entry, else ``None``."""
    if item.get("type") == "function" and isinstance(item.get("function"), dict):
        return item["function"], path + ("function",), "openai"
    if item.get("type") == "function" and isinstance(item.get("name"), str):
        return item, path, "openai"
    if "parameters" in item and isinstance(item.get("name"), str):
        return item, path, "openai"
    return None
