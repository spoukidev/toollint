"""Tool definitions from JSON/YAML manifests.

Recognizes, at the top level or under ``tools`` / ``functions`` / ``result.tools``:

* OpenAI function-calling JSON (see :mod:`toollint.loaders.openai_tools`)
* Anthropic tool use: ``{"name", "description", "input_schema"}``
* MCP ``tools/list`` results: ``{"name", "description", "inputSchema", "annotations"}``
* Generic YAML/JSON manifests with ``name`` + ``description`` (+ ``parameters``)
"""

from __future__ import annotations

from typing import Any

from toollint.document import IGNORE_KEY
from toollint.loaders.openai_tools import unwrap_openai
from toollint.model import JsonPath, Param, Tool

_MAX_SCHEMA_DEPTH = 8
_SCHEMA_KEYS = ("inputSchema", "input_schema", "parameters", "args_schema", "schema")


def _tool_lists(data: Any) -> list[tuple[list[Any], JsonPath]]:
    found: list[tuple[list[Any], JsonPath]] = []
    if isinstance(data, list):
        found.append((data, ()))
    elif isinstance(data, dict):
        for key in ("tools", "functions"):
            if isinstance(data.get(key), list):
                found.append((data[key], (key,)))
        result = data.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            found.append((result["tools"], ("result", "tools")))
        if isinstance(data.get("name"), str) and any(k in data for k in _SCHEMA_KEYS):
            found.append(([data], ()))
    return found


def _params(schema: Any, path: JsonPath, prefix: str = "", depth: int = 0) -> list[Param]:
    out: list[Param] = []
    if depth > _MAX_SCHEMA_DEPTH or not isinstance(schema, dict):
        return out
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, prop in props.items():
            if not isinstance(prop, dict):
                continue
            full = f"{prefix}{name}"
            ppath = path + ("properties", str(name))
            ptype = prop.get("type")
            out.append(
                Param(
                    name=full,
                    description=prop.get("description") if isinstance(prop.get("description"), str) else None,
                    type=ptype if isinstance(ptype, str) else None,
                    has_enum=isinstance(prop.get("enum"), list) or "const" in prop,
                    has_pattern=isinstance(prop.get("pattern"), str),
                    path=ppath,
                )
            )
            out.extend(_params(prop, ppath, f"{full}.", depth + 1))
            items = prop.get("items")
            if isinstance(items, dict):
                out.extend(_params(items, ppath + ("items",), f"{full}[].", depth + 1))
    return out


def _tool_from(item: dict[str, Any], path: JsonPath, flavor: str, source: str) -> Tool | None:
    name = item.get("name")
    if not isinstance(name, str):
        return None
    schema_key = next((k for k in _SCHEMA_KEYS if isinstance(item.get(k), dict)), None)
    desc = item.get("description")
    if not isinstance(desc, str) and schema_key is None:
        return None
    if flavor == "generic":
        if "inputSchema" in item:
            flavor = "mcp"
        elif "input_schema" in item:
            flavor = "anthropic"
    raw_ann = item.get("annotations")
    annotations: dict[str, Any] = raw_ann if isinstance(raw_ann, dict) else {}
    return Tool(
        name=name,
        description=desc if isinstance(desc, str) else "",
        title=item.get("title") if isinstance(item.get("title"), str) else None,
        params=_params(item[schema_key], path + (schema_key,)) if schema_key else [],
        annotations=dict(annotations),
        extensions={k: v for k, v in item.items() if isinstance(k, str) and k.startswith("x-") and k != IGNORE_KEY},
        source=source,
        flavor=flavor,
        path=path,
    )


def extract_tools(data: Any, source: str = "") -> list[Tool]:
    tools: list[Tool] = []
    for items, base in _tool_lists(data):
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            ipath: JsonPath = base + (i,) if base != () or isinstance(data, list) else ()
            unwrapped = unwrap_openai(item, ipath)
            if unwrapped:
                tdict, tpath, flavor = unwrapped
            else:
                tdict, tpath, flavor = item, ipath, "generic"
            tool = _tool_from(tdict, tpath, flavor, source)
            if tool is not None:
                tools.append(tool)
    return tools
