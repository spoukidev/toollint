from __future__ import annotations

from pathlib import Path

import pytest

from toollint.loaders import LoadError, load_document, load_text, parse_text
from toollint.locate import locate_json, locate_yaml


def test_json_positions() -> None:
    text = '{\n  "mcpServers": {\n    "a": {"command": "npx", "args": ["-y", "pkg"]}\n  }\n}\n'
    loc = locate_json(text)
    span = loc.find(("mcpServers", "a", "args", 1))
    assert span is not None and (span.line, span.column) == (3, 44)
    assert text[span.start : span.end] == '"pkg"'


def test_jsonc_positions_with_comments_and_trailing_commas() -> None:
    text = '// c\n{\n  /* block */ "a": {\n    "b": \'x\', // trailing\n  },\n}\n'
    loc = locate_json(text)
    span = loc.find(("a", "b"))
    assert span is not None and span.line == 4


def test_unicode_escaped_keys_are_decoded() -> None:
    loc = locate_json('{"g\\u0456thub": 1}')
    assert loc.find(("g\u0456thub",)) is not None


def test_locator_falls_back_to_ancestor() -> None:
    loc = locate_json('{"a": {"b": 1}}')
    assert loc.find(("a", "zzz")) == loc.find(("a",))


def test_locator_tolerates_garbage() -> None:
    loc = locate_json('{"a": [1, 2')
    assert loc.find(("a", 0)) is not None


def test_yaml_positions() -> None:
    text = "tools:\n  - name: x\n    description: hello\n"
    loc = locate_yaml(text)
    span = loc.find(("tools", 0, "description"))
    assert span is not None and span.line == 3


def test_yaml_alias_bomb_is_linear(tmp_path: Path) -> None:
    lines = ['a0: &a0 ["x", "x", "x", "x", "x", "x", "x", "x", "x", "x"]']
    for i in range(1, 12):
        lines.append(f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]")
    lines.append("tools:\n  - name: bomb\n    description: *a11")
    p = tmp_path / "bomb.yaml"
    p.write_text("\n".join(lines))
    from toollint.config import Config
    from toollint.engine import scan

    result = scan([str(p)], Config(), root=tmp_path)
    assert result.errors == []


def test_deep_nesting_is_an_error_not_a_crash(tmp_path: Path) -> None:
    p = tmp_path / "deep.json"
    p.write_text("[" * 100_000 + "]" * 100_000)
    with pytest.raises(LoadError):
        load_document(p)


@pytest.mark.parametrize(
    ("text", "kinds", "flavor"),
    [
        ('{"mcpServers": {"a": {"command": "x"}}}', ["mcp-config"], "mcpServers"),
        ('{"servers": {"a": {"type": "stdio", "command": "x"}}}', ["mcp-config"], "servers"),
        ('{"mcp": {"servers": {"a": {"command": "x"}}}}', ["mcp-config"], "servers"),
        ('{"context_servers": {"a": {"command": {"path": "x", "args": []}}}}', ["mcp-config"], "context_servers"),
        ('{"projects": {"/p": {"mcpServers": {"a": {"command": "x"}}}}}', ["mcp-config"], "mcpServers"),
        ('[{"type": "function", "function": {"name": "f", "parameters": {}}}]', ["tool-definitions"], None),
        ('{"tools": [{"name": "f", "description": "d", "input_schema": {}}]}', ["tool-definitions"], None),
        ('{"result": {"tools": [{"name": "f", "description": "d", "inputSchema": {}}]}}', ["tool-definitions"], None),
    ],
)
def test_shape_detection(text: str, kinds: list[str], flavor: str | None) -> None:
    doc = load_text(text, Path("x.json"), "x.json")
    assert doc is not None
    assert doc.kinds == kinds
    assert doc.config_flavor == flavor


def test_zed_nested_command_paths() -> None:
    doc = load_text(
        '{"context_servers": {"a": {"command": {"path": "npx", "args": ["-y", "pkg"]}}}}', Path("z.json"), "z.json"
    )
    assert doc is not None
    s = doc.servers[0]
    assert s.command == "npx" and s.args == ["-y", "pkg"]
    assert s.arg_path(1) == ("context_servers", "a", "command", "args", 1)


def test_continue_yaml_list() -> None:
    doc = load_text("mcpServers:\n  - name: db\n    command: uvx\n    args: [x]\n", Path("c.yaml"), "c.yaml")
    assert doc is not None and doc.servers[0].name == "db"


def test_unrecognized_documents_return_none() -> None:
    assert load_text('{"name": "my-package", "version": "1.0.0"}', Path("package.json"), "package.json") is None


def test_invalid_json_raises() -> None:
    with pytest.raises(LoadError):
        parse_text("{nope", ".json")


def test_non_utf8_is_an_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_bytes(b'{"a": "\xff"}')
    with pytest.raises(LoadError):
        load_document(p)


def test_openai_tool_parameters_are_flattened() -> None:
    text = '[{"type":"function","function":{"name":"f","description":"d","parameters":{"type":"object","properties":{"a":{"type":"object","properties":{"b":{"type":"string","description":"inner"}}}}}}}]'
    doc = load_text(text, Path("t.json"), "t.json")
    assert doc is not None
    names = [p.name for p in doc.tools[0].params]
    assert names == ["a", "a.b"]
    assert doc.tools[0].flavor == "openai"
