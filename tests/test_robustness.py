"""Untrusted input must never crash the scanner."""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.conftest import lint

scalars = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=40))
values = st.recursive(
    scalars,
    lambda c: st.one_of(st.lists(c, max_size=4), st.dictionaries(st.text(max_size=12), c, max_size=4)),
    max_leaves=20,
)
server_like = st.dictionaries(
    st.sampled_from(["command", "args", "env", "url", "headers", "type", "x-toollint-ignore", "inheritEnv"]),
    values,
    max_size=6,
)
tool_like = st.dictionaries(
    st.sampled_from(["name", "description", "inputSchema", "parameters", "annotations", "title"]), values, max_size=6
)


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(st.dictionaries(st.text(max_size=10), server_like, max_size=4))
def test_random_server_configs(servers: dict) -> None:
    lint({"mcpServers": servers})
    lint({"servers": servers})
    lint({"context_servers": servers})


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(tool_like, max_size=4))
def test_random_tool_lists(tools: list) -> None:
    lint({"tools": tools})
    lint(json.dumps(tools))


@settings(max_examples=100)
@given(st.text(max_size=300))
def test_random_descriptions(text: str) -> None:
    lint(
        {
            "tools": [
                {
                    "name": "t",
                    "description": text,
                    "inputSchema": {"type": "object", "properties": {"p": {"type": "string", "description": text}}},
                }
            ]
        }
    )
