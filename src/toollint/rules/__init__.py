"""Rule registry. Importing this package registers every built-in rule."""

from __future__ import annotations

from toollint.rules import hidden_instructions, permissions, secrets, supply_chain  # noqa: F401
from toollint.rules.base import REGISTRY, Rule, ScanContext


def all_rules() -> list[type[Rule]]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]


def get_rule(code_or_name: str) -> type[Rule] | None:
    key = code_or_name.strip()
    if key.upper() in REGISTRY:
        return REGISTRY[key.upper()]
    for cls in REGISTRY.values():
        if cls.name == key.lower():
            return cls
    return None


__all__ = ["REGISTRY", "Rule", "ScanContext", "all_rules", "get_rule"]
