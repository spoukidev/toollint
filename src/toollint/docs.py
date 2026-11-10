"""Render rule documentation (used by ``toollint explain`` and ``scripts/gen_docs.py``)."""

from __future__ import annotations

from toollint.rules.base import Rule


def render_rule_markdown(cls: type[Rule]) -> str:
    header = (
        f"# {cls.id}: {cls.name}\n\n"
        f"| Code | Name | Category | Default severity | Autofix |\n"
        f"|---|---|---|---|---|\n"
        f"| `{cls.id}` | `{cls.name}` | {cls.category.value} | {cls.severity.value} | {'yes' if cls.fixable else 'no'} |\n\n"
        f"**{cls.summary}.**\n\n"
    )
    footer = (
        "\n\n## Suppressing\n\n"
        f'Add `"x-toollint-ignore": ["{cls.id}"]` to the server or tool object, put\n'
        f"`// toollint: ignore[{cls.id}]` (JSONC) or `# toollint: ignore[{cls.id}]` (YAML) on the\n"
        f'line, or add `ignore = ["{cls.id}"]` to `toollint.toml`.\n'
    )
    return header + cls.docs() + footer
