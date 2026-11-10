#!/usr/bin/env python3
"""Render docs/assets/demo.svg: a real colored scan of the examples, for the README."""

from __future__ import annotations

import os
from pathlib import Path

from rich.console import Console
from rich.text import Text

from toollint.config import Config
from toollint.engine import scan
from toollint.report.terminal import render_text

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    os.chdir(ROOT)
    sink = open(os.devnull, "w")  # noqa: SIM115 - rich records output; nothing is shown
    console = Console(record=True, width=168, height=60, force_terminal=True, color_system="truecolor", file=sink)
    examples = ROOT / "examples"
    os.chdir(examples)
    console.print(
        Text("$ toollint scan poisoned_tools.json insecure_claude_desktop_config.json -q", style="bold green")
    )
    result = scan(["poisoned_tools.json", "insecure_claude_desktop_config.json"], Config(), root=examples)
    render_text(result, console, quiet=True)
    out = ROOT / "docs" / "assets" / "demo.svg"
    console.save_svg(str(out), title="toollint")
    sink.close()
    print(f"wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
