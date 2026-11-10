"""Well-known MCP config locations per OS (read-only; nothing is modified)."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def candidate_paths(
    home: Path | None = None, cwd: Path | None = None, platform: str | None = None, env: dict[str, str] | None = None
) -> list[tuple[str, Path]]:
    """Return ``(client, path)`` pairs to check, whether or not they exist."""
    home = home or Path.home()
    cwd = cwd or Path.cwd()
    platform = platform or sys.platform
    env = dict(os.environ) if env is None else env
    out: list[tuple[str, Path]] = []

    if platform == "darwin":
        app_support = home / "Library" / "Application Support"
        out += [
            ("Claude Desktop", app_support / "Claude" / "claude_desktop_config.json"),
            ("VS Code", app_support / "Code" / "User" / "mcp.json"),
            ("VS Code", app_support / "Code" / "User" / "settings.json"),
            ("VS Code Insiders", app_support / "Code - Insiders" / "User" / "mcp.json"),
            ("Cursor", app_support / "Cursor" / "User" / "settings.json"),
        ]
    elif platform.startswith("win"):
        appdata = Path(env.get("APPDATA", str(home / "AppData" / "Roaming")))
        out += [
            ("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json"),
            ("VS Code", appdata / "Code" / "User" / "mcp.json"),
            ("VS Code", appdata / "Code" / "User" / "settings.json"),
            ("VS Code Insiders", appdata / "Code - Insiders" / "User" / "mcp.json"),
        ]
    else:
        config = Path(env.get("XDG_CONFIG_HOME", str(home / ".config")))
        out += [
            ("Claude Desktop", config / "Claude" / "claude_desktop_config.json"),
            ("VS Code", config / "Code" / "User" / "mcp.json"),
            ("VS Code", config / "Code" / "User" / "settings.json"),
            ("VS Code Insiders", config / "Code - Insiders" / "User" / "mcp.json"),
            ("Zed", config / "zed" / "settings.json"),
        ]
    out += [
        ("Cursor", home / ".cursor" / "mcp.json"),
        ("Claude Code", home / ".claude.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("Gemini CLI", home / ".gemini" / "settings.json"),
        ("Amazon Q", home / ".aws" / "amazonq" / "mcp.json"),
        # Project-level configs in the current directory
        ("Cursor (project)", cwd / ".cursor" / "mcp.json"),
        ("VS Code (project)", cwd / ".vscode" / "mcp.json"),
        ("Claude Code (project)", cwd / ".mcp.json"),
        ("Gemini CLI (project)", cwd / ".gemini" / "settings.json"),
    ]
    return out


def discover(home: Path | None = None, cwd: Path | None = None, platform: str | None = None) -> list[tuple[str, Path]]:
    """Existing config files from :func:`candidate_paths`, de-duplicated."""
    seen: set[Path] = set()
    found: list[tuple[str, Path]] = []
    for client, path in candidate_paths(home, cwd, platform):
        try:
            if path.is_file() and path.resolve() not in seen:
                seen.add(path.resolve())
                found.append((client, path))
        except OSError:
            continue
    return found
