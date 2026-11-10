"""Output formats: Rich terminal text, JSON, SARIF 2.1.0 and GitHub workflow annotations."""

from toollint.report.github import render_github
from toollint.report.json_out import render_json
from toollint.report.sarif import render_sarif
from toollint.report.terminal import render_text

FORMATS = ("text", "json", "sarif", "github")

__all__ = ["FORMATS", "render_github", "render_json", "render_sarif", "render_text"]
