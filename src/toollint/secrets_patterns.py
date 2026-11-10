"""Known credential formats and redaction.

Patterns are matched offline only: ToolLint never checks whether a key is live.
Anything that matches is printed redacted (prefix plus length) everywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    id: str
    label: str
    regex: re.Pattern[str]


def _p(id_: str, label: str, pattern: str, flags: int = 0) -> SecretPattern:
    return SecretPattern(id_, label, re.compile(pattern, flags))


PATTERNS: tuple[SecretPattern, ...] = (
    _p("pem-private-key", "PEM private key block", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    _p("aws-access-key-id", "AWS access key ID", r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])"),
    _p("github-token", "GitHub token", r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}"),
    _p("github-fine-grained-pat", "GitHub fine-grained PAT", r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,}"),
    _p("slack-token", "Slack token", r"(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}"),
    _p("slack-webhook", "Slack webhook URL", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"),
    _p("anthropic-key", "Anthropic API key", r"(?<![A-Za-z0-9])sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}"),
    _p(
        "openai-key", "OpenAI-style API key", r"(?<![A-Za-z0-9])sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"
    ),
    _p("stripe-key", "Stripe secret key", r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    _p("google-api-key", "Google API key", r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}"),
    _p("npm-token", "npm access token", r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}"),
    _p("huggingface-token", "Hugging Face token", r"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}"),
    _p("jwt", "JSON Web Token", r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)


@dataclass(frozen=True)
class SecretMatch:
    pattern: SecretPattern
    start: int
    end: int
    value: str


def find_known_secrets(text: str) -> list[SecretMatch]:
    out: list[SecretMatch] = []
    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            if any(o.start <= m.start() < o.end for o in out):
                continue
            out.append(SecretMatch(pat, m.start(), m.end(), m.group(0)))
    return sorted(out, key=lambda s: s.start)


def redact(value: str, keep: int = 4) -> str:
    """``AKIAXXXXXXXXXXXXXXXX`` -> ``AKIA…[redacted, 20 chars]``. Short values reveal nothing."""
    if len(value) <= keep * 2:
        return f"[redacted, {len(value)} chars]"
    return f"{value[:keep]}…[redacted, {len(value)} chars]"


def redact_known_secrets(text: str) -> str:
    """Replace every known-format secret inside ``text`` with its redacted form."""
    matches = find_known_secrets(text)
    if not matches:
        return text
    out, pos = [], 0
    for m in matches:
        out.append(text[pos : m.start])
        out.append(redact(m.value))
        pos = m.end
    out.append(text[pos:])
    return "".join(out)
