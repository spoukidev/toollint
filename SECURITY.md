# Security Policy

ToolLint parses untrusted files by design, so bugs in it can be security bugs. Thank
you for helping keep it safe.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Report privately using
GitHub's "Report a vulnerability" button (Security → Advisories) on this repository.
Include:

- the ToolLint version (`toollint --version`) and Python version
- a minimal input file that reproduces the problem (use fake credentials)
- what happened and what you expected

You should get an acknowledgement within 5 working days. We will agree on a
disclosure timeline with you, usually within 90 days, and credit you in the release
notes unless you prefer otherwise.

## What counts as a vulnerability

In scope:

- crashes, hangs or unbounded memory/CPU use on crafted input (ToolLint should
  report an error instead)
- terminal or log injection: attacker-controlled text that reaches the terminal
  without being escaped (ANSI escape sequences, Rich markup)
- a secret printed unredacted in any output format
- any network access without `--online`, or any execution of scanned commands
- `--fix` writing outside the scanned file and its `.env.example`, or changing
  anything except the literal secret value

Not vulnerabilities (but please open a normal issue):

- **detection gaps (false negatives) and false positives.** ToolLint is a heuristic
  linter. A bypass of a rule is a welcome bug report or pull request; please include
  a fixture.

## Design guarantees

- No network access unless `--online` is passed (enforced by `tests/test_offline.py`).
- ToolLint never runs the servers or commands it inspects. `--online` only queries
  servers that already have an HTTP(S) `url`.
- Matches for credential patterns are always redacted (`tests/test_redaction.py`).
- YAML is loaded with `yaml.safe_load`. Input size and nesting depth are capped.
