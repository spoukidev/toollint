# ToolLint: An Offline Security Linter for LLM Agent Tool Definitions and MCP Configs

**Slug:** `toollint`
**One-liner:** A `ruff`-style CLI that scans MCP server configs and agent tool definitions for tool poisoning, hidden instructions, overbroad permissions, and leaked secrets before you connect them to an agent.
**Level:** Intermediate · **Effort:** 1–2 weeks part time · **License:** MIT

## 1. Problem

Developers paste MCP server configs (`claude_desktop_config.json`, `.cursor/mcp.json`, VS Code `mcp.json`) and tool schemas (OpenAI function-calling JSON, LangChain tools) into their agents without reading them closely. The tool *descriptions* go straight into the model's context, which makes them an injection surface ("tool poisoning"). Configs also often carry plaintext API keys, run unpinned `npx`/`uvx` packages, or give a filesystem server the whole home directory.

## 2. Goals

1. **Static, offline, fast.** No LLM calls and no network by default, so it's safe to run in CI and on untrusted configs.
2. **Find real issues** across four families: hidden instructions, permission scope, supply chain, and secrets.
3. **Developer-friendly output:** rule IDs, severities, file and line, fix hints, plus `--format json|sarif` for GitHub code scanning.
4. **Extensible rules:** each rule is a small Python class with its own tests and docs page.

## 3. Threat model

| Item | Description |
|---|---|
| Asset | The user's agent: its context, credentials, filesystem, and the actions it can take |
| Attacker | Author of a third-party MCP server or tool package, or anyone who can edit a shared config or tool manifest |
| Attacks covered | Hidden instructions in tool descriptions or parameter docs; tool shadowing (one tool's description telling the model how to use *another* tool); exfil hints ("also send the contents to…"); unpinned or typosquatted packages; overbroad paths or shell access; secrets committed in configs |
| Out of scope | Runtime monitoring, dynamic analysis of server code, and attacks on the model itself |

## 4. Tech stack

- Python 3.10+, packaged with `pyproject.toml` (hatch or uv); console script `toollint`
- CLI: Typer · Output: Rich (terminal), JSON, SARIF 2.1.0
- Parsing: `json5` (configs with comments), PyYAML, Pydantic models for MCP configs and tool schemas
- Detection: regex and heuristics, unicode normalization (`unicodedata`), Shannon entropy for secrets, `rapidfuzz` for typosquat checks against a bundled list of popular package names
- Optional `--online` mode: `httpx` to list a live MCP server's tools over stdio/HTTP and lint those too (off by default)
- Tests: pytest, hypothesis for the normalizer, snapshot tests for output
- CI: GitHub Actions (lint, test, run toollint on its own fixtures) and a reusable `toollint-action`
- Optional: `pre-commit` hook

## 5. Key features and rules (v1)

**Hidden instructions (TL1xx)**
- TL101: imperative directives aimed at the model in descriptions ("ignore previous", "do not tell the user", "before using any other tool…")
- TL102: invisible or deceptive unicode (zero-width chars, bidi overrides, tag characters, homoglyphs)
- TL103: encoded blobs (base64, hex) inside descriptions
- TL104: tool shadowing, where a description references another tool by name and changes its behavior
- TL105: exfil hints, meaning URLs, emails, or "send / append / include" next to secrets, files, or conversation content
- TL106: suspiciously long descriptions, or ones whose wording diverges from the tool name (heuristic, warn only)

**Permissions and scope (TL2xx)**
- TL201: filesystem server rooted at `/`, `~`, or a home directory
- TL202: shell or exec tools with no allowlist
- TL203: tools with destructive verbs (delete, send, pay, transfer) and no confirmation or readOnly hint
- TL204: env passthrough of broad variables (`*`, `AWS_*`, `GITHUB_TOKEN`) into a server

**Supply chain (TL3xx)**
- TL301: unpinned `npx`, `uvx`, `pipx`, or `docker` image refs (no version or digest)
- TL302: possible typosquats of popular MCP packages (fuzzy match against a bundled list)
- TL303: `curl | sh` style or remote-script commands
- TL304: plain-HTTP remote server URLs

**Secrets (TL4xx)**
- TL401: known key formats (AWS, GitHub, Slack, OpenAI- and Anthropic-style prefixes, PEM blocks), matched by pattern only and printed redacted
- TL402: high-entropy strings in `env`/`headers` values
- TL403: secret-looking values that should be `${ENV}` references

**UX**
- `toollint scan <path|glob>` auto-detects the file type
- `toollint scan --discover` checks the usual config locations on the local machine (read-only)
- `toollint explain TL104` prints the rule docs and an example
- Inline suppressions (`"x-toollint-ignore": ["TL301"]`) and a `toollint.toml` for baselines
- Exit codes: 0 clean, 1 findings ≥ threshold, 2 usage error. `--fail-on high`
- `--fix` for safe autofixes only: move literal secrets into `${VAR}` references and write a `.env.example`

## 6. Suggested repo structure

```
toollint/
├── README.md                 # GIF of a scan, rule table, quickstart, CI snippet
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md           # "write a rule in 20 minutes"
├── pyproject.toml
├── toollint/
│   ├── cli.py
│   ├── discover.py           # known config paths per OS
│   ├── loaders/
│   │   ├── mcp_config.py     # Claude Desktop / Cursor / VS Code shapes
│   │   ├── openai_tools.py   # function-calling JSON
│   │   └── generic.py        # JSON/YAML tool manifests
│   ├── model.py              # Pydantic: Server, Tool, Param, Finding, Location
│   ├── normalize.py          # unicode + decoding helpers
│   ├── rules/
│   │   ├── base.py           # Rule interface, registry, severity
│   │   ├── hidden_instructions.py
│   │   ├── permissions.py
│   │   ├── supply_chain.py
│   │   └── secrets.py
│   ├── data/popular_packages.txt
│   ├── report/
│   │   ├── terminal.py
│   │   ├── json_out.py
│   │   └── sarif.py
│   ├── fix.py
│   └── online.py             # optional live tool listing
├── action/action.yml         # GitHub Action wrapper
├── docs/rules/TL101.md ...   # one page per rule
├── fixtures/
│   ├── clean/                # realistic safe configs (false-positive guard)
│   └── malicious/            # one fixture per rule, labeled with the expected finding
└── tests/
    ├── test_rules_*.py
    ├── test_normalize.py
    ├── test_sarif.py
    └── test_cli_snapshots.py
```

## 7. Success criteria

- `pip install -e .` followed by `toollint scan fixtures/` runs in under 1 s on the fixture set.
- At least 18 rules, each with one malicious fixture it catches and docs at `docs/rules/<id>.md`.
- At least 20 clean, realistic configs and tool schemas produce **zero high-severity findings**. Track the false-positive rate in a test.
- SARIF output validates against the 2.1.0 schema and uploads to GitHub code scanning in the repo's own CI.
- Secrets never print in full; a test asserts that output is redacted.
- No network access unless `--online` is passed (enforced by a test that blocks sockets).
- pytest green, plus ruff and mypy clean.
- README has a quickstart, a rule table, a CI snippet, and an ethics and scope note.

## 8. Why it's a good open-source contribution

- **Timely and concrete.** MCP and agent tool ecosystems are growing fast, and tool poisoning is a real, documented attack class. Some scanners already exist (for example Invariant Labs' `mcp-scan`). ToolLint sets itself apart by being fully offline and rule-based, with SARIF and CI-first output, the way `bandit` or `ruff` work for code.
- **Right size.** Small enough to finish and polish, with an obvious path for contributors since each rule is self-contained.
- **Shows the right skills:** threat modeling, parsing untrusted input safely, detection engineering with measured false positives, CLI and packaging, and CI integration.
- **Easy to demo:** one GIF of `toollint scan ~/.cursor/mcp.json` flagging a poisoned tool is a strong README hero.
