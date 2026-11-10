# BUILT.md: build report

ToolLint 0.1.0 is an offline, ruff-style linter for MCP server configs and LLM agent
tool definitions. It was built from `BRIEF.md`, which is kept in the repo unchanged.

## What was built

- **Package:** `src/toollint/` uses a src layout, hatchling, the `toollint` console
  script, `python -m toollint`, and ships `py.typed`. It needs Python 3.10 or newer.
- **Loaders:** MCP client configs from Claude Desktop, Claude Code `.mcp.json`, Cursor,
  Windsurf, VS Code (`servers` / `mcp.servers`, JSONC), Zed `context_servers`,
  Continue YAML and Gemini CLI. Tool definitions from MCP `tools/list` results,
  OpenAI Chat and Responses, Anthropic `input_schema`, and generic JSON/YAML tool
  lists. Findings point at exact line:column positions, using a tolerant JSON5 scanner
  and the YAML node tree.
- **Normalization:** NFKC, invisible and bidi characters, Unicode tag-character
  smuggling, a confusables skeleton, mixed-script detection, base64/hex payload
  decoding and Shannon entropy.
- **Launcher analysis:** npx, bunx, pnpm/yarn dlx, npm exec, uvx, uv tool run,
  pipx run and docker/podman run, including when wrapped in `cmd /c`, `bash -c` or `env`.
- **19 rules in 4 categories** (the brief asks for at least 18). Each rule has a
  malicious fixture and a generated `docs/rules/<ID>.md` page.

| ID | Name | Category | Default severity |
|----|------|----------|------------------|
| TL101 | directive-in-description | hidden-instructions | high |
| TL102 | deceptive-unicode | hidden-instructions | high |
| TL103 | encoded-blob | hidden-instructions | medium |
| TL104 | tool-shadowing | hidden-instructions | high |
| TL105 | exfiltration-hint | hidden-instructions | high |
| TL106 | suspicious-description | hidden-instructions | low |
| TL201 | broad-filesystem-root | permissions | high |
| TL202 | unrestricted-shell | permissions | high |
| TL203 | destructive-without-confirmation | permissions | medium |
| TL204 | broad-env-passthrough | permissions | medium |
| TL301 | unpinned-package | supply-chain | medium |
| TL302 | possible-typosquat | supply-chain | high |
| TL303 | remote-script-execution | supply-chain | critical |
| TL304 | plain-http-remote | supply-chain | medium |
| TL305 | tls-verification-disabled | supply-chain | high |
| TL401 | known-secret-format | secrets | high |
| TL402 | high-entropy-value | secrets | medium |
| TL403 | literal-secret-value | secrets | high |
| TL404 | credential-in-url | secrets | high |

- **CLI (Typer + Rich):**
  - Commands: `scan` (alias `check`), `rules`, `explain <ID>` and `--version`.
  - Output formats: `text`, `json`, `sarif` (2.1.0) and `github` (workflow annotations).
  - Options: `--select` / `--ignore` (by ID, prefix or category), `--fail-on` (default
    `medium`), `--fix` with `.env.example` generation, `--baseline` /
    `--write-baseline`, `--discover` for known client config locations, and opt-in
    `--online`.
  - Exit codes: 0 = clean / below threshold, 1 = findings, 2 = usage or parse error.
- **Config:** `[tool.toollint]` in `pyproject.toml` or `toollint.toml`. It supports
  select/ignore, severity overrides, per-file-ignores, an allowlist and extra popular
  packages.
- **Suppression:** an `"x-toollint-ignore": ["TL202"]` key in JSON, a
  `# toollint: ignore[TL202]` comment in YAML or JSONC, per-file-ignores and baselines.
- **Safety:**
  - Scans never run a server and make no network calls unless you pass `--online`
    (HTTP/SSE `tools/list` only; stdio servers are never launched).
  - Secrets are redacted in every output format.
  - Terminal output escapes control and invisible characters, so a scanned file
    can't spoof the report.
- **Packaging extras:** composite GitHub Action in `action/`, `.pre-commit-hooks.yaml`,
  CI workflow (lint, mypy, tests on 3.10–3.13 for Linux/macOS/Windows, and a self-scan
  that requires the clean corpus to pass and the malicious one to fail, keeping the SARIF
  as an artifact), Makefile, `examples/`, README, MIT LICENSE, CHANGELOG, SECURITY,
  CONTRIBUTING and `docs/assets/demo.svg`.

## How to run

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'   # or: uv pip install -e '.[dev]'
.venv/bin/toollint scan fixtures/malicious
.venv/bin/toollint scan path/to/mcp.json --format sarif -o toollint.sarif
.venv/bin/toollint explain TL101
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy
.venv/bin/python scripts/gen_docs.py --check
.venv/bin/pytest -q
```

## Verified results (2026-11-10)

| Check | Result |
|-------|--------|
| `pytest` (Python 3.12) | **426 passed** in about 6 s, 92% branch coverage |
| `pytest` (Python 3.10, installed from wheel/editable) | 426 passed |
| `ruff check`, `ruff format --check`, `mypy --strict` | clean |
| Malicious corpus (`fixtures/malicious`, 23 files) | 23/23 flagged with the intended rule; 54 findings; 0.26 s wall time |
| Clean corpus (`fixtures/clean`, 26 realistic configs and tool lists) | 0 critical/high/medium. 1 low (TL106, the real 1856-char Sequential Thinking description). Exit code 0 |
| SARIF | validated against the official OASIS 2.1.0 schema (vendored in `tests/data`) |
| Redaction | no fake secret appears in text, JSON, SARIF or GitHub output |
| Offline guarantee | full scan passes with sockets monkeypatched to raise |
| Wheel | builds, includes `data/popular_packages.txt` and `py.typed`; installed CLI works on 3.10 |

The tests cover:

- every rule, with positive and negative cases;
- loaders and position mapping;
- launcher parsing;
- normalization, including property-based tests;
- config and suppressions;
- CLI exit codes and options;
- golden snapshots of each output format (`tests/snapshots`);
- `--fix`;
- online mode with a mocked transport;
- robustness against malformed and huge inputs;
- docs/README sync.

All secrets in the fixtures are obvious fakes, such as `AKIAEXAMPLEFAKEKEY00`,
`ghp_FAKE0TOKEN0FOR0TOOLLINT0TESTS0000000` and `xoxb-FAKE-…`. Tests build theirs at
runtime. Domains use `.test`, `.example` and `.invalid`.

## Known limits

- The rules are heuristics. Hidden-instruction directive patterns are English-only,
  and a determined attacker can paraphrase around them. ToolLint is a lint layer,
  not a sandbox.
- The typosquat check compares against a bundled snapshot of about 80 popular
  npm/PyPI/Docker names (you can extend it in config). It doesn't query registries.
- `--online` only supports HTTP/SSE servers. Tool descriptions that a stdio server
  serves at runtime are only checked if you export them to a file first.
- `--fix` rewrites secrets to `${env:VAR}` (VS Code/Cursor) or `${VAR}`. Some clients,
  e.g. Claude Desktop, may not expand variables, so check before relying on it.
- `OWNER/toollint` placeholders in README, `examples/pre-commit-config.yaml` and the
  Action snippet need the real GitHub path after publishing.
- `make` wasn't available on the build box. Every Makefile target's underlying command
  was run directly instead.
- `examples/insecure_claude_desktop_config.json` and `fixtures/malicious` fail a scan on
  purpose. Running `toollint scan .` at the repo root therefore exits 1.
- The demo is a static SVG (`scripts/render_demo.py`), not an animated GIF.
