# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Rule codes are stable: a code is never
reused for a different check.

## [Unreleased]

## [0.1.0] - 2026-11-10

### Added

- `toollint scan` (alias `check`) for files, directories and globs, with content-based
  detection of MCP client configs (Claude Desktop, Cursor, Windsurf, Claude Code,
  Gemini CLI, VS Code `mcp.json` / `settings.json`, Zed, Continue) and tool definitions
  (OpenAI, Anthropic, MCP `tools/list`, generic JSON/YAML manifests).
- 19 rules:
  - Hidden instructions: TL101 directive-in-description, TL102 deceptive-unicode,
    TL103 encoded-blob, TL104 tool-shadowing, TL105 exfiltration-hint,
    TL106 suspicious-description.
  - Permissions: TL201 broad-filesystem-root, TL202 unrestricted-shell,
    TL203 destructive-without-confirmation, TL204 broad-env-passthrough.
  - Supply chain: TL301 unpinned-package, TL302 possible-typosquat,
    TL303 remote-script-execution, TL304 plain-http-remote, TL305 tls-verification-disabled.
  - Secrets: TL401 known-secret-format, TL402 high-entropy-value,
    TL403 literal-secret-value, TL404 credential-in-url.
- Output formats: Rich text, JSON, SARIF 2.1.0 and GitHub workflow annotations.
- `--fix`: moves literal secrets in `env`/`headers` into environment references and
  writes `.env.example`, preserving comments and formatting.
- Configuration through `toollint.toml` or `[tool.toollint]`: select/ignore by code,
  prefix or name, `fail-on`, `exclude`, `per-file-ignores`, baselines.
- Suppressions with `x-toollint-ignore` keys and `toollint: ignore[...]` line comments.
- `toollint rules`, `toollint explain <code>`, `toollint scan --discover`.
- Optional `--online` mode that lints live `tools/list` results from remote HTTP servers.
- GitHub Action (`action/action.yml`) and pre-commit hook.
