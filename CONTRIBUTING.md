# Contributing to ToolLint

Thanks for helping! Bug reports, false-positive reports (with a realistic config),
detection bypasses and new rules are all welcome.

## Setup

```bash
git clone <repo-url> toollint && cd toollint
make install          # creates .venv and installs '.[dev]'
make check            # ruff, ruff format --check, mypy --strict, docs check, pytest
```

## Write a rule in 20 minutes

1. **Pick a code.** Codes are `TL<family><nn>`: `1` hidden instructions,
   `2` permissions, `3` supply chain, `4` secrets. Take the next free number in the
   family. Codes are never reused.

2. **Add a class** to the matching module in `src/toollint/rules/`. The docstring is
   the rule's documentation and must have the four sections shown:

   ```python
   @register
   class NoFooServers(Rule):
       """
       ## What it does
       Flags servers named "foo".

       ## Why is this bad?
       Foo servers are known to be bad.

       ## Example
       ```json
       {"mcpServers": {"foo": {"command": "foo-mcp"}}}
       ```

       ## Fix
       Use a bar server instead.
       """

       id = "TL205"
       name = "no-foo-servers"            # kebab-case, stable
       category = Category.PERMISSIONS
       severity = Severity.MEDIUM
       summary = "Servers named foo"

       def check(self, doc: Document, ctx: ScanContext) -> Iterator[Finding]:
           for server in doc.servers:
               if server.name == "foo":
                   yield self.report(doc, server.path, f"Server '{safe_display(server.name)}' is a foo server",
                                     fix="Use a bar server.")
   ```

   Useful building blocks:

   - `doc.servers` / `doc.tools`: normalized `Server` / `Tool` models with `.path` for locations
   - `toollint.commands.analyze(server)`: packages, versions, docker mounts and env flags
   - `tool_text_fields(tool)`: every model-visible string of a tool
   - `normalize_for_matching(text)`: match against this, not raw text
   - `safe_display(text)`: wrap **every** attacker-controlled string you put in a message

3. **Add a malicious fixture** `fixtures/malicious/TL205_<what>.json`. The filename
   prefix is the rule it must trigger, and `tests/test_fixtures.py` checks it.

4. **Add tests** to `tests/test_rules_<family>.py`: at least one positive and one
   negative case, including a realistic near-miss.

5. **Regenerate docs:** `make docs` (writes `docs/rules/TL205.md`), and add the rule
   to the table in `README.md`.

6. **Check false positives:** `make check`. The clean corpus in `fixtures/clean/`
   must produce no high-severity findings. If your rule fires on a realistic clean
   config, tighten it, or lower its severity and explain why in the docstring.

## Guidelines

- Rules must be pure: no I/O, no network, no subprocesses.
- Never print a secret. Use `redact()` and let `Rule.report` do its redaction pass.
- Prefer precision over recall for `high` and `critical`. Noisy heuristics belong at
  `low` (warn only).
- Fake credentials in tests are assembled at runtime (see `tests/conftest.py::FAKE`)
  so that complete token-shaped strings never land in git. Use reserved domains
  (`.example`, `.test`, `.invalid`) in fixtures.
- Update `CHANGELOG.md` under *Unreleased*.
