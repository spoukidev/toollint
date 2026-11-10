PY ?= .venv/bin/python
VENV ?= .venv

.PHONY: help install lint format typecheck test docs docs-check demo check scan sarif clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Create .venv and install with dev extras
	python3 -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e '.[dev]'

lint:  ## ruff check + format check
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format:  ## Apply ruff formatting and safe fixes
	$(PY) -m ruff format .
	$(PY) -m ruff check --fix .

typecheck:  ## mypy --strict
	$(PY) -m mypy

test:  ## Run the test suite
	$(PY) -m pytest

docs:  ## Regenerate docs/rules from rule docstrings
	$(PY) scripts/gen_docs.py

docs-check:
	$(PY) scripts/gen_docs.py --check

demo:  ## Regenerate docs/assets/demo.svg
	$(PY) scripts/render_demo.py

check: lint typecheck docs-check test  ## Everything CI runs

scan:  ## Scan the bundled fixtures
	$(VENV)/bin/toollint scan fixtures --isolated --exit-zero

sarif:  ## Write toollint.sarif for the fixtures
	$(VENV)/bin/toollint scan fixtures --isolated --format sarif --output toollint.sarif --exit-zero

clean:  ## Remove caches and build artifacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .hypothesis .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
