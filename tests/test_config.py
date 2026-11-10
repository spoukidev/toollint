from __future__ import annotations

import pytest

from toollint.config import ConfigError, parse_config, resolve_rules
from toollint.model import Severity
from toollint.rules import all_rules

CODES = [r.id for r in all_rules()]
NAMES = {r.name: r.id for r in all_rules()}


def test_defaults() -> None:
    cfg = parse_config({})
    assert cfg.select == ["ALL"] and cfg.fail_on is Severity.MEDIUM


def test_parse_all_keys() -> None:
    cfg = parse_config(
        {
            "select": ["TL1", "TL4"],
            "ignore": "TL106",
            "fail-on": "HIGH",
            "exclude": ["vendor"],
            "per-file-ignores": {"x/*.json": ["TL301"]},
            "baseline": "b.json",
            "max-description-length": 500,
            "entropy-threshold": 3.5,
            "extra-popular-packages": ["npm:@acme/x"],
        }
    )
    assert cfg.ignore == ["TL106"] and cfg.fail_on is Severity.HIGH and cfg.max_description_length == 500


@pytest.mark.parametrize("bad", [{"nope": 1}, {"fail-on": "severe"}, {"select": 3}, {"per-file-ignores": []}])
def test_invalid(bad: dict) -> None:
    with pytest.raises(ConfigError):
        parse_config(bad)


def test_selection_prefixes_and_names() -> None:
    assert resolve_rules(["TL1"], ["TL106"], CODES, NAMES) == {"TL101", "TL102", "TL103", "TL104", "TL105"}
    assert resolve_rules(["ALL"], [], CODES, NAMES) == set(CODES)
    assert resolve_rules(["tool-shadowing"], [], CODES, NAMES) == {"TL104"}
    with pytest.raises(ConfigError):
        resolve_rules(["TL9"], [], CODES, NAMES)
