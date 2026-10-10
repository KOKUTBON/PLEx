from __future__ import annotations

from plex.config.validate import validate_raw_config


def test_validate_unknown_key() -> None:
    errors = validate_raw_config({"unknown": True})
    assert any("Unknown key" in err for err in errors)


def test_validate_languages() -> None:
    errors = validate_raw_config({"languages": ["python", "brainfuck"]})
    assert any("unsupported" in err for err in errors)


def test_validate_rule_stability() -> None:
    assert not validate_raw_config({"rule_stability": "stable"})
    assert not validate_raw_config({"rule_stability": "experimental"})
    assert not validate_raw_config({"rule_stability": "all"})

    errs = validate_raw_config({"rule_stability": "invalid_choice"})
    assert any("rule_stability must be one of" in err for err in errs)
