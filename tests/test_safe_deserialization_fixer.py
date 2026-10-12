"""Unit and integration tests for SafeDeserializationFixer (CWE-502)."""

from __future__ import annotations

from plex.repair.models import PatchCandidate
from plex.repair.safe_deserialization import SafeDeserializationFixer


def test_safe_deserialization_fixer_metadata() -> None:
    fixer = SafeDeserializationFixer()
    assert fixer.rule_id == "xbnd.unsafe-deserialization"
    assert fixer.name == "safe_deserialization"


def test_fix_yaml_load_no_loader() -> None:
    fixer = SafeDeserializationFixer()
    source = """import yaml

data = yaml.load(raw_input)
"""
    fixed, changes = fixer.fix(source, "loader.py")

    assert "yaml.safe_load(raw_input)" in fixed
    assert "yaml.load(raw_input)" not in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.unsafe-deserialization"
    assert changes[0].lineno == 3


def test_fix_yaml_load_with_unsafe_loader() -> None:
    fixer = SafeDeserializationFixer()
    source = """import yaml

data = yaml.load(raw_input, Loader=yaml.Loader)
"""
    fixed, changes = fixer.fix(source, "loader.py")

    assert "yaml.load(raw_input, Loader=yaml.SafeLoader)" in fixed
    assert "yaml.Loader" not in fixed
    assert len(changes) == 1


def test_fix_yaml_load_with_cloader() -> None:
    fixer = SafeDeserializationFixer()
    source = """import yaml

data = yaml.load(raw_input, Loader=yaml.CLoader)
"""
    fixed, changes = fixer.fix(source, "loader.py")

    assert "yaml.load(raw_input, Loader=yaml.SafeLoader)" in fixed
    assert len(changes) == 1


def test_fix_pickle_loads_to_json() -> None:
    fixer = SafeDeserializationFixer()
    source = """import pickle

def parse(payload):
    return pickle.loads(payload)
"""
    fixed, changes = fixer.fix(source, "parser.py")

    assert "import json" in fixed
    assert "json.loads(payload)" in fixed
    assert "pickle.loads(payload)" not in fixed
    assert len(changes) >= 1


def test_safe_code_is_noop() -> None:
    fixer = SafeDeserializationFixer()
    source = """import yaml
import json

data1 = yaml.safe_load(raw_input)
data2 = yaml.load(raw_input, Loader=yaml.SafeLoader)
data3 = json.loads(payload)
"""
    fixed, changes = fixer.fix(source, "safe.py")
    assert fixed == source
    assert len(changes) == 0


def test_propose_patch_candidate_yaml() -> None:
    fixer = SafeDeserializationFixer()
    source = 'data = yaml.load(payload)\n'
    candidate = fixer.propose_patch(
        source=source,
        target_file="app/config.py",
        finding_ids=("find-cwe-502",),
        metadata={"priority": "high"},
    )

    assert candidate is not None
    assert isinstance(candidate, PatchCandidate)
    assert candidate.rule_id == "xbnd.unsafe-deserialization"
    assert candidate.engine == "security"
    assert candidate.target_file == "app/config.py"
    assert "-data = yaml.load(payload)" in candidate.diff
    assert "+data = yaml.safe_load(payload)" in candidate.diff
    assert candidate.rollback_diff != ""
    assert candidate.source_digest.startswith("sha256:")


def test_propose_patch_noop_returns_none() -> None:
    fixer = SafeDeserializationFixer()
    source = 'data = yaml.safe_load(payload)\n'
    candidate = fixer.propose_patch(source=source, target_file="app/config.py")
    assert candidate is None
