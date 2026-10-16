"""Preconditions, abstention and semantic fixtures for the safe YAML loader repair (CWE-502)."""

from __future__ import annotations

import ast
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.safe_deserialization import SafeDeserializationFixer

YAML = "import yaml\n\n"


def _fix(src: str, header: str = YAML) -> tuple[str, SafeDeserializationFixer]:
    fixer = SafeDeserializationFixer()
    fixed, _ = fixer.fix(header + textwrap.dedent(src))
    return fixed, fixer


def _reasons(fixer: SafeDeserializationFixer) -> list[str]:
    return [a.reason for a in fixer.abstentions]


def test_fixer_metadata() -> None:
    assert SafeDeserializationFixer.rule_id == "xbnd.unsafe-deserialization"
    assert SafeDeserializationFixer.name == "safe_deserialization"
    assert SafeDeserializationFixer.auto_apply is True


# --- call and loader shapes -------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "body", "expected"),
    [
        (YAML, "yaml.load(body)", "yaml.safe_load(body)"),
        (YAML, "yaml.load(body, Loader=yaml.Loader)", "yaml.load(body, Loader=yaml.SafeLoader)"),
        (YAML, "yaml.load(body, yaml.UnsafeLoader)", "yaml.load(body, yaml.SafeLoader)"),
        (YAML, "yaml.load(body, Loader=yaml.CLoader)", "yaml.load(body, Loader=yaml.CSafeLoader)"),
        (
            YAML,
            "yaml.load(stream=body, Loader=yaml.Loader)",
            "yaml.load(stream=body, Loader=yaml.SafeLoader)",
        ),
        (YAML, "yaml.unsafe_load(body)", "yaml.safe_load(body)"),
        (
            YAML,
            "list(yaml.load_all(body, Loader=yaml.Loader))",
            "list(yaml.load_all(body, Loader=yaml.SafeLoader))",
        ),
        (YAML, "list(yaml.unsafe_load_all(body))", "list(yaml.safe_load_all(body))"),
        (
            YAML,
            "yaml.load(body, Loader=yaml.loader.Loader)",
            "yaml.load(body, Loader=yaml.loader.SafeLoader)",
        ),
        (
            "import yaml as y\n\n",
            "y.load(body, Loader=y.Loader)",
            "y.load(body, Loader=y.SafeLoader)",
        ),
        ("import yaml as y\n\n", "y.load(body)", "y.safe_load(body)"),
        (
            "from yaml import load, Loader\n\n",
            "load(body, Loader=Loader)",
            "from yaml import SafeLoader\n\ndef view(body):\n    return load(body, Loader=SafeLoader)",
        ),
        (
            "from yaml import load, SafeLoader as SL, Loader\n\n",
            "load(body, Loader=Loader)",
            "load(body, Loader=SL)",
        ),
        (
            "import yaml\nfrom yaml import unsafe_load\n\n",
            "unsafe_load(body)",
            "yaml.safe_load(body)",
        ),
        ("from yaml import load\n\n", "load(body)", "from yaml import safe_load\n"),
    ],
)
def test_user_fed_loads_use_the_safe_loader(header: str, body: str, expected: str) -> None:
    fixed, fixer = _fix(f"def view(body):\n    return {body}\n", header)
    assert fixer.abstentions == [], _reasons(fixer)
    assert expected in fixed, fixed
    ast.parse(fixed)


@pytest.mark.parametrize(
    "src",
    [
        "def view(body):\n    return yaml.safe_load(body)\n",
        "def view(body):\n    return yaml.load(body, Loader=yaml.SafeLoader)\n",
        "def view(body):\n    return yaml.load(body, Loader=yaml.CSafeLoader)\n",
        "def view(body):\n    return yaml.load(body, Loader=yaml.BaseLoader)\n",
        "def view(body):\n    return yaml.full_load(body)\n",
        # Trusted config files may use !!python/* tags on purpose.
        "CONFIG = yaml.load(open('settings.yml'), Loader=yaml.Loader)\n",
        "def view():\n    with open('settings.yml') as fh:\n        return yaml.load(fh, Loader=yaml.Loader)\n",
        "def view(body):\n    return json.load(body)\n",
        "def view(body):\n    loader = Loader()\n    return loader.load(body)\n",
    ],
)
def test_safe_and_trusted_code_is_untouched(src: str) -> None:
    fixed, fixer = _fix(src)
    assert fixed == YAML + src
    assert fixer.abstentions == []


def test_input_and_request_streams_are_user_input() -> None:
    fixed, _ = _fix("CFG = yaml.load(input(), Loader=yaml.Loader)\n")
    assert "Loader=yaml.SafeLoader" in fixed
    fixed, _ = _fix("def view(request):\n    return yaml.load(request.data)\n")
    assert "yaml.safe_load(request.data)" in fixed
    fixed, _ = _fix("def view(path):\n    with open(path) as fh:\n        return yaml.load(fh)\n")
    assert "yaml.safe_load(fh)" in fixed


@pytest.mark.parametrize(
    ("header", "body", "reason"),
    [
        (YAML, "yaml.load(body, Loader=MyLoader)", "custom class or a variable"),
        (YAML, "yaml.load(body, Loader=loaders[0])", "custom class or a variable"),
        (YAML, "yaml.load(body, **opts)", "**kwargs"),
        (YAML, "yaml.load(*body)", "*args"),
        ("import pickle\n\n", "pickle.loads(body)", "sign the payloads"),
        ("import pickle\n\n", "pickle.load(body, encoding='latin1')", "sign the payloads"),
        ("from pickle import loads\n\n", "loads(body)", "pickle.loads"),
        ("import marshal, dill, shelve\n\n", "marshal.loads(body)", "marshal.loads"),
        ("import jsonpickle\n\n", "jsonpickle.decode(body)", "jsonpickle.decode"),
        ("from yaml import load\nsafe_load = None\n\n", "load(body)", "already used"),
        (
            "from yaml import load, Loader\n\ndef SafeLoader(): ...\n\n",
            "load(body, Loader=Loader)",
            "already used",
        ),
    ],
)
def test_unsafe_shapes_abstain(header: str, body: str, reason: str) -> None:
    src = f"def view(body, opts=None):\n    return {body}\n"
    fixed, fixer = _fix(src, header)
    assert fixed == header + src
    assert any(reason in r for r in _reasons(fixer)), _reasons(fixer)


def test_shadowed_yaml_is_not_rewritten() -> None:
    src = "def view(body):\n    yaml = Parser()\n    return yaml.load(body)\n"
    fixed, fixer = _fix(src)
    assert fixed == YAML + src
    assert fixer.abstentions == []


def test_comments_layout_and_imports_are_preserved() -> None:
    src = (
        '"""Loader."""\nfrom __future__ import annotations\n\nfrom yaml import load, Loader\n\n\n'
        "def view(body):\n"
        "    return load(\n"
        "        body,  # request body\n"
        "        Loader=Loader,\n"
        "    )\n\n\n"
        "def other(body):\n    return load(body)\n"
    )
    fixer = SafeDeserializationFixer()
    fixed, changes = fixer.fix(src)
    assert len(changes) == 2
    assert "        body,  # request body\n        Loader=SafeLoader,\n" in fixed
    assert "    return safe_load(body)\n" in fixed
    assert fixed.splitlines()[3:5] == [
        "from yaml import load, Loader",
        "from yaml import SafeLoader, safe_load",
    ]
    ast.parse(fixed)


def test_idempotent() -> None:
    fixed, _ = _fix(
        "def a(b):\n    return yaml.load(b)\n\ndef c(b):\n    return yaml.load(b, Loader=yaml.Loader)\n"
    )
    again, more = SafeDeserializationFixer().fix(fixed)
    assert again == fixed and more == []


def test_patch_records_preconditions_and_abstentions() -> None:
    src = "import pickle\nimport yaml\n\ndef a(b):\n    return yaml.load(b)\n\ndef c(b):\n    return pickle.loads(b)\n"
    patch = SafeDeserializationFixer().propose_patch(src, "app/config.py", finding_ids=("f1",))
    assert patch is not None
    assert patch.risk == "low"
    assert patch.generator_version == "2.0.0"
    assert patch.engine == "security"
    assert any("!!python" in p for p in patch.preconditions)
    assert patch.metadata["abstentions"][0]["lineno"] == 8
    assert "-    return yaml.load(b)" in patch.diff
    assert "+    return yaml.safe_load(b)" in patch.diff
    assert patch.rollback_diff
    assert patch.source_digest.startswith("sha256:")


def test_pickle_only_file_yields_no_patch() -> None:
    fixer = SafeDeserializationFixer()
    src = "import pickle\n\ndef parse(payload):\n    return pickle.loads(payload)\n"
    assert fixer.propose_patch(src, "parser.py") is None
    assert len(fixer.abstentions) == 1


# --- semantic fixture: code runs before, rejected after, plain data unchanged ------------

APP = textwrap.dedent(
    """\
    import yaml
    from yaml import Loader, load


    def parse(body):
        return yaml.load(body, Loader=yaml.Loader)


    def parse_legacy(body):
        return yaml.unsafe_load(body)


    def parse_many(body):
        return list(yaml.load_all(body, Loader=yaml.UnsafeLoader))


    def parse_short(body):
        return load(body, Loader=Loader)
    """
)

# Calls os.getcwd() while loading: a stand-in for os.system with an attacker's command.
EXPLOIT = "!!python/object/apply:os.getcwd []"

PLAIN = (
    "a: 1\nb: [x, 2.5, null, true]\n",
    "when: 2026-10-15 12:30:00\nday: 2026-10-15\n",
    "blob: !!binary aGVsbG8=\nset: !!set {a, b}\n",
    "base: &b {x: 1}\nchild:\n  <<: *b\n  y: 2\n",
    'name: "Caf\\u00e9 ✓"\nmulti: |\n  line 1\n  line 2\n',
    "- 1\n- [2, 3]\n- {k: v}\n",
    "",
)


def _load(src: str) -> ModuleType:
    mod = ModuleType("app_under_test")
    exec(compile(src, "app_under_test.py", "exec"), mod.__dict__)
    return mod


def _parsers(mod: ModuleType) -> list[object]:
    return [mod.parse, mod.parse_legacy, mod.parse_many, mod.parse_short]


def test_code_execution_before_and_rejected_after() -> None:
    fixed_src, changes = SafeDeserializationFixer().fix(APP)
    assert len(changes) == 4
    before, after = _load(APP), _load(fixed_src)

    for parse in _parsers(before):
        result = parse(EXPLOIT)  # type: ignore[operator]
        assert Path.cwd().as_posix() in str(result)  # the payload ran
    for parse in _parsers(after):
        with pytest.raises(yaml.constructor.ConstructorError):
            parse(EXPLOIT)  # type: ignore[operator]
        with pytest.raises(yaml.constructor.ConstructorError):
            parse("!!python/name:os.system")  # type: ignore[operator]

    for doc in PLAIN:
        for old, new in zip(_parsers(before), _parsers(after), strict=True):
            assert old(doc) == new(doc), doc  # type: ignore[operator]


def test_c_loader_stays_on_libyaml() -> None:
    if not yaml.__with_libyaml__:
        pytest.skip("libyaml is not available")
    src = "import yaml\n\ndef parse(body):\n    return yaml.load(body, Loader=yaml.CLoader)\n"
    fixed_src, _ = SafeDeserializationFixer().fix(src)
    before, after = _load(src), _load(fixed_src)
    assert "yaml.CSafeLoader" in fixed_src
    assert Path.cwd().as_posix() in str(before.parse(EXPLOIT))
    with pytest.raises(yaml.constructor.ConstructorError):
        after.parse(EXPLOIT)
    for doc in PLAIN:
        assert before.parse(doc) == after.parse(doc)


def test_verified_repair_is_applied_and_rescan_is_clean(tmp_path: Path) -> None:
    src = textwrap.dedent(
        """\
        import yaml


        def upload(request):
            return yaml.load(request.data, Loader=yaml.Loader)
        """
    )
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    (tmp_path / "check_app.py").write_text(
        "import app, yaml\n\n"
        "def req(data):\n"
        "    return type('Request', (), {'data': data})()\n\n"
        "assert app.upload(req('a: [1, 2]')) == {'a': [1, 2]}\n"
        "try:\n"
        "    app.upload(req('!!python/object/apply:os.getcwd []'))\n"
        "except yaml.constructor.ConstructorError:\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit('unsafe YAML loader still constructs objects')\n",
        encoding="utf-8",
    )
    before = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    assert any(f.rule_id == "xbnd.unsafe-deserialization" for f in before.findings)

    coordinator = RemediationCoordinator(fixers=[SafeDeserializationFixer()])
    plan = coordinator.plan_and_verify(
        tmp_path, test_command=[sys.executable, "check_app.py"], check_performance=False
    )
    assert [r.status for r in plan.repairs] == ["verified"]
    assert coordinator.apply_plan(plan) == ["app.py"]
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    assert not any(
        f.rule_id == "xbnd.unsafe-deserialization" and f.file == "app.py" for f in outcome.findings
    )


def test_unverified_repair_is_not_applied(tmp_path: Path) -> None:
    src = "import yaml\n\ndef upload(request):\n    return yaml.load(request.data)\n"
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    coordinator = RemediationCoordinator(fixers=[SafeDeserializationFixer()])
    plan = coordinator.plan_and_verify(tmp_path, check_performance=False)
    assert [r.status for r in plan.repairs] == ["inconclusive"]
    assert coordinator.apply_plan(plan) == []
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == src


# --- detector: safe loaders are recognised however they are spelled ----------------------


@pytest.mark.parametrize(
    ("src", "flagged"),
    [
        (
            "import yaml\n\ndef f(request):\n    return yaml.load(request.data, yaml.SafeLoader)\n",
            False,
        ),
        (
            "import yaml as y\n\ndef f(request):\n    return y.load(request.data, Loader=y.SafeLoader)\n",
            False,
        ),
        (
            "import yaml\n\ndef f(request):\n    return yaml.load(request.data, Loader=yaml.CSafeLoader)\n",
            False,
        ),
        ("import yaml\n\ndef f(request):\n    return yaml.load(request.data, yaml.Loader)\n", True),
        (
            "import yaml\n\ndef f(request):\n    return list(yaml.load_all(request.data, Loader=yaml.Loader))\n",
            True,
        ),
        (
            "import yaml\n\ndef f(request):\n    return list(yaml.unsafe_load_all(request.data))\n",
            True,
        ),
        (
            "import yaml\n\ndef f(request):\n    return list(yaml.load_all(request.data, Loader=yaml.SafeLoader))\n",
            False,
        ),
    ],
)
def test_detector_resolves_yaml_loaders(tmp_path: Path, src: str, flagged: bool) -> None:
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    found = any(f.rule_id == "xbnd.unsafe-deserialization" for f in outcome.findings)
    assert found is flagged


@pytest.mark.parametrize("loader", ["FullLoader", "CFullLoader"])
def test_full_loader_schema_is_left_for_review(loader: str) -> None:
    src = YAML + f"def view(body):\n    return yaml.load(body, Loader=yaml.{loader})\n"
    fixer = SafeDeserializationFixer()
    fixed, changes = fixer.fix(src)
    assert fixed == src and not changes
    assert "Python-specific data" in _reasons(fixer)[0]


@pytest.mark.parametrize(
    "src",
    [
        "import yaml\nyaml = Parser()\ndef view(body):\n    return yaml.load(body)\n",
        "import yaml\ndef outer(yaml):\n    def view(body):\n        return yaml.load(body)\n    return view\n",
        "from yaml import load, Loader\ndef view(body, Loader):\n    return load(body, Loader=Loader)\n",
        "from yaml import load, Loader, SafeLoader\ndef view(body, SafeLoader):\n    return load(body, Loader=Loader)\n",
        "from yaml import load\nfrom custom import *\ndef view(body):\n    return load(body)\n",
        "import yaml\ndef view(body):\n    return yaml.load(body, yaml.Loader, Loader=yaml.Loader)\n",
        "import yaml\ndef view(body):\n    return yaml.load(body, yaml.Loader, True)\n",
        "import yaml\ndef view(body):\n    return yaml.unsafe_load(body, Loader=yaml.Loader)\n",
    ],
)
def test_ambiguous_bindings_and_signatures_are_unchanged(src: str) -> None:
    fixed, changes = SafeDeserializationFixer().fix(src)
    assert fixed == src and not changes


def test_detector_does_not_trust_a_loader_by_its_spelling(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import yaml\nfrom yaml import SafeLoader\n"
        "def view(request, SafeLoader):\n    return yaml.load(request.data, Loader=SafeLoader)\n",
        encoding="utf-8",
    )
    outcome = run_providers(AnalysisTask(repo_root=tmp_path), [XBoundaryProvider()])
    assert any(f.rule_id == "xbnd.unsafe-deserialization" for f in outcome.findings)


@pytest.mark.parametrize(
    "customization",
    [
        "yaml.add_constructor('!id', make_id, Loader=yaml.Loader)",
        "yaml.Loader.add_constructor('!id', make_id)",
        "yaml.Loader = CustomLoader",
    ],
)
def test_visible_loader_customizations_require_review(customization: str) -> None:
    src = (
        YAML
        + customization
        + "\n\ndef parse(body):\n    return yaml.load(body, Loader=yaml.Loader)\n"
    )
    fixer = SafeDeserializationFixer()
    fixed, changes = fixer.fix(src)
    assert fixed == src and not changes
    assert "customized" in _reasons(fixer)[0]


@pytest.mark.parametrize(
    "body",
    [
        "class Parser:\n    yaml = custom\n    result = yaml.load(input())\n",
        "result = [yaml.load(input()) for yaml in parsers]\n",
    ],
)
def test_class_and_comprehension_bindings_are_not_global_imports(body: str) -> None:
    src = YAML + body
    fixed, changes = SafeDeserializationFixer().fix(src)
    assert fixed == src and not changes


def test_full_loader_python_tuple_schema_keeps_working() -> None:
    src = YAML + "def parse(body):\n    return yaml.load(body, Loader=yaml.FullLoader)\n"
    fixed, changes = SafeDeserializationFixer().fix(src)
    assert not changes
    assert _load(fixed).parse("!!python/tuple [1, 2]") == (1, 2)
