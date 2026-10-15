"""Unit tests for the plex.fix subsystem and individual AST fixers."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.fix.all_in_superset import AllInSupersetFixer
from plex.fix.comprehension_in_call import UnnecessaryComprehensionInCallFixer
from plex.fix.dict_comp_to_copy import DictItemsComprehensionToCopyFixer
from plex.fix.dict_fromkeys import DictFromkeysFixer
from plex.fix.dict_get_default_none import DictGetDefaultNoneFixer
from plex.fix.dict_get_fallback import DictGetFallbackFixer
from plex.fix.dict_items_value_unused import DictItemsValueUnusedFixer
from plex.fix.engine import FixEngine
from plex.fix.filter_truthy import FilterTruthyFixer
from plex.fix.if_pass_else_invert import IfPassElseInvertFixer
from plex.fix.isinstance_tuple import IsinstanceTupleFixer
from plex.fix.itertools_chain_from_iterable import ItertoolsChainFromIterableFixer
from plex.fix.itertools_islice import ItertoolsIsliceFixer
from plex.fix.linear_search import LinearSearchFixer
from plex.fix.manual_list_extend import ManualListExtendFixer
from plex.fix.math_log_base import MathLogBaseFixer
from plex.fix.math_pow import MathPowFixer
from plex.fix.membership_in_literal_list import MembershipInLiteralListFixer
from plex.fix.mutable_default_arg import MutableDefaultArgFixer
from plex.fix.re_sub_literal import ReSubLiteralFixer
from plex.fix.redundant_collection_call import RedundantCollectionCallFixer
from plex.fix.redundant_comprehension import RedundantComprehensionFixer
from plex.fix.redundant_fstring import RedundantFStringFixer
from plex.fix.short_circuit_comprehension import ShortCircuitComprehensionFixer
from plex.fix.sorted_min_max import SortedMinMaxFixer
from plex.fix.str_removeprefix_suffix import StrRemoveprefixSuffixFixer
from plex.fix.str_split_maxsplit import StrSplitMaxsplitFixer
from plex.fix.str_startswith_tuple import StrStartswithTupleFixer
from plex.fix.string_concat import StringConcatFixer
from plex.fix.sync_sleep import SyncSleepInAsyncFixer
from plex.fix.try_except_dict_get import TryExceptDictGetFixer
from plex.fix.try_except_next_default import TryExceptNextDefaultFixer
from plex.fix.try_except_pop_default import TryExceptPopDefaultFixer
from plex.fix.uncompiled_regex import UncompiledRegexFixer
from plex.fix.unnecessary_async_def import UnnecessaryAsyncDefFixer
from plex.fix.unnecessary_dict_keys import UnnecessaryDictKeysFixer
from plex.fix.unnecessary_enumerate import UnnecessaryEnumerateFixer
from plex.fix.unnecessary_lambda import UnnecessaryLambdaFixer
from plex.fix.unnecessary_len import UnnecessaryLenFixer


class TestStringConcatFixer:
    def test_transforms_string_accumulation_in_loop(self) -> None:
        source = """
def concat_items(items):
    s = ""
    for item in items:
        s += str(item)
    return s
"""
        fixer = StringConcatFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "s_chunks = []" in new_source
        assert "s_chunks.append(str(item))" in new_source
        assert "s = ''.join(s_chunks)" in new_source
        # Verify valid python syntax
        ast.parse(new_source)

    def test_ignores_numeric_accumulation(self) -> None:
        source = """
def sum_items(items):
    total = 0
    for x in items:
        total += x
    return total
"""
        fixer = StringConcatFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source

    def test_handles_syntax_error_gracefully(self) -> None:
        bad_source = "def broken(:"
        fixer = StringConcatFixer()
        new_source, changes = fixer.fix(bad_source)
        assert not changes
        assert new_source == bad_source


class TestLinearSearchFixer:
    def test_hoists_set_for_variable_lookup(self) -> None:
        source = """
def filter_matches(queries, targets):
    results = []
    for q in queries:
        if q in targets:
            results.append(q)
    return results
"""
        fixer = LinearSearchFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "targets_set = set(targets)" in new_source
        assert "if q in targets_set:" in new_source
        ast.parse(new_source)

    def test_converts_list_literal_to_set(self) -> None:
        source = """
def is_special(items):
    matches = []
    for x in items:
        if x in [1, 2, 3]:
            matches.append(x)
    return matches
"""
        fixer = LinearSearchFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "if x in {1, 2, 3}:" in new_source
        ast.parse(new_source)

    def test_ignores_membership_outside_loop(self) -> None:
        source = """
def check_once(item, targets):
    return item in targets
"""
        fixer = LinearSearchFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestUncompiledRegexFixer:
    def test_hoists_regex_compilation(self) -> None:
        source = """
import re

def find_digits(lines):
    results = []
    for line in lines:
        m = re.search(r"\\d+", line)
        if m:
            results.append(m.group())
    return results
"""
        fixer = UncompiledRegexFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert (
            "_compiled_re_1 = re.compile('\\\\d+')" in new_source
            or "_compiled_re_1 = re.compile" in new_source
        )
        assert "_compiled_re_1.search(line)" in new_source
        ast.parse(new_source)

    def test_ignores_regex_outside_loop(self) -> None:
        source = """
import re

def parse_header(line):
    return re.search(r"^#", line)
"""
        fixer = UncompiledRegexFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestRedundantComprehensionFixer:
    def test_unwraps_list_around_list_comprehension(self) -> None:
        source = "nums = list([x * 2 for x in items])\n"
        fixer = RedundantComprehensionFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert new_source.strip() == "nums = [x * 2 for x in items]"
        ast.parse(new_source)

    def test_converts_list_generator_to_list_comp(self) -> None:
        source = "nums = list(x * 2 for x in items)\n"
        fixer = RedundantComprehensionFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert new_source.strip() == "nums = [x * 2 for x in items]"
        ast.parse(new_source)

    def test_converts_set_comprehension(self) -> None:
        source = "unique = set([x for x in items])\n"
        fixer = RedundantComprehensionFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert new_source.strip() == "unique = {x for x in items}"
        ast.parse(new_source)

    def test_converts_dict_comprehension(self) -> None:
        source = "mapping = dict([(x, str(x)) for x in items])\n"
        fixer = RedundantComprehensionFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert new_source.strip() == "mapping = {x: str(x) for x in items}"
        ast.parse(new_source)


class TestUnnecessaryDictKeysFixer:
    def test_removes_keys_from_for_loop(self) -> None:
        source = """
def iterate(d):
    for k in d.keys():
        print(k)
"""
        fixer = UnnecessaryDictKeysFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "for k in d:" in new_source
        ast.parse(new_source)

    def test_removes_keys_from_in_and_not_in(self) -> None:
        source = """
def check(d, k):
    if k in d.keys():
        pass
    if k not in d.keys():
        pass
"""
        fixer = UnnecessaryDictKeysFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 2
        assert "if k in d:" in new_source
        assert "if k not in d:" in new_source
        ast.parse(new_source)


class TestSyncSleepInAsyncFixer:
    def test_transforms_time_sleep_in_async_func(self) -> None:
        source = """
import time

async def worker():
    time.sleep(1)
"""
        fixer = SyncSleepInAsyncFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "await asyncio.sleep(1)" in new_source
        assert "import asyncio" in new_source
        ast.parse(new_source)

    def test_leaves_time_sleep_in_sync_func(self) -> None:
        source = """
import time

def worker():
    time.sleep(1)
"""
        fixer = SyncSleepInAsyncFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestUnnecessaryLenFixer:
    def test_transforms_len_comparisons(self) -> None:
        source = """
def check(items):
    if len(items) > 0:
        print("has items")
    if len(items) != 0:
        print("not empty")
    if len(items) == 0:
        print("empty")
    if len(items) <= 0:
        print("non-positive")
"""
        fixer = UnnecessaryLenFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 4
        assert (
            "if items:\n        print('has items')" in new_source
            or 'if items:\n        print("has items")' in new_source
        )
        assert (
            "if items:\n        print('not empty')" in new_source
            or 'if items:\n        print("not empty")' in new_source
        )
        assert (
            "if not items:\n        print('empty')" in new_source
            or 'if not items:\n        print("empty")' in new_source
        )
        assert (
            "if not items:\n        print('non-positive')" in new_source
            or 'if not items:\n        print("non-positive")' in new_source
        )
        ast.parse(new_source)


class TestMathPowFixer:
    def test_transforms_math_pow_and_pow_in_loop(self) -> None:
        source = """
import math

def calculate(values):
    results = []
    for x in values:
        results.append(math.pow(x, 2))
        results.append(pow(x, 2))
    return results
"""
        fixer = MathPowFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 2
        assert "results.append(x * x)" in new_source
        ast.parse(new_source)

    def test_ignores_math_pow_outside_loop(self) -> None:
        source = """
import math

def calculate(x):
    return math.pow(x, 2)
"""
        fixer = MathPowFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source

    def test_ignores_non_square_power(self) -> None:
        source = """
import math

def calculate(values):
    for x in values:
        _ = math.pow(x, 3)
"""
        fixer = MathPowFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestDictGetFallbackFixer:
    def test_transforms_dict_lookup_fallback(self) -> None:
        source = """
def lookup(data, key):
    if key in data:
        val = data[key]
    else:
        val = "default_value"
    return val
"""
        fixer = DictGetFallbackFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert (
            'val = data.get(key, "default_value")' in new_source
            or "val = data.get(key, 'default_value')" in new_source
        )
        ast.parse(new_source)

    def test_ignores_mismatched_key_or_dict(self) -> None:
        source = """
def lookup(data, key, other_dict):
    if key in data:
        val = other_dict[key]
    else:
        val = "default_value"
    return val
"""
        fixer = DictGetFallbackFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestMutableDefaultArgFixer:
    def test_transforms_mutable_defaults_with_docstring(self) -> None:
        source = '''def process(data, items=[], options={}):
    """Process data."""
    return len(items) + len(options)
'''
        fixer = MutableDefaultArgFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 2
        assert "def process(data, items=None, options=None):" in new_source
        assert '"""Process data."""' in new_source
        assert "if items is None:\n        items = []" in new_source
        assert "if options is None:\n        options = {}" in new_source
        ast.parse(new_source)

    def test_transforms_keyword_only_defaults(self) -> None:
        source = """def query(*, filters=[]):
    return len(filters)
"""
        fixer = MutableDefaultArgFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "def query(*, filters=None):" in new_source
        assert "if filters is None:\n        filters = []" in new_source
        ast.parse(new_source)

    def test_ignores_immutable_defaults(self) -> None:
        source = """def configure(timeout=30, debug=False, name="default", retries=None):
    pass
"""
        fixer = MutableDefaultArgFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestManualListExtendFixer:
    def test_transforms_for_loop_append(self) -> None:
        source = """def collect(items):
    out = []
    for x in items:
        out.append(x)
    return out
"""
        fixer = ManualListExtendFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "out.extend(items)" in new_source
        ast.parse(new_source)

    def test_ignores_append_with_expression(self) -> None:
        source = """def collect(items):
    out = []
    for x in items:
        out.append(x * 2)
    return out
"""
        fixer = ManualListExtendFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestShortCircuitComprehensionFixer:
    def test_transforms_any_and_all_listcomp(self) -> None:
        source = """def check(items):
    has_pos = any([x > 0 for x in items])
    all_pos = all([x > 0 for x in items])
    return has_pos, all_pos
"""
        fixer = ShortCircuitComprehensionFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 2
        assert (
            "any((x > 0 for x in items))" in new_source or "any(x > 0 for x in items)" in new_source
        )
        assert (
            "all((x > 0 for x in items))" in new_source or "all(x > 0 for x in items)" in new_source
        )
        ast.parse(new_source)

    def test_ignores_already_generator(self) -> None:
        source = """def check(items):
    return any(x > 0 for x in items)
"""
        fixer = ShortCircuitComprehensionFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestSortedMinMaxFixer:
    def test_transforms_sorted_subscripts(self) -> None:
        source = """def extremes(items):
    low = sorted(items)[0]
    high = sorted(items)[-1]
    keyed_low = sorted(items, key=len)[0]
    rev_high = sorted(items, reverse=True)[0]
    rev_low = sorted(items, reverse=True)[-1]
    return low, high, keyed_low, rev_high, rev_low
"""
        fixer = SortedMinMaxFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 5
        assert "low = min(items)" in new_source
        assert "high = max(items)" in new_source
        assert "keyed_low = min(items, key=len)" in new_source
        assert "rev_high = max(items)" in new_source
        assert "rev_low = min(items)" in new_source
        ast.parse(new_source)

    def test_ignores_other_subscripts(self) -> None:
        source = """def third(items):
    return sorted(items)[2]
"""
        fixer = SortedMinMaxFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestUnnecessaryComprehensionInCallFixer:
    def test_transforms_sum_and_tuple_listcomp(self) -> None:
        source = """def aggregates(items):
    total = sum([x * 2 for x in items])
    t = tuple([x for x in items])
    return total, t
"""
        fixer = UnnecessaryComprehensionInCallFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 2
        assert (
            "sum((x * 2 for x in items))" in new_source or "sum(x * 2 for x in items)" in new_source
        )
        assert "tuple((x for x in items))" in new_source or "tuple(x for x in items)" in new_source
        ast.parse(new_source)

    def test_ignores_already_generator(self) -> None:
        source = """def aggregates(items):
    return sum(x for x in items)
"""
        fixer = UnnecessaryComprehensionInCallFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestMembershipInLiteralListFixer:
    def test_transforms_list_in_compare(self) -> None:
        source = """def check(status, num):
    if status in ['active', 'pending']:
        return True
    if num not in [1, 2, 3]:
        return False
    return None
"""
        fixer = MembershipInLiteralListFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 2
        assert (
            "if status in {'active', 'pending'}:" in new_source
            or 'if status in {"active", "pending"}:' in new_source
        )
        assert "if num not in {1, 2, 3}:" in new_source
        ast.parse(new_source)

    def test_ignores_non_constant_list(self) -> None:
        source = """def check(status, dynamic_val):
    if status in [dynamic_val, 'other']:
        return True
    return False
"""
        fixer = MembershipInLiteralListFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestUnnecessaryLambdaFixer:
    def test_transforms_forwarding_lambda(self) -> None:
        source = """def transform(items):
    m = map(lambda x: int(x), items)
    s = sorted(items, key=lambda val: len(val))
    meth = lambda item: self.process(item)
    return m, s, meth
"""
        fixer = UnnecessaryLambdaFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 3
        assert "m = map(int, items)" in new_source
        assert "s = sorted(items, key=len)" in new_source
        assert "meth = self.process" in new_source
        ast.parse(new_source)

    def test_ignores_complex_lambda(self) -> None:
        source = """def transform(items):
    m = map(lambda x: x * 2, items)
    two_args = lambda x, y: int(x)
    return m, two_args
"""
        fixer = UnnecessaryLambdaFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestDictGetDefaultNoneFixer:
    def test_transforms_get_none(self) -> None:
        source = """def lookup(d, k):
    v1 = d.get(k, None)
    v2 = d.get(k, default=None)
    v3 = d.get(k, 0)
    return v1, v2, v3
"""
        fixer = DictGetDefaultNoneFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 2
        assert "v1 = d.get(k)" in new_source
        assert "v2 = d.get(k)" in new_source
        assert "v3 = d.get(k, 0)" in new_source
        ast.parse(new_source)


class TestFixEngine:
    def test_engine_applies_multiple_fixers(self, tmp_path: Path) -> None:
        code = """
import re

def process(items, targets):
    s = ""
    for item in items:
        if item in targets:
            s += str(item)
    return s
"""
        test_file = tmp_path / "app.py"
        test_file.write_text(code, encoding="utf-8")

        engine = FixEngine()
        results = engine.fix_path(test_file, dry_run=False)

        assert len(results) == 1
        res = results[0]
        assert res.has_changes
        # Both string concat and linear search were fixed
        rule_ids = {c.rule_id for c in res.changes}
        assert "plex.string-concat-in-loop" in rule_ids
        assert "plex.linear-search-in-loop" in rule_ids

        # File on disk was modified and is valid python
        updated = test_file.read_text(encoding="utf-8")
        assert "targets_set = set(targets)" in updated
        assert "s_chunks = []" in updated
        ast.parse(updated)

    def test_engine_dry_run_preserves_disk(self, tmp_path: Path) -> None:
        code = """
def f(items):
    s = ""
    for x in items:
        s += str(x)
    return s
"""
        test_file = tmp_path / "app.py"
        test_file.write_text(code, encoding="utf-8")

        engine = FixEngine()
        results = engine.fix_path(test_file, dry_run=True)

        assert len(results) == 1
        assert results[0].has_changes
        assert results[0].diff != ""
        # File on disk was NOT modified
        assert test_file.read_text(encoding="utf-8") == code

    def test_engine_rule_filter(self, tmp_path: Path) -> None:
        code = """
def f(items, targets):
    s = ""
    for x in items:
        if x in targets:
            s += str(x)
    return s
"""
        test_file = tmp_path / "app.py"
        test_file.write_text(code, encoding="utf-8")

        engine = FixEngine()
        results = engine.fix_path(
            test_file,
            rule_filter={"plex.linear-search-in-loop"},
            dry_run=True,
        )

        assert len(results) == 1
        rule_ids = {c.rule_id for c in results[0].changes}
        assert rule_ids == {"plex.linear-search-in-loop"}

    def test_interactive_selective_approval(self, tmp_path: Path) -> None:
        code = """def f(items, d, k):
    if k in ['a', 'b']:
        pass
    return d.get(k, None)
"""
        test_file = tmp_path / "app.py"
        test_file.write_text(code, encoding="utf-8")

        engine = FixEngine()
        # Answers: "y" for first fixer, "n" for second fixer
        answers = iter(["y", "n"])

        def mock_prompt(p: Path, rule_id: str, changes: list, diff: str) -> str:
            return next(answers)

        results = engine.fix_path_interactive(
            test_file,
            prompt_fn=mock_prompt,
            dry_run=False,
        )

        assert len(results) == 1
        assert len(results[0].changes) == 1
        assert results[0].changes[0].rule_id == "plex.membership-in-literal-list"
        modified = test_file.read_text(encoding="utf-8")
        assert "if k in {'a', 'b'}:" in modified or 'if k in {"a", "b"}:' in modified
        # second fix was rejected
        assert "d.get(k, None)" in modified

    def test_interactive_accept_all(self, tmp_path: Path) -> None:
        code = """def f(items, d, k):
    if k in ['a', 'b']:
        pass
    return d.get(k, None)
"""
        test_file = tmp_path / "app.py"
        test_file.write_text(code, encoding="utf-8")

        engine = FixEngine()
        prompt_count = 0

        def mock_prompt(p: Path, rule_id: str, changes: list, diff: str) -> str:
            nonlocal prompt_count
            prompt_count += 1
            return "a"

        results = engine.fix_path_interactive(
            test_file,
            prompt_fn=mock_prompt,
            dry_run=False,
        )

        assert len(results) == 1
        assert len(results[0].changes) == 2
        # Prompt called only once because 'a' accepts all remaining
        assert prompt_count == 1
        modified = test_file.read_text(encoding="utf-8")
        assert "d.get(k)" in modified

    def test_interactive_quit_early(self, tmp_path: Path) -> None:
        code = """def f(items, d, k):
    if k in ['a', 'b']:
        pass
    return d.get(k, None)
"""
        test_file = tmp_path / "app.py"
        test_file.write_text(code, encoding="utf-8")

        engine = FixEngine()

        def mock_prompt(p: Path, rule_id: str, changes: list, diff: str) -> str:
            return "q"

        results = engine.fix_path_interactive(
            test_file,
            prompt_fn=mock_prompt,
            dry_run=False,
        )

        assert len(results) == 0
        assert test_file.read_text(encoding="utf-8") == code

    def test_interactive_skip_file(self, tmp_path: Path) -> None:
        code1 = """def f(k):
    if k in ['a', 'b']:
        pass
"""
        code2 = """def g(d, k):
    return d.get(k, None)
"""
        f1 = tmp_path / "f1.py"
        f2 = tmp_path / "f2.py"
        f1.write_text(code1, encoding="utf-8")
        f2.write_text(code2, encoding="utf-8")

        engine = FixEngine()

        def mock_prompt(p: Path, rule_id: str, changes: list, diff: str) -> str:
            if "f1.py" in str(p):
                return "d"  # skip this file
            return "y"  # accept other file

        results = engine.fix_path_interactive(
            tmp_path,
            prompt_fn=mock_prompt,
            dry_run=False,
        )

        assert len(results) == 1
        assert results[0].path.name == "f2.py"
        assert f1.read_text(encoding="utf-8") == code1
        assert "d.get(k)" in f2.read_text(encoding="utf-8")

    def test_default_interactive_prompt_options(self, monkeypatch) -> None:
        from plex.fix.base import FixChange
        from plex.fix.engine import _default_interactive_prompt

        changes = [FixChange(rule_id="test", description="desc", lineno=1, before="b", after="a")]

        # Test 'y'
        monkeypatch.setattr("builtins.input", lambda _: "y")
        assert _default_interactive_prompt(Path("test.py"), "test", changes, "+ diff") == "y"

        # Test 'n'
        monkeypatch.setattr("builtins.input", lambda _: "no")
        assert _default_interactive_prompt(Path("test.py"), "test", changes, "+ diff") == "n"

        # Test 'a'
        monkeypatch.setattr("builtins.input", lambda _: "all")
        assert _default_interactive_prompt(Path("test.py"), "test", changes, "+ diff") == "a"

        # Test 'd'
        monkeypatch.setattr("builtins.input", lambda _: "d")
        assert _default_interactive_prompt(Path("test.py"), "test", changes, "+ diff") == "d"

        # Test 'q'
        monkeypatch.setattr("builtins.input", lambda _: "quit")
        assert _default_interactive_prompt(Path("test.py"), "test", changes, "+ diff") == "q"

        # Test EOFError -> 'q'
        def raise_eof(_):
            raise EOFError

        monkeypatch.setattr("builtins.input", raise_eof)
        assert _default_interactive_prompt(Path("test.py"), "test", changes, "+ diff") == "q"

        # Test '?' followed by 'y'
        seq = iter(["?", "y"])
        monkeypatch.setattr("builtins.input", lambda _: next(seq))
        assert _default_interactive_prompt(Path("test.py"), "test", changes, "+ diff") == "y"


class TestUnnecessaryAsyncDefFixer:
    def test_converts_async_def_to_def(self) -> None:
        source = """
async def calculate(x, y):
    total = x + y
    return total
"""
        fixer = UnnecessaryAsyncDefFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert changes[0].rule_id == "plex.unnecessary-async-def"
        assert "def calculate(x, y):" in new_source
        assert "async def calculate" not in new_source
        ast.parse(new_source)

    def test_ignores_coroutine_with_await(self) -> None:
        source = """
async def fetch(url):
    return await client.get(url)
"""
        fixer = UnnecessaryAsyncDefFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source

    def test_ignores_abstract_and_stub_methods(self) -> None:
        source = """
from abc import abstractmethod

class BaseService:
    @abstractmethod
    async def run(self):
        pass

    async def stub(self):
        ...
"""
        fixer = UnnecessaryAsyncDefFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestUnnecessaryEnumerateFixer:
    def test_removes_underscore_index(self) -> None:
        source = """
def process(items):
    for _, item in enumerate(items):
        print(item)
"""
        fixer = UnnecessaryEnumerateFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "for item in items:" in new_source
        assert "enumerate" not in new_source
        ast.parse(new_source)

    def test_removes_unused_named_index(self) -> None:
        source = """
def process(items):
    for idx, item in enumerate(items):
        print(item)
"""
        fixer = UnnecessaryEnumerateFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "for item in items:" in new_source
        assert "enumerate" not in new_source
        ast.parse(new_source)

    def test_ignores_used_index(self) -> None:
        source = """
def process(items):
    for idx, item in enumerate(items):
        print(idx, item)
"""
        fixer = UnnecessaryEnumerateFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestDictItemsValueUnusedFixer:
    def test_removes_underscore_value(self) -> None:
        source = """
def process(d):
    for k, _ in d.items():
        print(k)
"""
        fixer = DictItemsValueUnusedFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "for k in d:" in new_source
        assert ".items()" not in new_source
        ast.parse(new_source)

    def test_removes_unused_named_value(self) -> None:
        source = """
def process(d):
    for key, val in d.items():
        print(key)
"""
        fixer = DictItemsValueUnusedFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "for key in d:" in new_source
        assert ".items()" not in new_source
        ast.parse(new_source)

    def test_ignores_used_value(self) -> None:
        source = """
def process(d):
    for key, val in d.items():
        print(key, val)
"""
        fixer = DictItemsValueUnusedFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestDictItemsComprehensionToCopyFixer:
    def test_transforms_dict_comprehension_to_copy(self) -> None:
        source = """
def copy_dict(d):
    c1 = {k: v for k, v in d.items()}
    c2 = {key: val for key, val in d.items()}
    return c1, c2
"""
        fixer = DictItemsComprehensionToCopyFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 2
        assert "c1 = d.copy()" in new_source
        assert "c2 = d.copy()" in new_source
        ast.parse(new_source)

    def test_ignores_modified_keys_or_values(self) -> None:
        source = """
def process(d):
    c1 = {k: v * 2 for k, v in d.items()}
    c2 = {k.upper(): v for k, v in d.items()}
    c3 = {k: v for k, v in d.items() if v > 0}
    return c1, c2, c3
"""
        fixer = DictItemsComprehensionToCopyFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestRedundantCollectionCallFixer:
    def test_transforms_nested_collection_calls(self) -> None:
        source = """
def process(items):
    a = list(list(items))
    b = set(set(items))
    c = tuple(tuple(items))
    d = dict(dict(items))
    return a, b, c, d
"""
        fixer = RedundantCollectionCallFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 4
        assert "a = list(items)" in new_source
        assert "b = set(items)" in new_source
        assert "c = tuple(items)" in new_source
        assert "d = dict(items)" in new_source
        ast.parse(new_source)

    def test_ignores_different_collections(self) -> None:
        source = """
def process(items):
    a = list(tuple(items))
    b = set(list(items))
    c = list(items)
    return a, b, c
"""
        fixer = RedundantCollectionCallFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestRedundantFStringFixer:
    def test_transforms_redundant_fstring(self) -> None:
        source = """
def greet():
    s1 = f"hello world"
    s2 = f'constant message'
    return s1, s2
"""
        fixer = RedundantFStringFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 2
        assert "s1 = 'hello world'" in new_source or 's1 = "hello world"' in new_source
        assert "s2 = 'constant message'" in new_source or 's2 = "constant message"' in new_source
        ast.parse(new_source)

    def test_ignores_interpolated_fstrings(self) -> None:
        source = """
def greet(name):
    s1 = f"hello {name}"
    s2 = f"{name}"
    s3 = "normal string"
    return s1, s2, s3
"""
        fixer = RedundantFStringFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestStrStartswithTupleFixer:
    def test_combines_startswith_calls(self) -> None:
        source = """
def check(s):
    if s.startswith("http://") or s.startswith("https://") or s.startswith("ftp://"):
        return True
    return False
"""
        fixer = StrStartswithTupleFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert (
            "s.startswith(('http://', 'https://', 'ftp://'))" in new_source
            or 's.startswith(("http://", "https://", "ftp://"))' in new_source
        )
        ast.parse(new_source)

    def test_combines_endswith_calls(self) -> None:
        source = """
def is_image(path):
    return path.endswith(".png") or path.endswith(".jpg")
"""
        fixer = StrStartswithTupleFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert (
            "path.endswith(('.png', '.jpg'))" in new_source
            or 'path.endswith((".png", ".jpg"))' in new_source
        )
        ast.parse(new_source)

    def test_ignores_different_targets(self) -> None:
        source = """
def check(s, path):
    return s.startswith("a") or path.startswith("b")
"""
        fixer = StrStartswithTupleFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestDictFromkeysFixer:
    def test_transforms_constant_value(self) -> None:
        source = """
def init_dict(keys):
    d = {k: 0 for k in keys}
    return d
"""
        fixer = DictFromkeysFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "d = dict.fromkeys(keys, 0)" in new_source
        ast.parse(new_source)

    def test_transforms_none_value(self) -> None:
        source = """
def init_dict(keys):
    d = {k: None for k in keys}
    return d
"""
        fixer = DictFromkeysFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "d = dict.fromkeys(keys)" in new_source
        ast.parse(new_source)

    def test_ignores_dynamic_values_and_filters(self) -> None:
        source = """
def init_dict(keys):
    d1 = {k: k * 2 for k in keys}
    d2 = {k: 0 for k in keys if k}
    return d1, d2
"""
        fixer = DictFromkeysFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestItertoolsChainFromIterableFixer:
    def test_transforms_itertools_chain(self) -> None:
        source = """
import itertools

def flatten(nested):
    return list(itertools.chain(*nested))
"""
        fixer = ItertoolsChainFromIterableFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "list(itertools.chain.from_iterable(nested))" in new_source
        ast.parse(new_source)

    def test_transforms_chain_direct_import(self) -> None:
        source = """
from itertools import chain

def flatten(nested):
    return list(chain(*nested))
"""
        fixer = ItertoolsChainFromIterableFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "list(chain.from_iterable(nested))" in new_source
        ast.parse(new_source)

    def test_ignores_unstarred_chain(self) -> None:
        source = """
from itertools import chain

def combine(a, b):
    return chain(a, b)
"""
        fixer = ItertoolsChainFromIterableFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestTryExceptDictGetFixer:
    def test_transforms_try_except_keyerror_with_default(self) -> None:
        source = """
def lookup(d, k):
    try:
        val = d[k]
    except KeyError:
        val = "fallback"
    return val
"""
        fixer = TryExceptDictGetFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert (
            "val = d.get(k, 'fallback')" in new_source or 'val = d.get(k, "fallback")' in new_source
        )
        ast.parse(new_source)

    def test_transforms_try_except_keyerror_with_none_default(self) -> None:
        source = """
def lookup(d, k):
    try:
        val = d[k]
    except KeyError:
        val = None
    return val
"""
        fixer = TryExceptDictGetFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "val = d.get(k)" in new_source
        ast.parse(new_source)

    def test_ignores_different_variables(self) -> None:
        source = """
def lookup(d, k):
    try:
        val = d[k]
    except KeyError:
        other = None
    return val
"""
        fixer = TryExceptDictGetFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestTryExceptPopDefaultFixer:
    def test_transforms_pop_with_pass(self) -> None:
        source = """
def clean(d, k):
    try:
        d.pop(k)
    except KeyError:
        pass
"""
        fixer = TryExceptPopDefaultFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "d.pop(k, None)" in new_source
        ast.parse(new_source)

    def test_transforms_pop_with_assign(self) -> None:
        source = """
def clean(d, k):
    try:
        v = d.pop(k)
    except KeyError:
        v = 0
    return v
"""
        fixer = TryExceptPopDefaultFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "v = d.pop(k, 0)" in new_source
        ast.parse(new_source)

    def test_ignores_non_keyerror(self) -> None:
        source = """
def clean(d, k):
    try:
        d.pop(k)
    except ValueError:
        pass
"""
        fixer = TryExceptPopDefaultFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestIfPassElseInvertFixer:
    def test_inverts_comparison(self) -> None:
        source = """
def check(x):
    if x > 0:
        pass
    else:
        print("negative")
"""
        fixer = IfPassElseInvertFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "if x <= 0:" in new_source
        assert "print('negative')" in new_source or 'print("negative")' in new_source
        ast.parse(new_source)

    def test_inverts_unary_not(self) -> None:
        source = """
def check(flag):
    if not flag:
        pass
    else:
        run()
"""
        fixer = IfPassElseInvertFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "if flag:" in new_source
        assert "run()" in new_source
        ast.parse(new_source)

    def test_inverts_general_test(self) -> None:
        source = """
def check(cond):
    if is_ready(cond):
        pass
    else:
        wait()
"""
        fixer = IfPassElseInvertFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "if not is_ready(cond):" in new_source
        assert "wait()" in new_source
        ast.parse(new_source)

    def test_ignores_if_with_non_pass(self) -> None:
        source = """
def check(x):
    if x > 0:
        print("positive")
    else:
        print("negative")
"""
        fixer = IfPassElseInvertFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestIsinstanceTupleFixer:
    def test_combines_two_isinstance_calls(self) -> None:
        source = """
def check(x):
    if isinstance(x, int) or isinstance(x, str):
        return True
    return False
"""
        fixer = IsinstanceTupleFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "isinstance(x, (int, str))" in new_source
        ast.parse(new_source)

    def test_combines_three_isinstance_calls_flattening_tuple(self) -> None:
        source = """
def check(x):
    if isinstance(x, int) or isinstance(x, (float, complex)):
        return True
    return False
"""
        fixer = IsinstanceTupleFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "isinstance(x, (int, float, complex))" in new_source
        ast.parse(new_source)

    def test_ignores_different_targets(self) -> None:
        source = """
def check(x, y):
    if isinstance(x, int) or isinstance(y, str):
        return True
    return False
"""
        fixer = IsinstanceTupleFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestItertoolsIsliceFixer:
    def test_transforms_list_slice(self) -> None:
        source = """
def get_first(seq):
    return list(seq)[:10]
"""
        fixer = ItertoolsIsliceFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "import itertools" in new_source
        assert "list(itertools.islice(seq, 10))" in new_source
        ast.parse(new_source)

    def test_transforms_tuple_slice_with_existing_itertools(self) -> None:
        source = """
import itertools

def get_first(seq):
    return tuple(seq)[:5]
"""
        fixer = ItertoolsIsliceFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "tuple(itertools.islice(seq, 5))" in new_source
        ast.parse(new_source)

    def test_uses_direct_islice_if_imported(self) -> None:
        source = """
from itertools import islice

def get_first(seq):
    return list(seq)[:5]
"""
        fixer = ItertoolsIsliceFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "list(islice(seq, 5))" in new_source
        ast.parse(new_source)

    def test_ignores_negative_slice(self) -> None:
        source = """
def get_tail(seq):
    return list(seq)[:-1]
"""
        fixer = ItertoolsIsliceFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestReSubLiteralFixer:
    def test_transforms_re_sub_literal(self) -> None:
        source = """
import re

def clean(text):
    return re.sub("foo", "bar", text)
"""
        fixer = ReSubLiteralFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert (
            'text.replace("foo", "bar")' in new_source or "text.replace('foo', 'bar')" in new_source
        )
        ast.parse(new_source)

    def test_transforms_re_sub_with_positive_count(self) -> None:
        source = """
import re

def clean(text):
    return re.sub("foo", "bar", text, 2)
"""
        fixer = ReSubLiteralFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert (
            "text.replace('foo', 'bar', 2)" in new_source
            or 'text.replace("foo", "bar", 2)' in new_source
        )
        ast.parse(new_source)

    def test_ignores_regex_metacharacters(self) -> None:
        source = """
import re

def clean(text):
    return re.sub("foo.*bar", "baz", text)
"""
        fixer = ReSubLiteralFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source

    def test_ignores_when_flags_present(self) -> None:
        source = """
import re

def clean(text):
    return re.sub("foo", "bar", text, flags=re.IGNORECASE)
"""
        fixer = ReSubLiteralFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestStrRemoveprefixSuffixFixer:
    def test_transforms_startswith_slice(self) -> None:
        source = """
def clean(s, p):
    if s.startswith(p):
        s = s[len(p):]
    return s
"""
        fixer = StrRemoveprefixSuffixFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "s = s.removeprefix(p)" in new_source
        ast.parse(new_source)

    def test_transforms_endswith_slice(self) -> None:
        source = """
def clean(s, suffix):
    if s.endswith(suffix):
        s = s[:-len(suffix)]
    return s
"""
        fixer = StrRemoveprefixSuffixFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "s = s.removesuffix(suffix)" in new_source
        ast.parse(new_source)

    def test_ignores_non_assignment(self) -> None:
        source = """
def clean(s, p):
    if s.startswith(p):
        print(s)
    return s
"""
        fixer = StrRemoveprefixSuffixFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestMathLogBaseFixer:
    def test_transforms_math_log_base_2(self) -> None:
        source = """
import math

def compute(x):
    return math.log(x, 2)
"""
        fixer = MathLogBaseFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "math.log2(x)" in new_source
        ast.parse(new_source)

    def test_transforms_math_log_base_10(self) -> None:
        source = """
import math

def compute(x):
    return math.log(x, 10)
"""
        fixer = MathLogBaseFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "math.log10(x)" in new_source
        ast.parse(new_source)

    def test_transforms_imported_log(self) -> None:
        source = """
from math import log

def compute(x):
    return log(x, 2)
"""
        fixer = MathLogBaseFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "log2(x)" in new_source
        ast.parse(new_source)

    def test_ignores_other_bases(self) -> None:
        source = """
import math

def compute(x):
    return math.log(x, 3)
"""
        fixer = MathLogBaseFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestTryExceptNextDefaultFixer:
    def test_transforms_try_except_stopiteration(self) -> None:
        source = """
def get_val(it):
    try:
        val = next(it)
    except StopIteration:
        val = -1
    return val
"""
        fixer = TryExceptNextDefaultFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "val = next(it, -1)" in new_source
        ast.parse(new_source)

    def test_transforms_with_none_default(self) -> None:
        source = """
def get_val(it):
    try:
        item = next(it)
    except StopIteration:
        item = None
    return item
"""
        fixer = TryExceptNextDefaultFixer()
        new_source, changes = fixer.fix(source)

        assert len(changes) == 1
        assert "item = next(it, None)" in new_source
        ast.parse(new_source)

    def test_ignores_non_stopiteration(self) -> None:
        source = """
def get_val(it):
    try:
        val = next(it)
    except RuntimeError:
        val = 0
    return val
"""
        fixer = TryExceptNextDefaultFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestStrSplitMaxsplitFixer:
    def test_transforms_split_zero_no_args(self) -> None:
        source = """
def parse(s):
    return s.split()[0]
"""
        fixer = StrSplitMaxsplitFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "s.split(maxsplit=1)[0]" in new_source
        ast.parse(new_source)

    def test_transforms_split_zero_with_sep(self) -> None:
        source = """
def parse(s):
    return s.split(":")[0]
"""
        fixer = StrSplitMaxsplitFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "s.split(':', 1)[0]" in new_source or 's.split(":", 1)[0]' in new_source
        ast.parse(new_source)

    def test_transforms_rsplit_neg_one(self) -> None:
        source = """
def parse(s):
    return s.rsplit("/")[-1]
"""
        fixer = StrSplitMaxsplitFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "s.rsplit('/', 1)[-1]" in new_source or 's.rsplit("/", 1)[-1]' in new_source
        ast.parse(new_source)

    def test_ignores_already_has_maxsplit(self) -> None:
        source = """
def parse(s):
    return s.split(":", 1)[0]
"""
        fixer = StrSplitMaxsplitFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source

    def test_ignores_other_indices(self) -> None:
        source = """
def parse(s):
    return s.split(":")[1]
"""
        fixer = StrSplitMaxsplitFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestFilterTruthyFixer:
    def test_transforms_list_comp(self) -> None:
        source = """
def clean(items):
    return [x for x in items if x]
"""
        fixer = FilterTruthyFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "list(filter(None, items))" in new_source
        ast.parse(new_source)

    def test_transforms_list_generator_call(self) -> None:
        source = """
def clean(items):
    return list(x for x in items if x)
"""
        fixer = FilterTruthyFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "list(filter(None, items))" in new_source
        ast.parse(new_source)

    def test_ignores_non_truthy_comp(self) -> None:
        source = """
def clean(items):
    return [x for x in items if x > 0]
"""
        fixer = FilterTruthyFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source

    def test_ignores_transformed_elt(self) -> None:
        source = """
def clean(items):
    return [x * 2 for x in items if x]
"""
        fixer = FilterTruthyFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source


class TestAllInSupersetFixer:
    def test_transforms_all_in_variable(self) -> None:
        source = """
def check(a, b):
    return all(x in b for x in a)
"""
        fixer = AllInSupersetFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "set(b).issuperset(a)" in new_source
        ast.parse(new_source)

    def test_transforms_all_in_set_literal(self) -> None:
        source = """
def check(a):
    return all(x in {1, 2, 3} for x in a)
"""
        fixer = AllInSupersetFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "{1, 2, 3}.issuperset(a)" in new_source
        ast.parse(new_source)

    def test_transforms_all_in_set_call(self) -> None:
        source = """
def check(a, b):
    return all(x in set(b) for x in a)
"""
        fixer = AllInSupersetFixer()
        new_source, changes = fixer.fix(source)
        assert len(changes) == 1
        assert "set(b).issuperset(a)" in new_source
        ast.parse(new_source)

    def test_ignores_non_in_comparison(self) -> None:
        source = """
def check(a, b):
    return all(x not in b for x in a)
"""
        fixer = AllInSupersetFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source

    def test_ignores_with_if_condition(self) -> None:
        source = """
def check(a, b):
    return all(x in b for x in a if x > 0)
"""
        fixer = AllInSupersetFixer()
        new_source, changes = fixer.fix(source)
        assert not changes
        assert new_source == source
