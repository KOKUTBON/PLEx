"""Orchestrator for the PLEx automated quick-fix engine."""

from __future__ import annotations

import difflib
from collections.abc import Callable, Sequence
from pathlib import Path

from .all_in_superset import AllInSupersetFixer
from .base import BaseFixer, FileFixResult, FixChange
from .comprehension_in_call import UnnecessaryComprehensionInCallFixer
from .dict_comp_to_copy import DictItemsComprehensionToCopyFixer
from .dict_fromkeys import DictFromkeysFixer
from .dict_get_default_none import DictGetDefaultNoneFixer
from .dict_get_fallback import DictGetFallbackFixer
from .dict_items_value_unused import DictItemsValueUnusedFixer
from .filter_truthy import FilterTruthyFixer
from .if_pass_else_invert import IfPassElseInvertFixer
from .isinstance_tuple import IsinstanceTupleFixer
from .itertools_chain_from_iterable import ItertoolsChainFromIterableFixer
from .itertools_islice import ItertoolsIsliceFixer
from .linear_search import LinearSearchFixer
from .manual_list_extend import ManualListExtendFixer
from .math_log_base import MathLogBaseFixer
from .math_pow import MathPowFixer
from .membership_in_literal_list import MembershipInLiteralListFixer
from .mutable_default_arg import MutableDefaultArgFixer
from .re_sub_literal import ReSubLiteralFixer
from .redundant_collection_call import RedundantCollectionCallFixer
from .redundant_comprehension import RedundantComprehensionFixer
from .redundant_fstring import RedundantFStringFixer
from .short_circuit_comprehension import ShortCircuitComprehensionFixer
from .sorted_min_max import SortedMinMaxFixer
from .str_removeprefix_suffix import StrRemoveprefixSuffixFixer
from .str_split_maxsplit import StrSplitMaxsplitFixer
from .str_startswith_tuple import StrStartswithTupleFixer
from .string_concat import StringConcatFixer
from .sync_sleep import SyncSleepInAsyncFixer
from .try_except_dict_get import TryExceptDictGetFixer
from .try_except_next_default import TryExceptNextDefaultFixer
from .try_except_pop_default import TryExceptPopDefaultFixer
from .uncompiled_regex import UncompiledRegexFixer
from .unnecessary_async_def import UnnecessaryAsyncDefFixer
from .unnecessary_dict_keys import UnnecessaryDictKeysFixer
from .unnecessary_enumerate import UnnecessaryEnumerateFixer
from .unnecessary_lambda import UnnecessaryLambdaFixer
from .unnecessary_len import UnnecessaryLenFixer

DEFAULT_FIXERS: list[BaseFixer] = [
    StringConcatFixer(),
    LinearSearchFixer(),
    UncompiledRegexFixer(),
    RedundantComprehensionFixer(),
    UnnecessaryDictKeysFixer(),
    SyncSleepInAsyncFixer(),
    UnnecessaryLenFixer(),
    MathPowFixer(),
    DictGetFallbackFixer(),
    MutableDefaultArgFixer(),
    ManualListExtendFixer(),
    ShortCircuitComprehensionFixer(),
    SortedMinMaxFixer(),
    UnnecessaryComprehensionInCallFixer(),
    MembershipInLiteralListFixer(),
    UnnecessaryLambdaFixer(),
    DictGetDefaultNoneFixer(),
    UnnecessaryAsyncDefFixer(),
    UnnecessaryEnumerateFixer(),
    DictItemsValueUnusedFixer(),
    DictItemsComprehensionToCopyFixer(),
    RedundantCollectionCallFixer(),
    RedundantFStringFixer(),
    StrStartswithTupleFixer(),
    DictFromkeysFixer(),
    ItertoolsChainFromIterableFixer(),
    TryExceptDictGetFixer(),
    TryExceptPopDefaultFixer(),
    IfPassElseInvertFixer(),
    IsinstanceTupleFixer(),
    ItertoolsIsliceFixer(),
    ReSubLiteralFixer(),
    StrRemoveprefixSuffixFixer(),
    MathLogBaseFixer(),
    TryExceptNextDefaultFixer(),
    StrSplitMaxsplitFixer(),
    FilterTruthyFixer(),
    AllInSupersetFixer(),
]

_IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "out",
    "dist",
    "build",
}


def _compute_diff(original: str, modified: str, path: str) -> str:
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        mod_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    )
    return "".join(diff)


PromptCallback = Callable[[Path, str, list[FixChange], str], str]


def _default_interactive_prompt(
    path: Path,
    rule_id: str,
    changes: list[FixChange],
    diff: str,
) -> str:
    first_change = changes[0]
    first_lineno = first_change.lineno
    desc = first_change.description

    print("\n" + "─" * 70)
    print(f"Fix [{rule_id}] in {path}:{first_lineno}")
    print(f"Description: {desc}")
    if diff:
        print(diff.rstrip())
    print("─" * 70)

    while True:
        try:
            choice = input("Apply this fix? [y,n,a,d,q,?]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return "q"

        if choice in {"y", "yes"}:
            return "y"
        elif choice in {"n", "no"}:
            return "n"
        elif choice in {"a", "all"}:
            return "a"
        elif choice in {"d", "dir", "file", "skip-file"}:
            return "d"
        elif choice in {"q", "quit", "exit"}:
            return "q"
        elif choice == "?":
            print("\n  y - apply this fix")
            print("  n - skip this fix")
            print("  a - apply this fix and all remaining fixes")
            print("  d - skip remaining fixes in this file")
            print("  q - quit and save accepted fixes")
            print("  ? - show this help message\n")
        else:
            print("Invalid response. Type '?' for help.")


class FixEngine:
    def __init__(self, fixers: Sequence[BaseFixer] | None = None) -> None:
        self.fixers: list[BaseFixer] = list(fixers or DEFAULT_FIXERS)

    def fix_source(
        self,
        source: str,
        file_path: str = "",
        rule_filter: set[str] | None = None,
    ) -> tuple[str, list[FixChange]]:
        current_source = source
        all_changes: list[FixChange] = []

        for fixer in self.fixers:
            if rule_filter is not None and fixer.rule_id not in rule_filter:
                continue
            new_source, changes = fixer.fix(current_source, file_path=file_path)
            if changes:
                current_source = new_source
                all_changes.extend(changes)

        return current_source, all_changes

    def fix_file(
        self,
        file_path: Path,
        rule_filter: set[str] | None = None,
        dry_run: bool = False,
    ) -> FileFixResult | None:
        try:
            original = file_path.read_text(encoding="utf-8")
        except Exception:
            return None

        fixed, changes = self.fix_source(
            original,
            file_path=str(file_path),
            rule_filter=rule_filter,
        )
        if not changes or original == fixed:
            return None

        diff = _compute_diff(original, fixed, str(file_path))
        result = FileFixResult(
            path=file_path,
            original_source=original,
            fixed_source=fixed,
            changes=changes,
            diff=diff,
        )

        if not dry_run:
            file_path.write_text(fixed, encoding="utf-8")

        return result

    def _collect_files(self, target_path: Path) -> list[Path]:
        if target_path.is_file():
            return [target_path] if target_path.suffix == ".py" else []
        return [
            p
            for p in sorted(target_path.rglob("*.py"))
            if not any(part in _IGNORED_DIRS for part in p.parts)
        ]

    def fix_path(
        self,
        target_path: Path,
        rule_filter: set[str] | None = None,
        dry_run: bool = False,
    ) -> list[FileFixResult]:
        results: list[FileFixResult] = []
        for p in self._collect_files(target_path):
            res = self.fix_file(p, rule_filter=rule_filter, dry_run=dry_run)
            if res and res.has_changes:
                results.append(res)
        return results

    def fix_path_interactive(
        self,
        target_path: Path,
        rule_filter: set[str] | None = None,
        dry_run: bool = False,
        prompt_fn: PromptCallback | None = None,
    ) -> list[FileFixResult]:
        if prompt_fn is None:
            prompt_fn = _default_interactive_prompt

        results: list[FileFixResult] = []
        files = self._collect_files(target_path)
        apply_all = False
        quit_requested = False

        for file_path in files:
            if quit_requested:
                break

            try:
                original = file_path.read_text(encoding="utf-8")
            except Exception:
                continue

            current_source = original
            accepted_changes: list[FixChange] = []
            skip_file = False

            for fixer in self.fixers:
                if quit_requested or skip_file:
                    break
                if rule_filter is not None and fixer.rule_id not in rule_filter:
                    continue

                new_source, changes = fixer.fix(current_source, file_path=str(file_path))
                if not changes or new_source == current_source:
                    continue

                if apply_all:
                    current_source = new_source
                    accepted_changes.extend(changes)
                    continue

                diff = _compute_diff(current_source, new_source, str(file_path))
                ans = prompt_fn(file_path, fixer.rule_id, changes, diff)

                if ans == "y":
                    current_source = new_source
                    accepted_changes.extend(changes)
                elif ans == "n":
                    continue
                elif ans == "a":
                    apply_all = True
                    current_source = new_source
                    accepted_changes.extend(changes)
                elif ans == "d":
                    skip_file = True
                    break
                elif ans == "q":
                    quit_requested = True
                    break

            if accepted_changes and current_source != original:
                diff = _compute_diff(original, current_source, str(file_path))
                res = FileFixResult(
                    path=file_path,
                    original_source=original,
                    fixed_source=current_source,
                    changes=accepted_changes,
                    diff=diff,
                )
                if not dry_run:
                    file_path.write_text(current_source, encoding="utf-8")
                results.append(res)

        return results
