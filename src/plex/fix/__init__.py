"""PLEx automated quick-fix and code remediation subsystem."""

from __future__ import annotations

from .all_in_superset import AllInSupersetFixer
from .base import BaseFixer, FileFixResult, FixChange
from .comprehension_in_call import UnnecessaryComprehensionInCallFixer
from .dict_comp_to_copy import DictItemsComprehensionToCopyFixer
from .dict_fromkeys import DictFromkeysFixer
from .dict_get_default_none import DictGetDefaultNoneFixer
from .dict_get_fallback import DictGetFallbackFixer
from .dict_items_value_unused import DictItemsValueUnusedFixer
from .engine import DEFAULT_FIXERS, FixEngine, PromptCallback
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

__all__ = [
    "AllInSupersetFixer",
    "BaseFixer",
    "DEFAULT_FIXERS",
    "DictFromkeysFixer",
    "DictGetDefaultNoneFixer",
    "DictGetFallbackFixer",
    "DictItemsComprehensionToCopyFixer",
    "DictItemsValueUnusedFixer",
    "FileFixResult",
    "FilterTruthyFixer",
    "FixChange",
    "FixEngine",
    "IfPassElseInvertFixer",
    "IsinstanceTupleFixer",
    "ItertoolsChainFromIterableFixer",
    "ItertoolsIsliceFixer",
    "LinearSearchFixer",
    "ManualListExtendFixer",
    "MathLogBaseFixer",
    "MathPowFixer",
    "MembershipInLiteralListFixer",
    "MutableDefaultArgFixer",
    "PromptCallback",
    "ReSubLiteralFixer",
    "RedundantCollectionCallFixer",
    "RedundantComprehensionFixer",
    "RedundantFStringFixer",
    "ShortCircuitComprehensionFixer",
    "SortedMinMaxFixer",
    "StrRemoveprefixSuffixFixer",
    "StrSplitMaxsplitFixer",
    "StrStartswithTupleFixer",
    "StringConcatFixer",
    "SyncSleepInAsyncFixer",
    "TryExceptDictGetFixer",
    "TryExceptNextDefaultFixer",
    "TryExceptPopDefaultFixer",
    "UncompiledRegexFixer",
    "UnnecessaryAsyncDefFixer",
    "UnnecessaryComprehensionInCallFixer",
    "UnnecessaryDictKeysFixer",
    "UnnecessaryEnumerateFixer",
    "UnnecessaryLambdaFixer",
    "UnnecessaryLenFixer",
]
