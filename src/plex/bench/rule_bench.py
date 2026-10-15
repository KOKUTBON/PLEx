"""Microbenchmark suite for PLEx automated rule remediations.

Measures latency and memory allocations of unoptimized code vs.
auto-fixed code across PLEx's rule catalog.
"""

from __future__ import annotations

import itertools
import math
import platform
import random
import re
import sys
import time
import tracemalloc
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class RuleBenchmarkResult:
    rule_id: str
    name: str
    description: str
    before_median_us: float
    after_median_us: float
    speedup: float
    latency_reduction_pct: float
    before_alloc_bytes: int
    after_alloc_bytes: int
    memory_reduction_pct: float
    iterations: int


@dataclass
class RuleBenchmarkReport:
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    python: str = field(
        default_factory=lambda: (
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
    )
    platform: str = field(default_factory=lambda: f"{platform.system()} {platform.machine()}")
    results: list[RuleBenchmarkResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _CaseRunner:
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        setup_fn: Callable[[], tuple[Callable[[], Any], Callable[[], Any]]],
    ) -> None:
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.setup_fn = setup_fn

    def run(self, iterations: int = 50, warmups: int = 5) -> RuleBenchmarkResult:
        before_fn, after_fn = self.setup_fn()

        # Warmup
        for _ in range(max(1, warmups)):
            before_fn()
            after_fn()

        # Measure before
        t0 = time.perf_counter_ns()
        for _ in range(iterations):
            before_fn()
        t1 = time.perf_counter_ns()
        before_us = (t1 - t0) / (iterations * 1000.0)

        # Measure after
        t2 = time.perf_counter_ns()
        for _ in range(iterations):
            after_fn()
        t3 = time.perf_counter_ns()
        after_us = (t3 - t2) / (iterations * 1000.0)

        # Ensure after_us is at least 0.001 us to avoid division by zero
        after_us = max(after_us, 0.001)
        before_us = max(before_us, 0.001)

        speedup = before_us / after_us
        latency_reduction = max(0.0, (1.0 - (after_us / before_us)) * 100.0)

        # Memory profiling
        before_alloc = self._measure_alloc(before_fn)
        after_alloc = self._measure_alloc(after_fn)

        if before_alloc > 0:
            mem_reduction = max(0.0, float(before_alloc - after_alloc) / before_alloc * 100.0)
        else:
            mem_reduction = 0.0

        return RuleBenchmarkResult(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            before_median_us=round(before_us, 3),
            after_median_us=round(after_us, 3),
            speedup=round(speedup, 2),
            latency_reduction_pct=round(latency_reduction, 1),
            before_alloc_bytes=before_alloc,
            after_alloc_bytes=after_alloc,
            memory_reduction_pct=round(mem_reduction, 1),
            iterations=iterations,
        )

    @staticmethod
    def _measure_alloc(fn: Callable[[], Any]) -> int:
        tracemalloc.start()
        try:
            fn()
            _curr, peak = tracemalloc.get_traced_memory()
            return peak
        finally:
            tracemalloc.stop()


def _get_benchmark_cases() -> list[_CaseRunner]:
    rng = random.Random(42)

    def _setup_sorted_min_max() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = [rng.randint(0, 100_000) for _ in range(2000)]
        return (lambda: sorted(items)[0], lambda: min(items))

    def _setup_short_circuit() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = [15] + list(range(2000))
        return (
            lambda: any([x > 10 for x in items]),
            lambda: any(x > 10 for x in items),
        )

    def _setup_linear_search() -> tuple[Callable[[], Any], Callable[[], Any]]:
        queries = list(range(50))
        targets = list(range(25, 525))
        targets_set = set(targets)

        def before() -> int:
            c = 0
            for q in queries:
                if q in targets:
                    c += 1
            return c

        def after() -> int:
            c = 0
            for q in queries:
                if q in targets_set:
                    c += 1
            return c

        return before, after

    def _setup_manual_extend() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = list(range(500))

        def before() -> list[int]:
            out: list[int] = []
            for x in items:
                out.append(x)
            return out

        def after() -> list[int]:
            out: list[int] = []
            out.extend(items)
            return out

        return before, after

    def _setup_math_pow() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = [float(x) for x in range(500)]

        def before() -> list[float]:
            return [math.pow(x, 2) for x in items]

        def after() -> list[float]:
            return [x * x for x in items]

        return before, after

    def _setup_membership_literal() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = list(range(500))
        target_list = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        target_set = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100}

        def before() -> int:
            return sum(1 for x in items if x in target_list)

        def after() -> int:
            return sum(1 for x in items if x in target_set)

        return before, after

    def _setup_unnecessary_lambda() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = [str(x) for x in range(500)]
        return (
            lambda: list(map(lambda x: int(x), items)),
            lambda: list(map(int, items)),
        )

    def _setup_string_concat() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = list(range(250))

        def before() -> str:
            s = ""
            for x in items:
                s += str(x)
            return s

        def after() -> str:
            s_chunks = []
            for x in items:
                s_chunks.append(str(x))
            return "".join(s_chunks)

        return before, after

    def _setup_dict_get_fallback() -> tuple[Callable[[], Any], Callable[[], Any]]:
        d = {f"k_{i}": i for i in range(500)}
        keys = [f"k_{i}" if i % 2 == 0 else f"missing_{i}" for i in range(500)]

        def before() -> list[int]:
            out = []
            for k in keys:
                if k in d:
                    out.append(d[k])
                else:
                    out.append(0)
            return out

        def after() -> list[int]:
            out = []
            for k in keys:
                out.append(d.get(k, 0))
            return out

        return before, after

    def _setup_dict_keys() -> tuple[Callable[[], Any], Callable[[], Any]]:
        d = {i: i * 2 for i in range(500)}

        def before() -> int:
            return sum(1 for k in d.keys())

        def after() -> int:
            return sum(1 for k in d)

        return before, after

    def _setup_dict_get_none() -> tuple[Callable[[], Any], Callable[[], Any]]:
        d = {i: i * 2 for i in range(500)}
        keys = list(range(500))

        def before() -> list[int | None]:
            return [d.get(k, None) for k in keys]

        def after() -> list[int | None]:
            return [d.get(k) for k in keys]

        return before, after

    def _setup_unnecessary_len() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = list(range(100))

        def before() -> int:
            c = 0
            for _ in range(50):
                if len(items) > 0:
                    c += 1
            return c

        def after() -> int:
            c = 0
            for _ in range(50):
                if items:
                    c += 1
            return c

        return before, after

    def _setup_unnecessary_async_def() -> tuple[Callable[[], Any], Callable[[], Any]]:
        import asyncio

        async def async_fn(x: int) -> int:
            return x * 2

        def sync_fn(x: int) -> int:
            return x * 2

        loop = asyncio.new_event_loop()

        def before() -> int:
            return loop.run_until_complete(async_fn(42))

        def after() -> int:
            return sync_fn(42)

        return before, after

    def _setup_unnecessary_enumerate() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items = list(range(500))

        def before() -> int:
            s = 0
            for _, x in enumerate(items):
                s += x
            return s

        def after() -> int:
            s = 0
            for x in items:
                s += x
            return s

        return before, after

    def _setup_dict_items_value_unused() -> tuple[Callable[[], Any], Callable[[], Any]]:
        d = {i: i * 2 for i in range(500)}

        def before() -> int:
            s = 0
            for k, _ in d.items():
                s += k
            return s

        def after() -> int:
            s = 0
            for k in d:
                s += k
            return s

        return before, after

    def _setup_dict_comp_to_copy() -> tuple[Callable[[], Any], Callable[[], Any]]:
        d = {f"k{i}": i * 10 for i in range(1000)}

        def before() -> dict[str, int]:
            return {k: v for k, v in d.items()}

        def after() -> dict[str, int]:
            return d.copy()

        return before, after

    def _setup_redundant_collection() -> tuple[Callable[[], Any], Callable[[], Any]]:
        lst = list(range(1000))

        def before() -> list[int]:
            return list(list(lst))

        def after() -> list[int]:
            return list(lst)

        return before, after

    def _setup_redundant_fstring() -> tuple[Callable[[], Any], Callable[[], Any]]:
        def before() -> str:
            return f"constant static string without formatting"  # noqa: F541

        def after() -> str:
            return "constant static string without formatting"

        return before, after

    def _setup_str_startswith_tuple() -> tuple[Callable[[], Any], Callable[[], Any]]:
        s = "https://example.com/api/v1/resource/endpoint"

        def before() -> bool:
            return s.startswith("ftp://") or s.startswith("ws://") or s.startswith("https://")

        def after() -> bool:
            return s.startswith(("ftp://", "ws://", "https://"))

        return before, after

    def _setup_dict_fromkeys() -> tuple[Callable[[], Any], Callable[[], Any]]:
        keys = [f"key_{i}" for i in range(500)]

        def before() -> dict[str, int]:
            return {k: 0 for k in keys}

        def after() -> dict[str, int]:
            return dict.fromkeys(keys, 0)

        return before, after

    def _setup_itertools_chain() -> tuple[Callable[[], Any], Callable[[], Any]]:
        nested = [list(range(20)) for _ in range(50)]

        def before() -> list[int]:
            return list(itertools.chain(*nested))

        def after() -> list[int]:
            return list(itertools.chain.from_iterable(nested))

        return before, after

    def _setup_try_except_dict_get() -> tuple[Callable[[], Any], Callable[[], Any]]:
        d = {f"k_{i}": i for i in range(100)}
        query_keys = [f"k_{i}" if i % 2 == 0 else f"missing_{i}" for i in range(200)]

        def before() -> list[int]:
            res = []
            for k in query_keys:
                try:
                    v = d[k]
                except KeyError:
                    v = -1
                res.append(v)
            return res

        def after() -> list[int]:
            res = []
            for k in query_keys:
                v = d.get(k, -1)
                res.append(v)
            return res

        return before, after

    def _setup_try_except_pop_default() -> tuple[Callable[[], Any], Callable[[], Any]]:
        query_keys = [f"k_{i}" for i in range(100)]

        def before() -> int:
            d = {f"k_{i}": i for i in range(50)}
            count = 0
            for k in query_keys:
                try:
                    d.pop(k)
                    count += 1
                except KeyError:
                    pass
            return count

        def after() -> int:
            d = {f"k_{i}": i for i in range(50)}
            count = 0
            for k in query_keys:
                if d.pop(k, None) is not None:
                    count += 1
            return count

        return before, after

    def _setup_if_pass_else_invert() -> tuple[Callable[[], Any], Callable[[], Any]]:
        nums = list(range(500))

        def before() -> int:
            total = 0
            for x in nums:
                if x % 2 == 0:
                    pass
                else:
                    total += x
            return total

        def after() -> int:
            total = 0
            for x in nums:
                if x % 2 != 0:
                    total += x
            return total

        return before, after

    def _setup_isinstance_tuple() -> tuple[Callable[[], Any], Callable[[], Any]]:
        items: list[Any] = [1, "two", 3.0, [4], {"five": 5}, (6,), None] * 50

        def before() -> int:
            count = 0
            for x in items:
                if isinstance(x, int) or isinstance(x, float) or isinstance(x, str):
                    count += 1
            return count

        def after() -> int:
            count = 0
            for x in items:
                if isinstance(x, (int, float, str)):
                    count += 1
            return count

        return before, after

    def _setup_itertools_islice() -> tuple[Callable[[], Any], Callable[[], Any]]:
        def before() -> list[int]:
            return list(range(10000))[:20]

        def after() -> list[int]:
            return list(itertools.islice(range(10000), 20))

        return before, after

    def _setup_re_sub_literal() -> tuple[Callable[[], Any], Callable[[], Any]]:
        text = "The quick brown fox jumps over the lazy dog. The fox is clever and quick." * 20

        def before() -> str:
            return re.sub("fox", "cat", text)

        def after() -> str:
            return text.replace("fox", "cat")

        return before, after

    def _setup_str_removeprefix_suffix() -> tuple[Callable[[], Any], Callable[[], Any]]:
        urls = [f"https://example.com/api/v1/resource/{i}" for i in range(200)]
        prefix = "https://"

        def before() -> list[str]:
            res = []
            for u in urls:
                if u.startswith(prefix):
                    u = u[len(prefix) :]
                res.append(u)
            return res

        def after() -> list[str]:
            res = []
            for u in urls:
                u = u.removeprefix(prefix)
                res.append(u)
            return res

        return before, after

    def _setup_math_log_base() -> tuple[Callable[[], Any], Callable[[], Any]]:
        nums = [float(x * 10) for x in range(1, 500)]

        def before() -> list[float]:
            return [math.log(x, 2) for x in nums]

        def after() -> list[float]:
            return [math.log2(x) for x in nums]

        return before, after

    def _setup_try_except_next_default() -> tuple[Callable[[], Any], Callable[[], Any]]:
        seqs = [range(1 if i % 2 == 0 else 0) for i in range(200)]

        def before() -> list[int]:
            res = []
            for s in seqs:
                it = iter(s)
                try:
                    val = next(it)
                except StopIteration:
                    val = -1
                res.append(val)
            return res

        def after() -> list[int]:
            res = []
            for s in seqs:
                it = iter(s)
                val = next(it, -1)
                res.append(val)
            return res

        return before, after

    def _setup_str_split_maxsplit() -> tuple[Callable[[], Any], Callable[[], Any]]:
        text = "user:password:hash:salt:info:extra:fields:long:data"

        def before() -> str:
            return text.split(":")[0]

        def after() -> str:
            return text.split(":", 1)[0]

        return before, after

    def _setup_filter_truthy() -> tuple[Callable[[], Any], Callable[[], Any]]:
        data = [i if i % 3 != 0 else None for i in range(1000)]

        def before() -> list[Any]:
            return [x for x in data if x]

        def after() -> list[Any]:
            return list(filter(None, data))

        return before, after

    def _setup_all_in_superset() -> tuple[Callable[[], Any], Callable[[], Any]]:
        allowed = set(range(500))
        check = list(range(100))

        def before() -> bool:
            return all(x in allowed for x in check)

        def after() -> bool:
            return allowed.issuperset(check)

        return before, after

    return [
        _CaseRunner(
            "plex.sorted-min-max",
            "min() vs sorted()[0]",
            "O(n) linear search vs O(n log n) sorting",
            _setup_sorted_min_max,
        ),
        _CaseRunner(
            "plex.short-circuit-comprehension",
            "any(...) vs any([...])",
            "Generator short-circuiting vs eager list allocation",
            _setup_short_circuit,
        ),
        _CaseRunner(
            "plex.linear-search-in-loop",
            "set lookup vs list scan",
            "O(1) set membership vs O(n) linear scan in loop",
            _setup_linear_search,
        ),
        _CaseRunner(
            "plex.manual-list-extend",
            "list.extend vs append loop",
            "C-level batch extend vs repetitive append calls",
            _setup_manual_extend,
        ),
        _CaseRunner(
            "plex.math-pow-vs-operator",
            "x * x vs math.pow(x, 2)",
            "Direct multiplication vs C library pow dispatch",
            _setup_math_pow,
        ),
        _CaseRunner(
            "plex.membership-in-literal-list",
            "in {...} vs in [...]",
            "Constant frozenset vs heap-allocated list literal",
            _setup_membership_literal,
        ),
        _CaseRunner(
            "plex.unnecessary-lambda",
            "map(func) vs map(lambda)",
            "Direct C builtin call vs Python lambda stack frame",
            _setup_unnecessary_lambda,
        ),
        _CaseRunner(
            "plex.string-concat-in-loop",
            "''.join vs s += str",
            "Single buffer allocation vs quadratic string reallocation",
            _setup_string_concat,
        ),
        _CaseRunner(
            "plex.dict-get-fallback",
            "dict.get vs if-in-dict",
            "Single hash lookup vs dual probe check + access",
            _setup_dict_get_fallback,
        ),
        _CaseRunner(
            "plex.unnecessary-dict-keys",
            "for k in d vs d.keys()",
            "Direct dict key iteration vs keys-view object creation",
            _setup_dict_keys,
        ),
        _CaseRunner(
            "plex.dict-get-default-none",
            "d.get(k) vs d.get(k, None)",
            "Fast-path 1-arg lookup vs 2-arg default passing",
            _setup_dict_get_none,
        ),
        _CaseRunner(
            "plex.unnecessary-len",
            "if items vs if len(items) > 0",
            "Direct truthiness check vs len() call + comparison",
            _setup_unnecessary_len,
        ),
        _CaseRunner(
            "plex.unnecessary-async-def",
            "def foo() vs async def foo()",
            "Direct synchronous call vs coroutine event loop scheduling",
            _setup_unnecessary_async_def,
        ),
        _CaseRunner(
            "plex.unnecessary-enumerate",
            "for x in seq vs for _, x in enumerate",
            "Direct iterator vs 2-tuple allocation + counter tracking",
            _setup_unnecessary_enumerate,
        ),
        _CaseRunner(
            "plex.dict-items-value-unused",
            "for k in d vs for k, _ in d.items()",
            "Direct dict key iteration vs 2-tuple allocation and value lookup",
            _setup_dict_items_value_unused,
        ),
        _CaseRunner(
            "plex.dict-items-comprehension-to-copy",
            "d.copy() vs {k: v for k, v in d.items()}",
            "Fast C copy vs Python bytecode loop & unpacking",
            _setup_dict_comp_to_copy,
        ),
        _CaseRunner(
            "plex.redundant-collection-call",
            "list(x) vs list(list(x))",
            "Single collection copy vs redundant intermediate allocation",
            _setup_redundant_collection,
        ),
        _CaseRunner(
            "plex.redundant-fstring",
            "'literal' vs f'literal'",
            "Direct string literal constant vs f-string build opcode",
            _setup_redundant_fstring,
        ),
        _CaseRunner(
            "plex.str-startswith-tuple",
            "startswith(tuple) vs chained or",
            "Single C loop scan vs multiple method dispatch checks",
            _setup_str_startswith_tuple,
        ),
        _CaseRunner(
            "plex.dict-fromkeys",
            "dict.fromkeys vs comprehension",
            "Preallocated C hash table vs bytecode loop allocation",
            _setup_dict_fromkeys,
        ),
        _CaseRunner(
            "plex.itertools-chain-from-iterable",
            "chain.from_iterable vs chain(*)",
            "Lazy iterator consumption vs call stack argument unpacking",
            _setup_itertools_chain,
        ),
        _CaseRunner(
            "plex.try-except-dict-get",
            "dict.get vs try-except KeyError",
            "Default lookup vs exception raising & stack unwinding",
            _setup_try_except_dict_get,
        ),
        _CaseRunner(
            "plex.try-except-pop-default",
            "pop(k, None) vs try-except pop",
            "Safe removal with default vs exception handling",
            _setup_try_except_pop_default,
        ),
        _CaseRunner(
            "plex.if-pass-else-invert",
            "if not cond vs if cond: pass else",
            "Inverted branch vs jump bytecode around empty pass",
            _setup_if_pass_else_invert,
        ),
        _CaseRunner(
            "plex.isinstance-tuple",
            "isinstance(tuple) vs chained or",
            "Single tuple type check vs multiple isinstance dispatches",
            _setup_isinstance_tuple,
        ),
        _CaseRunner(
            "plex.itertools-islice",
            "itertools.islice vs list(seq)[:n]",
            "O(1) lazy slice vs full sequence memory allocation",
            _setup_itertools_islice,
        ),
        _CaseRunner(
            "plex.re-sub-literal",
            "str.replace vs re.sub(literal)",
            "Fast C string substitution vs regex parsing and execution",
            _setup_re_sub_literal,
        ),
        _CaseRunner(
            "plex.str-removeprefix-suffix",
            "removeprefix/suffix vs manual slice",
            "Direct C prefix/suffix stripping vs manual len & slice",
            _setup_str_removeprefix_suffix,
        ),
        _CaseRunner(
            "plex.math-log-base",
            "math.log2/log10 vs math.log(x, base)",
            "Specialized FPU hardware instruction vs base arithmetic",
            _setup_math_log_base,
        ),
        _CaseRunner(
            "plex.try-except-next-default",
            "next(it, default) vs try-except",
            "Iterator default argument vs StopIteration exception unwinding",
            _setup_try_except_next_default,
        ),
        _CaseRunner(
            "plex.str-split-maxsplit",
            "split(sep, 1)[0] vs split(sep)[0]",
            "Bound maxsplit tokenization vs full string splitting",
            _setup_str_split_maxsplit,
        ),
        _CaseRunner(
            "plex.filter-truthy",
            "list(filter(None, seq)) vs [x for x in seq if x]",
            "C-level truthiness filtering vs Python comprehension loop",
            _setup_filter_truthy,
        ),
        _CaseRunner(
            "plex.all-in-superset",
            "set.issuperset vs all(x in s for x in a)",
            "C-level superset check vs generator bytecode iteration",
            _setup_all_in_superset,
        ),
    ]


def run_rule_benchmarks(
    rule_ids: Iterable[str] | None = None,
    iterations: int = 50,
    warmups: int = 5,
) -> RuleBenchmarkReport:
    """Run performance microbenchmarks for PLEx remediable rules."""
    filter_set = set(rule_ids) if rule_ids else None
    cases = _get_benchmark_cases()
    results: list[RuleBenchmarkResult] = []

    for case in cases:
        if filter_set is not None and case.rule_id not in filter_set:
            continue
        res = case.run(iterations=iterations, warmups=warmups)
        results.append(res)

    return RuleBenchmarkReport(results=results)


def format_rule_benchmark_table(report: RuleBenchmarkReport) -> str:
    """Format benchmark results into a clean terminal report table."""
    lines: list[str] = [
        "",
        "═" * 98,
        "                    PLEx Rule Remediation Performance Microbenchmarks",
        f"  Environment: Python {report.python} | Platform: {report.platform}",
        "═" * 98,
        f"{'Rule ID':<36} {'Before':>10} {'After':>10} {'Speedup':>10} {'Alloc Delta':>13} {'Status':>10}",
        "─" * 98,
    ]

    for r in report.results:
        before_str = f"{r.before_median_us:.2f} µs"
        after_str = f"{r.after_median_us:.2f} µs"
        speedup_str = f"{r.speedup:.1f}x"
        if r.memory_reduction_pct > 0:
            alloc_str = f"-{r.memory_reduction_pct:.1f}%"
        elif r.before_alloc_bytes == 0 and r.after_alloc_bytes == 0:
            alloc_str = "0 B"
        else:
            alloc_str = f"{r.after_alloc_bytes - r.before_alloc_bytes:+d} B"

        status = "FASTER" if r.speedup >= 1.05 else "EQUIV"
        lines.append(
            f"{r.rule_id:<36} {before_str:>10} {after_str:>10} {speedup_str:>10} {alloc_str:>13} {status:>10}"
        )

    lines.append("═" * 98)
    return "\n".join(lines)
