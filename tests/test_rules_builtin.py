from __future__ import annotations

from pathlib import Path

from plex.analyze.static_ast import analyze_source
from plex.ir.registry import build_ir_modules
from plex.rules.base import RuleContext
from plex.rules.registry import run_rules


def _run_rules(src: str, path: str = "src/app.py"):
    findings = analyze_source(Path(path), src)
    sources = {path: src}
    ir_modules = build_ir_modules(Path("."), sources, findings)
    context = RuleContext(
        repo_root=Path("."),
        sources=sources,
        findings=findings,
        ir_modules=ir_modules,
        rule_config={},
    )
    return run_rules(context)


def test_db_in_loop_rule() -> None:
    src = """
class User:
    objects = None

def f(items):
    for item in items:
        User.objects.filter(id=item)
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.db-in-loop" for f in findings)


def test_json_in_loop_rule() -> None:
    src = """
import json

def f(items):
    for item in items:
        json.dumps(item)
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.json-in-loop" for f in findings)


def test_pandas_row_iteration_rule() -> None:
    src = """
def f(df):
    for row in df.iterrows():
        _ = row
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.pandas-iterrows" for f in findings)


def test_regex_catastrophe_rule() -> None:
    src = """
import re

def f(text):
    return re.compile("(a+)+").search(text)
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.regex-catastrophic" for f in findings)


def test_http_in_loop_rule() -> None:
    src = """
import requests

def f(urls):
    for url in urls:
        requests.get(url)
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.http-in-loop" for f in findings)

    # Negative case: outside loop
    src_safe = """
import requests

def f(url):
    return requests.get(url)
"""
    findings_safe = _run_rules(src_safe)
    assert not any(f.rule_id == "plex.http-in-loop" for f in findings_safe)


def test_unbounded_file_io_rule() -> None:
    src = """
def f(files):
    for path in files:
        with open(path) as fh:
            data = fh.read()
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.unbounded-file-io" for f in findings)

    # Negative case: open outside loop
    src_safe = """
def f(path):
    with open(path) as fh:
        return fh.read()
"""
    findings_safe = _run_rules(src_safe)
    assert not any(f.rule_id == "plex.unbounded-file-io" for f in findings_safe)


def test_string_concat_in_loop_rule() -> None:
    src = """
def f(chunks):
    s = ""
    for c in chunks:
        s += c + "!"
    return s
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.string-concat-in-loop" for f in findings)

    # Negative case: integer addition must NOT trigger string concat rule
    src_safe = """
def f(items):
    total = 0
    for x in items:
        total += x
    return total
"""
    findings_safe = _run_rules(src_safe)
    assert not any(f.rule_id == "plex.string-concat-in-loop" for f in findings_safe)


def test_uncompiled_regex_in_loop_rule() -> None:
    src = """
import re

def f(queries, text):
    for q in queries:
        re.search(q, text)
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.uncompiled-regex-in-loop" for f in findings)

    # Negative case: outside loop
    src_safe = """
import re

def f(query, text):
    return re.search(query, text)
"""
    findings_safe = _run_rules(src_safe)
    assert not any(f.rule_id == "plex.uncompiled-regex-in-loop" for f in findings_safe)


def test_linear_search_in_loop_rule() -> None:
    src = """
def f(targets, queries):
    my_list = [1, 2, 3, 4]
    matches = []
    for q in queries:
        if q in my_list:
            matches.append(q)
    return matches
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.linear-search-in-loop" for f in findings)

    # Negative case: set lookup must NOT trigger
    src_safe = """
def f(targets, queries):
    my_set = set(targets)
    matches = []
    for q in queries:
        if q in my_set:
            matches.append(q)
    return matches
"""
    findings_safe = _run_rules(src_safe)
    assert not any(f.rule_id == "plex.linear-search-in-loop" for f in findings_safe)


def test_sync_io_in_async_rule() -> None:
    src_sleep = """
import time

async def fetch():
    time.sleep(1)
"""
    findings = _run_rules(src_sleep)
    assert any(f.rule_id == "plex.sync-io-in-async" for f in findings)

    src_open = """
async def read_config():
    with open("config.json") as f:
        return f.read()
"""
    findings = _run_rules(src_open)
    assert any(f.rule_id == "plex.sync-io-in-async" for f in findings)

    src_requests = """
import requests

async def get_data():
    return requests.get("https://api.example.com")
"""
    findings = _run_rules(src_requests)
    assert any(f.rule_id == "plex.sync-io-in-async" for f in findings)

    # Negative case: sync def function with time.sleep is NOT an async event loop stall
    src_safe = """
import time

def sync_worker():
    time.sleep(1)
"""
    findings_safe = _run_rules(src_safe)
    assert not any(f.rule_id == "plex.sync-io-in-async" for f in findings_safe)


def test_deepcopy_in_loop_rule() -> None:
    src = """
import copy

def clone_items(items):
    clones = []
    for item in items:
        clones.append(copy.deepcopy(item))
    return clones
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "plex.deepcopy-in-loop" for f in findings)

    # Negative case: deepcopy outside loop
    src_safe = """
import copy

def clone_template(items, template):
    base = copy.deepcopy(template)
    clones = []
    for item in items:
        clones.append(base.copy())
    return clones
"""
    findings_safe = _run_rules(src_safe)
    assert not any(f.rule_id == "plex.deepcopy-in-loop" for f in findings_safe)


def test_repeated_sort_in_loop_rule() -> None:
    src_sorted = """
def process_matrix(matrix):
    results = []
    for row in matrix:
        results.append(sorted(row))
    return results
"""
    findings = _run_rules(src_sorted)
    assert any(f.rule_id == "plex.repeated-sort-in-loop" for f in findings)

    src_sort_method = """
def sort_rows(matrix):
    for row in matrix:
        row.sort()
"""
    findings = _run_rules(src_sort_method)
    assert any(f.rule_id == "plex.repeated-sort-in-loop" for f in findings)

    # Negative case: sort outside loop
    src_safe = """
def process_data(items):
    ordered = sorted(items)
    for x in ordered:
        pass
"""
    findings_safe = _run_rules(src_safe)
    assert not any(f.rule_id == "plex.repeated-sort-in-loop" for f in findings_safe)


def test_rule_stability_graduation() -> None:
    from plex.rules.builtin import BUILTIN_RULES

    stable_rules = {r.id for r in BUILTIN_RULES if r.stability == "stable"}
    experimental_rules = {r.id for r in BUILTIN_RULES if r.stability == "experimental"}

    assert stable_rules == {
        "plex.db-in-loop",
        "plex.http-in-loop",
        "plex.unbounded-file-io",
        "plex.string-concat-in-loop",
        "plex.linear-search-in-loop",
        "plex.redundant-comprehension",
        "plex.unnecessary-dict-keys",
        "plex.unnecessary-len",
        "plex.math-pow-vs-operator",
        "plex.dict-get-fallback",
        "plex.mutable-default-arg",
        "plex.manual-list-extend",
        "plex.unclosed-resource",
        "plex.short-circuit-comprehension",
        "plex.sorted-min-max",
        "plex.unnecessary-comprehension-in-call",
        "plex.membership-in-literal-list",
        "plex.unnecessary-lambda",
        "plex.dict-get-default-none",
        "plex.unnecessary-async-def",
        "plex.unnecessary-enumerate",
        "plex.dict-items-value-unused",
        "plex.dict-items-comprehension-to-copy",
        "plex.redundant-collection-call",
        "plex.redundant-fstring",
        "plex.str-startswith-tuple",
        "plex.dict-fromkeys",
        "plex.itertools-chain-from-iterable",
        "plex.try-except-dict-get",
        "plex.try-except-pop-default",
        "plex.if-pass-else-invert",
        "plex.isinstance-tuple",
        "plex.itertools-islice",
        "plex.re-sub-literal",
        "plex.str-removeprefix-suffix",
        "plex.math-log-base",
        "plex.try-except-next-default",
        "plex.str-split-maxsplit",
        "plex.filter-truthy",
        "plex.all-in-superset",
    }
    assert experimental_rules == {
        "plex.json-in-loop",
        "plex.pandas-iterrows",
        "plex.regex-catastrophic",
        "plex.uncompiled-regex-in-loop",
        "plex.sync-io-in-async",
        "plex.deepcopy-in-loop",
        "plex.repeated-sort-in-loop",
    }


def test_redundant_comprehension_rule() -> None:
    src = """
def f(items):
    a = list([x * 2 for x in items])
    b = list(x * 2 for x in items)
    c = set([x for x in items])
    d = dict([(x, x * 2) for x in items])
    return a, b, c, d
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.redundant-comprehension"]
    assert len(hits) == 4


def test_unnecessary_dict_keys_rule() -> None:
    src = """
def check(d, key):
    for k in d.keys():
        if key in d.keys():
            pass
        if key not in d.keys():
            pass
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.unnecessary-dict-keys"]
    assert len(hits) == 3


def test_unnecessary_len_rule() -> None:
    src = """
def check(items):
    if len(items) > 0:
        pass
    if len(items) != 0:
        pass
    if len(items) == 0:
        pass
    if len(items) <= 0:
        pass
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.unnecessary-len"]
    assert len(hits) == 4


def test_math_pow_vs_operator_rule() -> None:
    src = """
import math

def compute(values):
    res = []
    for x in values:
        res.append(math.pow(x, 2))
        res.append(pow(x, 2))
    return res
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.math-pow-vs-operator"]
    assert len(hits) == 2


def test_dict_get_fallback_rule() -> None:
    src = """
def lookup(d, k):
    if k in d:
        v = d[k]
    else:
        v = "default"
    return v
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.dict-get-fallback"]
    assert len(hits) == 1


def test_mutable_default_arg_rule() -> None:
    src = """
def process(data, items=[], options={}, *, tags=set()):
    return len(items) + len(options) + len(tags)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.mutable-default-arg"]
    assert len(hits) == 3


def test_manual_list_extend_rule() -> None:
    src = """
def collect(items):
    out = []
    for x in items:
        out.append(x)
    return out
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.manual-list-extend"]
    assert len(hits) == 1


def test_unclosed_resource_rule() -> None:
    src = """
def read_data(path):
    f = open(path)
    return f.read()

def read_with(path):
    with open(path) as f:
        return f.read()
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.unclosed-resource"]
    assert len(hits) == 1


def test_short_circuit_comprehension_rule() -> None:
    src = """
def check_any(items):
    return any([x > 0 for x in items])

def check_all(items):
    return all([x > 0 for x in items])

def check_gen(items):
    return any(x > 0 for x in items)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.short-circuit-comprehension"]
    assert len(hits) == 2


def test_sorted_min_max_rule() -> None:
    src = """
def get_extremes(items):
    first = sorted(items)[0]
    last = sorted(items)[-1]
    rev_first = sorted(items, reverse=True)[0]
    other = sorted(items)[2]
    return first, last, rev_first, other
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.sorted-min-max"]
    assert len(hits) == 3
    assert any("min()" in f.message for f in hits)
    assert any("max()" in f.message for f in hits)


def test_unnecessary_comprehension_in_call_rule() -> None:
    src = """
def calc_totals(items):
    t1 = sum([x * 2 for x in items])
    t2 = tuple([x for x in items])
    t3 = sum(x * 2 for x in items)
    return t1, t2, t3
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.unnecessary-comprehension-in-call"]
    assert len(hits) == 2


def test_membership_in_literal_list_rule() -> None:
    src = """
def check_status(status, role):
    if status in ['active', 'pending']:
        pass
    if role not in [1, 2, 3]:
        pass
    if status in {'admin', 'user'}:
        pass
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.membership-in-literal-list"]
    assert len(hits) == 2


def test_unnecessary_lambda_rule() -> None:
    src = """
def process(items):
    m = map(lambda x: int(x), items)
    s = sorted(items, key=lambda x: len(x))
    k = map(lambda x: x + 1, items)
    return m, s, k
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.unnecessary-lambda"]
    assert len(hits) == 2


def test_dict_get_default_none_rule() -> None:
    src = """
def lookup(d, k):
    v1 = d.get(k, None)
    v2 = d.get(k, default=None)
    v3 = d.get(k, 0)
    v4 = d.get(k)
    return v1, v2, v3, v4
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.dict-get-default-none"]
    assert len(hits) == 2


def test_run_rules_stability_filter() -> None:
    # A source with both stable (db-in-loop) and experimental (json-in-loop)
    src = """
import json
class User:
    objects = None

def process(items):
    for item in items:
        User.objects.filter(id=item)
        json.dumps(item)
"""
    findings = analyze_source(Path("src/app.py"), src)
    sources = {"src/app.py": src}
    ir_modules = build_ir_modules(Path("."), sources, findings)
    context = RuleContext(
        repo_root=Path("."),
        sources=sources,
        findings=findings,
        ir_modules=ir_modules,
        rule_config={},
    )

    stable_findings = run_rules(context, stability="stable")
    assert any(f.rule_id == "plex.db-in-loop" for f in stable_findings)
    assert not any(f.rule_id == "plex.json-in-loop" for f in stable_findings)

    exp_findings = run_rules(context, stability="experimental")
    assert not any(f.rule_id == "plex.db-in-loop" for f in exp_findings)
    assert any(f.rule_id == "plex.json-in-loop" for f in exp_findings)

    all_findings = run_rules(context, stability="all")
    assert any(f.rule_id == "plex.db-in-loop" for f in all_findings)
    assert any(f.rule_id == "plex.json-in-loop" for f in all_findings)


def test_unnecessary_async_def_rule() -> None:
    src = """
from abc import abstractmethod

async def bad_func(x):
    return x * 2

async def bad_calc(a, b):
    res = a + b
    return res

async def good_await(coro):
    return await coro

async def good_async_for(agen):
    async for item in agen:
        pass

async def good_async_with(lock):
    async with lock:
        pass

async def stub_pass():
    pass

async def stub_ellipsis():
    ...

async def stub_raise():
    raise NotImplementedError("Subclass must implement")

@abstractmethod
async def abstract_method():
    pass
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.unnecessary-async-def"]
    assert len(hits) == 2
    assert any("bad_func" in h.message for h in hits)
    assert any("bad_calc" in h.message for h in hits)


def test_unnecessary_enumerate_rule() -> None:
    src = """
def process(items):
    # bad: underscore index
    for _, item in enumerate(items):
        print(item)

    # bad: named index unused
    for idx, val in enumerate(items):
        print(val)

    # good: index used
    for i, item in enumerate(items):
        print(i, item)

    # good: index used in condition
    for j, x in enumerate(items):
        if j % 2 == 0:
            print(x)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.unnecessary-enumerate"]
    assert len(hits) == 2


def test_dict_items_value_unused_rule() -> None:
    src = """
def process(d):
    # bad: underscore value
    for k, _ in d.items():
        print(k)

    # bad: named value unused
    for key, val in d.items():
        print(key)

    # good: value used
    for k, v in d.items():
        print(k, v)

    # good: direct iteration
    for k in d:
        print(k)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.dict-items-value-unused"]
    assert len(hits) == 2


def test_dict_items_comprehension_to_copy_rule() -> None:
    src = """
def test_fn(d):
    # bad: direct copy comprehension
    c1 = {k: v for k, v in d.items()}

    # bad: different variable names
    c2 = {key: val for key, val in d.items()}

    # good: modified value
    c3 = {k: v * 2 for k, v in d.items()}

    # good: modified key
    c4 = {k.upper(): v for k, v in d.items()}

    # good: filtered
    c5 = {k: v for k, v in d.items() if v > 0}

    # good: native copy
    c6 = d.copy()
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.dict-items-comprehension-to-copy"]
    assert len(hits) == 2
    assert any("d.copy()" in h.message for h in hits)


def test_redundant_collection_call_rule() -> None:
    src = """
def test_fn(items):
    # bad: redundant same collection wrapper
    a = list(list(items))
    b = set(set(items))
    c = tuple(tuple(items))
    d = dict(dict(items))

    # good: type conversion / different constructor
    e = list(tuple(items))
    f = set(list(items))
    g = tuple(list(items))
    h = list(items)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.redundant-collection-call"]
    assert len(hits) == 4
    assert any("list(list(...))" in h.message for h in hits)
    assert any("set(set(...))" in h.message for h in hits)


def test_redundant_fstring_rule() -> None:
    src = """
def test_fn(name):
    # bad: no interpolated expressions
    s1 = f"hello world"
    s2 = f'constant string'

    # good: interpolated expressions
    s3 = f"hello {name}"
    s4 = f"{name}"
    s5 = "plain string"
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.redundant-fstring"]
    assert len(hits) == 2
    assert any("Redundant f-string" in h.message for h in hits)


def test_str_startswith_tuple_rule() -> None:
    src = """
def test_fn(s, path):
    # bad: multiple startswith
    c1 = s.startswith("http://") or s.startswith("https://")

    # bad: multiple endswith
    c2 = path.endswith(".png") or path.endswith(".jpg") or path.endswith(".jpeg")

    # good: single startswith
    c3 = s.startswith("ftp://")

    # good: already a tuple
    c4 = s.startswith(("http://", "https://"))

    # good: different targets
    c5 = s.startswith("a") or path.startswith("b")
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.str-startswith-tuple"]
    assert len(hits) == 2
    assert any("startswith()" in h.message for h in hits)
    assert any("endswith()" in h.message for h in hits)


def test_dict_fromkeys_rule() -> None:
    src = """
def test_fn(keys):
    # bad: constant values
    d1 = {k: 0 for k in keys}
    d2 = {k: None for k in keys}
    d3 = {k: "default" for k in keys}

    # good: dynamic value
    d4 = {k: k * 2 for k in keys}

    # good: filtered
    d5 = {k: 0 for k in keys if k}

    # good: already dict.fromkeys
    d6 = dict.fromkeys(keys, 0)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.dict-fromkeys"]
    assert len(hits) == 3
    assert any("dict.fromkeys()" in h.message for h in hits)


def test_itertools_chain_from_iterable_rule() -> None:
    src = """
import itertools
from itertools import chain

def test_fn(nested):
    # bad: starred chain calls
    c1 = itertools.chain(*nested)
    c2 = chain(*nested)

    # good: already from_iterable
    c3 = itertools.chain.from_iterable(nested)
    c4 = chain.from_iterable(nested)

    # good: unstarred args
    c5 = chain(nested, [1, 2, 3])
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.itertools-chain-from-iterable"]
    assert len(hits) == 2
    assert any("chain.from_iterable" in h.message for h in hits)


def test_try_except_dict_get_rule() -> None:
    src = """
def test_fn(d, k):
    # bad: try-except KeyError for fallback
    try:
        v1 = d[k]
    except KeyError:
        v1 = None

    try:
        v2 = d[k]
    except KeyError:
        v2 = "default"

    # good: already using dict.get()
    v3 = d.get(k, "default")

    # good: different variable name in except
    try:
        v4 = d[k]
    except KeyError:
        other = 0

    # good: non-KeyError
    try:
        v5 = d[k]
    except IndexError:
        v5 = 0
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.try-except-dict-get"]
    assert len(hits) == 2
    assert any("`d.get()`" in h.message for h in hits)


def test_try_except_pop_default_rule() -> None:
    src = """
def test_fn(d, k):
    # bad: pop with pass
    try:
        d.pop(k)
    except KeyError:
        pass

    # bad: pop with assignment fallback
    try:
        val = d.pop(k)
    except KeyError:
        val = 0

    # good: already pop with default
    d.pop(k, None)
    val2 = d.pop(k, 0)

    # good: non-KeyError
    try:
        d.pop(k)
    except ValueError:
        pass
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.try-except-pop-default"]
    assert len(hits) == 2
    assert any("d.pop(k, None)" in h.message for h in hits)
    assert any("d.pop(k, default)" in h.message for h in hits)


def test_if_pass_else_invert_rule() -> None:
    src = """
def test_fn(x, items):
    # bad: if pass else
    if x > 0:
        pass
    else:
        print("negative")

    if not items:
        pass
    else:
        print("non-empty")

    # good: proper if without pass
    if x <= 0:
        print("negative")

    # good: if with body and else
    if x > 0:
        print("positive")
    else:
        print("non-positive")
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.if-pass-else-invert"]
    assert len(hits) == 2
    assert any("inverting the condition" in h.message for h in hits)


def test_isinstance_tuple_rule() -> None:
    src = """
def test_fn(x, y):
    # bad: chained isinstance on x
    if isinstance(x, int) or isinstance(x, str):
        print("int or str")

    # bad: 3 chained isinstance checks
    if isinstance(x, int) or isinstance(x, float) or isinstance(x, complex):
        print("number")

    # good: single isinstance check
    if isinstance(x, int):
        print("int")

    # good: already tuple check
    if isinstance(x, (int, str)):
        print("int or str")

    # good: different targets
    if isinstance(x, int) or isinstance(y, str):
        print("different")
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.isinstance-tuple"]
    assert len(hits) == 2
    assert any("Multiple `isinstance(x, ...)` checks" in h.message for h in hits)


def test_itertools_islice_rule() -> None:
    src = """
def test_fn(gen):
    # bad: list(gen)[:10]
    first_ten = list(gen)[:10]

    # bad: tuple(gen)[:5]
    top_five = tuple(gen)[:5]

    # bad: explicit 0 lower bound
    zero_bound = list(gen)[0:20]

    # good: negative slice cannot use islice
    tail = list(gen)[:-1]

    # good: normal list indexing
    item = list(gen)[0]
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.itertools-islice"]
    assert len(hits) == 3
    assert any("list(seq)[:n]" in h.message for h in hits)
    assert any("tuple(seq)[:n]" in h.message for h in hits)


def test_re_sub_literal_rule() -> None:
    src = """
import re

def test_fn(s):
    # bad: literal pattern and repl
    out1 = re.sub("foo", "bar", s)

    # bad: direct sub call
    from re import sub
    out2 = sub("hello", "world", s)

    # good: regex metacharacters
    out3 = re.sub(r"foo.*bar", "baz", s)

    # good: flags passed
    out4 = re.sub("foo", "bar", s, flags=re.IGNORECASE)

    # good: non-literal repl (backreference)
    out5 = re.sub("foo", r"\\1", s)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.re-sub-literal"]
    assert len(hits) == 2
    assert any("str.replace()" in h.message for h in hits)


def test_str_removeprefix_suffix_rule() -> None:
    src = """
def test_fn(s, prefix, suffix):
    # bad: startswith slice
    if s.startswith(prefix):
        s = s[len(prefix):]

    # bad: endswith slice
    if s.endswith(suffix):
        s = s[:-len(suffix)]

    # good: non-slice body
    if s.startswith(prefix):
        print(s)

    # good: different target
    if s.startswith(prefix):
        other = s[len(prefix):]
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.str-removeprefix-suffix"]
    assert len(hits) == 2
    assert any("removeprefix" in h.message for h in hits)
    assert any("removesuffix" in h.message for h in hits)


def test_math_log_base_rule() -> None:
    src = """
import math
from math import log

def test_fn(x):
    # bad: base 2 with math.log
    a = math.log(x, 2)

    # bad: base 10 with imported log
    b = log(x, 10)

    # good: specialized calls
    c = math.log2(x)
    d = math.log10(x)

    # good: base 3 or other
    e = math.log(x, 3)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.math-log-base"]
    assert len(hits) == 2
    assert any("math.log2" in h.message for h in hits)
    assert any("log10" in h.message for h in hits)


def test_try_except_next_default_rule() -> None:
    src = """
def test_fn(it):
    # bad: try-except StopIteration with default
    try:
        val = next(it)
    except StopIteration:
        val = -1

    # bad: default is None
    try:
        item = next(it)
    except StopIteration:
        item = None

    # good: non-StopIteration
    try:
        val = next(it)
    except RuntimeError:
        val = 0

    # good: multiple statements
    try:
        val = next(it)
        print(val)
    except StopIteration:
        val = None
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.try-except-next-default"]
    assert len(hits) == 2
    assert any("next(it, default)" in h.message for h in hits)


def test_str_split_maxsplit_rule() -> None:
    src = """
def test_fn(s):
    # bad: split()[0] without maxsplit
    a = s.split()[0]

    # bad: split(sep)[0] without maxsplit
    b = s.split(":")[0]

    # bad: rsplit(sep)[-1] without maxsplit
    c = s.rsplit("/", 1)[-1]  # wait, this has maxsplit=1!

    # bad: rsplit(sep)[-1] without maxsplit
    d = s.rsplit("/")[-1]

    # good: maxsplit already provided
    e = s.split(":", 1)[0]
    f = s.split(maxsplit=1)[0]

    # good: non-0 / non-(-1) indexing or slice
    g = s.split(":")[1:]
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.str-split-maxsplit"]
    assert len(hits) == 3
    assert any("maxsplit=1" in h.suggestions[0] for h in hits)


def test_filter_truthy_rule() -> None:
    src = """
def test_fn(seq, other):
    # bad: [x for x in seq if x]
    a = [x for x in seq if x]

    # bad: [item for item in seq if item]
    b = [item for item in seq if item]

    # good: transformation in elt
    c = [x * 2 for x in seq if x]

    # good: different condition
    d = [x for x in seq if x > 0]

    # good: multiple ifs
    e = [x for x in seq if x if other]
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.filter-truthy"]
    assert len(hits) == 2
    assert any("filter(None" in h.message for h in hits)


def test_all_in_superset_rule() -> None:
    src = """
def test_fn(a, b, allowed):
    # bad: all(x in b for x in a)
    res1 = all(x in b for x in a)

    # bad: with set literal
    res2 = all(item in {1, 2, 3} for item in a)

    # good: any() instead of all()
    res3 = any(x in b for x in a)

    # good: has if condition
    res4 = all(x in b for x in a if x > 0)

    # good: different compare op
    res5 = all(x not in b for x in a)
"""
    findings = _run_rules(src)
    hits = [f for f in findings if f.rule_id == "plex.all-in-superset"]
    assert len(hits) == 2
    assert any("issuperset" in h.message for h in hits)
