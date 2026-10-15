from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from plex.report.models import FindingReport, PLExReport, RegressionFinding
from plex.util.languages import language_for_path

_LANG_LABELS = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "kotlin": "kotlin",
    "go": "go",
}


_SNIPPETS = {
    "nested_loops": {
        "python": """# Pre-index to avoid nested loops
index = {item.id: item for item in items}
for row in rows:
    item = index.get(row.id)
    if item is not None:
        # ...
        pass
""",
        "javascript": """// Pre-index to avoid nested loops
const index = new Map(items.map(item => [item.id, item]));
for (const row of rows) {
  const item = index.get(row.id);
  if (item) {
    // ...
  }
}
""",
        "typescript": """// Pre-index to avoid nested loops
const index = new Map(items.map(item => [item.id, item]));
for (const row of rows) {
  const item = index.get(row.id);
  if (item) {
    // ...
  }
}
""",
        "java": """// Pre-index to avoid nested loops
Map<Key, Item> index = items.stream()
    .collect(Collectors.toMap(Item::getId, item -> item));
for (Row row : rows) {
    Item item = index.get(row.getId());
    if (item != null) {
        // ...
    }
}
""",
        "kotlin": """// Pre-index to avoid nested loops
val index = items.associateBy { it.id }
for (row in rows) {
    val item = index[row.id]
    if (item != null) {
        // ...
    }
}
""",
        "go": """// Pre-index to avoid nested loops
index := make(map[int]Item, len(items))
for _, item := range items {
    index[item.ID] = item
}
for _, row := range rows {
    if item, ok := index[row.ID]; ok {
        // ...
    }
}
""",
        "generic": """// Pre-index to avoid nested loops
index = build_index(items)
for row in rows:
    item = index.get(row.key)
    if item:
        # ...
""",
    },
    "sort_in_loop": {
        "python": """# Sort once outside the loop
rows_sorted = sorted(rows, key=lambda r: r.key)
for row in rows_sorted:
    # ...
    pass
""",
        "javascript": """// Sort once outside the loop
const rowsSorted = [...rows].sort((a, b) => a.key - b.key);
for (const row of rowsSorted) {
  // ...
}
""",
        "typescript": """// Sort once outside the loop
const rowsSorted = [...rows].sort((a, b) => a.key - b.key);
for (const row of rowsSorted) {
  // ...
}
""",
        "java": """// Sort once outside the loop
List<Row> rowsSorted = new ArrayList<>(rows);
rowsSorted.sort(Comparator.comparing(Row::getKey));
for (Row row : rowsSorted) {
    // ...
}
""",
        "kotlin": """// Sort once outside the loop
val rowsSorted = rows.sortedBy { it.key }
for (row in rowsSorted) {
    // ...
}
""",
        "go": """// Sort once outside the loop
rowsSorted := append([]Row(nil), rows...)
sort.Slice(rowsSorted, func(i, j int) bool { return rowsSorted[i].Key < rowsSorted[j].Key })
for _, row := range rowsSorted {
    // ...
}
""",
        "generic": """// Sort once outside the loop
rows_sorted = sort(rows, key=...)
for row in rows_sorted:
    # ...
""",
    },
    "recursion": {
        "python": """from functools import lru_cache

@lru_cache(maxsize=None)
def f(n):
    # base cases...
    return f(n - 1) + f(n - 2)
""",
        "javascript": """const memo = new Map();
function f(n) {
  if (memo.has(n)) return memo.get(n);
  const value = /* compute */ n;
  memo.set(n, value);
  return value;
}
""",
        "typescript": """const memo = new Map<number, number>();
function f(n: number): number {
  if (memo.has(n)) return memo.get(n)!;
  const value = /* compute */ n;
  memo.set(n, value);
  return value;
}
""",
        "java": """Map<Key, Value> memo = new HashMap<>();
Value f(Key key) {
    if (memo.containsKey(key)) return memo.get(key);
    Value value = /* compute */;
    memo.put(key, value);
    return value;
}
""",
        "kotlin": """val memo = mutableMapOf<Key, Value>()
fun f(key: Key): Value {
    memo[key]?.let { return it }
    val value = /* compute */
    memo[key] = value
    return value
}
""",
        "go": """var memo = map[int]int{}
func f(n int) int {
    if v, ok := memo[n]; ok {
        return v
    }
    v := /* compute */
    memo[n] = v
    return v
}
""",
        "generic": """# Memoize recursive calls
memo = {}
def f(x):
    if x in memo:
        return memo[x]
    value = compute(x)
    memo[x] = value
    return value
""",
    },
    "call_in_loop": {
        "python": """# Cache expensive calls in loops
cache = {}
for item in items:
    key = item.id
    if key not in cache:
        cache[key] = expensive_call(item)
    value = cache[key]
    # ...
""",
        "javascript": """// Cache expensive calls in loops
const cache = new Map();
for (const item of items) {
  const key = item.id;
  if (!cache.has(key)) {
    cache.set(key, expensiveCall(item));
  }
  const value = cache.get(key);
  // ...
}
""",
        "typescript": """// Cache expensive calls in loops
const cache = new Map<string, Value>();
for (const item of items) {
  const key = item.id;
  if (!cache.has(key)) {
    cache.set(key, expensiveCall(item));
  }
  const value = cache.get(key)!;
  // ...
}
""",
        "java": """// Cache expensive calls in loops
Map<Key, Value> cache = new HashMap<>();
for (Item item : items) {
    Key key = item.getId();
    Value value = cache.computeIfAbsent(key, k -> expensiveCall(item));
    // ...
}
""",
        "kotlin": """// Cache expensive calls in loops
val cache = mutableMapOf<Key, Value>()
for (item in items) {
    val key = item.id
    val value = cache.getOrPut(key) { expensiveCall(item) }
    // ...
}
""",
        "go": """// Cache expensive calls in loops
cache := make(map[Key]Value)
for _, item := range items {
    key := item.ID
    value, ok := cache[key]
    if !ok {
        value = expensiveCall(item)
        cache[key] = value
    }
    // ...
}
""",
        "generic": """// Cache expensive calls in loops
cache = {}
for item in items:
    key = item.key
    if key not in cache:
        cache[key] = expensive_call(item)
    value = cache[key]
    # ...
""",
    },
    "db_in_loop": {
        "python": """# Prefetch related rows in one query, then index in memory
ids = [item.user_id for item in items]
users = User.objects.filter(id__in=ids)
users_by_id = {u.id: u for u in users}
for item in items:
    user = users_by_id.get(item.user_id)
    # ...
""",
        "generic": """// Batch fetch once, then lookup in memory
keys = collect_keys(items)
rows = fetch_all(keys)
index = index_by_key(rows)
for item in items:
    row = index.get(item.key)
    // ...
""",
    },
    "json_in_loop": {
        "python": """# Serialize once (or in chunks) outside the inner loop
payloads = [row.to_payload() for row in rows]
encoded = [json.dumps(payload) for payload in payloads]
for body in encoded:
    send(body)
""",
        "generic": """// Move JSON serialization out of tight loops
payloads = build_payloads(rows)
encoded = encode_all(payloads)
for body in encoded:
    send(body)
""",
    },
    "pandas_row_iteration": {
        "python": """# Prefer vectorized pandas operations
df = df.assign(total=df["price"] * df["qty"])
result = df.loc[df["total"] > 0, ["id", "total"]]
""",
        "generic": """// Replace row-by-row loops with vectorized/batch dataframe ops
table = table.withColumn("total", col("price") * col("qty"))
result = table.filter(col("total") > 0)
""",
    },
    "regex_catastrophic": {
        "python": """# Avoid nested quantifiers and ambiguous repetition
# Prefer anchored, non-ambiguous patterns
safe = re.compile(r"^a+$")
""",
        "generic": """// Use linear-time regex patterns where possible
// Avoid nested quantifiers like (a+)+ or (.*)+
pattern = compile_safe_pattern(input)
""",
    },
    "generic": {
        "generic": """// General optimization sketch
// - Precompute lookups
// - Move expensive work outside loops
// - Cache repeated calls
""",
    },
}


_KIND_TITLES = {
    "nested_loops": "Avoid nested loops",
    "sort_in_loop": "Move sort out of loop",
    "recursion": "Memoize recursion",
    "call_in_loop": "Cache expensive calls in loops",
    "db_in_loop": "Batch database access outside loops",
    "json_in_loop": "Move JSON serialization out of loops",
    "pandas_row_iteration": "Vectorize pandas operations",
    "regex_catastrophic": "Rewrite catastrophic regex patterns",
    "generic": "General optimization sketch",
}

_RULE_KIND_MAP = {
    "plex.db-in-loop": "db_in_loop",
    "plex.json-in-loop": "json_in_loop",
    "plex.pandas-iterrows": "pandas_row_iteration",
    "plex.regex-catastrophic": "regex_catastrophic",
}


def _lang_for_file(path_str: str) -> str:
    lang = language_for_path(Path(path_str))
    return lang or "generic"


def _snippet_for(kind: str, lang: str) -> tuple[str, str]:
    lang_key = lang if lang in _SNIPPETS.get(kind, {}) else "generic"
    snippet = _SNIPPETS.get(kind, {}).get(lang_key) or _SNIPPETS["generic"]["generic"]
    label = _LANG_LABELS.get(lang_key, "text")
    return label, snippet


def _classify_regression(item: RegressionFinding) -> list[str]:
    kinds: list[str] = []
    base = item.base_signals or {}
    head = item.head_signals or {}
    if int(head.get("max_loop_depth", 0)) > int(base.get("max_loop_depth", 0)):
        kinds.append("nested_loops")
    if int(head.get("sort_calls", 0)) > int(base.get("sort_calls", 0)):
        kinds.append("sort_in_loop")
    if bool(head.get("recursion")) and not bool(base.get("recursion")):
        kinds.append("recursion")
    if "inside a loop" in (item.explanation or "").lower():
        kinds.append("call_in_loop")
    return kinds or ["generic"]


def _classify_finding(item: FindingReport) -> list[str]:
    kinds: list[str] = []
    rule_kind = _RULE_KIND_MAP.get(item.rule_id)
    if rule_kind:
        kinds.append(rule_kind)
    signals = item.signals or {}
    if int(signals.get("max_loop_depth", 0)) >= 2:
        kinds.append("nested_loops")
    if int(signals.get("sort_calls", 0)) > 0 and int(signals.get("loops", 0)) > 0:
        kinds.append("sort_in_loop")
    if bool(signals.get("recursion")):
        kinds.append("recursion")
    if "inside a loop" in (item.explanation or "").lower():
        kinds.append("call_in_loop")
    if not kinds:
        return ["generic"]
    return list(dict.fromkeys(kinds))


def _items_for_report(report: PLExReport) -> Iterable:
    if report.regression_mode and report.regressions:
        return report.regressions
    return report.findings


def to_snippets_markdown(report: PLExReport, top_n: int = 10) -> str:
    lines: list[str] = []
    lines.append("# PLEx quick fix snippets")
    lines.append("")
    lines.append("These are manual copy-paste templates; adjust to your code.")
    lines.append("")
    items = list(_items_for_report(report))
    if not items:
        lines.append("No findings to generate snippets for.")
        return "\n".join(lines)

    for item in items[:top_n]:
        file = getattr(item, "file", "")
        lineno = int(getattr(item, "lineno", 1))
        qualname = getattr(item, "qualname", "")
        lines.append(f"## {file}:{lineno} `{qualname}`")
        explanation = getattr(item, "explanation", "") or getattr(item, "complexity_hint", "")
        if explanation:
            lines.append(f"- Context: {explanation}")
        lang = _lang_for_file(file)
        kinds = (
            _classify_regression(item)
            if isinstance(item, RegressionFinding)
            else _classify_finding(item)
        )
        for kind in kinds:
            title = _KIND_TITLES.get(kind, "Quick fix")
            label, snippet = _snippet_for(kind, lang)
            lines.append(f"- Snippet: {title}")
            lines.append(f"```{label}")
            lines.append(snippet.rstrip())
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


def write_snippets(report: PLExReport, path: Path, top_n: int = 10) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_snippets_markdown(report, top_n=top_n), encoding="utf-8")


__all__ = ["to_snippets_markdown", "write_snippets"]
