# Built-in Rules

PLEx ships with 47 built-in rules (40 stable, 7 experimental)
and 38 automated fixers. High-confidence rules are graduated to
`stable` for production CI enforcement, while newer heuristics remain `experimental`.

### Rule Stability & Filtering

You can filter rules by stability level in CLI commands or configuration:

```bash
# Analyze only with stable rules
plex analyze --stability stable

# List rules by stability
plex rules list --stability stable
plex rules list --stability experimental
```

In `.plex.yml`:
```yaml
rule_stability: "stable" # "all" (default), "stable", or "experimental"
```

| Rule ID | Stability | Severity | Auto-fix | Summary |
|---|---|---|---|---|
| `plex.db-in-loop` | **stable** | High | — | Database / ORM query inside loop (N+1 query) |
| `plex.http-in-loop` | **stable** | High | — | Unbatched HTTP/network call inside loop |
| `plex.string-concat-in-loop` | **stable** | Medium | yes | O(n^2) quadratic string accumulation in loop |
| `plex.unbounded-file-io` | **stable** | High | — | Repeated file open / read / write inside loop |
| `plex.linear-search-in-loop` | **stable** | High | yes | Linear search (`in list`) inside loop |
| `plex.redundant-comprehension` | **stable** | Low | yes | Redundant `list([...])`, `set(...)`, `dict(...)` wrapping |
| `plex.unnecessary-dict-keys` | **stable** | Low | yes | Redundant `.keys()` in `for k in d.keys():` or `k in d.keys()` |
| `plex.unnecessary-len` | **stable** | Low | yes | Redundant `len(seq) > 0`, `len(seq) == 0` boolean checks |
| `plex.math-pow-vs-operator` | **stable** | Medium | yes | `math.pow(x, 2)` or `pow(x, 2)` in loops instead of `x * x` |
| `plex.dict-get-fallback` | **stable** | Low | yes | Double dictionary lookup instead of single `dict.get()` |
| `plex.mutable-default-arg` | **stable** | Medium | yes | Mutable default argument in function definition (`[]`, `{}`) |
| `plex.manual-list-extend` | **stable** | Medium | yes | Manual `for x in seq: out.append(x)` loop instead of `list.extend()` |
| `plex.unclosed-resource` | **stable** | Medium | — | File opened via `open(...)` without context manager |
| `plex.short-circuit-comprehension` | **stable** | Medium | yes | Eager list comprehension inside `any()` or `all()` short-circuiting call |
| `plex.sorted-min-max` | **stable** | Medium | yes | `sorted(seq)[0]` or `sorted(seq)[-1]` instead of linear `min()` or `max()` |
| `plex.unnecessary-comprehension-in-call` | **stable** | Low | yes | Unnecessary list comprehension passed to `sum()` or `tuple()` |
| `plex.membership-in-literal-list` | **stable** | Medium | yes | Membership test against list literal instead of set literal |
| `plex.unnecessary-lambda` | **stable** | Low | yes | Unnecessary lambda wrapping a single function call |
| `plex.dict-get-default-none` | **stable** | Low | yes | Redundant `None` default argument in `dict.get(k, None)` |
| `plex.unnecessary-async-def` | **stable** | Medium | yes | Unnecessary async def coroutine |
| `plex.unnecessary-enumerate` | **stable** | Low | yes | Unused index in enumerate() loop |
| `plex.dict-items-value-unused` | **stable** | Low | yes | Unused value in dict.items() iteration |
| `plex.dict-items-comprehension-to-copy` | **stable** | Medium | yes | Dict comprehension duplicating dict.items() |
| `plex.redundant-collection-call` | **stable** | Low | yes | Redundant nested collection constructor call |
| `plex.redundant-fstring` | **stable** | Low | yes | Redundant f-string with no formatted expressions |
| `plex.str-startswith-tuple` | **stable** | Low | yes | Multiple startswith() or endswith() calls can use tuple argument |
| `plex.dict-fromkeys` | **stable** | Low | yes | Dictionary comprehension with constant value can use dict.fromkeys() |
| `plex.itertools-chain-from-iterable` | **stable** | Low | yes | itertools.chain(*iterables) can use itertools.chain.from_iterable() |
| `plex.try-except-dict-get` | **stable** | Low | yes | try-except KeyError instead of dict.get() |
| `plex.try-except-pop-default` | **stable** | Low | yes | try-except KeyError around dict.pop() instead of default argument |
| `plex.if-pass-else-invert` | **stable** | Low | yes | Empty if-pass-else branch can invert condition |
| `plex.isinstance-tuple` | **stable** | Low | yes | Multiple isinstance() checks can use tuple argument |
| `plex.itertools-islice` | **stable** | Medium | yes | Slicing list() or tuple() of iterable instead of itertools.islice() |
| `plex.re-sub-literal` | **stable** | Low | yes | re.sub() with literal string pattern instead of str.replace() |
| `plex.str-removeprefix-suffix` | **stable** | Low | yes | Manual prefix or suffix slicing instead of removeprefix/removesuffix |
| `plex.math-log-base` | **stable** | Low | yes | math.log() with base 2 or 10 instead of math.log2() or math.log10() |
| `plex.try-except-next-default` | **stable** | Low | yes | try-except StopIteration around next() instead of default argument |
| `plex.str-split-maxsplit` | **stable** | Medium | yes | Unbounded string split before indexing |
| `plex.filter-truthy` | **stable** | Low | yes | Comprehension truthiness filtering instead of filter(None, ...) |
| `plex.all-in-superset` | **stable** | Medium | yes | Membership iteration in all() instead of set.issuperset() |
| `plex.json-in-loop` | experimental | Medium | — | Repeated JSON dumps/loads in loop |
| `plex.pandas-iterrows` | experimental | Medium | — | Iterating DataFrame rows (`iterrows`, `itertuples`) |
| `plex.regex-catastrophic` | experimental | High | — | Regular expression prone to catastrophic backtracking |
| `plex.uncompiled-regex-in-loop` | experimental | Medium | yes | Direct `re.search/match` in loop without precompilation |
| `plex.sync-io-in-async` | experimental | High | yes | Synchronous blocking I/O inside async coroutine |
| `plex.deepcopy-in-loop` | experimental | High | — | Recursive `copy.deepcopy` inside loop |
| `plex.repeated-sort-in-loop` | experimental | Medium | — | Sorting (`sorted`, `list.sort`) inside loop |

Rules run on the IR and are designed to be conservative. Use `exclude`,
`min_function_lines`, and suppressions to reduce noise.

<a id="plexhotspot"></a>
## plex.hotspot

<a id="plexhotspot"></a>

Detects functions exhibiting elevated algorithmic complexity signals (nested loops, recursion, unbatched sort calls) exceeding standard heuristic thresholds.

Signals:
- Deeply nested loops (max loop depth >= 2).
- Recursive call trees without memoization.
- Multiple sorting operations over large sequences.

Suggestions:
- Refactor nested iterations using pre-indexed lookup tables (dict, set).
- Defer or hoist repeated sorting and conversions outside inner scopes.

<a id="plexregression"></a>
## plex.regression

<a id="plexregression"></a>

Detects complexity regressions when comparing the change set against the target baseline branch.

Signals:
- Elevated risk score delta (risk_delta > 0).
- Complexity hint tier increase (e.g., O(1) -> O(n), or O(n) -> O(n^2)).

Suggestions:
- Inspect newly added iterations, sorting calls, or recursive paths.
- Run baseline benchmarks to measure real-world performance impact.

<a id="plexdb-in-loop"></a>
## plex.db-in-loop (high)

Detects ORM/SQL calls inside loops (possible N+1 queries).

Signals:
- Known query methods (filter/get/select/execute/query/etc).
- ORM-like receiver names (objects/session/db/engine/connection).

Suggestions:
- Batch queries or prefetch related data.
- Move queries outside the loop.

<a id="plexjson-in-loop"></a>
## plex.json-in-loop (medium)

Detects `json.dumps/loads` inside loops.

Suggestions:
- Batch serialization or move it outside the loop.

<a id="plexpandas-iterrows"></a>
## plex.pandas-iterrows (medium)

Detects row-by-row pandas usage inside loops (`iterrows`, `itertuples`,
`apply`, `append`, `to_dict`).

Suggestions:
- Prefer vectorized operations.
- Avoid row iteration in hot paths.

<a id="plexregex-catastrophic"></a>
## plex.regex-catastrophic (high)

Detects regex patterns prone to catastrophic backtracking.

Suggestions:
- Avoid nested quantifiers.
- Use non-greedy patterns or safe regex forms.

<a id="plexhttp-in-loop"></a>
## plex.http-in-loop (high)

Detects unbatched network and HTTP calls inside loops (`requests`, `httpx`, `urllib`, `session`, `aiohttp`, `fetch`, `axios`).

Suggestions:
- Batch requests or use concurrent async fetching (e.g., `asyncio.gather` or connection pooling).
- Move HTTP requests outside the loop or cache responses.

<a id="plexunbounded-file-io"></a>
## plex.unbounded-file-io (high)

Detects repeated file open and read/write operations inside loops (`open()`, `Path.read_text()`, `write_text()`).

Suggestions:
- Open and read files once before the loop, or buffer/batch file operations.
- Use streaming generators to process file contents without reopening inside the loop.

<a id="plexstring-concat-in-loop"></a>
## plex.string-concat-in-loop (medium)

Detects repeated string concatenation in loops (`+=` or `s = s + ...`) causing $O(n^2)$ memory reallocation.

Suggestions:
- Collect substring chunks in a list and join them with `''.join(chunks)` after the loop.
- Use `io.StringIO` when streaming large textual output.

<a id="plexuncompiled-regex-in-loop"></a>
## plex.uncompiled-regex-in-loop (medium)

Detects direct `re.search()`, `re.match()`, `re.findall()`, or `re.sub()` calls inside loops.

Suggestions:
- Precompile regex patterns outside the loop with `pattern = re.compile(...)` and reuse the compiled pattern object.

<a id="plexlinear-search-in-loop"></a>
## plex.linear-search-in-loop (high)

Detects linear membership tests (`item in sequence`) inside loops where the target is a list, tuple, or `dict.values()`, causing $O(n \times m)$ quadratic behavior.

Suggestions:
- Convert the collection to a `set` outside the loop for $O(1)$ lookup complexity (`lookup_set = set(my_list)`).
- Use dictionary key lookups (`dict[key]` or `key in dict`) instead of scanning lists.



<a id="plexsync-io-in-async"></a>
## plex.sync-io-in-async (high)

Detects synchronous blocking operations (`time.sleep()`, `open()`, `requests.get/post()`, `subprocess.run()`, `urllib.request.urlopen()`) inside `async def` coroutines, which block the event loop and freeze concurrent tasks.

Suggestions:
- Use `await asyncio.sleep(...)` instead of `time.sleep(...)`.
- Use asynchronous file I/O libraries such as `aiofiles` or offload to a thread pool via `await asyncio.to_thread(open, ...)`.
- Use asynchronous HTTP clients like `httpx.AsyncClient` or `aiohttp.ClientSession`.
- Use `await asyncio.create_subprocess_exec(...)` instead of `subprocess.run(...)`.

<a id="plexdeepcopy-in-loop"></a>
## plex.deepcopy-in-loop (high)

Detects calls to `copy.deepcopy()` or `deepcopy()` inside loops. Recursive traversal of arbitrary object graphs causes severe CPU bottlenecks and memory allocation churn.

Suggestions:
- Use shallow copies (`dict.copy()`, `list[:]`, or `copy.copy()`) if nested data is immutable or structural sharing is safe.
- Move `copy.deepcopy()` outside the loop or reuse pre-allocated template structures.

<a id="plexrepeated-sort-in-loop"></a>
## plex.repeated-sort-in-loop (medium)

Detects calls to `sorted()` or `.sort()` inside loops, potentially degrading algorithmic complexity to $O(n \times m \log m)$.

Suggestions:
- Sort the collection once outside the loop if the collection does not change per iteration.
- If maintaining a running top-K or priority order, maintain a min-heap using `heapq` (e.g., `heappush`/`heappop`) for $O(\log k)$ updates instead of full sorts.
<a id="plexredundant-comprehension"></a>
## plex.redundant-comprehension (low)

Detects redundant wrapping of list/set/dict comprehensions or generator expressions in `list()`, `set()`, or `dict()` calls (e.g. `list([x for x in seq])`, `set([x for x in seq])`, or `dict([(k, v) for k, v in seq])`), allocating unnecessary intermediate collections.

Suggestions:
- Remove redundant wrapping calls or convert directly to comprehensions (`[...]`, `{...}`, or `{k: v for ...}`).
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexunnecessary-dict-keys"></a>
## plex.unnecessary-dict-keys (low)

Detects redundant `.keys()` calls in `for k in d.keys():` and `if k in d.keys():` / `if k not in d.keys():` checks. Calling `.keys()` creates a dictionary keys view object on each check/iteration, whereas operating directly on `d` utilizes dictionary hash lookups without allocations.

Suggestions:
- Iterate directly over the dictionary (`for k in d:`).
- Check membership directly against the dictionary (`if k in d:`).
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexunnecessary-len"></a>
## plex.unnecessary-len (low)

Detects redundant `len(...)` calls compared against `0` in conditional contexts (e.g. `len(seq) > 0`, `len(seq) != 0`, `len(seq) == 0`, or `len(seq) <= 0`). Direct truthiness checks (`if seq:`, `if not seq:`) avoid sequence traversal and length calculation overhead while adhering to PEP 8 idioms.

Suggestions:
- Use direct truthiness testing (`if seq:` or `if not seq:`).
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexmath-pow-vs-operator"></a>
## plex.math-pow-vs-operator (medium)

Detects `math.pow(x, 2)` or `pow(x, 2)` inside loops. In tight numerical loops, direct multiplication (`x * x`) executes 3-5x faster by avoiding C-level floating point function dispatch overhead.

Suggestions:
- Replace `math.pow(x, 2)` or `pow(x, 2)` with direct multiplication `x * x`.
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexdict-get-fallback"></a>
## plex.dict-get-fallback (low)

Detects the two-step dictionary lookup pattern:
```python
if key in d:
    val = d[key]
else:
    val = default
```
This pattern performs two distinct hash lookups against `d`. Using `dict.get()` reduces this to a single hash lookup.

Suggestions:
- Replace with `val = d.get(key, default)`.
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexmutable-default-arg"></a>
## plex.mutable-default-arg (medium)

Detects mutable default arguments (`def fn(x=[], y={})`) in function definitions. In Python, default arguments are evaluated only once at definition time and shared across all invocations, creating hidden state retention, memory leaks, and unintended data bleeding across requests.

Suggestions:
- Use `None` as the default value and initialize the collection inside the function body (`if x is None: x = []`).
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexmanual-list-extend"></a>
## plex.manual-list-extend (medium)

Detects manual iterative append loops:
```python
for item in seq:
    target.append(item)
```
Manual Python loops incur repeated function dispatch overhead and incremental list resizing. `target.extend(seq)` allocates required memory upfront in C and executes 2–4x faster.

Suggestions:
- Replace with `target.extend(seq)`.
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexunclosed-resource"></a>
## plex.unclosed-resource (medium)

Detects file handle initialization via `open(...)` outside of a `with` context manager block. Unclosed file handles leak operating system file descriptors and cause deferred garbage collection stalls.

Suggestions:
- Wrap file operations in `with open(...) as f:` to guarantee immediate deterministic cleanup.

<a id="plexshort-circuit-comprehension"></a>
## plex.short-circuit-comprehension (medium)

Detects eager list comprehensions inside short-circuiting calls:
```python
any([is_valid(x) for x in large_stream])
all([is_prime(x) for x in large_stream])
```
Passing a list comprehension `[...]` eagerly allocates all items into memory upfront and evaluates all elements, completely eliminating the benefit of short-circuiting. Replacing with a generator expression `(...)` streams items lazily and halts immediately on the first match or mismatch.

Suggestions:
- Replace with `any(x for x in seq)` or `all(x for x in seq)`.
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexsorted-min-max"></a>
## plex.sorted-min-max (medium)

Detects `sorted(seq)[0]` or `sorted(seq)[-1]` instead of `min()` or `max()`. Sorting an entire sequence executes in $O(n \log n)$ time and allocates a completely new sorted list in memory ($O(n)$ space). `min()` and `max()` scan the sequence in a single pass in $O(n)$ linear time and $O(1)$ constant memory without list allocation.

Suggestions:
- Replace `sorted(seq)[0]` with `min(seq)` (or `max(seq)` if `reverse=True`).
- Replace `sorted(seq)[-1]` with `max(seq)` (or `min(seq)` if `reverse=True`).
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexunnecessary-comprehension-in-call"></a>
## plex.unnecessary-comprehension-in-call (low)

Detects unnecessary intermediate list comprehensions passed to single-pass iterable consumers:
```python
total = sum([item.price for item in cart])
tags = tuple([t.strip() for t in raw_tags])
```
Passing a list comprehension `[...]` constructs a transient heap-allocated list that is consumed once and promptly discarded. A generator expression `sum(... for ... in ...)` streams elements on demand with $O(1)$ auxiliary memory.

Suggestions:
- Replace `sum([...])` with `sum(...)`.
- Replace `tuple([...])` with `tuple(...)`.
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexmembership-in-literal-list"></a>
## plex.membership-in-literal-list (medium)

Detects membership checks against inline list literals:
```python
if status in ["active", "pending", "approved"]:
    ...
if ext not in [".jpg", ".png", ".webp"]:
    ...
```
In Python, evaluating `x in [...]` executes a `BUILD_LIST` bytecode instruction, allocating a new list on the heap every single time this line executes and scanning it linearly in $O(n)$ time. By contrast, a set literal `{...}` with constant values is folded by CPython into an immutable `frozenset` constant at compilation time, achieving zero heap allocations and $O(1)$ constant-time lookup.

Suggestions:
- Replace `in [...]` with `in {...}`.
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexunnecessary-lambda"></a>
## plex.unnecessary-lambda (low)

Detects trivial forwarding lambdas that simply wrap a single function call:
```python
numbers = map(lambda x: int(x), items)
lengths = sorted(words, key=lambda s: len(s))
```
In Python, calling a lambda introduces an extra Python execution frame on the call stack and adds Python bytecode evaluation overhead for each item. Passing the underlying callable directly (`int`, `len`, `str`, etc.) bypasses the intermediate frame and dispatches directly (often 2–5x faster for built-ins).

Suggestions:
- Replace `lambda x: func(x)` with `func`.
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexdict-get-default-none"></a>
## plex.dict-get-default-none (low)

Detects explicit `None` defaults passed to `dict.get()`:
```python
val = config.get("timeout", None)
```
In Python, `dict.get(key)` returns `None` by default when the key is absent. Passing `None` as the second argument is completely redundant, adds unnecessary argument evaluation overhead, and bypasses CPython's 2-argument fast-path.

Suggestions:
- Replace `dict.get(key, None)` with `dict.get(key)`.
- Automatically remediable via `plex fix` and VS Code Quick Fix (`Cmd+.`).

<a id="plexunnecessary-async-def"></a>
## plex.unnecessary-async-def (medium)

Detects `async def` coroutines containing no await/async with/async for expressions, which incur coroutine allocation and event loop overhead.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexunnecessary-enumerate"></a>
## plex.unnecessary-enumerate (low)

Detects `for idx, item in enumerate(...)` where `idx` is never referenced, incurring unnecessary tuple construction and counter tracking.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexdict-items-value-unused"></a>
## plex.dict-items-value-unused (low)

Detects `for key, value in d.items()` loops where `value` is unused, incurring unnecessary 2-tuple allocations on every iteration.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexdict-items-comprehension-to-copy"></a>
## plex.dict-items-comprehension-to-copy (medium)

Detects `{k: v for k, v in d.items()}` which can be replaced with `d.copy()`, avoiding Python loop overhead and running ~8.5x faster.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexredundant-collection-call"></a>
## plex.redundant-collection-call (low)

Detects redundant nested collection calls like `list(list(x))` or `set(set(x))` that allocate redundant intermediate memory.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexredundant-fstring"></a>
## plex.redundant-fstring (low)

Detects f-strings that contain no interpolated expressions and can be written as plain string literals.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexstr-startswith-tuple"></a>
## plex.str-startswith-tuple (low)

Detects multiple startswith() or endswith() calls on the same string joined with 'or' and suggests combining them into a single call with a tuple.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexdict-fromkeys"></a>
## plex.dict-fromkeys (low)

Detects dictionary comprehensions of the form '{k: <constant> for k in keys}' and suggests 'dict.fromkeys(keys, <constant>)' for faster C-level hash table allocation.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexitertools-chain-from-iterable"></a>
## plex.itertools-chain-from-iterable (low)

Detects 'itertools.chain(*iterables)' unpacking an iterable and suggests 'itertools.chain.from_iterable(iterables)' to avoid argument tuple allocation.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plextry-except-dict-get"></a>
## plex.try-except-dict-get (low)

Detects 'try: var = d[k] except KeyError: var = default' patterns and suggests 'd.get(k, default)' to eliminate expensive exception handling.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plextry-except-pop-default"></a>
## plex.try-except-pop-default (low)

Detects 'try: d.pop(k) except KeyError: pass' or assignment fallback and suggests 'd.pop(k, default)'.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexif-pass-else-invert"></a>
## plex.if-pass-else-invert (low)

Detects 'if condition: pass else: body' and suggests inverting the condition to eliminate the empty branch and jump opcodes.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexisinstance-tuple"></a>
## plex.isinstance-tuple (low)

Detects multiple isinstance(x, T) checks on the same target chained with 'or' and suggests combining them into isinstance(x, (T1, T2)).

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexitertools-islice"></a>
## plex.itertools-islice (medium)

Detects list(seq)[:n] and tuple(seq)[:n] patterns that realize entire sequences in memory before slicing; itertools.islice() consumes lazily with O(1) allocation.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexre-sub-literal"></a>
## plex.re-sub-literal (low)

Detects re.sub() calls with literal patterns and replacements lacking regex metacharacters; str.replace() bypasses the regex engine and runs 3x faster.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexstr-removeprefix-suffix"></a>
## plex.str-removeprefix-suffix (low)

Detects 'if s.startswith(p): s = s[len(p):]' or 'if s.endswith(suf): s = s[:-len(suf)]' and suggests s.removeprefix(p) or s.removesuffix(suf).

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexmath-log-base"></a>
## plex.math-log-base (low)

Detects math.log(x, 2) and math.log(x, 10) calls; specialized math.log2() and math.log10() use direct C/FPU instructions, running 2x faster.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plextry-except-next-default"></a>
## plex.try-except-next-default (low)

Detects 'try: v = next(it) except StopIteration: v = default' and suggests 'v = next(it, default)' to avoid exception frame unwinding.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexstr-split-maxsplit"></a>
## plex.str-split-maxsplit (medium)

Detects s.split(...)[0] or s.rsplit(...)[-1] without maxsplit; supplying maxsplit avoids allocating and traversing a list of all tokens.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexfilter-truthy"></a>
## plex.filter-truthy (low)

Detects [x for x in seq if x]; list(filter(None, seq)) executes truthiness filtering in C with 1.5x speedup and lower memory overhead.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

<a id="plexall-in-superset"></a>
## plex.all-in-superset (medium)

Detects all(x in b for x in a); set(b).issuperset(a) is up to 3.5x faster, avoiding bytecode iteration and generator framing.

Suggestions:
- Automatically remediable via `plex fix` and the VS Code quick fix.

## Suppressing rules

### Statement-Level Suppressions

For targeted suppressions without ignoring the entire enclosing function, use statement-level directives on the line immediately preceding the finding:

```python
# Suppress performance rule on next line:
# plex: disable-next[plex.db-in-loop] reason="batched iterator with bounded page size"
record = db.query(Model).get(item_id)

# Suppress security injection rule on next line:
# plex: disable-next[xbnd.sql-injection] reason="query constructed from static enum mapping"
cursor.execute(sql)
```

Supported comment directives:
- `# plex: disable-next[<rule_id>] reason="..."`: Suppresses `<rule_id>` on the next non-comment line.
- `# plex: disable-next-line[<rule_id>] reason="..."`: Equivalent alias for `disable-next`.
- `# plex: ignore[<rule_id>] reason="..."`: Suppresses on the same line or next line.

### Function-Level Suppressions

Suppressions can also apply to an entire function definition:

```python
# plex: ignore reason="legacy path" ticket="PERF-123"
def slow_but_expected(...):
    ...
```

Suppressions are recorded in the generated scan report for auditability and compliance tracking.

---

## Known Boundaries & Limitations

### Algorithmic Complexity Rules
- **Static Heuristics**: Signals like nested loops and recursion depth are analyzed statically on the IR. Complex dynamic loop break conditions or external pagination boundaries that limit iterations at runtime should be annotated with statement-level suppressions.
- **Dynamic Verification**: Heuristic findings are graduated with dynamic benchmarking fixtures when available.

### Security Injection Analysis (xBOUNDARY)
- **Dynamic Reflection**: Taint tracking does not inspect dynamic attributes (`getattr`), dynamic imports (`importlib`), or metaclass runtime dispatch.
- **Sanitizer Modeling**: Type conversions (`int`, `float`, `bool`) strip taint. Arbitrary quoting functions (`shlex.quote`, string replacements) preserve taint by default unless explicitly configured in `.plex/security.yml`.
- **Parameterization**: Parameterized query structures (`cursor.execute(sql, params)`) are modeled as safe, whereas interpolated strings passed to the query parameter remain flagged.

