from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass

from plex.rules.base import Rule, RuleContext, RuleFinding

_DB_CALLS = {
    "filter",
    "exclude",
    "get",
    "all",
    "select",
    "update",
    "delete",
    "create",
    "execute",
    "query",
    "scalars",
    "fetchone",
    "fetchall",
}

_DB_OBJECT_HINTS = {
    "objects",
    "session",
    "db",
    "cursor",
    "queryset",
    "engine",
    "conn",
    "connection",
}

_PANDAS_CALLS = {"iterrows", "itertuples"}
_PANDAS_MAYBE_CALLS = {"apply", "append", "to_dict"}
_PANDAS_OBJECT_HINTS = {"df", "frame", "dataframe", "series", "table", "data"}


def _object_matches_db_hint(obj_name: str | None) -> bool:
    if not obj_name:
        return False
    lowered = obj_name.lower()
    if any(hint in lowered for hint in _DB_OBJECT_HINTS):
        return True
    if lowered.endswith(".objects"):
        return True
    return False


def _object_matches_pandas_hint(obj_name: str | None) -> bool:
    if not obj_name:
        return False
    lowered = obj_name.lower()
    return any(hint in lowered for hint in _PANDAS_OBJECT_HINTS)


def _make_finding(
    rule: Rule,
    context: RuleContext,
    file_path: str,
    qualname: str,
    lineno: int,
    message: str,
    suggestions: list[str],
    severity: str | None = None,
    confidence: float = 0.6,
) -> RuleFinding:
    finding = context.finding_for(file_path, qualname) or context.finding_for_line(
        file_path, lineno
    )
    if finding:
        return RuleFinding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=severity or rule.default_severity,
            message=message,
            file=finding.file,
            lineno=lineno,
            end_lineno=finding.end_lineno,
            qualname=finding.qualname,
            function_id=finding.function_id,
            body_hash=finding.body_hash,
            suggestions=suggestions,
            confidence=confidence,
        )
    return RuleFinding(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=severity or rule.default_severity,
        message=message,
        file=file_path,
        lineno=lineno,
        end_lineno=lineno,
        qualname=qualname,
        function_id="",
        body_hash="",
        suggestions=suggestions,
        confidence=confidence,
    )


class DbCallInLoopRule(Rule):
    id = "plex.db-in-loop"
    name = "Database call inside loop"
    description = "Detects potential N+1 patterns by spotting ORM/SQL calls in loops."
    default_severity = "high"
    stability = "stable"
    tags = ["performance", "orm", "database"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    if call.name not in _DB_CALLS:
                        continue
                    if not _object_matches_db_hint(call.object_name):
                        continue
                    message = f"Database call `{call.name}()` inside a loop may cause N+1 queries."
                    suggestions = [
                        "Batch queries or prefetch related data before the loop.",
                        "Move queries outside loops or use select_related/prefetch_related.",
                    ]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


class JsonInLoopRule(Rule):
    id = "plex.json-in-loop"
    name = "JSON serialization inside loop"
    description = "Detects json.dumps/loads in tight loops."
    default_severity = "medium"
    stability = "experimental"
    tags = ["performance", "serialization"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    if call.name not in {"dumps", "loads"}:
                        continue
                    if call.object_name not in {"json"}:
                        continue
                    message = f"JSON `{call.name}()` inside loop can be expensive."
                    suggestions = ["Batch serialization or move it outside the loop."]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


class PandasRowIterationRule(Rule):
    id = "plex.pandas-iterrows"
    name = "Pandas row iteration in loop"
    description = "Detects row-by-row pandas usage in loops."
    default_severity = "medium"
    stability = "experimental"
    tags = ["performance", "pandas"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    is_pandas = False
                    if call.name in _PANDAS_CALLS:
                        is_pandas = True
                    elif call.name in _PANDAS_MAYBE_CALLS and _object_matches_pandas_hint(
                        call.object_name
                    ):
                        is_pandas = True
                    if not is_pandas:
                        continue
                    message = f"Pandas `{call.name}()` inside loop can be slow."
                    suggestions = [
                        "Prefer vectorized operations instead of row iteration.",
                        "Use DataFrame.apply sparingly or precompute with vectorized ops.",
                    ]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


_REGEX_BAD_PATTERNS = [
    re.compile(r"\([^)]*[*+][^)]*\)[*+]"),
    re.compile(r"\.\*[+*]"),
    re.compile(r"\(\?:[^)]*[*+][^)]*\)[*+]"),
]


def _is_catastrophic_regex(pattern: str) -> bool:
    for rx in _REGEX_BAD_PATTERNS:
        if rx.search(pattern):
            return True
    return False


@dataclass
class _RegexHit:
    lineno: int
    pattern: str


class _RegexVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_RegexHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = None
        obj = None
        if isinstance(func, ast.Attribute):
            name = func.attr
            if isinstance(func.value, ast.Name):
                obj = func.value.id
        elif isinstance(func, ast.Name):
            name = func.id
        if name in {"compile", "search", "match", "findall", "fullmatch"} and obj == "re":
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                pattern = node.args[0].value
                if _is_catastrophic_regex(pattern):
                    self.hits.append(
                        _RegexHit(lineno=int(getattr(node, "lineno", 1)), pattern=pattern)
                    )
        self.generic_visit(node)


class RegexCatastropheRule(Rule):
    id = "plex.regex-catastrophic"
    name = "Potential catastrophic regex"
    description = "Detects regex patterns that may cause catastrophic backtracking."
    default_severity = "high"
    stability = "experimental"
    tags = ["performance", "regex"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _RegexVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                message = "Regex pattern may cause catastrophic backtracking."
                suggestions = [
                    "Avoid nested quantifiers or use non-greedy patterns.",
                    "Consider precompiling with safe patterns or using regex timeouts.",
                ]
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    message,
                    suggestions,
                    confidence=0.5,
                )


_HTTP_CALLS = {"get", "post", "put", "delete", "patch", "head", "request"}
_HTTP_OBJECT_HINTS = {
    "requests",
    "httpx",
    "session",
    "client",
    "http",
    "http_client",
    "aiohttp",
    "urllib",
    "axios",
}


def _object_matches_http_hint(obj_name: str | None) -> bool:
    if not obj_name:
        return False
    lowered = obj_name.lower()
    return any(hint in lowered for hint in _HTTP_OBJECT_HINTS)


class HttpCallInLoopRule(Rule):
    id = "plex.http-in-loop"
    name = "HTTP request inside loop"
    description = "Detects unbatched network and HTTP calls in loops."
    default_severity = "high"
    stability = "stable"
    tags = ["performance", "network", "http"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    is_http = False
                    if call.name in _HTTP_CALLS and _object_matches_http_hint(call.object_name):
                        is_http = True
                    elif call.name in {"urlopen", "fetch"}:
                        is_http = True
                    if not is_http:
                        continue
                    target = (
                        f"{call.object_name}.{call.name}()"
                        if call.object_name
                        else f"{call.name}()"
                    )
                    message = f"HTTP request `{target}` inside a loop may cause severe latency bottlenecks."
                    suggestions = [
                        "Batch requests or use concurrent async fetching (e.g., asyncio.gather or a connection pool).",
                        "Move HTTP calls outside the loop or cache responses.",
                    ]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


_FILE_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes"}


class UnboundedFileIoRule(Rule):
    id = "plex.unbounded-file-io"
    name = "File I/O inside loop"
    description = "Detects repetitive file open and read/write operations inside loops."
    default_severity = "high"
    stability = "stable"
    tags = ["performance", "io", "filesystem"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    is_file_io = False
                    if call.name == "open" and (
                        call.object_name is None or call.object_name in {"builtins", "os", "io"}
                    ):
                        is_file_io = True
                    elif call.name in _FILE_METHODS:
                        is_file_io = True
                    if not is_file_io:
                        continue
                    target = (
                        f"{call.object_name}.{call.name}()"
                        if call.object_name
                        else f"{call.name}()"
                    )
                    message = f"File I/O `{target}` inside a loop can cause significant disk and syscall overhead."
                    suggestions = [
                        "Open and read files once before the loop, or buffer/batch file operations.",
                        "Use streaming generators to process file contents without reopening inside the loop.",
                    ]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


@dataclass
class _StringConcatHit:
    lineno: int
    var_name: str


def _is_str_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "str":
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "decode"}:
            return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_str_expr(node.left) or _is_str_expr(node.right)
    return False


class _StringConcatVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_StringConcatHit] = []
        self._loop_depth = 0

    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if self._loop_depth > 0 and isinstance(node.op, ast.Add):
            if _is_str_expr(node.value):
                var_name = node.target.id if isinstance(node.target, ast.Name) else "variable"
                self.hits.append(
                    _StringConcatHit(lineno=int(getattr(node, "lineno", 1)), var_name=var_name)
                )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if (
            self._loop_depth > 0
            and isinstance(node.value, ast.BinOp)
            and isinstance(node.value.op, ast.Add)
        ):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            left_name = node.value.left.id if isinstance(node.value.left, ast.Name) else None
            right = node.value.right
            if left_name and left_name in target_names and _is_str_expr(right):
                self.hits.append(
                    _StringConcatHit(lineno=int(getattr(node, "lineno", 1)), var_name=left_name)
                )
        self.generic_visit(node)


class StringConcatInLoopRule(Rule):
    id = "plex.string-concat-in-loop"
    name = "String concatenation in loop"
    description = "Detects repeated string concatenation in loops causing O(n^2) reallocation."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "string", "memory"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _StringConcatVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                message = f"Repeated string concatenation on `{hit.var_name}` in loop causes quadratic memory copying."
                suggestions = [
                    "Collect substring chunks in a list and join them with `''.join(chunks)` after the loop.",
                    "Use io.StringIO if streaming large textual output.",
                ]
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    message,
                    suggestions,
                    confidence=0.7,
                )


_RE_UNCOMPILED_CALLS = {
    "search",
    "match",
    "fullmatch",
    "findall",
    "finditer",
    "sub",
    "subn",
    "split",
}


class UncompiledRegexInLoopRule(Rule):
    id = "plex.uncompiled-regex-in-loop"
    name = "Uncompiled regex inside loop"
    description = "Detects direct re.search/match calls inside loops."
    default_severity = "medium"
    stability = "experimental"
    tags = ["performance", "regex"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    if call.name not in _RE_UNCOMPILED_CALLS:
                        continue
                    if call.object_name != "re":
                        continue
                    message = (
                        f"Uncompiled `re.{call.name}()` inside loop; "
                        "precompiling with `re.compile()` avoids repeated pattern parsing."
                    )
                    suggestions = [
                        "Compile regex patterns outside the loop with `pattern = re.compile(...)` and reuse.",
                    ]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


@dataclass
class _LinearSearchHit:
    lineno: int
    target_repr: str


class _LinearSearchVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_LinearSearchHit] = []
        self._loop_depth = 0
        self._list_vars: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev_list_vars = set(self._list_vars)
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                if isinstance(stmt.value, (ast.List, ast.Tuple)):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            self._list_vars.add(t.id)
                elif isinstance(stmt.value, ast.Call):
                    if isinstance(stmt.value.func, ast.Name) and stmt.value.func.id in {
                        "list",
                        "tuple",
                    }:
                        for t in stmt.targets:
                            if isinstance(t, ast.Name):
                                self._list_vars.add(t.id)
        self.generic_visit(node)
        self._list_vars = prev_list_vars

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_Compare(self, node: ast.Compare) -> None:
        if self._loop_depth > 0:
            for op, comparator in zip(node.ops, node.comparators, strict=False):
                if isinstance(op, (ast.In, ast.NotIn)):
                    is_linear = False
                    repr_name = "collection"
                    if isinstance(comparator, ast.List):
                        is_linear = True
                        repr_name = "list literal"
                    elif isinstance(comparator, ast.Call):
                        if (
                            isinstance(comparator.func, ast.Attribute)
                            and comparator.func.attr == "values"
                        ):
                            is_linear = True
                            repr_name = "dict.values()"
                        elif isinstance(comparator.func, ast.Name) and comparator.func.id in {
                            "list",
                            "tuple",
                        }:
                            is_linear = True
                            repr_name = f"{comparator.func.id}()"
                    elif isinstance(comparator, ast.Name):
                        name = comparator.id
                        if name in self._list_vars:
                            is_linear = True
                            repr_name = f"`{name}` (list)"
                        elif any(
                            name.lower().endswith(suffix)
                            for suffix in ("_list", "_items", "_array")
                        ):
                            is_linear = True
                            repr_name = f"`{name}`"
                    if is_linear:
                        self.hits.append(
                            _LinearSearchHit(
                                lineno=int(getattr(node, "lineno", 1)),
                                target_repr=repr_name,
                            )
                        )
        self.generic_visit(node)


class LinearSearchInLoopRule(Rule):
    id = "plex.linear-search-in-loop"
    name = "Linear search inside loop"
    description = (
        "Detects linear membership testing (x in list) inside loops causing quadratic behavior."
    )
    default_severity = "high"
    stability = "stable"
    tags = ["performance", "algorithmic", "complexity"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _LinearSearchVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                message = f"Linear membership check `in {hit.target_repr}` inside loop can cause O(n*m) quadratic performance."
                suggestions = [
                    "Convert the target collection to a `set` outside the loop for O(1) membership lookups.",
                    "Use a `dict` for key-value index lookups instead of scanning lists.",
                ]
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    message,
                    suggestions,
                    confidence=0.8,
                )


@dataclass
class _SyncIoHit:
    lineno: int
    call_repr: str
    message: str
    suggestions: list[str]


class _SyncIoInAsyncVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_SyncIoHit] = []
        self._fn_stack: list[str] = []

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._fn_stack.append("async")
        self.generic_visit(node)
        self._fn_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._fn_stack.append("sync")
        self.generic_visit(node)
        self._fn_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if self._fn_stack and self._fn_stack[-1] == "async":
            # 1. time.sleep(...)
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "time"
                and node.func.attr == "sleep"
            ):
                self.hits.append(
                    _SyncIoHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_repr="time.sleep()",
                        message="Synchronous blocking `time.sleep()` inside async function freezes the event loop.",
                        suggestions=[
                            "Replace with `await asyncio.sleep(...)` to allow concurrent tasks to run.",
                        ],
                    )
                )
            # 2. open(...)
            elif isinstance(node.func, ast.Name) and node.func.id == "open":
                self.hits.append(
                    _SyncIoHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_repr="open()",
                        message="Synchronous file `open()` inside async function blocks the event loop on disk I/O.",
                        suggestions=[
                            "Use an asynchronous file library like `aiofiles` (`async with aiofiles.open(...)`).",
                            "Delegate blocking file I/O to a thread pool via `await asyncio.to_thread(open, ...)` or `loop.run_in_executor`.",
                        ],
                    )
                )
            # 3. requests.<method>(...)
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "requests"
                and node.func.attr
                in {"get", "post", "put", "delete", "patch", "head", "options", "request"}
            ):
                self.hits.append(
                    _SyncIoHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_repr=f"requests.{node.func.attr}()",
                        message=f"Synchronous HTTP call `requests.{node.func.attr}()` inside async function blocks the event loop.",
                        suggestions=[
                            "Use an asynchronous HTTP client such as `httpx.AsyncClient` or `aiohttp.ClientSession`.",
                            "Offload blocking requests to a worker thread via `await asyncio.to_thread(...)`.",
                        ],
                    )
                )
            # 4. subprocess.run/call/check_output
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in {"run", "call", "check_call", "check_output"}
            ):
                self.hits.append(
                    _SyncIoHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_repr=f"subprocess.{node.func.attr}()",
                        message=f"Synchronous process invocation `subprocess.{node.func.attr}()` inside async function blocks the event loop.",
                        suggestions=[
                            "Use `await asyncio.create_subprocess_exec(...)` or `await asyncio.create_subprocess_shell(...)`.",
                            "Offload process execution with `await asyncio.to_thread(...)`.",
                        ],
                    )
                )
            # 5. urllib.request.urlopen
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "urlopen":
                self.hits.append(
                    _SyncIoHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_repr="urlopen()",
                        message="Synchronous network call `urlopen()` inside async function blocks the event loop.",
                        suggestions=[
                            "Use an asynchronous HTTP client such as `httpx.AsyncClient` or `aiohttp.ClientSession`.",
                        ],
                    )
                )
        self.generic_visit(node)


class SyncIoInAsyncRule(Rule):
    id = "plex.sync-io-in-async"
    name = "Synchronous blocking I/O in async function"
    description = "Detects synchronous blocking operations (time.sleep, open, requests) inside async coroutines that block the event loop."
    default_severity = "high"
    stability = "experimental"
    tags = ["performance", "async", "concurrency", "event-loop"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _SyncIoInAsyncVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.85,
                )


class DeepcopyInLoopRule(Rule):
    id = "plex.deepcopy-in-loop"
    name = "Deepcopy inside loop"
    description = "Detects copy.deepcopy calls inside loops causing extensive object traversal and allocation overhead."
    default_severity = "high"
    stability = "experimental"
    tags = ["performance", "memory", "allocation"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    if call.name == "deepcopy" and (
                        call.object_name is None or call.object_name in {"copy", "copylib"}
                    ):
                        target = (
                            f"{call.object_name}.{call.name}()"
                            if call.object_name
                            else f"{call.name}()"
                        )
                        message = f"Recursive `{target}` inside a loop causes heavy object graph traversal and memory allocation."
                        suggestions = [
                            "Use shallow copying (e.g., `dict.copy()`, `list[:]`, or `copy.copy()`) if elements are immutable or structural sharing is safe.",
                            "Instantiate a new object directly or move the deepcopy outside the loop.",
                        ]
                        yield _make_finding(
                            self,
                            context,
                            module.file,
                            fn.qualname,
                            call.lineno,
                            message,
                            suggestions,
                            confidence=0.8,
                        )


class RepeatedSortInLoopRule(Rule):
    id = "plex.repeated-sort-in-loop"
    name = "Sorting inside loop"
    description = (
        "Detects sorted() or list.sort() calls inside loops causing O(n * m log m) complexity."
    )
    default_severity = "medium"
    stability = "experimental"
    tags = ["performance", "algorithmic", "complexity"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    is_sort = False
                    if call.name == "sorted" and (
                        call.object_name is None or call.object_name in {"builtins"}
                    ):
                        is_sort = True
                    elif call.name == "sort":
                        is_sort = True
                    if not is_sort:
                        continue
                    target = (
                        f"{call.object_name}.{call.name}()"
                        if call.object_name
                        else f"{call.name}()"
                    )
                    message = f"Sorting call `{target}` inside a loop can degrade performance to O(n * m log m)."
                    suggestions = [
                        "Sort the collection once outside the loop if the collection does not change per iteration.",
                        "If tracking top-K elements, maintain a min-heap using `heapq` (e.g. `heappush`/`heappop`) for O(log k) operations instead of full sorts.",
                        "If incrementally inserting elements in order, use `bisect.insort`.",
                    ]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                        confidence=0.75,
                    )


@dataclass
class _RedundantCompHit:
    lineno: int
    call_name: str
    message: str
    suggestions: list[str]


class _RedundantComprehensionVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_RedundantCompHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and len(node.args) == 1 and not node.keywords:
            fn_name = node.func.id
            arg = node.args[0]
            if fn_name == "list" and isinstance(arg, ast.ListComp):
                self.hits.append(
                    _RedundantCompHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_name="list()",
                        message="Redundant `list()` call around list comprehension allocates an unnecessary intermediate copy.",
                        suggestions=[
                            "Remove `list(...)` and use the list comprehension `[...]` directly."
                        ],
                    )
                )
            elif fn_name == "list" and isinstance(arg, ast.GeneratorExp):
                self.hits.append(
                    _RedundantCompHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_name="list()",
                        message="Redundant `list()` call around generator expression is slower than a direct list comprehension.",
                        suggestions=[
                            "Convert `list(x for ...)` to list comprehension `[x for ...]`."
                        ],
                    )
                )
            elif fn_name == "set" and isinstance(arg, (ast.ListComp, ast.GeneratorExp)):
                self.hits.append(
                    _RedundantCompHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_name="set()",
                        message="Redundant `set()` call around comprehension or generator.",
                        suggestions=["Use set comprehension `{x for ...}` directly."],
                    )
                )
            elif fn_name == "dict" and isinstance(arg, (ast.ListComp, ast.GeneratorExp)):
                if isinstance(arg.elt, (ast.Tuple, ast.List)) and len(arg.elt.elts) == 2:
                    self.hits.append(
                        _RedundantCompHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            call_name="dict()",
                            message="Redundant `dict()` call around 2-tuple comprehension or generator.",
                            suggestions=["Use dict comprehension `{k: v for ...}` directly."],
                        )
                    )
        self.generic_visit(node)


class RedundantComprehensionRule(Rule):
    id = "plex.redundant-comprehension"
    name = "Redundant comprehension or conversion call"
    description = "Detects redundant wrapping of list/set/dict comprehensions or generator expressions in list(), set(), or dict() calls."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "idiomatic", "allocation"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _RedundantComprehensionVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _UnnecessaryDictKeysHit:
    lineno: int
    message: str
    suggestions: list[str]


class _UnnecessaryDictKeysVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_UnnecessaryDictKeysHit] = []

    def visit_For(self, node: ast.For) -> None:
        self._check_iter(node.iter, int(getattr(node, "lineno", 1)))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._check_iter(node.iter, int(getattr(node, "lineno", 1)))
        self.generic_visit(node)

    def _check_iter(self, iter_node: ast.expr, lineno: int) -> None:
        if (
            isinstance(iter_node, ast.Call)
            and isinstance(iter_node.func, ast.Attribute)
            and iter_node.func.attr == "keys"
            and not iter_node.args
            and not iter_node.keywords
        ):
            self.hits.append(
                _UnnecessaryDictKeysHit(
                    lineno=lineno,
                    message="Unnecessary `.keys()` call in loop iteration; iterating directly on the dictionary yields keys without allocating a view.",
                    suggestions=["Iterate directly over the dictionary (e.g. `for k in d:`)."],
                )
            )

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, comp in zip(node.ops, node.comparators, strict=False):
            if isinstance(op, (ast.In, ast.NotIn)):
                if (
                    isinstance(comp, ast.Call)
                    and isinstance(comp.func, ast.Attribute)
                    and comp.func.attr == "keys"
                    and not comp.args
                    and not comp.keywords
                ):
                    self.hits.append(
                        _UnnecessaryDictKeysHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            message="Unnecessary `.keys()` call in membership test; testing `in dict` directly performs an O(1) hash lookup without allocating a view.",
                            suggestions=[
                                "Test membership directly against the dictionary (e.g. `if key in d:`)."
                            ],
                        )
                    )
        self.generic_visit(node)


class UnnecessaryDictKeysRule(Rule):
    id = "plex.unnecessary-dict-keys"
    name = "Unnecessary dict.keys() iteration or membership check"
    description = "Detects redundant .keys() calls in 'for ... in d.keys()' and 'x in d.keys()' membership tests."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "idiomatic", "lookup"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _UnnecessaryDictKeysVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _UnnecessaryLenHit:
    lineno: int
    message: str
    suggestions: list[str]


class _UnnecessaryLenVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_UnnecessaryLenHit] = []

    def visit_Compare(self, node: ast.Compare) -> None:
        if (
            isinstance(node.left, ast.Call)
            and isinstance(node.left.func, ast.Name)
            and node.left.func.id == "len"
            and len(node.left.args) == 1
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value == 0
        ):
            op = node.ops[0]
            if isinstance(op, (ast.Gt, ast.NotEq, ast.Eq, ast.LtE)):
                self.hits.append(
                    _UnnecessaryLenHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        message="Unnecessary `len(...)` call in comparison with 0; truthiness tests (`if x:`, `if not x:`) are faster and idiomatic.",
                        suggestions=[
                            "Use boolean truthiness directly (`if seq:` or `if not seq:`).",
                        ],
                    )
                )
        self.generic_visit(node)


class UnnecessaryLenRule(Rule):
    id = "plex.unnecessary-len"
    name = "Unnecessary len() call in boolean context"
    description = "Detects len(x) > 0, len(x) == 0, and len(x) != 0 in conditions; truthiness checks (if x:, if not x:) are more idiomatic and faster."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "idiomatic"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _UnnecessaryLenVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _MathPowHit:
    lineno: int
    call_repr: str
    message: str
    suggestions: list[str]


class _MathPowVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_MathPowHit] = []
        self._loop_depth = 0

    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if self._loop_depth > 0 and len(node.args) == 2:
            is_pow = False
            call_repr = ""
            exp_arg = node.args[1]
            if isinstance(exp_arg, ast.Constant) and exp_arg.value == 2:
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "math"
                    and node.func.attr == "pow"
                ):
                    is_pow = True
                    call_repr = "math.pow(x, 2)"
                elif isinstance(node.func, ast.Name) and node.func.id == "pow":
                    is_pow = True
                    call_repr = "pow(x, 2)"

            if is_pow:
                self.hits.append(
                    _MathPowHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        call_repr=call_repr,
                        message=f"Function call `{call_repr}` in loop can be replaced with `x * x` for 3-5x faster execution.",
                        suggestions=[
                            "Replace `math.pow(x, 2)` or `pow(x, 2)` with direct multiplication `x * x`.",
                        ],
                    )
                )
        self.generic_visit(node)


class MathPowVsOperatorRule(Rule):
    id = "plex.math-pow-vs-operator"
    name = "math.pow() or pow() in loop instead of multiplication operator"
    description = "Detects math.pow(x, 2) or pow(x, 2) in loops; x * x executes 3-5x faster in tight numerical loops."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "math", "numerical"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _MathPowVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.85,
                )


@dataclass
class _DictGetFallbackHit:
    lineno: int
    target_var: str
    dict_name: str
    message: str
    suggestions: list[str]


class _DictGetFallbackVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_DictGetFallbackHit] = []

    def visit_If(self, node: ast.If) -> None:
        if (
            isinstance(node.test, ast.Compare)
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.In)
            and len(node.test.comparators) == 1
            and len(node.body) == 1
            and len(node.orelse) == 1
        ):
            key_expr = node.test.left
            dict_expr = node.test.comparators[0]
            true_stmt = node.body[0]
            false_stmt = node.orelse[0]

            if (
                isinstance(true_stmt, ast.Assign)
                and len(true_stmt.targets) == 1
                and isinstance(false_stmt, ast.Assign)
                and len(false_stmt.targets) == 1
            ):
                t_true = true_stmt.targets[0]
                t_false = false_stmt.targets[0]
                if (
                    isinstance(t_true, ast.Name)
                    and isinstance(t_false, ast.Name)
                    and t_true.id == t_false.id
                    and isinstance(true_stmt.value, ast.Subscript)
                ):
                    sub = true_stmt.value
                    if ast.dump(sub.value) == ast.dump(dict_expr) and ast.dump(
                        sub.slice
                    ) == ast.dump(key_expr):
                        d_name = (
                            getattr(dict_expr, "id", "d")
                            if isinstance(dict_expr, ast.Name)
                            else "d"
                        )
                        self.hits.append(
                            _DictGetFallbackHit(
                                lineno=int(getattr(node, "lineno", 1)),
                                target_var=t_true.id,
                                dict_name=d_name,
                                message="Double dictionary lookup in 'if k in d: v = d[k] else: v = default'; dict.get() avoids the redundant hash search.",
                                suggestions=[
                                    f"Replace with `{t_true.id} = {d_name}.get(key, default)`.",
                                ],
                            )
                        )
        self.generic_visit(node)


class DictGetFallbackRule(Rule):
    id = "plex.dict-get-fallback"
    name = "Double dictionary lookup instead of dict.get()"
    description = "Detects 'if k in d: v = d[k] else: v = default' pattern; dict.get() performs a single hash lookup instead of two."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "dictionary", "lookup"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _DictGetFallbackVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _MutableDefaultArgHit:
    lineno: int
    arg_name: str
    message: str
    suggestions: list[str]


class _MutableDefaultArgVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_MutableDefaultArgHit] = []

    def _check_default(self, arg_name: str, default: ast.AST | None, lineno: int) -> None:
        if default is None:
            return
        is_mutable = False
        if isinstance(default, (ast.List, ast.Dict, ast.Set)):
            is_mutable = True
        elif (
            isinstance(default, ast.Call)
            and isinstance(default.func, ast.Name)
            and default.func.id in {"list", "dict", "set"}
            and not default.args
            and not default.keywords
        ):
            is_mutable = True

        if is_mutable:
            self.hits.append(
                _MutableDefaultArgHit(
                    lineno=lineno,
                    arg_name=arg_name,
                    message=f"Mutable default argument `{arg_name}` retains state across invocations, risking subtle bugs and memory retention.",
                    suggestions=[
                        f"Replace `{arg_name}` default with `None` and initialize inside the function body (`if {arg_name} is None: {arg_name} = ...`).",
                    ],
                )
            )

    def _check_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        pos_args = node.args.args
        defaults = node.args.defaults
        offset = len(pos_args) - len(defaults)
        for i, default in enumerate(defaults):
            arg = pos_args[offset + i]
            self._check_default(
                arg.arg, default, int(getattr(default, "lineno", getattr(node, "lineno", 1)))
            )

        for kwarg, kw_default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
            if kw_default is not None:
                self._check_default(
                    kwarg.arg,
                    kw_default,
                    int(getattr(kw_default, "lineno", getattr(node, "lineno", 1))),
                )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_func(node)


class MutableDefaultArgRule(Rule):
    id = "plex.mutable-default-arg"
    name = "Mutable default argument in function definition"
    description = "Detects mutable default arguments ([], {}, set()) in function definitions; defaults are instantiated once at module load, leading to state leaks across calls."
    default_severity = "medium"
    stability = "stable"
    tags = ["memory", "correctness", "performance"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _MutableDefaultArgVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.95,
                )


@dataclass
class _ManualListExtendHit:
    lineno: int
    target_name: str
    iter_name: str
    message: str
    suggestions: list[str]


class _ManualListExtendVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_ManualListExtendHit] = []

    def visit_For(self, node: ast.For) -> None:
        if len(node.body) == 1 and not node.orelse:
            stmt = node.body[0]
            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Attribute)
                and stmt.value.func.attr == "append"
                and len(stmt.value.args) == 1
            ):
                append_arg = stmt.value.args[0]
                if (
                    isinstance(node.target, ast.Name)
                    and isinstance(append_arg, ast.Name)
                    and node.target.id == append_arg.id
                ):
                    target_name = (
                        getattr(stmt.value.func.value, "id", "list")
                        if isinstance(stmt.value.func.value, ast.Name)
                        else "list"
                    )
                    iter_repr = (
                        getattr(node.iter, "id", "seq")
                        if isinstance(node.iter, ast.Name)
                        else "seq"
                    )
                    self.hits.append(
                        _ManualListExtendHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            target_name=target_name,
                            iter_name=iter_repr,
                            message=f"Loop manually appends items to `{target_name}`; `{target_name}.extend()` executes 2-4x faster via batch memory allocation.",
                            suggestions=[
                                f"Replace loop with `{target_name}.extend({iter_repr})`.",
                            ],
                        )
                    )
        self.generic_visit(node)


class ManualListExtendRule(Rule):
    id = "plex.manual-list-extend"
    name = "Manual loop append instead of list.extend()"
    description = "Detects 'for item in seq: out.append(item)'; list.extend() performs a single pre-allocation in C and executes 2-4x faster."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "idiomatic", "loop"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _ManualListExtendVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _UnclosedResourceHit:
    lineno: int
    message: str
    suggestions: list[str]


class _UnclosedResourceVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_UnclosedResourceHit] = []
        self._with_depth = 0

    def visit_With(self, node: ast.With) -> None:
        self._with_depth += 1
        self.generic_visit(node)
        self._with_depth -= 1

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._with_depth += 1
        self.generic_visit(node)
        self._with_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if self._with_depth == 0:
            if isinstance(node.func, ast.Name) and node.func.id == "open":
                self.hits.append(
                    _UnclosedResourceHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        message="File opened without a context manager (`with open(...)`); risk of unclosed file descriptors and OS handle leaks.",
                        suggestions=[
                            "Wrap file operations in a `with open(...) as f:` block to ensure prompt descriptor release.",
                        ],
                    )
                )
        self.generic_visit(node)


class UnclosedResourceRule(Rule):
    id = "plex.unclosed-resource"
    name = "Resource opened without context manager"
    description = "Detects open() calls outside of 'with' statements, risking unclosed file descriptors and deferred garbage collection stalls."
    default_severity = "medium"
    stability = "stable"
    tags = ["resource", "io", "performance"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _UnclosedResourceVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.85,
                )


@dataclass
class _ShortCircuitComprehensionHit:
    lineno: int
    func_name: str
    message: str
    suggestions: list[str]


class _ShortCircuitComprehensionVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_ShortCircuitComprehensionHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"any", "all"}
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.ListComp)
        ):
            fn = node.func.id
            self.hits.append(
                _ShortCircuitComprehensionHit(
                    lineno=int(getattr(node, "lineno", 1)),
                    func_name=fn,
                    message=f"Eager list comprehension inside `{fn}()` evaluates all elements upfront and defeats short-circuiting.",
                    suggestions=[
                        f"Pass a generator expression to `{fn}()` instead (`{fn}(... for ... in ...)`).",
                    ],
                )
            )
        self.generic_visit(node)


class ShortCircuitComprehensionRule(Rule):
    id = "plex.short-circuit-comprehension"
    name = "Eager list comprehension in any() or all() short-circuiting call"
    description = "Detects any([x for x in seq]) and all([x for x in seq]); eagerly allocating a list prevents short-circuiting and wastes memory."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "comprehension", "memory"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _ShortCircuitComprehensionVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _SortedMinMaxHit:
    lineno: int
    target_func: str
    index_repr: str
    message: str
    suggestions: list[str]


class _SortedMinMaxVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_SortedMinMaxHit] = []

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "sorted"
            and len(node.value.args) >= 1
        ):
            target_fn = ""
            idx_repr = ""
            if isinstance(node.slice, ast.Constant) and node.slice.value == 0:
                idx_repr = "0"
            elif (
                isinstance(node.slice, ast.UnaryOp)
                and isinstance(node.slice.op, ast.USub)
                and isinstance(node.slice.operand, ast.Constant)
                and node.slice.operand.value == 1
            ):
                idx_repr = "-1"

            if idx_repr:
                reverse_val: bool | None = None
                for kw in node.value.keywords:
                    if (
                        kw.arg == "reverse"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, bool)
                    ):
                        reverse_val = kw.value.value
                if reverse_val is True:
                    target_fn = "max" if idx_repr == "0" else "min"
                else:
                    target_fn = "min" if idx_repr == "0" else "max"

            if target_fn:
                self.hits.append(
                    _SortedMinMaxHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        target_func=target_fn,
                        index_repr=idx_repr,
                        message=f"Calling `sorted(...)[{idx_repr}]` executes in O(n log n) time and allocates a full list; `{target_fn}()` executes in O(n) time with O(1) memory.",
                        suggestions=[
                            f"Replace with `{target_fn}(...)`.",
                        ],
                    )
                )
        self.generic_visit(node)


class SortedMinMaxRule(Rule):
    id = "plex.sorted-min-max"
    name = "sorted()[0] or sorted()[-1] instead of min() or max()"
    description = "Detects sorted(seq)[0] or sorted(seq)[-1]; min() and max() run in linear O(n) time and O(1) space instead of O(n log n) sort."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "algorithmic", "sorting"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _SortedMinMaxVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _UnnecessaryComprehensionInCallHit:
    lineno: int
    func_name: str
    message: str
    suggestions: list[str]


class _UnnecessaryComprehensionInCallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_UnnecessaryComprehensionInCallHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"sum", "tuple"}
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.ListComp)
        ):
            fn = node.func.id
            self.hits.append(
                _UnnecessaryComprehensionInCallHit(
                    lineno=int(getattr(node, "lineno", 1)),
                    func_name=fn,
                    message=f"List comprehension passed to `{fn}()` allocates an unnecessary intermediate list; generator expression streams items without allocation.",
                    suggestions=[
                        f"Use generator expression `{fn}(... for ... in ...)`.",
                    ],
                )
            )
        self.generic_visit(node)


class UnnecessaryComprehensionInCallRule(Rule):
    id = "plex.unnecessary-comprehension-in-call"
    name = "Unnecessary list comprehension passed to iterable consumer"
    description = "Detects sum([...]) and tuple([...]); passing generator expression avoids intermediate list allocation."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "comprehension", "memory"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _UnnecessaryComprehensionInCallVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.85,
                )


@dataclass
class _MembershipInLiteralListHit:
    lineno: int
    op_repr: str
    message: str
    suggestions: list[str]


class _MembershipInLiteralListVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_MembershipInLiteralListHit] = []

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, comp in zip(node.ops, node.comparators, strict=False):
            if (
                isinstance(op, (ast.In, ast.NotIn))
                and isinstance(comp, ast.List)
                and len(comp.elts) > 0
            ):
                if all(isinstance(elt, ast.Constant) for elt in comp.elts):
                    op_str = "in" if isinstance(op, ast.In) else "not in"
                    self.hits.append(
                        _MembershipInLiteralListHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            op_repr=op_str,
                            message=f"Testing membership `{op_str} [...]` against a list literal allocates a new list on every evaluation and executes in O(n) time.",
                            suggestions=[
                                "Use a set literal `{...}` instead for O(1) lookup and compile-time constant folding.",
                            ],
                        )
                    )
        self.generic_visit(node)


class MembershipInLiteralListRule(Rule):
    id = "plex.membership-in-literal-list"
    name = "Membership test against list literal instead of set"
    description = "Detects `x in [...]` or `x not in [...]`; list literals allocate a new list heap object on every evaluation and perform O(n) search. Using a set literal `{...}` compiles to a constant frozenset with O(1) lookup."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "membership", "collection"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _MembershipInLiteralListVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _UnnecessaryLambdaHit:
    lineno: int
    func_name: str
    message: str
    suggestions: list[str]


class _UnnecessaryLambdaVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_UnnecessaryLambdaHit] = []

    def visit_Lambda(self, node: ast.Lambda) -> None:
        if (
            len(node.args.args) == 1
            and not node.args.vararg
            and not node.args.kwarg
            and not node.args.kwonlyargs
            and not node.args.defaults
        ):
            arg_name = node.args.args[0].arg
            if (
                isinstance(node.body, ast.Call)
                and len(node.body.args) == 1
                and not node.body.keywords
            ):
                if (
                    isinstance(node.body.args[0], ast.Name)
                    and node.body.args[0].id == arg_name
                    and isinstance(node.body.func, (ast.Name, ast.Attribute))
                ):
                    func_name = ast.unparse(node.body.func)
                    self.hits.append(
                        _UnnecessaryLambdaHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            func_name=func_name,
                            message=f"Lambda `lambda {arg_name}: {func_name}({arg_name})` adds redundant call frame overhead.",
                            suggestions=[
                                f"Pass `{func_name}` directly without lambda wrapper.",
                            ],
                        )
                    )
        self.generic_visit(node)


class UnnecessaryLambdaRule(Rule):
    id = "plex.unnecessary-lambda"
    name = "Unnecessary lambda wrapping single function call"
    description = "Detects `lambda x: f(x)` wrappers; passing `f` directly avoids extra Python call frame allocation and function invocation overhead."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "functional", "overhead"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _UnnecessaryLambdaVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _DictGetDefaultNoneHit:
    lineno: int
    message: str
    suggestions: list[str]


class _DictGetDefaultNoneVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_DictGetDefaultNoneHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            has_redundant_none = False
            if (
                len(node.args) == 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value is None
                and not node.keywords
            ):
                has_redundant_none = True
            elif (
                len(node.args) == 1
                and len(node.keywords) == 1
                and node.keywords[0].arg == "default"
                and isinstance(node.keywords[0].value, ast.Constant)
                and node.keywords[0].value.value is None
            ):
                has_redundant_none = True

            if has_redundant_none:
                self.hits.append(
                    _DictGetDefaultNoneHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        message="Explicitly specifying `None` as the default in `dict.get(key, None)` is redundant.",
                        suggestions=[
                            "Omit the second argument: `dict.get(key)`.",
                        ],
                    )
                )
        self.generic_visit(node)


class DictGetDefaultNoneRule(Rule):
    id = "plex.dict-get-default-none"
    name = "Redundant None default in dict.get()"
    description = "Detects `dict.get(key, None)`; None is already the default return value for dict.get(), so passing None explicitly is redundant."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "idiomatic", "dictionary"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _DictGetDefaultNoneVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _UnnecessaryAsyncDefHit:
    lineno: int
    message: str
    suggestions: list[str]


class _AsyncOpChecker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.has_async = False

    def visit_Await(self, node: ast.Await) -> None:
        self.has_async = True

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.has_async = True

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.has_async = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        pass


def _is_abstract_or_override(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Name):
        return decorator.id in {"abstractmethod", "override"}
    if isinstance(decorator, ast.Attribute):
        return decorator.attr in {"abstractmethod", "override"}
    if isinstance(decorator, ast.Call):
        return _is_abstract_or_override(decorator.func)
    return False


def _is_stub_body(body: list[ast.stmt]) -> bool:
    if not body:
        return True
    stmts = body
    if (
        isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    if not stmts:
        return True
    if len(stmts) == 1:
        stmt = stmts[0]
        if isinstance(stmt, ast.Pass):
            return True
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is ...
        ):
            return True
        if isinstance(stmt, ast.Raise):
            if isinstance(stmt.exc, ast.Name) and stmt.exc.id in {
                "NotImplementedError",
                "NotImplemented",
            }:
                return True
            if (
                isinstance(stmt.exc, ast.Call)
                and isinstance(stmt.exc.func, ast.Name)
                and stmt.exc.func.id in {"NotImplementedError", "NotImplemented"}
            ):
                return True
    return False


class _UnnecessaryAsyncDefVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_UnnecessaryAsyncDefHit] = []

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if any(_is_abstract_or_override(d) for d in node.decorator_list):
            self.generic_visit(node)
            return

        if _is_stub_body(node.body):
            self.generic_visit(node)
            return

        checker = _AsyncOpChecker()
        for stmt in node.body:
            checker.visit(stmt)
            if checker.has_async:
                break

        if not checker.has_async:
            self.hits.append(
                _UnnecessaryAsyncDefHit(
                    lineno=int(getattr(node, "lineno", 1)),
                    message=f"Function '{node.name}' is defined as 'async def' but contains no 'await', 'async with', or 'async for' operations.",
                    suggestions=[
                        f"Define '{node.name}' as a synchronous function ('def {node.name}(...):') to eliminate coroutine allocation and event loop scheduling overhead.",
                    ],
                )
            )

        self.generic_visit(node)


class UnnecessaryAsyncDefRule(Rule):
    id = "plex.unnecessary-async-def"
    name = "Unnecessary async def coroutine"
    description = "Detects `async def` coroutines containing no await/async with/async for expressions, which incur coroutine allocation and event loop overhead."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "async", "concurrency"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _UnnecessaryAsyncDefVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _UnnecessaryEnumerateHit:
    lineno: int
    message: str
    suggestions: list[str]


class _NameLoadChecker(ast.NodeVisitor):
    def __init__(self, target_id: str) -> None:
        self.target_id = target_id
        self.found = False

    def visit_Name(self, node: ast.Name) -> None:
        if node.id == self.target_id and isinstance(node.ctx, ast.Load):
            self.found = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        pass


class _UnnecessaryEnumerateVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_UnnecessaryEnumerateHit] = []

    def _check_loop(self, node: ast.For | ast.AsyncFor) -> None:
        if isinstance(node.iter, ast.Call):
            call = node.iter
            if (
                isinstance(call.func, ast.Name)
                and call.func.id == "enumerate"
                and len(call.args) >= 1
            ):
                if isinstance(node.target, (ast.Tuple, ast.List)) and len(node.target.elts) == 2:
                    idx_node, _ = node.target.elts
                    if isinstance(idx_node, ast.Name):
                        unused = False
                        if idx_node.id == "_":
                            unused = True
                        else:
                            checker = _NameLoadChecker(idx_node.id)
                            for stmt in node.body:
                                checker.visit(stmt)
                            for stmt in node.orelse:
                                checker.visit(stmt)
                            if not checker.found:
                                unused = True

                        if unused:
                            self.hits.append(
                                _UnnecessaryEnumerateHit(
                                    lineno=int(getattr(node, "lineno", 1)),
                                    message=f"Loop iterates with 'enumerate()' but index variable '{idx_node.id}' is never used.",
                                    suggestions=[
                                        "Iterate directly over the sequence without 'enumerate()' to eliminate tuple allocations and counter tracking.",
                                    ],
                                )
                            )

    def visit_For(self, node: ast.For) -> None:
        self._check_loop(node)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._check_loop(node)
        self.generic_visit(node)


class UnnecessaryEnumerateRule(Rule):
    id = "plex.unnecessary-enumerate"
    name = "Unused index in enumerate() loop"
    description = "Detects `for idx, item in enumerate(...)` where `idx` is never referenced, incurring unnecessary tuple construction and counter tracking."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "collections", "loops"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _UnnecessaryEnumerateVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _DictItemsValueUnusedHit:
    lineno: int
    message: str
    suggestions: list[str]


class _DictItemsValueUnusedVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_DictItemsValueUnusedHit] = []

    def _check_loop(self, node: ast.For | ast.AsyncFor) -> None:
        if isinstance(node.iter, ast.Call):
            call = node.iter
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "items"
                and len(call.args) == 0
                and not call.keywords
            ):
                if isinstance(node.target, (ast.Tuple, ast.List)) and len(node.target.elts) == 2:
                    key_node, val_node = node.target.elts
                    if isinstance(key_node, ast.Name) and isinstance(val_node, ast.Name):
                        unused = False
                        if val_node.id == "_":
                            unused = True
                        else:
                            checker = _NameLoadChecker(val_node.id)
                            for stmt in node.body:
                                checker.visit(stmt)
                            for stmt in node.orelse:
                                checker.visit(stmt)
                            if not checker.found:
                                unused = True

                        if unused:
                            self.hits.append(
                                _DictItemsValueUnusedHit(
                                    lineno=int(getattr(node, "lineno", 1)),
                                    message=f"Loop iterates over '.items()' but value variable '{val_node.id}' is never used.",
                                    suggestions=[
                                        "Iterate directly over the dictionary ('for key in d:') to avoid 2-tuple allocations and value lookups.",
                                    ],
                                )
                            )

    def visit_For(self, node: ast.For) -> None:
        self._check_loop(node)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._check_loop(node)
        self.generic_visit(node)


class DictItemsValueUnusedRule(Rule):
    id = "plex.dict-items-value-unused"
    name = "Unused value in dict.items() iteration"
    description = "Detects `for key, value in d.items()` loops where `value` is unused, incurring unnecessary 2-tuple allocations on every iteration."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "collections", "loops", "dictionary"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _DictItemsValueUnusedVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _DictItemsComprehensionToCopyHit:
    lineno: int
    message: str
    suggestions: list[str]


class _DictItemsComprehensionToCopyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_DictItemsComprehensionToCopyHit] = []

    def visit_DictComp(self, node: ast.DictComp) -> None:
        if (
            len(node.generators) == 1
            and not node.generators[0].ifs
            and not node.generators[0].is_async
        ):
            gen = node.generators[0]
            if (
                isinstance(gen.target, (ast.Tuple, ast.List))
                and len(gen.target.elts) == 2
                and isinstance(gen.target.elts[0], ast.Name)
                and isinstance(gen.target.elts[1], ast.Name)
            ):
                tk, tv = gen.target.elts[0].id, gen.target.elts[1].id
                if (
                    isinstance(node.key, ast.Name)
                    and node.key.id == tk
                    and isinstance(node.value, ast.Name)
                    and node.value.id == tv
                ):
                    if (
                        isinstance(gen.iter, ast.Call)
                        and isinstance(gen.iter.func, ast.Attribute)
                        and gen.iter.func.attr == "items"
                        and not gen.iter.args
                        and not gen.iter.keywords
                    ):
                        self.hits.append(
                            _DictItemsComprehensionToCopyHit(
                                lineno=int(getattr(node, "lineno", 1)),
                                message="Dictionary comprehension '{k: v for k, v in d.items()}' duplicates dictionary; use 'd.copy()' instead.",
                                suggestions=[
                                    "Use 'd.copy()' to execute a direct C-level shallow copy ~8.5x faster.",
                                ],
                            )
                        )
        self.generic_visit(node)


class DictItemsComprehensionToCopyRule(Rule):
    id = "plex.dict-items-comprehension-to-copy"
    name = "Dict comprehension duplicating dict.items()"
    description = "Detects `{k: v for k, v in d.items()}` which can be replaced with `d.copy()`, avoiding Python loop overhead and running ~8.5x faster."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "dictionary", "collections"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _DictItemsComprehensionToCopyVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _RedundantCollectionCallHit:
    lineno: int
    message: str
    suggestions: list[str]


class _RedundantCollectionCallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_RedundantCollectionCallHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"list", "set", "tuple", "dict", "sorted"}
            and len(node.args) == 1
            and not node.keywords
        ):
            inner = node.args[0]
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == node.func.id
                and len(inner.args) == 1
                and not inner.keywords
            ):
                fn = node.func.id
                self.hits.append(
                    _RedundantCollectionCallHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        message=f"`{fn}({fn}(...))` redundantly converts collection twice.",
                        suggestions=[
                            f"Simplify to `{fn}(...)` to eliminate redundant intermediate heap allocations.",
                        ],
                    )
                )
        self.generic_visit(node)


class RedundantCollectionCallRule(Rule):
    id = "plex.redundant-collection-call"
    name = "Redundant nested collection constructor call"
    description = "Detects redundant nested collection calls like `list(list(x))` or `set(set(x))` that allocate redundant intermediate memory."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "collections", "memory"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _RedundantCollectionCallVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _RedundantFStringHit:
    lineno: int
    message: str
    suggestions: list[str]


class _RedundantFStringVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_RedundantFStringHit] = []

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if all(isinstance(elt, ast.Constant) and isinstance(elt.value, str) for elt in node.values):
            self.hits.append(
                _RedundantFStringHit(
                    lineno=int(getattr(node, "lineno", 1)),
                    message="Redundant f-string: contains no formatted expressions and should be a standard string literal.",
                    suggestions=[
                        "Remove the 'f' prefix: replace with a standard string literal to avoid runtime formatting overhead.",
                    ],
                )
            )
        self.generic_visit(node)


class RedundantFStringRule(Rule):
    id = "plex.redundant-fstring"
    name = "Redundant f-string with no formatted expressions"
    description = "Detects f-strings that contain no interpolated expressions and can be written as plain string literals."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "strings", "idiomatic"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _RedundantFStringVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _StrStartswithTupleHit:
    lineno: int
    method_name: str
    target_repr: str
    message: str
    suggestions: list[str]


class _StrStartswithTupleVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_StrStartswithTupleHit] = []

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if isinstance(node.op, ast.Or):
            counts: dict[tuple[str, str], int] = {}
            first_lines: dict[tuple[str, str], int] = {}
            for val in node.values:
                if (
                    isinstance(val, ast.Call)
                    and isinstance(val.func, ast.Attribute)
                    and val.func.attr in {"startswith", "endswith"}
                    and len(val.args) == 1
                    and not val.keywords
                    and isinstance(val.func.value, (ast.Name, ast.Attribute))
                ):
                    target_repr = ast.unparse(val.func.value)
                    key = (val.func.attr, target_repr)
                    counts[key] = counts.get(key, 0) + 1
                    if key not in first_lines:
                        first_lines[key] = int(getattr(val, "lineno", 1))

            for (method_name, target_repr), count in counts.items():
                if count >= 2:
                    self.hits.append(
                        _StrStartswithTupleHit(
                            lineno=first_lines[(method_name, target_repr)],
                            method_name=method_name,
                            target_repr=target_repr,
                            message=f"Multiple `{target_repr}.{method_name}()` calls chained with `or` can be combined into a single tuple check.",
                            suggestions=[
                                f"Pass a tuple of prefixes/suffixes to `{target_repr}.{method_name}((...))` to avoid repeated method dispatches.",
                            ],
                        )
                    )
        self.generic_visit(node)


class StrStartswithTupleRule(Rule):
    id = "plex.str-startswith-tuple"
    name = "Multiple startswith() or endswith() calls can use tuple argument"
    description = "Detects multiple startswith() or endswith() calls on the same string joined with 'or' and suggests combining them into a single call with a tuple."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "strings", "idiomatic"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _StrStartswithTupleVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _DictFromkeysHit:
    lineno: int
    message: str
    suggestions: list[str]


class _DictFromkeysVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_DictFromkeysHit] = []

    def visit_DictComp(self, node: ast.DictComp) -> None:
        if (
            len(node.generators) == 1
            and not node.generators[0].ifs
            and isinstance(node.generators[0].target, ast.Name)
            and isinstance(node.key, ast.Name)
            and node.key.id == node.generators[0].target.id
            and isinstance(node.value, ast.Constant)
        ):
            self.hits.append(
                _DictFromkeysHit(
                    lineno=int(getattr(node, "lineno", 1)),
                    message="Dictionary comprehension with constant value can use `dict.fromkeys()` for faster C-level hash table allocation.",
                    suggestions=[
                        "Replace with `dict.fromkeys(keys, value)` (or `dict.fromkeys(keys)` if default is `None`).",
                    ],
                )
            )
        self.generic_visit(node)


class DictFromkeysRule(Rule):
    id = "plex.dict-fromkeys"
    name = "Dictionary comprehension with constant value can use dict.fromkeys()"
    description = "Detects dictionary comprehensions of the form '{k: <constant> for k in keys}' and suggests 'dict.fromkeys(keys, <constant>)' for faster C-level hash table allocation."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "collections", "idiomatic"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _DictFromkeysVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _ItertoolsChainFromIterableHit:
    lineno: int
    message: str
    suggestions: list[str]


class _ItertoolsChainFromIterableVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_ItertoolsChainFromIterableHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        is_chain = False
        if isinstance(node.func, ast.Attribute) and node.func.attr == "chain":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "itertools":
                is_chain = True
        elif isinstance(node.func, ast.Name) and node.func.id == "chain":
            is_chain = True

        if (
            is_chain
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Starred)
            and not node.keywords
        ):
            self.hits.append(
                _ItertoolsChainFromIterableHit(
                    lineno=int(getattr(node, "lineno", 1)),
                    message="`chain(*iterables)` unpacks all items onto the call stack; use `chain.from_iterable(iterables)` to stream elements lazily without stack overhead.",
                    suggestions=[
                        "Replace with `chain.from_iterable(iterables)` (or `itertools.chain.from_iterable(iterables)`).",
                    ],
                )
            )
        self.generic_visit(node)


class ItertoolsChainFromIterableRule(Rule):
    id = "plex.itertools-chain-from-iterable"
    name = "itertools.chain(*iterables) can use itertools.chain.from_iterable()"
    description = "Detects 'itertools.chain(*iterables)' unpacking an iterable and suggests 'itertools.chain.from_iterable(iterables)' to avoid argument tuple allocation."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "collections", "memory", "idiomatic"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _ItertoolsChainFromIterableVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _TryExceptDictGetHit:
    lineno: int
    dict_name: str
    key_name: str
    target_var: str
    message: str
    suggestions: list[str]


class _TryExceptDictGetVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_TryExceptDictGetHit] = []

    def visit_Try(self, node: ast.Try) -> None:
        if (
            len(node.body) == 1
            and isinstance(node.body[0], ast.Assign)
            and len(node.body[0].targets) == 1
            and isinstance(node.body[0].targets[0], ast.Name)
            and isinstance(node.body[0].value, ast.Subscript)
            and len(node.handlers) == 1
            and len(node.handlers[0].body) == 1
            and not node.orelse
            and not node.finalbody
        ):
            handler = node.handlers[0]
            if (
                isinstance(handler.type, ast.Name)
                and handler.type.id == "KeyError"
                and isinstance(handler.body[0], ast.Assign)
                and len(handler.body[0].targets) == 1
                and isinstance(handler.body[0].targets[0], ast.Name)
            ):
                t_try = node.body[0].targets[0].id
                t_except = handler.body[0].targets[0].id
                if t_try == t_except:
                    sub = node.body[0].value
                    dict_name = ast.unparse(sub.value)
                    key_name = ast.unparse(sub.slice)
                    self.hits.append(
                        _TryExceptDictGetHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            dict_name=dict_name,
                            key_name=key_name,
                            target_var=t_try,
                            message=f"`try ... except KeyError` to set a fallback for `{dict_name}[{key_name}]` is slower than `{dict_name}.get()`.",
                            suggestions=[
                                f"Replace with `{t_try} = {dict_name}.get({key_name}, default)` to avoid exception handling overhead.",
                            ],
                        )
                    )
        self.generic_visit(node)


class TryExceptDictGetRule(Rule):
    id = "plex.try-except-dict-get"
    name = "try-except KeyError instead of dict.get()"
    description = "Detects 'try: var = d[k] except KeyError: var = default' patterns and suggests 'd.get(k, default)' to eliminate expensive exception handling."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "exceptions", "dictionary", "lookup"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _TryExceptDictGetVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _TryExceptPopDefaultHit:
    lineno: int
    dict_name: str
    key_name: str
    message: str
    suggestions: list[str]


class _TryExceptPopDefaultVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_TryExceptPopDefaultHit] = []

    def visit_Try(self, node: ast.Try) -> None:
        if (
            len(node.body) == 1
            and len(node.handlers) == 1
            and not node.orelse
            and not node.finalbody
        ):
            handler = node.handlers[0]
            if isinstance(handler.type, ast.Name) and handler.type.id == "KeyError":
                body_stmt = node.body[0]
                handler_stmt = handler.body[0] if handler.body else None

                if (
                    isinstance(body_stmt, ast.Expr)
                    and isinstance(body_stmt.value, ast.Call)
                    and isinstance(body_stmt.value.func, ast.Attribute)
                    and body_stmt.value.func.attr == "pop"
                    and len(body_stmt.value.args) == 1
                    and len(handler.body) == 1
                    and isinstance(handler_stmt, ast.Pass)
                ):
                    dict_name = ast.unparse(body_stmt.value.func.value)
                    key_name = ast.unparse(body_stmt.value.args[0])
                    self.hits.append(
                        _TryExceptPopDefaultHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            dict_name=dict_name,
                            key_name=key_name,
                            message=f"`try: {dict_name}.pop({key_name}) except KeyError: pass` can use default argument `{dict_name}.pop({key_name}, None)`.",
                            suggestions=[
                                f"Use `{dict_name}.pop({key_name}, None)` to avoid exception unwinding on missing keys.",
                            ],
                        )
                    )
                elif (
                    isinstance(body_stmt, ast.Assign)
                    and len(body_stmt.targets) == 1
                    and isinstance(body_stmt.targets[0], ast.Name)
                    and isinstance(body_stmt.value, ast.Call)
                    and isinstance(body_stmt.value.func, ast.Attribute)
                    and body_stmt.value.func.attr == "pop"
                    and len(body_stmt.value.args) == 1
                    and len(handler.body) == 1
                    and isinstance(handler_stmt, ast.Assign)
                    and len(handler_stmt.targets) == 1
                    and isinstance(handler_stmt.targets[0], ast.Name)
                    and body_stmt.targets[0].id == handler_stmt.targets[0].id
                ):
                    target_var = body_stmt.targets[0].id
                    dict_name = ast.unparse(body_stmt.value.func.value)
                    key_name = ast.unparse(body_stmt.value.args[0])
                    self.hits.append(
                        _TryExceptPopDefaultHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            dict_name=dict_name,
                            key_name=key_name,
                            message=f"`try ... except KeyError` around `{dict_name}.pop({key_name})` can use `{dict_name}.pop({key_name}, default)`.",
                            suggestions=[
                                f"Use `{target_var} = {dict_name}.pop({key_name}, default)` to avoid exception unwinding.",
                            ],
                        )
                    )
        self.generic_visit(node)


class TryExceptPopDefaultRule(Rule):
    id = "plex.try-except-pop-default"
    name = "try-except KeyError around dict.pop() instead of default argument"
    description = "Detects 'try: d.pop(k) except KeyError: pass' or assignment fallback and suggests 'd.pop(k, default)'."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "exceptions", "dictionary"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _TryExceptPopDefaultVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _IfPassElseInvertHit:
    lineno: int
    message: str
    suggestions: list[str]


class _IfPassElseInvertVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_IfPassElseInvertHit] = []

    def visit_If(self, node: ast.If) -> None:
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass) and len(node.orelse) > 0:
            self.hits.append(
                _IfPassElseInvertHit(
                    lineno=int(getattr(node, "lineno", 1)),
                    message="`if ...: pass else: ...` contains an empty branch; inverting the condition simplifies control flow.",
                    suggestions=[
                        "Invert condition (e.g. `if not condition: ...`) and remove the empty `pass` branch.",
                    ],
                )
            )
        self.generic_visit(node)


class IfPassElseInvertRule(Rule):
    id = "plex.if-pass-else-invert"
    name = "Empty if-pass-else branch can invert condition"
    description = "Detects 'if condition: pass else: body' and suggests inverting the condition to eliminate the empty branch and jump opcodes."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "control-flow", "idiomatic"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _IfPassElseInvertVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


REGEX_METACHARACTERS = set(r".*+?^${}()|[]\\")


@dataclass
class _IsinstanceTupleHit:
    lineno: int
    target_repr: str
    message: str
    suggestions: list[str]


class _IsinstanceTupleVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_IsinstanceTupleHit] = []

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if isinstance(node.op, ast.Or):
            counts: dict[str, int] = {}
            first_lines: dict[str, int] = {}
            for val in node.values:
                if (
                    isinstance(val, ast.Call)
                    and isinstance(val.func, ast.Name)
                    and val.func.id == "isinstance"
                    and len(val.args) == 2
                    and not val.keywords
                ):
                    target_repr = ast.unparse(val.args[0])
                    counts[target_repr] = counts.get(target_repr, 0) + 1
                    if target_repr not in first_lines:
                        first_lines[target_repr] = int(getattr(val, "lineno", 1))

            for target_repr, count in counts.items():
                if count >= 2:
                    self.hits.append(
                        _IsinstanceTupleHit(
                            lineno=first_lines[target_repr],
                            target_repr=target_repr,
                            message=f"Multiple `isinstance({target_repr}, ...)` checks chained with `or` can be combined into a single tuple check.",
                            suggestions=[
                                f"Pass a tuple of types to `isinstance({target_repr}, (...))` for faster type dispatch.",
                            ],
                        )
                    )
        self.generic_visit(node)


class IsinstanceTupleRule(Rule):
    id = "plex.isinstance-tuple"
    name = "Multiple isinstance() checks can use tuple argument"
    description = "Detects multiple isinstance(x, T) checks on the same target chained with 'or' and suggests combining them into isinstance(x, (T1, T2))."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "types", "idiomatic"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _IsinstanceTupleVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _ItertoolsIsliceHit:
    lineno: int
    container: str
    message: str
    suggestions: list[str]


class _ItertoolsIsliceVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_ItertoolsIsliceHit] = []

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in {"list", "tuple"}
            and len(node.value.args) == 1
            and not node.value.keywords
            and isinstance(node.slice, ast.Slice)
            and node.slice.step is None
        ):
            lower = node.slice.lower
            upper = node.slice.upper
            is_zero_start = lower is None or (isinstance(lower, ast.Constant) and lower.value == 0)
            if is_zero_start and upper is not None:
                is_negative = False
                if isinstance(upper, ast.UnaryOp) and isinstance(upper.op, ast.USub):
                    is_negative = True
                elif (
                    isinstance(upper, ast.Constant)
                    and isinstance(upper.value, (int, float))
                    and upper.value < 0
                ):
                    is_negative = True

                if not is_negative:
                    container = node.value.func.id
                    self.hits.append(
                        _ItertoolsIsliceHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            container=container,
                            message=f"Slicing `{container}(seq)[:n]` eagerly realizes the entire collection; use `itertools.islice(seq, n)` to avoid full allocation.",
                            suggestions=[
                                f"Replace with `{container}(itertools.islice(seq, n))` to consume only the requested elements lazily.",
                            ],
                        )
                    )
        self.generic_visit(node)


class ItertoolsIsliceRule(Rule):
    id = "plex.itertools-islice"
    name = "Slicing list() or tuple() of iterable instead of itertools.islice()"
    description = "Detects list(seq)[:n] and tuple(seq)[:n] patterns that realize entire sequences in memory before slicing; itertools.islice() consumes lazily with O(1) allocation."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "memory", "iterators", "itertools"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _ItertoolsIsliceVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _ReSubLiteralHit:
    lineno: int
    pattern: str
    message: str
    suggestions: list[str]


class _ReSubLiteralVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_ReSubLiteralHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        is_re_sub = False
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "sub"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
        ):
            is_re_sub = True
        elif isinstance(node.func, ast.Name) and node.func.id == "sub":
            is_re_sub = True

        if is_re_sub and len(node.args) >= 3:
            has_flags = any(kw.arg == "flags" for kw in node.keywords) or len(node.args) >= 5
            if not has_flags:
                pat_arg = node.args[0]
                repl_arg = node.args[1]
                if (
                    isinstance(pat_arg, ast.Constant)
                    and isinstance(pat_arg.value, str)
                    and len(pat_arg.value) > 0
                    and not any(ch in REGEX_METACHARACTERS for ch in pat_arg.value)
                    and isinstance(repl_arg, ast.Constant)
                    and isinstance(repl_arg.value, str)
                    and "\\" not in repl_arg.value
                ):
                    self.hits.append(
                        _ReSubLiteralHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            pattern=pat_arg.value,
                            message=f"`re.sub()` with literal pattern {pat_arg.value!r} incurs regex compilation overhead; use `str.replace()` for ~3x faster execution.",
                            suggestions=[
                                f"Replace with `s.replace({pat_arg.value!r}, {repl_arg.value!r})`.",
                            ],
                        )
                    )
        self.generic_visit(node)


class ReSubLiteralRule(Rule):
    id = "plex.re-sub-literal"
    name = "re.sub() with literal string pattern instead of str.replace()"
    description = "Detects re.sub() calls with literal patterns and replacements lacking regex metacharacters; str.replace() bypasses the regex engine and runs 3x faster."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "regex", "strings"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _ReSubLiteralVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


BUILTIN_RULES = [
    DbCallInLoopRule(),
    JsonInLoopRule(),
    PandasRowIterationRule(),
    RegexCatastropheRule(),
    HttpCallInLoopRule(),
    StringConcatInLoopRule(),
    UnboundedFileIoRule(),
    UncompiledRegexInLoopRule(),
    LinearSearchInLoopRule(),
    SyncIoInAsyncRule(),
    DeepcopyInLoopRule(),
    RepeatedSortInLoopRule(),
    RedundantComprehensionRule(),
    UnnecessaryDictKeysRule(),
    UnnecessaryLenRule(),
    MathPowVsOperatorRule(),
    DictGetFallbackRule(),
    MutableDefaultArgRule(),
    ManualListExtendRule(),
    UnclosedResourceRule(),
    ShortCircuitComprehensionRule(),
    SortedMinMaxRule(),
    UnnecessaryComprehensionInCallRule(),
    MembershipInLiteralListRule(),
    UnnecessaryLambdaRule(),
    DictGetDefaultNoneRule(),
    UnnecessaryAsyncDefRule(),
    UnnecessaryEnumerateRule(),
    DictItemsValueUnusedRule(),
    DictItemsComprehensionToCopyRule(),
    RedundantCollectionCallRule(),
    RedundantFStringRule(),
    StrStartswithTupleRule(),
    DictFromkeysRule(),
    ItertoolsChainFromIterableRule(),
    TryExceptDictGetRule(),
    TryExceptPopDefaultRule(),
    IfPassElseInvertRule(),
    IsinstanceTupleRule(),
    ItertoolsIsliceRule(),
    ReSubLiteralRule(),
]


@dataclass
class _StrRemoveprefixSuffixHit:
    lineno: int
    method_name: str
    target_str: str
    prefix_str: str
    message: str
    suggestions: list[str]


class _StrRemoveprefixSuffixVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_StrRemoveprefixSuffixHit] = []

    def visit_If(self, node: ast.If) -> None:
        if (
            len(node.body) == 1
            and not node.orelse
            and isinstance(node.test, ast.Call)
            and isinstance(node.test.func, ast.Attribute)
            and node.test.func.attr in {"startswith", "endswith"}
            and len(node.test.args) == 1
            and not node.test.keywords
        ):
            attr = node.test.func.attr
            s_test = ast.unparse(node.test.func.value)
            p_test = ast.unparse(node.test.args[0])
            stmt = node.body[0]
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and ast.unparse(stmt.targets[0]) == s_test
                and isinstance(stmt.value, ast.Subscript)
                and ast.unparse(stmt.value.value) == s_test
                and isinstance(stmt.value.slice, ast.Slice)
                and stmt.value.slice.step is None
            ):
                sl = stmt.value.slice
                matched = False
                method = "removeprefix" if attr == "startswith" else "removesuffix"
                if attr == "startswith":
                    if (
                        sl.upper is None
                        and isinstance(sl.lower, ast.Call)
                        and isinstance(sl.lower.func, ast.Name)
                        and sl.lower.func.id == "len"
                        and len(sl.lower.args) == 1
                        and ast.unparse(sl.lower.args[0]) == p_test
                    ):
                        matched = True
                elif attr == "endswith":
                    if (
                        sl.lower is None
                        and isinstance(sl.upper, ast.UnaryOp)
                        and isinstance(sl.upper.op, ast.USub)
                        and isinstance(sl.upper.operand, ast.Call)
                        and isinstance(sl.upper.operand.func, ast.Name)
                        and sl.upper.operand.func.id == "len"
                        and len(sl.upper.operand.args) == 1
                        and ast.unparse(sl.upper.operand.args[0]) == p_test
                    ):
                        matched = True

                if matched:
                    self.hits.append(
                        _StrRemoveprefixSuffixHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            method_name=method,
                            target_str=s_test,
                            prefix_str=p_test,
                            message=f"Manual string slicing after `{attr}()` can be replaced with `{s_test}.{method}({p_test})` for ~2x faster execution.",
                            suggestions=[
                                f"Replace with `{s_test} = {s_test}.{method}({p_test})`.",
                            ],
                        )
                    )
        self.generic_visit(node)


class StrRemoveprefixSuffixRule(Rule):
    id = "plex.str-removeprefix-suffix"
    name = "Manual prefix or suffix slicing instead of removeprefix/removesuffix"
    description = "Detects 'if s.startswith(p): s = s[len(p):]' or 'if s.endswith(suf): s = s[:-len(suf)]' and suggests s.removeprefix(p) or s.removesuffix(suf)."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "strings", "idiomatic"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _StrRemoveprefixSuffixVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _MathLogBaseHit:
    lineno: int
    base: int
    target_func: str
    message: str
    suggestions: list[str]


class _MathLogBaseVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_MathLogBaseHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        is_math_log = False
        prefix = "math."
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "log"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "math"
        ):
            is_math_log = True
            prefix = "math."
        elif isinstance(node.func, ast.Name) and node.func.id == "log":
            is_math_log = True
            prefix = ""

        if is_math_log and len(node.args) == 2 and not node.keywords:
            base_arg = node.args[1]
            if (
                isinstance(base_arg, ast.Constant)
                and isinstance(base_arg.value, int)
                and base_arg.value in (2, 10)
            ):
                base_val = base_arg.value
                target_func = f"{prefix}log2" if base_val == 2 else f"{prefix}log10"
                self.hits.append(
                    _MathLogBaseHit(
                        lineno=int(getattr(node, "lineno", 1)),
                        base=base_val,
                        target_func=target_func,
                        message=f"`math.log(x, {base_val})` can be replaced with `{target_func}(x)` for 2x faster hardware-accelerated evaluation.",
                        suggestions=[
                            f"Use specialized `{target_func}(...)` to avoid base-change arithmetic division.",
                        ],
                    )
                )
        self.generic_visit(node)


class MathLogBaseRule(Rule):
    id = "plex.math-log-base"
    name = "math.log() with base 2 or 10 instead of math.log2() or math.log10()"
    description = "Detects math.log(x, 2) and math.log(x, 10) calls; specialized math.log2() and math.log10() use direct C/FPU instructions, running 2x faster."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "math", "numerical"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _MathLogBaseVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _TryExceptNextDefaultHit:
    lineno: int
    var_name: str
    it_name: str
    message: str
    suggestions: list[str]


class _TryExceptNextDefaultVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_TryExceptNextDefaultHit] = []

    def visit_Try(self, node: ast.Try) -> None:
        if (
            len(node.body) == 1
            and len(node.handlers) == 1
            and not node.orelse
            and not node.finalbody
        ):
            handler = node.handlers[0]
            if (
                handler.type is not None
                and isinstance(handler.type, ast.Name)
                and handler.type.id == "StopIteration"
                and len(handler.body) == 1
            ):
                body_stmt = node.body[0]
                handler_stmt = handler.body[0]
                if (
                    isinstance(body_stmt, ast.Assign)
                    and len(body_stmt.targets) == 1
                    and isinstance(body_stmt.targets[0], ast.Name)
                    and isinstance(body_stmt.value, ast.Call)
                    and isinstance(body_stmt.value.func, ast.Name)
                    and body_stmt.value.func.id == "next"
                    and len(body_stmt.value.args) == 1
                    and not body_stmt.value.keywords
                    and isinstance(handler_stmt, ast.Assign)
                    and len(handler_stmt.targets) == 1
                    and isinstance(handler_stmt.targets[0], ast.Name)
                    and body_stmt.targets[0].id == handler_stmt.targets[0].id
                ):
                    var_name = body_stmt.targets[0].id
                    it_name = ast.unparse(body_stmt.value.args[0])
                    self.hits.append(
                        _TryExceptNextDefaultHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            var_name=var_name,
                            it_name=it_name,
                            message=f"`try ... except StopIteration` around `next({it_name})` can use `next({it_name}, default)`.",
                            suggestions=[
                                f"Use `{var_name} = next({it_name}, default)` to avoid exception unwinding overhead.",
                            ],
                        )
                    )
        self.generic_visit(node)


class TryExceptNextDefaultRule(Rule):
    id = "plex.try-except-next-default"
    name = "try-except StopIteration around next() instead of default argument"
    description = "Detects 'try: v = next(it) except StopIteration: v = default' and suggests 'v = next(it, default)' to avoid exception frame unwinding."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "iterators", "exceptions"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _TryExceptNextDefaultVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _StrSplitMaxsplitHit:
    lineno: int
    expr_repr: str
    message: str
    suggestions: list[str]


def _get_int_subscript_index(slice_node: ast.AST) -> int | None:
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, int):
        return slice_node.value
    if (
        isinstance(slice_node, ast.UnaryOp)
        and isinstance(slice_node.op, ast.USub)
        and isinstance(slice_node.operand, ast.Constant)
        and isinstance(slice_node.operand.value, int)
    ):
        return -slice_node.operand.value
    return None


class _StrSplitMaxsplitVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_StrSplitMaxsplitHit] = []

    def visit_Subscript(self, node: ast.Subscript) -> None:
        idx = _get_int_subscript_index(node.slice)
        if (
            idx is not None
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
        ):
            method = node.value.func.attr
            if (method == "split" and idx == 0) or (method == "rsplit" and idx == -1):
                has_maxsplit = any(kw.arg == "maxsplit" for kw in node.value.keywords)
                if not has_maxsplit and len(node.value.args) <= 1:
                    target_repr = ast.unparse(node.value.func.value)
                    call_repr = ast.unparse(node)
                    if len(node.value.args) == 0:
                        suggested = f"{target_repr}.{method}(maxsplit=1)[{idx}]"
                    else:
                        sep_repr = ast.unparse(node.value.args[0])
                        suggested = f"{target_repr}.{method}({sep_repr}, 1)[{idx}]"
                    self.hits.append(
                        _StrSplitMaxsplitHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            expr_repr=call_repr,
                            message=f"`{call_repr}` splits entire string into a list without `maxsplit`; providing `maxsplit=1` avoids allocating all tokens.",
                            suggestions=[
                                f"Pass `maxsplit=1` (e.g. `{suggested}`) to avoid token list allocation.",
                            ],
                        )
                    )
        self.generic_visit(node)


class StrSplitMaxsplitRule(Rule):
    id = "plex.str-split-maxsplit"
    name = "Unbounded string split before indexing"
    description = "Detects s.split(...)[0] or s.rsplit(...)[-1] without maxsplit; supplying maxsplit avoids allocating and traversing a list of all tokens."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "string", "allocation"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _StrSplitMaxsplitVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _FilterTruthyHit:
    lineno: int
    comp_repr: str
    message: str
    suggestions: list[str]


class _FilterTruthyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_FilterTruthyHit] = []

    def visit_ListComp(self, node: ast.ListComp) -> None:
        if (
            len(node.generators) == 1
            and not node.generators[0].is_async
            and isinstance(node.elt, ast.Name)
            and isinstance(node.generators[0].target, ast.Name)
            and node.elt.id == node.generators[0].target.id
            and len(node.generators[0].ifs) == 1
            and isinstance(node.generators[0].ifs[0], ast.Name)
            and node.generators[0].ifs[0].id == node.elt.id
        ):
            comp_repr = ast.unparse(node)
            iter_repr = ast.unparse(node.generators[0].iter)
            self.hits.append(
                _FilterTruthyHit(
                    lineno=int(getattr(node, "lineno", 1)),
                    comp_repr=comp_repr,
                    message=f"`{comp_repr}` filters truthy elements via list comprehension; `list(filter(None, {iter_repr}))` executes truthiness filtering in C for ~1.5x speedup.",
                    suggestions=[
                        f"Replace with `list(filter(None, {iter_repr}))` to leverage fast C-level truthiness filtering.",
                    ],
                )
            )
        self.generic_visit(node)


class FilterTruthyRule(Rule):
    id = "plex.filter-truthy"
    name = "Comprehension truthiness filtering instead of filter(None, ...)"
    description = "Detects [x for x in seq if x]; list(filter(None, seq)) executes truthiness filtering in C with 1.5x speedup and lower memory overhead."
    default_severity = "low"
    stability = "stable"
    tags = ["performance", "comprehension", "builtins"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _FilterTruthyVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


@dataclass
class _AllInSupersetHit:
    lineno: int
    call_repr: str
    message: str
    suggestions: list[str]


class _AllInSupersetVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_AllInSupersetHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "all"
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.GeneratorExp)
        ):
            gen_exp = node.args[0]
            if (
                len(gen_exp.generators) == 1
                and not gen_exp.generators[0].is_async
                and not gen_exp.generators[0].ifs
                and isinstance(gen_exp.generators[0].target, ast.Name)
            ):
                target_id = gen_exp.generators[0].target.id
                if (
                    isinstance(gen_exp.elt, ast.Compare)
                    and len(gen_exp.elt.ops) == 1
                    and isinstance(gen_exp.elt.ops[0], ast.In)
                    and len(gen_exp.elt.comparators) == 1
                    and isinstance(gen_exp.elt.left, ast.Name)
                    and gen_exp.elt.left.id == target_id
                ):
                    b_node = gen_exp.elt.comparators[0]
                    a_node = gen_exp.generators[0].iter
                    call_repr = ast.unparse(node)
                    b_repr = ast.unparse(b_node)
                    a_repr = ast.unparse(a_node)
                    if isinstance(b_node, (ast.Set, ast.SetComp)) or (
                        isinstance(b_node, ast.Call)
                        and isinstance(b_node.func, ast.Name)
                        and b_node.func.id == "set"
                    ):
                        suggested = f"{b_repr}.issuperset({a_repr})"
                    else:
                        suggested = f"set({b_repr}).issuperset({a_repr})"
                    self.hits.append(
                        _AllInSupersetHit(
                            lineno=int(getattr(node, "lineno", 1)),
                            call_repr=call_repr,
                            message=f"`{call_repr}` can be replaced with `{suggested}`, avoiding generator creation and bytecode iteration.",
                            suggestions=[
                                f"Use `{suggested}` for faster superset checking.",
                            ],
                        )
                    )
        self.generic_visit(node)


class AllInSupersetRule(Rule):
    id = "plex.all-in-superset"
    name = "Membership iteration in all() instead of set.issuperset()"
    description = "Detects all(x in b for x in a); set(b).issuperset(a) is up to 3.5x faster, avoiding bytecode iteration and generator framing."
    default_severity = "medium"
    stability = "stable"
    tags = ["performance", "set", "lookup"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _AllInSupersetVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    hit.message,
                    hit.suggestions,
                    confidence=0.9,
                )


BUILTIN_RULES = [
    DbCallInLoopRule(),
    JsonInLoopRule(),
    PandasRowIterationRule(),
    RegexCatastropheRule(),
    HttpCallInLoopRule(),
    StringConcatInLoopRule(),
    UnboundedFileIoRule(),
    UncompiledRegexInLoopRule(),
    LinearSearchInLoopRule(),
    SyncIoInAsyncRule(),
    DeepcopyInLoopRule(),
    RepeatedSortInLoopRule(),
    RedundantComprehensionRule(),
    UnnecessaryDictKeysRule(),
    UnnecessaryLenRule(),
    MathPowVsOperatorRule(),
    DictGetFallbackRule(),
    MutableDefaultArgRule(),
    ManualListExtendRule(),
    UnclosedResourceRule(),
    ShortCircuitComprehensionRule(),
    SortedMinMaxRule(),
    UnnecessaryComprehensionInCallRule(),
    MembershipInLiteralListRule(),
    UnnecessaryLambdaRule(),
    DictGetDefaultNoneRule(),
    UnnecessaryAsyncDefRule(),
    UnnecessaryEnumerateRule(),
    DictItemsValueUnusedRule(),
    DictItemsComprehensionToCopyRule(),
    RedundantCollectionCallRule(),
    RedundantFStringRule(),
    StrStartswithTupleRule(),
    DictFromkeysRule(),
    ItertoolsChainFromIterableRule(),
    TryExceptDictGetRule(),
    TryExceptPopDefaultRule(),
    IfPassElseInvertRule(),
    IsinstanceTupleRule(),
    ItertoolsIsliceRule(),
    ReSubLiteralRule(),
    StrRemoveprefixSuffixRule(),
    MathLogBaseRule(),
    TryExceptNextDefaultRule(),
    StrSplitMaxsplitRule(),
    FilterTruthyRule(),
    AllInSupersetRule(),
]
