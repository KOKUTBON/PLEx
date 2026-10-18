"""JavaScript and TypeScript source security taint analysis and vulnerability scanner."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from plex.report.unified import AnalysisFinding, finding_id


@dataclass
class JsTsToken:
    """A lexical token extracted from JavaScript/TypeScript source code."""

    type: str  # "ident", "keyword", "string", "template", "punct", "number", "comment"
    value: str
    lineno: int
    end_lineno: int
    start_pos: int
    end_pos: int


@dataclass
class TaintSource:
    name: str
    lineno: int
    source_kind: str  # "req.query", "req.body", "req.params", "process.argv", etc.


@dataclass(frozen=True)
class JsTsFunctionSummary:
    """Interprocedural taint summary for a JavaScript/TypeScript function or arrow helper."""

    name: str
    file_path: str
    lineno: int
    params: tuple[str, ...]
    returns_tainted_params: tuple[int, ...] = ()
    returns_direct_taint_source: str | None = None
    param_sinks: tuple[tuple[int, str, str, int], ...] = ()


# Common sinks in Node.js, Express, Fastify, and browser JS/TS
SQL_SINKS = {
    "query",
    "raw",
    "$queryRawUnsafe",
    "execute",
}

CMD_SINKS = {
    "exec",
    "execSync",
}

PATH_SINKS = {
    "readFile",
    "readFileSync",
    "createReadStream",
    "writeFile",
    "writeFileSync",
    "unlink",
    "unlinkSync",
    "sendFile",
}

EVAL_SINKS = {
    "eval",
    "Function",
    "runInThisContext",
    "runInNewContext",
}

NOSQL_SINKS = {
    "find",
    "findOne",
    "updateMany",
    "deleteMany",
    "countDocuments",
}

REDIRECT_SINKS = {
    "redirect",
}

XSS_SINKS = {
    "send",
    "write",
}

SSRF_SINKS = {
    "fetch",
    "get",
    "post",
    "request",
}


class JsTsLexer:
    """Pure-Python tokenizer for JavaScript and TypeScript source files."""

    def __init__(self, code: str) -> None:
        self.code = code
        self.length = len(code)
        self.pos = 0
        self.lineno = 1

    def tokenize(self) -> list[JsTsToken]:
        tokens: list[JsTsToken] = []
        while self.pos < self.length:
            char = self.code[self.pos]

            # 1. Whitespace & Newlines
            if char in " \t\r":
                self.pos += 1
                continue
            if char == "\n":
                self.lineno += 1
                self.pos += 1
                continue

            # 2. Line comment
            if char == "/" and self.pos + 1 < self.length and self.code[self.pos + 1] == "/":
                start_line = self.lineno
                start_p = self.pos
                end_p = self.code.find("\n", self.pos)
                if end_p == -1:
                    end_p = self.length
                text = self.code[start_p:end_p]
                self.pos = end_p
                tokens.append(JsTsToken("comment", text, start_line, start_line, start_p, end_p))
                continue

            # 3. Block comment
            if char == "/" and self.pos + 1 < self.length and self.code[self.pos + 1] == "*":
                start_line = self.lineno
                start_p = self.pos
                end_p = self.code.find("*/", self.pos + 2)
                if end_p == -1:
                    end_p = self.length
                else:
                    end_p += 2
                text = self.code[start_p:end_p]
                self.lineno += text.count("\n")
                self.pos = end_p
                tokens.append(JsTsToken("comment", text, start_line, self.lineno, start_p, end_p))
                continue

            # 4. Strings ('...' or "...")
            if char in ("'", '"'):
                start_line = self.lineno
                start_p = self.pos
                quote = char
                self.pos += 1
                escaped = False
                while self.pos < self.length:
                    c = self.code[self.pos]
                    if c == "\n":
                        self.lineno += 1
                    if escaped:
                        escaped = False
                    elif c == "\\":
                        escaped = True
                    elif c == quote:
                        self.pos += 1
                        break
                    self.pos += 1
                val = self.code[start_p : self.pos]
                tokens.append(JsTsToken("string", val, start_line, self.lineno, start_p, self.pos))
                continue

            # 5. Template literals (`...`)
            if char == "`":
                start_line = self.lineno
                start_p = self.pos
                self.pos += 1
                escaped = False
                while self.pos < self.length:
                    c = self.code[self.pos]
                    if c == "\n":
                        self.lineno += 1
                    if escaped:
                        escaped = False
                    elif c == "\\":
                        escaped = True
                    elif c == "`":
                        self.pos += 1
                        break
                    self.pos += 1
                val = self.code[start_p : self.pos]
                tokens.append(JsTsToken("template", val, start_line, self.lineno, start_p, self.pos))
                continue

            # 6. Identifiers / Keywords
            if char.isalpha() or char in "_$":
                start_line = self.lineno
                start_p = self.pos
                while self.pos < self.length and (
                    self.code[self.pos].isalnum() or self.code[self.pos] in "_$"
                ):
                    self.pos += 1
                val = self.code[start_p : self.pos]
                ttype = "keyword" if val in {
                    "const", "let", "var", "function", "return", "if", "else", "for",
                    "while", "import", "from", "export", "class", "async", "await",
                    "try", "catch", "throw", "new"
                } else "ident"
                tokens.append(JsTsToken(ttype, val, start_line, start_line, start_p, self.pos))
                continue

            # 7. Numbers
            if char.isdigit():
                start_line = self.lineno
                start_p = self.pos
                while self.pos < self.length and (
                    self.code[self.pos].isdigit() or self.code[self.pos] in ".xXabcdefABCDEF"
                ):
                    self.pos += 1
                val = self.code[start_p : self.pos]
                tokens.append(JsTsToken("number", val, start_line, start_line, start_p, self.pos))
                continue

            # 8. Punctuation / Operators
            start_line = self.lineno
            start_p = self.pos
            # Multi-char operators like ===, !==, =>, +=, etc.
            op_match = re.match(r"(===|!==|==|!=|=>|<=|>=|\+\+|--|\+=|-=|\*=|&&|\|\|)", self.code[self.pos : self.pos + 3])
            if op_match:
                op_val = op_match.group(1)
                self.pos += len(op_val)
                tokens.append(JsTsToken("punct", op_val, start_line, start_line, start_p, self.pos))
                continue

            self.pos += 1
            tokens.append(JsTsToken("punct", char, start_line, start_line, start_p, self.pos))

        return tokens


def _extract_param_list(tokens: list[JsTsToken], open_paren_idx: int) -> tuple[tuple[str, ...], int]:
    """Extract parameter names from '(' ... ')' and return (param_names, close_paren_idx)."""
    params: list[str] = []
    idx = open_paren_idx + 1
    depth = 1
    expect_param = True
    while idx < len(tokens) and depth > 0:
        t = tokens[idx]
        if t.value == "(":
            depth += 1
        elif t.value == ")":
            depth -= 1
            if depth == 0:
                return tuple(params), idx
        elif depth == 1:
            if t.value == ",":
                expect_param = True
            elif t.value in (":", "="):
                expect_param = False
            elif expect_param and t.type == "ident":
                params.append(t.value)
                expect_param = False
        idx += 1
    return tuple(params), idx


def _extract_brace_body(tokens: list[JsTsToken], open_brace_idx: int) -> tuple[list[JsTsToken], int]:
    """Extract tokens inside '{' ... '}' and return (body_tokens, close_brace_idx)."""
    body: list[JsTsToken] = []
    idx = open_brace_idx + 1
    depth = 1
    while idx < len(tokens) and depth > 0:
        t = tokens[idx]
        if t.value == "{":
            depth += 1
            body.append(t)
        elif t.value == "}":
            depth -= 1
            if depth == 0:
                return body, idx
            body.append(t)
        else:
            body.append(t)
        idx += 1
    return body, idx


def _token_mentions_var(tokens: list[JsTsToken], var_name: str) -> bool:
    for t in tokens:
        if t.type == "ident" and t.value == var_name:
            return True
        if t.type == "template" and (f"${{{var_name}}}" in t.value or f"$ {var_name}" in t.value):
            return True
    return False


def extract_jsts_function_summaries(
    file_path: str,
    source_code: str,
) -> dict[str, JsTsFunctionSummary]:
    """Extract interprocedural taint summaries for named and arrow functions in JS/TS source."""
    tokens = JsTsLexer(source_code).tokenize()
    summaries: dict[str, JsTsFunctionSummary] = {}
    idx = 0
    total = len(tokens)

    all_sinks = (
        SQL_SINKS
        | CMD_SINKS
        | PATH_SINKS
        | EVAL_SINKS
        | NOSQL_SINKS
        | REDIRECT_SINKS
        | XSS_SINKS
        | SSRF_SINKS
    )

    while idx < total:
        tok = tokens[idx]
        fn_name = ""
        fn_lineno = tok.lineno
        params: tuple[str, ...] = ()
        body_tokens: list[JsTsToken] = []
        is_expr_body = False

        # Case 1: function <name>(...) { ... }
        if tok.type == "keyword" and tok.value == "function" and idx + 2 < total:
            if tokens[idx + 1].type == "ident" and tokens[idx + 2].value == "(":
                fn_name = tokens[idx + 1].value
                params, close_p = _extract_param_list(tokens, idx + 2)
                # Skip optional TypeScript return type annotation before '{'
                scan = close_p + 1
                while scan < total and tokens[scan].value != "{":
                    if tokens[scan].value == ";":
                        break
                    scan += 1
                if scan < total and tokens[scan].value == "{":
                    body_tokens, idx = _extract_brace_body(tokens, scan)

        # Case 2: const/let/var <name> = [async] (...) => ...
        elif tok.type == "keyword" and tok.value in ("const", "let", "var") and idx + 4 < total:
            if tokens[idx + 1].type == "ident" and tokens[idx + 2].value == "=":
                cand_name = tokens[idx + 1].value
                p_start = idx + 3
                if p_start < total and tokens[p_start].value == "async":
                    p_start += 1
                if p_start < total and tokens[p_start].value == "(":
                    cand_params, close_p = _extract_param_list(tokens, p_start)
                    arrow_idx = close_p + 1
                    while arrow_idx < total and tokens[arrow_idx].value not in ("=>", ";", "{"):
                        arrow_idx += 1
                    if arrow_idx < total and tokens[arrow_idx].value == "=>":
                        fn_name = cand_name
                        params = cand_params
                        after_arrow = arrow_idx + 1
                        if after_arrow < total and tokens[after_arrow].value == "{":
                            body_tokens, idx = _extract_brace_body(tokens, after_arrow)
                        else:
                            is_expr_body = True
                            end_expr = after_arrow
                            while end_expr < total and tokens[end_expr].value != ";":
                                if (
                                    tokens[end_expr].type == "keyword"
                                    and tokens[end_expr].value in ("const", "let", "var", "function", "export")
                                ):
                                    break
                                body_tokens.append(tokens[end_expr])
                                end_expr += 1
                            idx = end_expr

        if fn_name:
            # Track which local variables inside body derive from which parameter indices
            param_derived: dict[int, set[str]] = {i: {p} for i, p in enumerate(params)}
            b_idx = 0
            b_len = len(body_tokens)
            while b_idx < b_len:
                bt = body_tokens[b_idx]
                if bt.type == "ident" and b_idx + 1 < b_len and body_tokens[b_idx + 1].value in ("=", "+="):
                    lhs_name = bt.value
                    rhs: list[JsTsToken] = []
                    r_idx = b_idx + 2
                    while r_idx < b_len and body_tokens[r_idx].value != ";":
                        if (
                            body_tokens[r_idx].type == "keyword"
                            and body_tokens[r_idx].value in ("const", "let", "var", "return")
                        ):
                            break
                        rhs.append(body_tokens[r_idx])
                        r_idx += 1
                    for names in param_derived.values():
                        if any(_token_mentions_var(rhs, n) for n in names):
                            names.add(lhs_name)
                b_idx += 1

            # Collect return expressions
            return_exprs: list[list[JsTsToken]] = []
            if is_expr_body:
                return_exprs.append(body_tokens)
            else:
                r_scan = 0
                while r_scan < b_len:
                    if body_tokens[r_scan].type == "keyword" and body_tokens[r_scan].value == "return":
                        ret_toks: list[JsTsToken] = []
                        k = r_scan + 1
                        while k < b_len and body_tokens[k].value != ";":
                            if body_tokens[k].value == "}":
                                break
                            ret_toks.append(body_tokens[k])
                            k += 1
                        return_exprs.append(ret_toks)
                        r_scan = k
                    else:
                        r_scan += 1

            ret_tainted_params: set[int] = set()
            ret_direct_source: str | None = None
            for rexpr in return_exprs:
                rexpr_str = "".join(t.value for t in rexpr)
                for pattern in (
                    r"req\.(query|body|params|headers|cookies|param)",
                    r"request\.(query|body|params|headers|cookies)",
                    r"searchParams\.get\(",
                    r"process\.argv",
                ):
                    m = re.search(pattern, rexpr_str)
                    if m:
                        ret_direct_source = m.group(0)
                        break
                for p_i, names in param_derived.items():
                    if any(_token_mentions_var(rexpr, n) for n in names):
                        ret_tainted_params.add(p_i)

            # Check sink calls inside function body
            param_sinks: list[tuple[int, str, str, int]] = []
            s_idx = 0
            while s_idx < b_len:
                st = body_tokens[s_idx]
                if st.type == "ident" and st.value in all_sinks and s_idx + 1 < b_len and body_tokens[s_idx + 1].value == "(":
                    callee = st.value
                    obj = ""
                    if s_idx > 1 and body_tokens[s_idx - 1].value == "." and body_tokens[s_idx - 2].type == "ident":
                        obj = body_tokens[s_idx - 2].value
                    # Extract call arguments inside body_tokens
                    call_args: list[list[JsTsToken]] = []
                    curr_arg: list[JsTsToken] = []
                    depth = 1
                    a_idx = s_idx + 2
                    while a_idx < b_len:
                        at = body_tokens[a_idx]
                        if at.value == "(":
                            depth += 1
                            curr_arg.append(at)
                        elif at.value == ")":
                            depth -= 1
                            if depth == 0:
                                if curr_arg:
                                    call_args.append(curr_arg)
                                break
                            curr_arg.append(at)
                        elif at.value == "," and depth == 1:
                            call_args.append(curr_arg)
                            curr_arg = []
                        else:
                            curr_arg.append(at)
                        a_idx += 1
                    if call_args:
                        first_arg = call_args[0]
                        is_param_query = len(call_args) > 1 and any(t.value == "[" for t in call_args[1])
                        if not (callee in SQL_SINKS and is_param_query):
                            for p_i, names in param_derived.items():
                                if any(_token_mentions_var(first_arg, n) for n in names):
                                    param_sinks.append((p_i, callee, obj, st.lineno))
                s_idx += 1

            summaries[fn_name] = JsTsFunctionSummary(
                name=fn_name,
                file_path=file_path,
                lineno=fn_lineno,
                params=params,
                returns_tainted_params=tuple(sorted(ret_tainted_params)),
                returns_direct_taint_source=ret_direct_source,
                param_sinks=tuple(param_sinks),
            )

        idx += 1

    return summaries


class JsTsTaintAnalyzer:
    """Performs bounded dataflow and taint tracking on JavaScript/TypeScript source code."""

    def __init__(
        self,
        file_path: str,
        source_code: str,
        summaries: Mapping[str, JsTsFunctionSummary] | None = None,
    ) -> None:
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.splitlines()
        local_summaries = extract_jsts_function_summaries(file_path, source_code)
        if summaries is not None:
            merged = dict(summaries)
            merged.update(local_summaries)
            self.summaries: dict[str, JsTsFunctionSummary] = merged
        else:
            self.summaries = local_summaries

    def analyze(self) -> list[AnalysisFinding]:
        lexer = JsTsLexer(self.source_code)
        tokens = lexer.tokenize()

        # 1. Identify taint sources and local assignments
        tainted_vars: dict[str, TaintSource] = {}
        findings: list[AnalysisFinding] = []

        # Find request parameters and variable declarations
        idx = 0
        total = len(tokens)

        while idx < total:
            tok = tokens[idx]

            # Detect variable declaration: const/let/var <name> = <expr>
            if tok.type == "keyword" and tok.value in ("const", "let", "var") and idx + 3 < total:
                # Direct name: const x = req.query.y
                if tokens[idx + 1].type == "ident" and tokens[idx + 2].value == "=":
                    var_name = tokens[idx + 1].value
                    rhs_tokens = self._extract_statement_rhs(tokens, idx + 3)
                    source_kind = self._detect_taint_source(rhs_tokens, tainted_vars)
                    if source_kind:
                        tainted_vars[var_name] = TaintSource(
                            name=var_name,
                            lineno=tok.lineno,
                            source_kind=source_kind,
                        )
                # Destructuring: const { id, name } = req.body
                elif tokens[idx + 1].value == "{":
                    destructured_names: list[str] = []
                    sub_idx = idx + 2
                    while sub_idx < total and tokens[sub_idx].value != "}":
                        if tokens[sub_idx].type == "ident":
                            destructured_names.append(tokens[sub_idx].value)
                        sub_idx += 1
                    if sub_idx + 1 < total and tokens[sub_idx + 1].value == "=":
                        rhs_tokens = self._extract_statement_rhs(tokens, sub_idx + 2)
                        source_kind = self._detect_taint_source(rhs_tokens, tainted_vars)
                        if source_kind:
                            for dn in destructured_names:
                                tainted_vars[dn] = TaintSource(
                                    name=dn,
                                    lineno=tok.lineno,
                                    source_kind=f"{source_kind}.{dn}",
                                )

            # Detect assignment without declaration: x = req.query...
            elif (
                tok.type == "ident"
                and idx + 1 < total
                and tokens[idx + 1].value in ("=", "+=")
            ):
                var_name = tok.value
                rhs_tokens = self._extract_statement_rhs(tokens, idx + 2)
                source_kind = self._detect_taint_source(rhs_tokens, tainted_vars)
                if source_kind:
                    tainted_vars[var_name] = TaintSource(
                        name=var_name,
                        lineno=tok.lineno,
                        source_kind=source_kind,
                    )
                    if var_name in ("innerHTML", "outerHTML"):
                        fid = finding_id("xboundary", "xbnd.xss", f"{self.file_path}:{tok.lineno}", f"DOM XSS in {var_name}")
                        findings.append(
                            AnalysisFinding(
                                id=fid,
                                engine="xboundary",
                                category="security",
                                rule_id="xbnd.xss",
                                severity="high",
                                title=f"DOM-based Cross-Site Scripting (XSS) via {var_name} assignment",
                                status="suspected",
                                confidence="derived",
                                file=self.file_path,
                                lineno=tok.lineno,
                                end_lineno=tok.lineno,
                                cwe=["CWE-79"],
                                owasp=["A03:2021"],
                                message=f"Untrusted input ({source_kind}) is assigned directly to DOM sink {var_name}.",
                                remediation=["Use textContent or an HTML sanitization library (such as DOMPurify) before writing to innerHTML."],
                                engine_meta={"finding_id": fid, "language": "javascript"},
                            )
                        )

            # Detect function calls (sinks or interprocedural helper calls)
            if tok.type == "ident":
                callee_name = tok.value
                # Check for member calls: db.query(...), child_process.exec(...), res.send(...)
                obj_name = ""
                if idx > 1 and tokens[idx - 1].value == "." and tokens[idx - 2].type == "ident":
                    obj_name = tokens[idx - 2].value

                # Is it a call? (followed by '(') and not a function definition `function foo(`
                is_fn_decl = idx > 0 and tokens[idx - 1].type == "keyword" and tokens[idx - 1].value == "function"
                if not is_fn_decl and idx + 1 < total and tokens[idx + 1].value == "(":
                    args_tokens = self._extract_call_args(tokens, idx + 2)
                    self._check_sink(
                        callee_name=callee_name,
                        obj_name=obj_name,
                        args_tokens=args_tokens,
                        lineno=tok.lineno,
                        tainted_vars=tainted_vars,
                        findings=findings,
                    )
                    # Interprocedural helper parameter-to-sink check
                    summary = self.summaries.get(callee_name)
                    if summary and summary.param_sinks:
                        for param_idx, sink_callee, sink_obj, _sink_line in summary.param_sinks:
                            if param_idx < len(args_tokens):
                                is_arg_tainted, arg_source = self._is_argument_tainted(
                                    args_tokens[param_idx], tainted_vars
                                )
                                if is_arg_tainted:
                                    synth_var = f"__interproc_{callee_name}_{param_idx}"
                                    synth_tainted = {
                                        **tainted_vars,
                                        synth_var: TaintSource(
                                            name=synth_var,
                                            lineno=tok.lineno,
                                            source_kind=f"{arg_source} (via {callee_name}())",
                                        ),
                                    }
                                    synth_tok = JsTsToken(
                                        "ident", synth_var, tok.lineno, tok.lineno, 0, 0
                                    )
                                    self._check_sink(
                                        callee_name=sink_callee,
                                        obj_name=sink_obj,
                                        args_tokens=[[synth_tok]],
                                        lineno=tok.lineno,
                                        tainted_vars=synth_tainted,
                                        findings=findings,
                                    )

            idx += 1

        return findings

    def _extract_statement_rhs(self, tokens: list[JsTsToken], start_idx: int) -> list[JsTsToken]:
        rhs: list[JsTsToken] = []
        idx = start_idx
        while idx < len(tokens):
            t = tokens[idx]
            if t.value == ";":
                break
            if t.type == "keyword" and t.value in ("const", "let", "var", "function", "return"):
                break
            rhs.append(t)
            idx += 1
        return rhs

    def _extract_call_args(self, tokens: list[JsTsToken], start_idx: int) -> list[list[JsTsToken]]:
        args: list[list[JsTsToken]] = []
        current: list[JsTsToken] = []
        depth = 1
        idx = start_idx
        while idx < len(tokens):
            t = tokens[idx]
            if t.value == "(":
                depth += 1
                current.append(t)
            elif t.value == ")":
                depth -= 1
                if depth == 0:
                    if current:
                        args.append(current)
                    break
                current.append(t)
            elif t.value == "," and depth == 1:
                args.append(current)
                current = []
            else:
                current.append(t)
            idx += 1
        return args

    def _detect_taint_source(
        self, tokens: list[JsTsToken], tainted_vars: dict[str, TaintSource]
    ) -> str | None:
        expr_str = "".join(t.value for t in tokens)

        # Numeric and boolean coercions neutralize string injection taint
        if re.match(
            r"^(Number\.)?(parseInt|parseFloat|isFinite|isInteger)\(|^(Number|Boolean|BigInt)\(",
            expr_str,
        ):
            return None

        # Check explicit request object sources
        for pattern in (
            r"req\.(query|body|params|headers|cookies|param)",
            r"request\.(query|body|params|headers|cookies)",
            r"searchParams\.get\(",
            r"process\.argv",
        ):
            m = re.search(pattern, expr_str)
            if m:
                return m.group(0)

        # Check existing tainted variables
        for t in tokens:
            if t.type == "ident" and t.value in tainted_vars:
                return f"derived from {tainted_vars[t.value].source_kind}"
            # Check template interpolation: `${var}`
            if t.type == "template":
                for var in tainted_vars:
                    if f"${{{var}}}" in t.value or f"$ {var}" in t.value:
                        return f"derived from {tainted_vars[var].source_kind}"

        # Check interprocedural helper calls returning taint
        for i, t in enumerate(tokens):
            if t.type == "ident" and t.value in self.summaries and i + 1 < len(tokens) and tokens[i + 1].value == "(":
                summary = self.summaries[t.value]
                if summary.returns_direct_taint_source:
                    return f"{summary.returns_direct_taint_source} (via {summary.name}())"
                if summary.returns_tainted_params:
                    call_args = self._extract_call_args(tokens, i + 2)
                    for p_idx in summary.returns_tainted_params:
                        if p_idx < len(call_args):
                            arg_toks = call_args[p_idx]
                            arg_src = self._detect_taint_source(arg_toks, tainted_vars)
                            if arg_src:
                                return f"derived from {arg_src} (via {summary.name}())"

        return None

    def _is_argument_tainted(
        self, arg_tokens: list[JsTsToken], tainted_vars: dict[str, TaintSource]
    ) -> tuple[bool, str]:
        # Direct taint check
        source_kind = self._detect_taint_source(arg_tokens, tainted_vars)
        if source_kind:
            return True, source_kind

        # Check concatenation with '+' or template literal
        has_concat = any(t.value == "+" for t in arg_tokens) or any(
            t.type == "template" and "${" in t.value for t in arg_tokens
        )
        if has_concat:
            for t in arg_tokens:
                if t.type == "ident" and t.value in tainted_vars:
                    return True, tainted_vars[t.value].source_kind
                if t.type == "template":
                    for var in tainted_vars:
                        if f"${{{var}}}" in t.value:
                            return True, tainted_vars[var].source_kind

        return False, ""

    def _check_sink(
        self,
        callee_name: str,
        obj_name: str,
        args_tokens: list[list[JsTsToken]],
        lineno: int,
        tainted_vars: dict[str, TaintSource],
        findings: list[AnalysisFinding],
    ) -> None:
        if not args_tokens:
            return

        first_arg = args_tokens[0]
        is_tainted, source = self._is_argument_tainted(first_arg, tainted_vars)

        line_text = self.lines[lineno - 1] if 0 <= lineno - 1 < len(self.lines) else ""

        # 1. SQL Injection: db.query("..." + input)
        if callee_name in SQL_SINKS or (obj_name in ("db", "client", "pool", "connection", "knex") and callee_name == "query"):
            is_parameterized = len(args_tokens) > 1 and any(
                t.value == "[" for t in args_tokens[1]
            )
            if is_tainted and not is_parameterized:
                fid = finding_id("xboundary", "xbnd.sql-injection", f"{self.file_path}:{lineno}", f"SQL Injection in {callee_name}")
                findings.append(
                    AnalysisFinding(
                        id=fid,
                        engine="xboundary",
                        category="security",
                        rule_id="xbnd.sql-injection",
                        severity="critical",
                        title=f"SQL Injection via dynamic query in {callee_name}()",
                        status="suspected",
                        confidence="derived",
                        file=self.file_path,
                        lineno=lineno,
                        end_lineno=lineno,
                        cwe=["CWE-89"],
                        owasp=["A03:2021"],
                        message=f"Untrusted input ({source}) is concatenated into a SQL statement in {callee_name}(). Use parameterized queries instead.",
                        remediation=["Use parameterized query placeholders ($1, ?) with query parameter arrays."],
                        engine_meta={"finding_id": fid, "language": "javascript"},
                    )
                )

        # 2. Command Injection: child_process.exec(cmd) / execSync(cmd)
        if callee_name in CMD_SINKS or (obj_name in ("child_process", "cp") and callee_name in ("exec", "execSync")):
            if is_tainted:
                fid = finding_id("xboundary", "xbnd.command-injection", f"{self.file_path}:{lineno}", f"Command Injection in {callee_name}")
                findings.append(
                    AnalysisFinding(
                        id=fid,
                        engine="xboundary",
                        category="security",
                        rule_id="xbnd.command-injection",
                        severity="critical",
                        title=f"Command Injection via untrusted shell execution in {callee_name}()",
                        status="suspected",
                        confidence="derived",
                        file=self.file_path,
                        lineno=lineno,
                        end_lineno=lineno,
                        cwe=["CWE-78"],
                        owasp=["A03:2021"],
                        message=f"Untrusted input ({source}) is passed to shell execution command {callee_name}(). Use execFile() with discrete argument arrays.",
                        remediation=["Replace child_process.exec with execFile or spawn without shell execution."],
                        engine_meta={"finding_id": fid, "language": "javascript"},
                    )
                )

        # 3. Path Traversal: fs.readFile(path) / res.sendFile(path)
        if callee_name in PATH_SINKS or (obj_name in ("fs", "res") and callee_name in PATH_SINKS):
            # Check if sanitized with path.resolve confinement check
            is_confined = "_plexWithinBase" in line_text or "path.resolve" in line_text and "startsWith" in line_text
            if is_tainted and not is_confined:
                fid = finding_id("xboundary", "xbnd.path-traversal", f"{self.file_path}:{lineno}", f"Path Traversal in {callee_name}")
                findings.append(
                    AnalysisFinding(
                        id=fid,
                        engine="xboundary",
                        category="security",
                        rule_id="xbnd.path-traversal",
                        severity="high",
                        title=f"Path Traversal in {callee_name}()",
                        status="suspected",
                        confidence="derived",
                        file=self.file_path,
                        lineno=lineno,
                        end_lineno=lineno,
                        cwe=["CWE-22"],
                        owasp=["A01:2021"],
                        message=f"Untrusted input ({source}) reaches filesystem sink {callee_name}() without boundary validation.",
                        remediation=["Verify that the target path resolves inside an authorized base directory before reading."],
                        engine_meta={"finding_id": fid, "language": "javascript"},
                    )
                )

        # 4. Code Eval Injection: eval(code) / new Function(code)
        if callee_name in EVAL_SINKS or (obj_name in ("vm",) and callee_name in EVAL_SINKS):
            if is_tainted:
                fid = finding_id("xboundary", "xbnd.eval-injection", f"{self.file_path}:{lineno}", f"Code Eval Injection in {callee_name}")
                findings.append(
                    AnalysisFinding(
                        id=fid,
                        engine="xboundary",
                        category="security",
                        rule_id="xbnd.eval-injection",
                        severity="critical",
                        title=f"Code Eval Injection via {callee_name}()",
                        status="suspected",
                        confidence="derived",
                        file=self.file_path,
                        lineno=lineno,
                        end_lineno=lineno,
                        cwe=["CWE-95"],
                        owasp=["A03:2021"],
                        message=f"Untrusted input ({source}) is dynamically evaluated as code in {callee_name}().",
                        remediation=["Avoid dynamic evaluation; parse structured formats with JSON.parse()."],
                        engine_meta={"finding_id": fid, "language": "javascript"},
                    )
                )

        # 5. NoSQL Injection: collection.find(query)
        if callee_name in NOSQL_SINKS or (obj_name in ("collection", "db", "User", "Account", "Model") and callee_name in NOSQL_SINKS):
            # Check if input is passed directly as filter
            is_sanitized = "_plexRejectOperators" in line_text or "sanitize" in line_text
            if is_tainted and not is_sanitized:
                fid = finding_id("xboundary", "xbnd.nosql-injection", f"{self.file_path}:{lineno}", f"NoSQL Injection in {callee_name}")
                findings.append(
                    AnalysisFinding(
                        id=fid,
                        engine="xboundary",
                        category="security",
                        rule_id="xbnd.nosql-injection",
                        severity="high",
                        title=f"NoSQL Operator Injection in {callee_name}()",
                        status="suspected",
                        confidence="derived",
                        file=self.file_path,
                        lineno=lineno,
                        end_lineno=lineno,
                        cwe=["CWE-943"],
                        owasp=["A03:2021"],
                        message=f"Untrusted request object ({source}) is used as a NoSQL query filter in {callee_name}().",
                        remediation=["Filter operator keys beginning with '$' or cast filter values to expected primitive types."],
                        engine_meta={"finding_id": fid, "language": "javascript"},
                    )
                )

        # 6. Open Redirect: res.redirect(url)
        if callee_name in REDIRECT_SINKS or (obj_name in ("res", "response") and callee_name == "redirect"):
            is_sanitized = "_plexSafeRedirect" in line_text or "isRelative" in line_text
            if is_tainted and not is_sanitized:
                fid = finding_id("xboundary", "xbnd.open-redirect", f"{self.file_path}:{lineno}", "Open Redirect in res.redirect")
                findings.append(
                    AnalysisFinding(
                        id=fid,
                        engine="xboundary",
                        category="security",
                        rule_id="xbnd.open-redirect",
                        severity="medium",
                        title="Open Redirect via untrusted URL in res.redirect()",
                        status="suspected",
                        confidence="derived",
                        file=self.file_path,
                        lineno=lineno,
                        end_lineno=lineno,
                        cwe=["CWE-601"],
                        owasp=["A01:2021"],
                        message=f"Untrusted input ({source}) is passed directly to res.redirect(). Validate target against relative URLs or an allowlist.",
                        remediation=["Validate redirect URLs with strict relative path checks or domain allowlists."],
                        engine_meta={"finding_id": fid, "language": "javascript"},
                    )
                )

        # 7. XSS: res.send("<h1>" + input)
        if callee_name in XSS_SINKS and obj_name in ("res", "response"):
            is_sanitized = "escapeHtml" in line_text or "validator.escape" in line_text or "DOMPurify" in line_text
            if is_tainted and not is_sanitized:
                fid = finding_id("xboundary", "xbnd.xss", f"{self.file_path}:{lineno}", "Cross-Site Scripting in res.send")
                findings.append(
                    AnalysisFinding(
                        id=fid,
                        engine="xboundary",
                        category="security",
                        rule_id="xbnd.xss",
                        severity="high",
                        title="Cross-Site Scripting (XSS) via unescaped HTML in res.send()",
                        status="suspected",
                        confidence="derived",
                        file=self.file_path,
                        lineno=lineno,
                        end_lineno=lineno,
                        cwe=["CWE-79"],
                        owasp=["A03:2021"],
                        message=f"Untrusted input ({source}) is concatenated into an HTTP response body without HTML entity encoding.",
                        remediation=["Encode untrusted text with an HTML entity escaper before interpolation."],
                        engine_meta={"finding_id": fid, "language": "javascript"},
                    )
                )

        # 8. SSRF: fetch(url) / axios.get(url)
        if callee_name in SSRF_SINKS or (obj_name in ("axios", "http", "https") and callee_name in SSRF_SINKS):
            is_sanitized = "allowlist" in line_text.lower() or "isallowed" in line_text.lower()
            if is_tainted and not is_sanitized:
                fid = finding_id("xboundary", "xbnd.ssrf", f"{self.file_path}:{lineno}", f"SSRF in {callee_name}")
                findings.append(
                    AnalysisFinding(
                        id=fid,
                        engine="xboundary",
                        category="security",
                        rule_id="xbnd.ssrf",
                        severity="high",
                        title=f"Server-Side Request Forgery (SSRF) in {callee_name}()",
                        status="suspected",
                        confidence="derived",
                        file=self.file_path,
                        lineno=lineno,
                        end_lineno=lineno,
                        cwe=["CWE-918"],
                        owasp=["A10:2021"],
                        message=f"Untrusted input ({source}) reaches HTTP client sink {callee_name}() without URL destination verification.",
                        remediation=["Validate destinations against an explicit host and port allowlist, refusing private IP addresses."],
                        engine_meta={"finding_id": fid, "language": "javascript"},
                    )
                )


def analyze_jsts_source(
    file_path: Path | str,
    source_code: str,
    summaries: Mapping[str, JsTsFunctionSummary] | None = None,
) -> list[AnalysisFinding]:
    """Analyze a JavaScript or TypeScript source file for security taint vulnerabilities."""
    analyzer = JsTsTaintAnalyzer(str(file_path), source_code, summaries=summaries)
    return analyzer.analyze()


def analyze_jsts_project(sources: Mapping[str, str]) -> list[AnalysisFinding]:
    """Analyze multiple JS/TS project files with cross-module interprocedural helper summaries."""
    project_summaries: dict[str, JsTsFunctionSummary] = {}
    for file_path, code in sources.items():
        project_summaries.update(extract_jsts_function_summaries(file_path, code))

    findings: list[AnalysisFinding] = []
    seen_ids: set[str] = set()
    for file_path, code in sources.items():
        for finding in analyze_jsts_source(file_path, code, summaries=project_summaries):
            if finding.id not in seen_ids:
                seen_ids.add(finding.id)
                findings.append(finding)
    return findings

