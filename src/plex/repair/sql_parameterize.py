"""Deterministic fixer and patch candidate proposer for Python SQL injection vulnerabilities.

The fixer only rewrites a call when every precondition holds; otherwise it abstains and
records why in ``abstentions``:

- the DB-API paramstyle is known, either declared by the caller or inferred from exactly
  one supported driver import (in the file, else in the project);
- the call is ``execute(<query>)`` or Django ``raw(<query>)`` with no parameters already
  supplied;
- the query is an f-string, ``+`` concatenation or ``%`` formatting whose interpolated
  values sit in SQL value positions (after ``=``, ``LIKE``, ``,`` and similar), not
  inside a partial string literal, a quoted identifier, an ``IN (...)`` list or an
  identifier/clause position;
- the constant SQL text contains nothing the target paramstyle would reinterpret.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

ParamStyle = Literal["qmark", "format"]

_PLACEHOLDERS: dict[str, str] = {"qmark": "?", "format": "%s"}

# Top-level module (or dotted prefix) -> DB-API paramstyle.
DRIVER_PARAMSTYLES: dict[str, ParamStyle] = {
    "sqlite3": "qmark",
    "aiosqlite": "qmark",
    "pysqlite2": "qmark",
    "pyodbc": "qmark",
    "duckdb": "qmark",
    "psycopg2": "format",
    "psycopg": "format",
    "pymysql": "format",
    "MySQLdb": "format",
    "mysql.connector": "format",
    "pg8000": "format",
    "aiomysql": "format",
    "aiopg": "format",
    "django.db": "format",
}

# Drivers whose call shape or paramstyle the fixer does not model.
UNSUPPORTED_DRIVERS: frozenset[str] = frozenset(
    {"asyncpg", "oracledb", "cx_Oracle", "sqlalchemy", "databases", "snowflake", "ibm_db"}
)

_PARAM_KEYWORDS = frozenset({"params", "parameters", "args", "vars", "values"})

# A value may follow these SQL tokens (case-insensitive, at the end of the preceding text).
_VALUE_POSITION = re.compile(
    r"(?:=|<|>|,|\(|\+|-|\*|/|\|\||"
    r"\b(?:LIKE|ILIKE|IS|NOT|AND|OR|BETWEEN|VALUES|LIMIT|OFFSET|THEN|ELSE|WHEN|RETURN))\s*$",
    re.IGNORECASE,
)
_IN_LIST = re.compile(r"\bIN\s*\(\s*$", re.IGNORECASE)
_PERCENT_SPEC = re.compile(r"%(?:%|s|d|.)", re.DOTALL)


class _Abstain(Exception):
    """Raised internally when a precondition does not hold."""


@dataclass(frozen=True)
class SQLFixAbstention:
    """A candidate call the fixer deliberately left unchanged."""

    lineno: int
    reason: str


@dataclass(frozen=True)
class _Param:
    expr: ast.expr


_Part = str | _Param


def _module_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _matches(module: str, driver: str) -> bool:
    return module == driver or module.startswith(driver + ".")


def detect_paramstyle(modules: set[str]) -> tuple[ParamStyle | None, str]:
    """Infer the paramstyle from imported module names.

    Returns ``(style, evidence)``; ``style`` is None when no supported driver is found,
    an unsupported driver is present, or imported drivers disagree.
    """
    unsupported = sorted(
        m for m in modules if any(_matches(m, d) for d in UNSUPPORTED_DRIVERS)
    )
    if unsupported:
        return None, f"unsupported database library imported: {', '.join(unsupported)}"
    found: dict[str, ParamStyle] = {}
    for module in modules:
        for driver, style in DRIVER_PARAMSTYLES.items():
            if _matches(module, driver):
                found[driver] = style
    styles = set(found.values())
    if not styles:
        return None, "no supported database driver import found"
    if len(styles) > 1:
        return None, f"drivers with different paramstyles imported: {', '.join(sorted(found))}"
    return styles.pop(), f"driver import: {', '.join(sorted(found))}"


def detect_project_paramstyle(repo_root: Path) -> tuple[ParamStyle | None, str]:
    """Infer one paramstyle from driver imports across a project's Python files."""
    modules: set[str] = set()
    for path in sorted(repo_root.rglob("*.py")):
        if any(part.startswith(".") or part in {"venv", "node_modules", "__pycache__"} for part in path.parts):
            continue
        try:
            modules |= _module_names(ast.parse(path.read_text(encoding="utf-8")))
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
            continue
    style, evidence = detect_paramstyle(modules)
    return style, f"project {evidence}"


def _query_parts(arg: ast.expr) -> list[_Part]:
    """Split a dynamic query expression into constant SQL text and interpolated values."""
    if isinstance(arg, ast.JoinedStr):
        parts: list[_Part] = []
        for val in arg.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                if val.conversion != -1 or val.format_spec is not None:
                    raise _Abstain("f-string conversion or format spec changes the bound value")
                parts.append(_Param(val.value))
            else:
                raise _Abstain("unsupported f-string component")
        return parts

    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        parts = []
        for op in _flatten_add(arg):
            if isinstance(op, ast.Constant):
                if not isinstance(op.value, str):
                    raise _Abstain("non-string constant in concatenation")
                parts.append(op.value)
            elif isinstance(op, ast.JoinedStr | ast.BinOp):
                raise _Abstain("nested formatting inside concatenation")
            else:
                parts.append(_Param(op))
        return parts

    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
        if not (isinstance(arg.left, ast.Constant) and isinstance(arg.left.value, str)):
            return []
        if isinstance(arg.right, ast.Dict):
            raise _Abstain("mapping-based %-formatting")
        template = arg.left.value
        specs = [m.group(0) for m in _PERCENT_SPEC.finditer(template)]
        if any(s not in {"%%", "%s", "%d"} for s in specs):
            raise _Abstain("unsupported %-format specifier")
        n_values = sum(1 for s in specs if s != "%%")
        if isinstance(arg.right, ast.Tuple):
            values = list(arg.right.elts)
            if any(isinstance(v, ast.Starred) for v in values) or len(values) != n_values:
                raise _Abstain("%-format argument count does not match specifiers")
        elif n_values == 1:
            values = [arg.right]
        else:
            raise _Abstain("%-format arguments are not a tuple literal")
        parts = []
        pos = 0
        it = iter(values)
        for m in _PERCENT_SPEC.finditer(template):
            if m.group(0) == "%%":
                continue
            parts.append(template[pos : m.start()].replace("%%", "%"))
            parts.append(_Param(next(it)))
            pos = m.end()
        parts.append(template[pos:].replace("%%", "%"))
        return parts

    return []


def _flatten_add(node: ast.expr) -> list[ast.expr]:
    """Flatten chained Add binary operations into an ordered sequence of operand nodes."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _merge_text(parts: list[_Part]) -> list[_Part]:
    merged: list[_Part] = []
    for part in parts:
        if isinstance(part, str) and merged and isinstance(merged[-1], str):
            merged[-1] += part
        else:
            merged.append(part)
    return merged


def _build_template(parts: list[_Part], style: ParamStyle) -> tuple[str, list[ast.expr]]:
    """Validate value positions, strip whole-literal quotes and emit the bound template."""
    parts = _merge_text(parts)
    params = [p.expr for p in parts if isinstance(p, _Param)]
    if not params:
        raise _Abstain("no interpolated values")

    original: list[str] = [p if isinstance(p, str) else "" for p in parts]
    if "".join(original).count("'") % 2:
        raise _Abstain("unbalanced string literal quotes")
    texts = list(original)
    for i, part in enumerate(parts):
        if not isinstance(part, _Param):
            continue
        if (i > 0 and isinstance(parts[i - 1], _Param)) or (
            i + 1 < len(parts) and isinstance(parts[i + 1], _Param)
        ):
            raise _Abstain("adjacent interpolations")
        before = texts[i - 1] if i > 0 else ""
        after = texts[i + 1] if i + 1 < len(parts) else ""
        if before.endswith(('"', "`")) or after.startswith(('"', "`")):
            raise _Abstain("interpolation inside a quoted identifier or double-quoted literal")
        inside_literal = "".join(original[:i]).count("'") % 2 == 1
        if inside_literal:
            # Only a value that forms the entire literal ('{x}') can become a parameter.
            if not (before.endswith("'") and after.startswith("'")):
                raise _Abstain("interpolation inside part of a string literal")
            before, after = before[:-1], after[1:]
            texts[i - 1] = before
            texts[i + 1] = after
        elif before.endswith("'") or after.startswith("'"):
            raise _Abstain("interpolation adjacent to a string literal")
        if _IN_LIST.search(before):
            raise _Abstain("interpolation inside an IN (...) list")
        if not _VALUE_POSITION.search(before) or after.lstrip().startswith("."):
            raise _Abstain("interpolation is not in a SQL value position")

    sql_text = "".join(texts)
    placeholder = _PLACEHOLDERS[style]
    if style == "qmark" and "?" in sql_text:
        raise _Abstain("SQL text already contains '?' characters")

    out: list[str] = []
    for i, part in enumerate(parts):
        if isinstance(part, _Param):
            out.append(placeholder)
        else:
            out.append(texts[i].replace("%", "%%") if style == "format" else texts[i])
    return "".join(out), params


class SQLParameterizeFixer(BaseFixer):
    """AST fixer that transforms unparameterized SQL calls into bound parameter executions."""

    rule_id = "xbnd.sql-injection"
    name = "sql_parameterize"
    # Meets its evidence contract: preconditions, abstention and semantic fixtures.
    auto_apply = True

    def __init__(self, placeholder: str | None = None, paramstyle: ParamStyle | None = None) -> None:
        if placeholder is not None and paramstyle is None:
            styles = {v: k for k, v in _PLACEHOLDERS.items()}
            if placeholder not in styles:
                raise ValueError(f"unsupported placeholder {placeholder!r}; use '?' or '%s'")
            paramstyle = styles[placeholder]  # type: ignore[assignment]
        self.paramstyle: ParamStyle | None = paramstyle
        self.project_paramstyle: ParamStyle | None = None
        self.project_evidence = ""
        self.abstentions: list[SQLFixAbstention] = []
        self.last_evidence = ""

    def prepare(self, repo_root: Path) -> None:
        """Record the project-wide paramstyle used when a file has no driver import."""
        self.project_paramstyle, self.project_evidence = detect_project_paramstyle(repo_root)

    def _resolve_style(self, tree: ast.Module, func_name: str) -> tuple[ParamStyle, str]:
        if self.paramstyle is not None:
            return self.paramstyle, "declared by caller"
        modules = _module_names(tree)
        if func_name == "raw":
            if any(_matches(m, "django") for m in modules):
                return "format", "Django raw() uses %s placeholders"
            raise _Abstain("raw() call outside a Django module")
        style, evidence = detect_paramstyle(modules)
        if style is not None:
            return style, evidence
        if evidence.startswith(("unsupported", "drivers with")):
            raise _Abstain(evidence)
        if self.project_paramstyle is not None:
            return self.project_paramstyle, self.project_evidence
        raise _Abstain(f"unknown database driver ({evidence})")

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        self.abstentions = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str]] = []
        evidence: set[str] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id
            else:
                continue
            if func_name not in {"execute", "raw"}:
                continue

            try:
                parts = _query_parts(node.args[0])
                if not parts:
                    continue
                if len(node.args) > 1 or any(
                    kw.arg is None or kw.arg in _PARAM_KEYWORDS for kw in node.keywords
                ):
                    raise _Abstain("call already supplies parameters")
                style, why = self._resolve_style(tree, func_name)
                template, params = _build_template(parts, style)
            except _Abstain as exc:
                self.abstentions.append(SQLFixAbstention(node.lineno, str(exc)))
                continue
            evidence.add(f"{style} ({why})")

            new_call = ast.Call(
                func=node.func,
                args=[ast.Constant(value=template), ast.Tuple(elts=params, ctx=ast.Load())],
                keywords=node.keywords,
            )
            new_code = ast.unparse(new_call)

            start_line = node.lineno
            end_line = node.end_lineno or node.lineno
            start_col = node.col_offset
            end_col = node.end_col_offset or len(lines[end_line - 1])
            if start_line == end_line:
                old_code = lines[start_line - 1][start_col:end_col]
            else:
                old_code = "".join(lines[start_line - 1 : end_line])
            replacements.append((start_line, end_line, start_col, end_col, old_code, new_code))

        self.last_evidence = "; ".join(sorted(evidence))
        if not replacements:
            return source, []

        # Sort replacements in reverse order so line/col edits don't invalidate later positions
        replacements.sort(key=lambda r: (r[0], r[2]), reverse=True)
        modified_lines = list(lines)

        for s_line, e_line, s_col, e_col, old_code, new_code in replacements:
            if s_line == e_line:
                line = modified_lines[s_line - 1]
                modified_lines[s_line - 1] = line[:s_col] + new_code + line[e_col:]
            else:
                first_part = modified_lines[s_line - 1][:s_col]
                last_part = modified_lines[e_line - 1][e_col:]
                modified_lines[s_line - 1 : e_line] = [first_part + new_code + last_part]

            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Parameterize dynamic SQL query with bound parameters",
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        return "".join(modified_lines), changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform source and construct a versioned PatchCandidate contract."""
        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        orig_lines = source.splitlines(keepends=True)
        fixed_lines = fixed_source.splitlines(keepends=True)

        diff = "".join(
            unified_diff(
                orig_lines,
                fixed_lines,
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            unified_diff(
                fixed_lines,
                orig_lines,
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        source_digest = f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"
        meta = dict(metadata or {})
        meta["paramstyle"] = self.last_evidence
        if self.abstentions:
            meta["abstentions"] = [
                {"lineno": a.lineno, "reason": a.reason} for a in self.abstentions
            ]

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Parameterize SQL statement and pass arguments as bound parameters",
            preconditions=(
                f"DB-API paramstyle: {self.last_evidence}",
                "Call supplied no parameters before the repair",
                "Every interpolated value is in a SQL value position",
            ),
            generator="plex.repair.sql_parameterize",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
