"""Native resource-lifecycle, concurrency hazard, and architectural boundary analyzer."""

from __future__ import annotations

import ast
import fnmatch
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from plex import __version__
from plex.config.schema import PLExConfig
from plex.providers.base import (
    AnalysisTask,
    EngineCapability,
    FindingSink,
    PreflightResult,
    ProviderEnv,
)
from plex.report.unified import AnalysisFinding, EngineRun, EvidenceRef, finding_id
from plex.sandbox import Sandbox

RESOURCE_CONSTRUCTORS: frozenset[str] = frozenset(
    {
        "open",
        "io.open",
        "socket.socket",
        "sqlite3.connect",
        "tempfile.NamedTemporaryFile",
    }
)

ASYNC_BLOCKING_CALLS: frozenset[str] = frozenset(
    {
        "time.sleep",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "requests.head",
        "requests.request",
        "urllib.request.urlopen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }
)


@dataclass(frozen=True)
class LayerBoundaryRule:
    """Declarative architectural layer boundary policy rule."""

    source_glob: str
    forbidden_prefixes: tuple[str, ...]
    rationale: str = "Architectural layer boundary violation"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LayerBoundaryRule:
        raw_prefixes = data.get("forbidden_prefixes") or data.get("forbid_imports") or ()
        return cls(
            source_glob=str(data["source_glob"]),
            forbidden_prefixes=tuple(str(p) for p in raw_prefixes),
            rationale=str(data.get("rationale", "Architectural layer boundary violation")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_glob": self.source_glob,
            "forbidden_prefixes": list(self.forbidden_prefixes),
            "rationale": self.rationale,
        }


def _call_qualname(node: ast.Call) -> str:
    """Resolve simple call target name (e.g., 'open', 'time.sleep', 'urllib.request.urlopen')."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    parts: list[str] = []
    curr: ast.AST = func
    while isinstance(curr, ast.Attribute):
        parts.append(curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


def _with_item_targets_And_calls(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[int]:
    """Return AST node IDs of Call nodes used directly as context managers in 'with'/'async with'."""
    managed_call_ids: set[int] = set()
    for sub in ast.walk(func_node):
        if isinstance(sub, (ast.With, ast.AsyncWith)):
            for item in sub.items:
                if isinstance(item.context_expr, ast.Call):
                    managed_call_ids.add(id(item.context_expr))
    return managed_call_ids


def _closed_variables(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return variable names that have .close() invoked on them inside func_node."""
    closed: set[str] = set()
    for sub in ast.walk(func_node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "close"
            and isinstance(sub.func.value, ast.Name)
        ):
            closed.add(sub.func.value.id)
    return closed


def _finally_released_variables(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return lock variable names that have .release() inside a try...finally block."""
    released: set[str] = set()
    for sub in ast.walk(func_node):
        if isinstance(sub, ast.Try) and sub.finalbody:
            for fin_stmt in sub.finalbody:
                for fin_node in ast.walk(fin_stmt):
                    if (
                        isinstance(fin_node, ast.Call)
                        and isinstance(fin_node.func, ast.Attribute)
                        and fin_node.func.attr == "release"
                        and isinstance(fin_node.func.value, ast.Name)
                    ):
                        released.add(fin_node.func.value.id)
    return released


class ReliabilityAnalyzer:
    """Evaluates Python ASTs for resource lifecycle, concurrency, and layer boundary defects."""

    def __init__(self, layer_rules: tuple[LayerBoundaryRule, ...] = ()) -> None:
        self.layer_rules = layer_rules

    @classmethod
    def from_repo(
        cls,
        repo_root: Path,
        extra_rules: tuple[LayerBoundaryRule, ...] = (),
    ) -> ReliabilityAnalyzer:
        rules: list[LayerBoundaryRule] = list(extra_rules)
        arch_json = repo_root / ".plex" / "architecture.json"
        if arch_json.is_file():
            try:
                raw = json.loads(arch_json.read_text(encoding="utf-8"))
                for item in raw.get("layer_rules", []):
                    if isinstance(item, dict) and "source_glob" in item:
                        rules.append(LayerBoundaryRule.from_dict(item))
            except (OSError, ValueError, KeyError):
                pass
        return cls(layer_rules=tuple(rules))

    def analyze_file(self, relative_path: str, source: str) -> list[AnalysisFinding]:
        try:
            tree = ast.parse(source, filename=relative_path)
        except SyntaxError:
            return []

        lines = source.splitlines()
        findings: list[AnalysisFinding] = []

        # 1. Check function-level resource lifecycle and concurrency rules
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(
                    self._check_unclosed_resources(node, relative_path, lines)
                )
                findings.extend(
                    self._check_unlocked_acquire(node, relative_path, lines)
                )
            if isinstance(node, ast.AsyncFunctionDef):
                findings.extend(
                    self._check_async_blocking_calls(node, relative_path, lines)
                )

        # 2. Check architectural layer boundary rules
        if self.layer_rules:
            findings.extend(
                self._check_layer_boundaries(tree, relative_path, lines)
            )

        return findings

    def _check_unclosed_resources(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        relative_path: str,
        lines: list[str],
    ) -> list[AnalysisFinding]:
        managed_calls = _with_item_targets_And_calls(func_node)
        closed_vars = _closed_variables(func_node)
        returned_vars: set[str] = set()
        for sub in ast.walk(func_node):
            if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Name):
                returned_vars.add(sub.value.id)

        out: list[AnalysisFinding] = []
        for sub in ast.walk(func_node):
            if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.Call):
                call_node = sub.value
                if id(call_node) in managed_calls:
                    continue
                qname = _call_qualname(call_node)
                if qname not in RESOURCE_CONSTRUCTORS:
                    continue
                target_names = [t.id for t in sub.targets if isinstance(t, ast.Name)]
                for var_name in target_names:
                    if var_name in closed_vars or var_name in returned_vars:
                        continue
                    lineno = sub.lineno
                    end_lineno = getattr(sub, "end_lineno", lineno) or lineno
                    snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
                    fid = finding_id(
                        "reliability",
                        "rel.unclosed-resource",
                        f"{relative_path}:{lineno}:{var_name}",
                        qname,
                    )
                    out.append(
                        AnalysisFinding(
                            id=fid,
                            engine="reliability",
                            category="quality",
                            rule_id="rel.unclosed-resource",
                            severity="medium",
                            title=f"Unclosed resource handle '{var_name}' from {qname}()",
                            status="suspected",
                            confidence="derived",
                            file=relative_path,
                            lineno=lineno,
                            end_lineno=end_lineno,
                            qualname=func_node.name,
                            cwe=["CWE-772"],
                            message=(
                                f"Resource '{var_name}' opened via '{qname}()' in '{func_node.name}' "
                                "is not managed by a 'with' context manager or explicitly closed."
                            ),
                            remediation=[
                                f"Wrap '{qname}(...)' in a 'with {qname}(...) as {var_name}:' block to guarantee deterministic cleanup."
                            ],
                            evidence=[
                                EvidenceRef(
                                    engine="reliability",
                                    kind="ast-resource-lifecycle",
                                    ref=f"{relative_path}:{lineno}:{snippet}",
                                    provider_version=__version__,
                                )
                            ],
                            verification={
                                "method": "static-ast-resource-lifecycle",
                                "status": "suspected",
                            },
                        )
                    )
        return out

    def _check_async_blocking_calls(
        self,
        func_node: ast.AsyncFunctionDef,
        relative_path: str,
        lines: list[str],
    ) -> list[AnalysisFinding]:
        out: list[AnalysisFinding] = []
        for sub in ast.walk(func_node):
            if isinstance(sub, ast.Call):
                qname = _call_qualname(sub)
                if qname not in ASYNC_BLOCKING_CALLS:
                    continue
                lineno = sub.lineno
                end_lineno = getattr(sub, "end_lineno", lineno) or lineno
                snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
                fid = finding_id(
                    "reliability",
                    "rel.async-blocking-call",
                    f"{relative_path}:{lineno}:{func_node.name}",
                    qname,
                )
                out.append(
                    AnalysisFinding(
                        id=fid,
                        engine="reliability",
                        category="quality",
                        rule_id="rel.async-blocking-call",
                        severity="high",
                        title=f"Blocking call '{qname}()' inside async function '{func_node.name}'",
                        status="suspected",
                        confidence="derived",
                        file=relative_path,
                        lineno=lineno,
                        end_lineno=end_lineno,
                        qualname=func_node.name,
                        cwe=["CWE-400"],
                        message=(
                            f"Synchronous blocking call '{qname}()' inside 'async def {func_node.name}' "
                            "stalls the event loop and degrades concurrency."
                        ),
                        remediation=[
                            "Use non-blocking async primitives (e.g., 'await asyncio.sleep(...)', 'httpx.AsyncClient', or 'asyncio.to_thread(...)')."
                        ],
                        evidence=[
                            EvidenceRef(
                                engine="reliability",
                                kind="ast-concurrency",
                                ref=f"{relative_path}:{lineno}:{snippet}",
                                provider_version=__version__,
                            )
                        ],
                        verification={
                            "method": "static-ast-concurrency",
                            "status": "suspected",
                        },
                    )
                )
        return out

    def _check_unlocked_acquire(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        relative_path: str,
        lines: list[str],
    ) -> list[AnalysisFinding]:
        finally_released = _finally_released_variables(func_node)
        out: list[AnalysisFinding] = []
        for sub in ast.walk(func_node):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == "acquire"
                and isinstance(sub.func.value, ast.Name)
            ):
                lock_var = sub.func.value.id
                if lock_var in finally_released:
                    continue
                lineno = sub.lineno
                end_lineno = getattr(sub, "end_lineno", lineno) or lineno
                snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
                fid = finding_id(
                    "reliability",
                    "rel.unlocked-acquire",
                    f"{relative_path}:{lineno}:{lock_var}",
                    "acquire",
                )
                out.append(
                    AnalysisFinding(
                        id=fid,
                        engine="reliability",
                        category="quality",
                        rule_id="rel.unlocked-acquire",
                        severity="high",
                        title=f"Lock '{lock_var}.acquire()' without 'with' or 'try...finally' release",
                        status="suspected",
                        confidence="derived",
                        file=relative_path,
                        lineno=lineno,
                        end_lineno=end_lineno,
                        qualname=func_node.name,
                        cwe=["CWE-667"],
                        message=(
                            f"Lock '{lock_var}.acquire()' in '{func_node.name}' is not guarded by a "
                            "'with' statement or a 'try...finally: {lock_var}.release()' block, risking deadlock on exceptions."
                        ),
                        remediation=[
                            f"Use 'with {lock_var}:' or release '{lock_var}' inside a 'finally:' block."
                        ],
                        evidence=[
                            EvidenceRef(
                                engine="reliability",
                                kind="ast-concurrency",
                                ref=f"{relative_path}:{lineno}:{snippet}",
                                provider_version=__version__,
                            )
                        ],
                        verification={
                            "method": "static-ast-concurrency",
                            "status": "suspected",
                        },
                    )
                )
        return out

    def _check_layer_boundaries(
        self,
        tree: ast.AST,
        relative_path: str,
        lines: list[str],
    ) -> list[AnalysisFinding]:
        matching_rules = [
            r
            for r in self.layer_rules
            if fnmatch.fnmatchcase(relative_path, r.source_glob)
            or (
                r.source_glob.startswith("**/")
                and fnmatch.fnmatchcase(relative_path, r.source_glob[3:])
            )
        ]
        if not matching_rules:
            return []

        out: list[AnalysisFinding] = []
        for node in ast.walk(tree):
            imported_modules: list[tuple[str, int]] = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.append((alias.name, node.lineno))
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append((node.module, node.lineno))

            for mod_name, lineno in imported_modules:
                for rule in matching_rules:
                    for forbidden in rule.forbidden_prefixes:
                        if mod_name == forbidden or mod_name.startswith(forbidden + "."):
                            snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
                            fid = finding_id(
                                "reliability",
                                "arch.layer-violation",
                                f"{relative_path}:{lineno}:{mod_name}",
                                forbidden,
                            )
                            out.append(
                                AnalysisFinding(
                                    id=fid,
                                    engine="reliability",
                                    category="quality",
                                    rule_id="arch.layer-violation",
                                    severity="medium",
                                    title=f"Forbidden layer import '{mod_name}' in '{relative_path}'",
                                    status="suspected",
                                    confidence="derived",
                                    file=relative_path,
                                    lineno=lineno,
                                    end_lineno=lineno,
                                    cwe=["CWE-1061"],
                                    message=(
                                        f"Module '{relative_path}' (matching '{rule.source_glob}') "
                                        f"imports forbidden layer '{mod_name}' ({rule.rationale})."
                                    ),
                                    remediation=[
                                        f"Remove direct dependency on '{forbidden}' and depend on an allowed interface or domain abstraction."
                                    ],
                                    evidence=[
                                        EvidenceRef(
                                            engine="reliability",
                                            kind="ast-layer-policy",
                                            ref=f"{relative_path}:{lineno}:{snippet}",
                                            provider_version=__version__,
                                        )
                                    ],
                                    verification={
                                        "method": "static-ast-layer-policy",
                                        "status": "suspected",
                                    },
                                )
                            )
        return out


class ReliabilityProvider:
    """AnalysisProvider wrapper for ReliabilityAnalyzer (resource lifecycle, concurrency, architecture)."""

    capability = EngineCapability("reliability", ("quality",), default_enabled=False)
    version = __version__

    def __init__(self, layer_rules: tuple[LayerBoundaryRule, ...] = ()) -> None:
        self.layer_rules = layer_rules

    def preflight(self, env: ProviderEnv) -> PreflightResult:
        if env.task.target_kind != "source_tree" or not env.task.repo_root.is_dir():
            return PreflightResult(
                False, ("ReliabilityProvider requires an existing source-tree directory",)
            )
        return PreflightResult(True)

    def run(self, task: AnalysisTask, sink: FindingSink, sandbox: Sandbox) -> EngineRun:
        preflight = self.preflight(ProviderEnv(task, sandbox))
        if not preflight.ready:
            return EngineRun(
                "reliability",
                self.version,
                "skipped",
                limitations=list(preflight.limitations),
                isolation=sandbox.isolation,
            )

        root = task.repo_root.resolve()
        opt_rules: list[LayerBoundaryRule] = list(self.layer_rules)
        raw_layer_rules = task.options.get("layer_rules", [])
        if isinstance(raw_layer_rules, list):
            for item in raw_layer_rules:
                if isinstance(item, dict) and "source_glob" in item:
                    opt_rules.append(LayerBoundaryRule.from_dict(item))

        analyzer = ReliabilityAnalyzer.from_repo(root, extra_rules=tuple(opt_rules))
        exclude = list(PLExConfig().exclude)
        limitations: list[str] = []

        for directory, dirs, files in os.walk(root, followlinks=False):
            parent = Path(directory)
            dirs[:] = sorted(
                d
                for d in dirs
                if not (parent / d).is_symlink()
                and not any(
                    fnmatch.fnmatchcase((parent / d).relative_to(root).as_posix(), pat)
                    for pat in exclude
                )
            )
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = parent / name
                rel = path.relative_to(root).as_posix()
                try:
                    source = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError) as exc:
                    limitations.append(f"Could not read {rel} ({type(exc).__name__})")
                    continue
                for finding in analyzer.analyze_file(rel, source):
                    sink.emit(finding)

        return EngineRun(
            "reliability",
            self.version,
            "partial" if limitations else "complete",
            limitations=limitations,
            isolation=sandbox.isolation,
        )
