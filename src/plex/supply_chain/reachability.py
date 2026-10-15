"""AST call-graph reachability analysis for third-party dependencies."""

from __future__ import annotations

import ast
import os
from pathlib import Path

from .models import (
    AdvisoryRecord,
    CallSiteEvidence,
    DependencyReachability,
    DependencyRecord,
)


class _CallGraphVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str, lines: list[str]) -> None:
        self.rel_path = rel_path
        self.lines = lines
        # Map local name/alias -> (package_name, prefix)
        self.alias_map: dict[str, tuple[str, str]] = {}
        # Variable name -> (package_name, instantiated_class_or_symbol)
        self.var_map: dict[str, tuple[str, str]] = {}
        self.imported_packages: dict[str, list[int]] = {}
        self.call_sites: list[CallSiteEvidence] = []
        self.scope_stack: list[str] = ["<module>"]

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            pkg_name = alias.name.split(".")[0].lower()
            local_name = alias.asname or alias.name
            self.alias_map[local_name] = (pkg_name, alias.name)
            self.imported_packages.setdefault(pkg_name, []).append(node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            pkg_name = node.module.split(".")[0].lower()
            self.imported_packages.setdefault(pkg_name, []).append(node.lineno)
            for alias in node.names:
                local_name = alias.asname or alias.name
                full_symbol = f"{node.module}.{alias.name}"
                self.alias_map[local_name] = (pkg_name, full_symbol)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check if RHS is a call to an imported symbol
        # e.g. pool = urllib3.PoolManager() or session = requests.Session()
        if isinstance(node.value, ast.Call):
            resolved = self._resolve_call_symbol(node.value.func)
            if resolved:
                pkg_name, full_sym = resolved
                cls_name = full_sym.split(".")[-1]
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.var_map[target.id] = (pkg_name, cls_name)
        self.generic_visit(node)

    def _resolve_call_symbol(self, func: ast.expr) -> tuple[str, str] | None:
        if isinstance(func, ast.Name):
            if func.id in self.alias_map:
                return self.alias_map[func.id]
        elif isinstance(func, ast.Attribute):
            root: ast.expr = func
            attrs: list[str] = []
            while isinstance(root, ast.Attribute):
                attrs.append(root.attr)
                root = root.value
            attrs.reverse()
            if isinstance(root, ast.Name):
                if root.id in self.alias_map:
                    pkg_name, prefix = self.alias_map[root.id]
                    full_sym = f"{prefix}.{'.'.join(attrs)}"
                    return (pkg_name, full_sym)
                elif root.id in self.var_map:
                    pkg_name, cls_name = self.var_map[root.id]
                    full_sym = f"{cls_name}.{'.'.join(attrs)}"
                    return (pkg_name, full_sym)
        return None

    def visit_Call(self, node: ast.Call) -> None:
        resolved = self._resolve_call_symbol(node.func)
        if resolved:
            pkg_name, full_sym = resolved
            source_line = (
                self.lines[node.lineno - 1].strip()
                if 0 < node.lineno <= len(self.lines)
                else ""
            )
            evidence = CallSiteEvidence(
                package=pkg_name,
                file=self.rel_path,
                lineno=node.lineno,
                col_offset=node.col_offset,
                caller_symbol=".".join(self.scope_stack),
                called_symbol=full_sym,
                source_line=source_line,
            )
            self.call_sites.append(evidence)
        self.generic_visit(node)


class ReachabilityAnalyzer:
    """Indexes Python source code to detect imported packages and invoked symbols."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self.package_imports: dict[str, list[tuple[str, int]]] = {}
        self.package_calls: dict[str, list[CallSiteEvidence]] = {}
        self._indexed = False

    def index(self) -> None:
        if self._indexed:
            return
        self._indexed = True

        for dirpath, dirnames, filenames in os.walk(self.repo_root):
            # Exclude virtual environments, node modules, and hidden directories
            dirnames[:] = [
                d
                for d in dirnames
                if not d.startswith(".")
                and d not in ("venv", ".venv", "node_modules", "__pycache__", "site-packages")
            ]

            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = Path(dirpath) / fname
                try:
                    rel_path = fpath.relative_to(self.repo_root).as_posix()
                    code = fpath.read_text(encoding="utf-8")
                    tree = ast.parse(code, filename=rel_path)
                except Exception:
                    continue

                lines = code.splitlines()
                visitor = _CallGraphVisitor(rel_path, lines)
                visitor.visit(tree)

                for pkg, lines_list in visitor.imported_packages.items():
                    for line_num in lines_list:
                        self.package_imports.setdefault(pkg, []).append((rel_path, line_num))

                for cs in visitor.call_sites:
                    self.package_calls.setdefault(cs.package, []).append(cs)

    def analyze_reachability(
        self,
        dep: DependencyRecord,
        adv: AdvisoryRecord,
    ) -> DependencyReachability:
        self.index()
        pkg_key = dep.name.lower().replace("-", "_")

        candidate_keys = {pkg_key, dep.name.lower(), dep.name.lower().replace("_", "-")}

        # Collect import sites for package name variants
        import_sites: list[tuple[str, int]] = []
        for k in candidate_keys:
            if k in self.package_imports:
                for site in self.package_imports[k]:
                    if site not in import_sites:
                        import_sites.append(site)

        if not import_sites:
            return DependencyReachability(
                dependency=dep,
                advisory=adv,
                status="unreachable",
                import_sites=(),
                call_sites=(),
                reason=f"Package '{dep.name}' is declared in {dep.file} but is never imported in project source code.",
            )

        # Collect calls across package name variants
        calls: list[CallSiteEvidence] = []
        for k in candidate_keys:
            if k in self.package_calls:
                for cs in self.package_calls[k]:
                    if cs not in calls:
                        calls.append(cs)

        if not adv.vulnerable_symbols:
            if calls:
                return DependencyReachability(
                    dependency=dep,
                    advisory=adv,
                    status="reachable",
                    import_sites=tuple(import_sites),
                    call_sites=tuple(calls),
                    reason=f"Package '{dep.name}' is actively invoked across {len(calls)} call site(s).",
                )
            else:
                return DependencyReachability(
                    dependency=dep,
                    advisory=adv,
                    status="imported_uninvoked",
                    import_sites=tuple(import_sites),
                    call_sites=(),
                    reason=f"Package '{dep.name}' is imported at {len(import_sites)} site(s), but no invocations were observed.",
                )

        # Check call sites against vulnerable symbols
        matching_calls: list[CallSiteEvidence] = []
        for cs in calls:
            for vs in adv.vulnerable_symbols:
                vs_lower = vs.lower()
                called_lower = cs.called_symbol.lower()
                if (
                    called_lower == vs_lower
                    or called_lower.endswith(f".{vs_lower}")
                    or vs_lower in called_lower
                ):
                    matching_calls.append(cs)
                    break

        if matching_calls:
            return DependencyReachability(
                dependency=dep,
                advisory=adv,
                status="reachable",
                import_sites=tuple(import_sites),
                call_sites=tuple(matching_calls),
                reason=(
                    f"Vulnerable symbol(s) {list(adv.vulnerable_symbols)} in {dep.name} are actively "
                    f"invoked at {len(matching_calls)} call site(s) in source code."
                ),
            )

        return DependencyReachability(
            dependency=dep,
            advisory=adv,
            status="imported_uninvoked",
            import_sites=tuple(import_sites),
            call_sites=(),
            reason=(
                f"Package '{dep.name}' is imported at {len(import_sites)} site(s), "
                f"but vulnerable symbols {list(adv.vulnerable_symbols)} are not invoked."
            ),
        )
