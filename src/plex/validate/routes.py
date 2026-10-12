"""Static route and API endpoint discovery linking source code to reachable URLs."""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RouteEndpoint:
    """An HTTP endpoint discovered from application source code."""

    path: str
    methods: tuple[str, ...]
    handler_qualname: str
    file: str
    lineno: int
    end_lineno: int
    framework: str


class _RouteVisitor(ast.NodeVisitor):
    def __init__(self, relative_path: str) -> None:
        self.relative_path = relative_path
        self.endpoints: list[RouteEndpoint] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_decorators(node)
        self.generic_visit(node)

    def _check_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue

            func = dec.func
            # Flask: @app.route("/path", methods=["GET", "POST"]) or @bp.route(...)
            if isinstance(func, ast.Attribute) and func.attr == "route":
                if (
                    dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    url_path = dec.args[0].value
                    methods: list[str] = []
                    for kw in dec.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    methods.append(elt.value.upper())
                    self.endpoints.append(
                        RouteEndpoint(
                            path=url_path,
                            methods=tuple(methods or ["GET"]),
                            handler_qualname=node.name,
                            file=self.relative_path,
                            lineno=node.lineno,
                            end_lineno=getattr(node, "end_lineno", node.lineno),
                            framework="flask",
                        )
                    )

            # FastAPI: @app.get("/path"), @app.post("/path"), @router.put("/path")
            elif isinstance(func, ast.Attribute) and func.attr.lower() in (
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "head",
                "options",
            ):
                if (
                    dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    url_path = dec.args[0].value
                    method = func.attr.upper()
                    self.endpoints.append(
                        RouteEndpoint(
                            path=url_path,
                            methods=(method,),
                            handler_qualname=node.name,
                            file=self.relative_path,
                            lineno=node.lineno,
                            end_lineno=getattr(node, "end_lineno", node.lineno),
                            framework="fastapi",
                        )
                    )

    def visit_Assign(self, node: ast.Assign) -> None:
        # Django: urlpatterns = [path('url/', views.my_view), ...]
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "urlpatterns":
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    self._parse_django_urlpatterns(node.value.elts)
        self.generic_visit(node)

    def _parse_django_urlpatterns(self, elements: list[ast.expr]) -> None:
        for item in elements:
            if not isinstance(item, ast.Call):
                continue
            func = item.func
            func_name = ""
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr

            if func_name in ("path", "re_path") and item.args:
                arg0 = item.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    url_path = "/" + arg0.value.lstrip("/")
                    handler = "view"
                    if len(item.args) > 1:
                        arg1 = item.args[1]
                        if isinstance(arg1, ast.Name):
                            handler = arg1.id
                        elif isinstance(arg1, ast.Attribute):
                            handler = f"{ast.unparse(arg1.value)}.{arg1.attr}"

                    self.endpoints.append(
                        RouteEndpoint(
                            path=url_path,
                            methods=("GET", "POST"),
                            handler_qualname=handler,
                            file=self.relative_path,
                            lineno=item.lineno,
                            end_lineno=getattr(item, "end_lineno", item.lineno),
                            framework="django",
                        )
                    )


def discover_routes(repo_root: Path) -> list[RouteEndpoint]:
    """Scan Python files in repo_root to discover declared API routes."""
    endpoints: list[RouteEndpoint] = []
    root = repo_root.resolve()
    for dirpath, _, filenames in os.walk(root):
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            fpath = Path(dirpath) / fname
            rel_path = fpath.relative_to(root).as_posix()
            try:
                content = fpath.read_text(encoding="utf-8")
                tree = ast.parse(content, filename=rel_path)
                visitor = _RouteVisitor(rel_path)
                visitor.visit(tree)
                endpoints.extend(visitor.endpoints)
            except Exception:
                continue
    return endpoints


def correlate_finding_to_route(
    finding_file: str,
    finding_lineno: int,
    routes: list[RouteEndpoint],
) -> RouteEndpoint | None:
    """Find the route enclosing or defining the finding's code location."""
    matching_file_routes = [r for r in routes if r.file == finding_file]
    if not matching_file_routes:
        return None

    # Find the route where finding_lineno falls between lineno and end_lineno
    for r in matching_file_routes:
        if r.lineno <= finding_lineno <= r.end_lineno:
            return r

    # Or find closest route prior to line
    prior_routes = [r for r in matching_file_routes if r.lineno <= finding_lineno]
    if prior_routes:
        return max(prior_routes, key=lambda r: r.lineno)

    return matching_file_routes[0]
