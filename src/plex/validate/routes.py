"""Static route and API endpoint discovery linking source code to reachable URLs."""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RouteEndpoint:
    """An HTTP endpoint discovered from application source code or API specifications."""

    path: str
    methods: tuple[str, ...]
    handler_qualname: str
    file: str
    lineno: int
    end_lineno: int
    framework: str
    parameters: tuple[str, ...] = ()


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


def parse_openapi_spec(
    spec_path: Path,
    repo_root: Path | None = None,
) -> list[RouteEndpoint]:
    """Parse OpenAPI 3.x or Swagger 2.0 specification to extract route endpoints."""
    resolved = spec_path.resolve()
    if not resolved.is_file():
        return []

    try:
        content = resolved.read_text(encoding="utf-8")
    except OSError:
        return []

    data: dict[str, Any] | None = None
    try:
        import yaml

        data = yaml.safe_load(content)
    except Exception:
        try:
            data = json.loads(content)
        except Exception:
            return []

    if not isinstance(data, dict):
        return []

    rel_file = resolved.as_posix()
    if repo_root:
        try:
            rel_file = resolved.relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            pass

    endpoints: list[RouteEndpoint] = []
    base_path = ""
    if "swagger" in data and isinstance(data.get("basePath"), str):
        bp = data["basePath"].strip()
        if bp and bp != "/":
            base_path = "/" + bp.strip("/")

    paths = data.get("paths")
    if not isinstance(paths, dict):
        return endpoints

    http_methods = ("get", "post", "put", "delete", "patch", "head", "options")

    for path_str, path_spec in paths.items():
        if not isinstance(path_str, str) or not isinstance(path_spec, dict):
            continue

        full_path = (base_path + "/" + path_str.lstrip("/")).rstrip("/") or "/"

        path_level_params: list[str] = []
        for p in path_spec.get("parameters", []):
            if isinstance(p, dict) and "name" in p:
                path_level_params.append(str(p["name"]))

        for method, op_spec in path_spec.items():
            if method.lower() not in http_methods or not isinstance(op_spec, dict):
                continue

            op_params = list(path_level_params)
            for p in op_spec.get("parameters", []):
                if isinstance(p, dict) and "name" in p:
                    op_params.append(str(p["name"]))

            handler_name = op_spec.get("operationId") or f"{method.upper()}_{path_str}"
            endpoints.append(
                RouteEndpoint(
                    path=full_path,
                    methods=(method.upper(),),
                    handler_qualname=str(handler_name),
                    file=rel_file,
                    lineno=1,
                    end_lineno=1,
                    framework="openapi",
                    parameters=tuple(dict.fromkeys(op_params)),
                )
            )

    return endpoints


def _discover_jsts_routes(fpath: Path, rel_path: str) -> list[RouteEndpoint]:
    """Extract Express.js, Fastify, and Next.js routes from JavaScript/TypeScript source."""
    endpoints: list[RouteEndpoint] = []
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return endpoints

    lines = content.splitlines()

    # 1. Express / Fastify / Router methods: app.get("/users", ...) or router.post(...)
    route_regex = re.compile(
        r'\b(?:app|router|server|fastify)\.(get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']'
    )
    for lno, line in enumerate(lines, start=1):
        for match in route_regex.finditer(line):
            method = match.group(1).upper()
            url_path = match.group(2)
            params = tuple(re.findall(r":([a-zA-Z_][a-zA-Z0-9_]*)", url_path))
            framework = "fastify" if "fastify" in line else "express"
            endpoints.append(
                RouteEndpoint(
                    path=url_path,
                    methods=(method,),
                    handler_qualname=f"{framework}_handler_L{lno}",
                    file=rel_path,
                    lineno=lno,
                    end_lineno=lno,
                    framework=framework,
                    parameters=params,
                )
            )

    # 2. Next.js App Router: app/**/route.{ts,js,mjs}
    fpath_str = fpath.as_posix()
    if "/app/" in fpath_str or fpath_str.startswith("app/"):
        fname_base = fpath.name.split(".")[0]
        if fname_base == "route":
            parts = fpath.parts
            if "app" in parts:
                app_idx = parts.index("app")
                route_parts = parts[app_idx + 1 : -1]
                clean_parts = [
                    p for p in route_parts if not (p.startswith("(") and p.endswith(")"))
                ]
                url_path = "/" + "/".join(clean_parts)
                methods: list[str] = []
                for m in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    if re.search(rf"\bexport\s+(?:async\s+)?function\s+{m}\b", content):
                        methods.append(m)
                if methods:
                    endpoints.append(
                        RouteEndpoint(
                            path=url_path,
                            methods=tuple(methods),
                            handler_qualname="nextjs_route_handler",
                            file=rel_path,
                            lineno=1,
                            end_lineno=len(lines),
                            framework="nextjs",
                        )
                    )

    # 3. Next.js Pages Router: pages/api/**/*.ts
    elif "/pages/api/" in fpath_str or fpath_str.startswith("pages/api/"):
        parts = fpath.parts
        if "pages" in parts:
            p_idx = parts.index("pages")
            api_parts = list(parts[p_idx + 1 : -1])
            stem = fpath.stem
            if stem != "index":
                api_parts.append(stem)
            url_path = "/" + "/".join(api_parts)
            endpoints.append(
                RouteEndpoint(
                    path=url_path,
                    methods=("GET", "POST"),
                    handler_qualname="nextjs_pages_handler",
                    file=rel_path,
                    lineno=1,
                    end_lineno=len(lines),
                    framework="nextjs",
                )
            )

    return endpoints


def discover_routes(
    repo_root: Path,
    spec_path: Path | None = None,
) -> list[RouteEndpoint]:
    """Scan Python and JS/TS files or API specifications in repo_root to discover declared routes."""
    endpoints: list[RouteEndpoint] = []
    root = repo_root.resolve()

    # 1. Parse explicitly supplied or auto-discovered OpenAPI/Swagger spec
    if spec_path and spec_path.is_file():
        endpoints.extend(parse_openapi_spec(spec_path, repo_root=root))
    else:
        for cand in (
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "swagger.json",
            "swagger.yaml",
            "swagger.yml",
        ):
            cand_path = root / cand
            if cand_path.is_file():
                endpoints.extend(parse_openapi_spec(cand_path, repo_root=root))
                break

    # 2. Walk repository source tree
    skip_dirs = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        ".tox",
        ".mypy_cache",
    }
    for dirpath, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel_path = fpath.relative_to(root).as_posix()

            # Python web routes (Flask, FastAPI, Django)
            if fname.endswith(".py"):
                try:
                    content = fpath.read_text(encoding="utf-8")
                    tree = ast.parse(content, filename=rel_path)
                    visitor = _RouteVisitor(rel_path)
                    visitor.visit(tree)
                    endpoints.extend(visitor.endpoints)
                except Exception:
                    continue

            # JavaScript / TypeScript routes (Express, Fastify, Next.js)
            elif fname.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
                endpoints.extend(_discover_jsts_routes(fpath, rel_path))

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
