"""Deterministic fixer and patch candidate proposer for unsafe deserialization (CWE-502)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate


class SafeDeserializationFixer(BaseFixer):
    """AST fixer that migrates unsafe deserialization (yaml.load, pickle.loads) to safe alternatives."""

    rule_id = "xbnd.unsafe-deserialization"
    name = "safe_deserialization"

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        replacements: list[tuple[int, int, int, int, str, str, str]] = []
        has_json_import = False
        migrated_pickle_to_json = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "json":
                        has_json_import = True
            elif isinstance(node, ast.ImportFrom) and node.module == "json":
                has_json_import = True

            if isinstance(node, ast.Call):
                # 1. yaml.load(...)
                is_yaml_load = False
                if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                        is_yaml_load = True

                if is_yaml_load:
                    loader_kw = None
                    for kw in node.keywords:
                        if kw.arg == "Loader":
                            loader_kw = kw
                            break

                    if loader_kw is not None:
                        # If Loader is not already SafeLoader, replace it
                        is_safe_loader = False
                        if isinstance(loader_kw.value, ast.Attribute) and loader_kw.value.attr == "SafeLoader":
                            is_safe_loader = True
                        elif isinstance(loader_kw.value, ast.Name) and loader_kw.value.id == "SafeLoader":
                            is_safe_loader = True

                        if not is_safe_loader:
                            new_loader_val: ast.expr
                            if isinstance(loader_kw.value, ast.Attribute):
                                new_loader_val = ast.Attribute(
                                    value=loader_kw.value.value, attr="SafeLoader", ctx=ast.Load()
                                )
                            else:
                                new_loader_val = ast.Name(id="SafeLoader", ctx=ast.Load())

                            new_keywords = [
                                ast.keyword(arg="Loader", value=new_loader_val)
                                if k.arg == "Loader"
                                else k
                                for k in node.keywords
                            ]
                            new_call = ast.Call(
                                func=node.func,
                                args=list(node.args),
                                keywords=new_keywords,
                            )
                            ast.copy_location(new_call, node)
                            ast.fix_missing_locations(new_call)
                            new_code = ast.unparse(new_call)

                            s_line = node.lineno
                            e_line = node.end_lineno or node.lineno
                            s_col = node.col_offset
                            e_col = node.end_col_offset or len(lines[e_line - 1])
                            old_code = (
                                lines[s_line - 1][s_col:e_col]
                                if s_line == e_line
                                else "".join(lines[s_line - 1 : e_line])
                            )
                            replacements.append(
                                (
                                    s_line,
                                    e_line,
                                    s_col,
                                    e_col,
                                    old_code,
                                    new_code,
                                    "Pin yaml.load Loader to SafeLoader (CWE-502)",
                                )
                            )

                    else:
                        # No Loader keyword: migrate yaml.load -> yaml.safe_load
                        assert isinstance(node.func, ast.Attribute)
                        new_func = ast.Attribute(
                            value=node.func.value,
                            attr="safe_load",
                            ctx=ast.Load(),
                        )
                        new_call = ast.Call(
                            func=new_func,
                            args=list(node.args),
                            keywords=list(node.keywords),
                        )
                        ast.copy_location(new_call, node)
                        ast.fix_missing_locations(new_call)
                        new_code = ast.unparse(new_call)

                        s_line = node.lineno
                        e_line = node.end_lineno or node.lineno
                        s_col = node.col_offset
                        e_col = node.end_col_offset or len(lines[e_line - 1])
                        old_code = (
                            lines[s_line - 1][s_col:e_col]
                            if s_line == e_line
                            else "".join(lines[s_line - 1 : e_line])
                        )
                        replacements.append(
                            (
                                s_line,
                                e_line,
                                s_col,
                                e_col,
                                old_code,
                                new_code,
                                "Migrate yaml.load to yaml.safe_load (CWE-502)",
                            )
                        )

                # 2. pickle.loads(...) -> json.loads(...)
                is_pickle_loads = False
                if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in (
                        "pickle",
                        "_pickle",
                    ):
                        is_pickle_loads = True

                if is_pickle_loads:
                    migrated_pickle_to_json = True
                    new_func = ast.Attribute(
                        value=ast.Name(id="json", ctx=ast.Load()),
                        attr="loads",
                        ctx=ast.Load(),
                    )
                    new_call = ast.Call(
                        func=new_func,
                        args=list(node.args),
                        keywords=list(node.keywords),
                    )
                    ast.copy_location(new_call, node)
                    ast.fix_missing_locations(new_call)
                    new_code = ast.unparse(new_call)

                    s_line = node.lineno
                    e_line = node.end_lineno or node.lineno
                    s_col = node.col_offset
                    e_col = node.end_col_offset or len(lines[e_line - 1])
                    old_code = (
                        lines[s_line - 1][s_col:e_col]
                        if s_line == e_line
                        else "".join(lines[s_line - 1 : e_line])
                    )
                    replacements.append(
                        (
                            s_line,
                            e_line,
                            s_col,
                            e_col,
                            old_code,
                            new_code,
                            "Migrate pickle.loads to json.loads safe deserialization (CWE-502)",
                        )
                    )

        if not replacements:
            return source, []

        replacements.sort(key=lambda r: (r[0], r[2]), reverse=True)
        modified_lines = list(lines)

        for s_line, e_line, s_col, e_col, old_code, new_code, desc in replacements:
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
                    description=desc,
                    lineno=s_line,
                    before=old_code,
                    after=new_code,
                )
            )

        # Inject import json if pickle was migrated and json is absent
        if migrated_pickle_to_json and not has_json_import:
            import_idx = 0
            for i, line in enumerate(modified_lines):
                stripped = line.strip()
                if stripped.startswith('"""') or stripped.startswith("'''") or stripped.startswith("#"):
                    continue
                if stripped.startswith("from __future__"):
                    import_idx = i + 1
                    continue
                break
            modified_lines.insert(import_idx, "import json\n")
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description="Import json module for safe deserialization",
                    lineno=import_idx + 1,
                    before="",
                    after="import json\n",
                )
            )

        new_source = "".join(modified_lines)
        return new_source, changes

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

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="security",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Migrate unsafe deserialization sink to safe serializer",
            generator="plex.repair.safe_deserialization",
            generator_version="1.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback_diff,
            metadata=metadata or {},
        )
