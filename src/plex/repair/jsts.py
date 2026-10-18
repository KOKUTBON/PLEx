"""Deterministic repair fixers for JavaScript and TypeScript security findings."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate

JS_TS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


def is_jsts_file(path_str: str) -> bool:
    return any(path_str.endswith(ext) for ext in JS_TS_EXTENSIONS)


class JsSQLParameterizeFixer(BaseFixer):
    """Deterministic fixer parameterizing dynamic SQL queries in JavaScript and TypeScript."""

    rule_id = "xbnd.sql-injection"
    name = "fix.js.sql-parameterize"
    auto_apply = True

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        if not is_jsts_file(file_path):
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        new_lines: list[str] = []

        param_token = "?" if ("mysql" in source.lower() or "sqlite" in source.lower()) else "$1"

        for lno, line in enumerate(lines, start=1):
            # Template literal: db.query(`SELECT ... ${var}`)
            t_match = re.search(
                r'(\b\w+)\.query\(\s*`([^`]*)\$\{([a-zA-Z0-9_\.]+)\}([^`]*)`\s*\)',
                line,
            )
            # String concat: db.query("SELECT ... " + var)
            c_match = re.search(
                r'(\b\w+)\.query\(\s*["\']([^"\']+)["\']\s*\+\s*([a-zA-Z0-9_\.]+)\s*\)',
                line,
            )

            if t_match:
                callee, prefix, var, suffix = t_match.groups()
                new_sql = f'"{prefix}{param_token}{suffix}"'
                rep = f"{callee}.query({new_sql}, [{var}])"
                fixed_line = line[: t_match.start()] + rep + line[t_match.end() :]
                new_lines.append(fixed_line)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description=f"Parameterize query placeholder for '{var}'",
                        lineno=lno,
                        before=line,
                        after=fixed_line,
                    )
                )
            elif c_match:
                callee, prefix, var = c_match.groups()
                new_sql = f'"{prefix}{param_token}"'
                rep = f"{callee}.query({new_sql}, [{var}])"
                fixed_line = line[: c_match.start()] + rep + line[c_match.end() :]
                new_lines.append(fixed_line)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description=f"Parameterize query placeholder for '{var}'",
                        lineno=lno,
                        before=line,
                        after=fixed_line,
                    )
                )
            else:
                new_lines.append(line)

        return "".join(new_lines), changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        if not is_jsts_file(target_file):
            return None

        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        diff = "".join(
            unified_diff(
                source.splitlines(keepends=True),
                fixed_source.splitlines(keepends=True),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback = "".join(
            unified_diff(
                fixed_source.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}",
            target_file=target_file,
            diff=diff,
            description="Parameterize dynamic SQL query in JavaScript/TypeScript",
            preconditions=("call is db.query with single interpolated value",),
            generator="plex.repair.jsts.sql",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback,
        )


class JsCommandArrayFixer(BaseFixer):
    """Deterministic fixer replacing shell execution with execFile argument arrays."""

    rule_id = "xbnd.command-injection"
    name = "fix.js.command-array"
    auto_apply = True

    ALLOWLISTED_COMMANDS = frozenset(
        {"cat", "ls", "wc", "git", "grep", "find", "head", "tail", "ping", "echo", "curl"}
    )

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        if not is_jsts_file(file_path):
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        new_lines: list[str] = []
        needs_execfile_import = False

        for lno, line in enumerate(lines, start=1):
            match = re.search(
                r'(\b[a-zA-Z0-9_]+\.)?exec\(\s*(?:["\']([^"\']+)["\']\s*\+\s*([a-zA-Z0-9_\.]+)|`([^`]+)\$\{([a-zA-Z0-9_\.]+)\}`)',
                line,
            )
            if not match:
                new_lines.append(line)
                continue

            callee = match.group(1) or ""
            prefix = (match.group(2) or match.group(4) or "").strip()
            arg = match.group(3) or match.group(5) or ""

            tokens = prefix.split()
            if not tokens:
                new_lines.append(line)
                continue

            cmd = tokens[0]
            if cmd not in self.ALLOWLISTED_COMMANDS:
                new_lines.append(line)
                continue

            flags = tokens[1:]
            flag_args = [f'"{f}"' for f in flags]
            all_args = flag_args + [arg]
            args_str = ", ".join(all_args)

            rep = f'{callee}execFile("{cmd}", [{args_str}]'
            fixed_line = line[: match.start()] + rep + line[match.end() :]
            new_lines.append(fixed_line)
            if not callee:
                needs_execfile_import = True
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description=f"Replace shell exec with execFile for '{cmd}'",
                    lineno=lno,
                    before=line,
                    after=fixed_line,
                )
            )

        if not changes:
            return source, []

        fixed_content = "".join(new_lines)
        if needs_execfile_import and "execFile" not in source:
            import_line = 'const { execFile } = require("child_process");\n'
            fixed_content = import_line + fixed_content

        return fixed_content, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        if not is_jsts_file(target_file):
            return None

        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        diff = "".join(
            unified_diff(
                source.splitlines(keepends=True),
                fixed_source.splitlines(keepends=True),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback = "".join(
            unified_diff(
                fixed_source.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}",
            target_file=target_file,
            diff=diff,
            description="Replace shell exec with execFile in JavaScript/TypeScript",
            preconditions=("command is allowlisted executable without shell syntax",),
            generator="plex.repair.jsts.command",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback,
        )


class JsPathBoundaryFixer(BaseFixer):
    """Deterministic fixer enforcing path confinement within base directory in JS/TS."""

    rule_id = "xbnd.path-traversal"
    name = "fix.js.path-boundary"
    auto_apply = True

    HELPER_CODE = """function _plexWithinBase(base, target) {
  const path = require("path");
  const resolved = path.resolve(base, target);
  if (!resolved.startsWith(path.resolve(base))) {
    throw new Error("Path traversal detected outside base directory");
  }
  return resolved;
}
"""

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        if not is_jsts_file(file_path):
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        new_lines: list[str] = []

        base_dir = "BASE_DIR" if "BASE_DIR" in source else "__dirname"

        for lno, line in enumerate(lines, start=1):
            match = re.search(
                r'(\bfs\.(?:readFile|readFileSync|createReadStream)|res\.sendFile)\(\s*([a-zA-Z0-9_\.]+)',
                line,
            )
            if not match:
                new_lines.append(line)
                continue

            sink = match.group(1)
            path_arg = match.group(2)

            rep = f"{sink}(_plexWithinBase({base_dir}, {path_arg})"
            fixed_line = line[: match.start()] + rep + line[match.end() :]
            new_lines.append(fixed_line)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description=f"Confine target file path inside base directory ({base_dir})",
                    lineno=lno,
                    before=line,
                    after=fixed_line,
                )
            )

        if not changes:
            return source, []

        fixed_content = "".join(new_lines)
        if "_plexWithinBase" not in source:
            fixed_content = self.HELPER_CODE + fixed_content

        return fixed_content, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        if not is_jsts_file(target_file):
            return None

        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        diff = "".join(
            unified_diff(
                source.splitlines(keepends=True),
                fixed_source.splitlines(keepends=True),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback = "".join(
            unified_diff(
                fixed_source.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}",
            target_file=target_file,
            diff=diff,
            description="Confine target path inside base directory in JavaScript/TypeScript",
            preconditions=("base directory is accessible",),
            generator="plex.repair.jsts.path",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback,
        )


class JsOpenRedirectFixer(BaseFixer):
    """Deterministic fixer wrapping target redirect URL in safe relative URL helper."""

    rule_id = "xbnd.open-redirect"
    name = "fix.js.open-redirect"
    auto_apply = True

    HELPER_CODE = """function _plexSafeRedirect(url) {
  if (typeof url === "string" && url.startsWith("/") && !url.startsWith("//") && !url.includes("\\\\")) {
    return url;
  }
  return "/";
}
"""

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        if not is_jsts_file(file_path):
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        new_lines: list[str] = []

        for lno, line in enumerate(lines, start=1):
            match = re.search(r'(\bres\.redirect)\(\s*([a-zA-Z0-9_\.]+)\s*\)', line)
            if not match:
                new_lines.append(line)
                continue

            sink = match.group(1)
            url_arg = match.group(2)

            rep = f"{sink}(_plexSafeRedirect({url_arg}))"
            fixed_line = line[: match.start()] + rep + line[match.end() :]
            new_lines.append(fixed_line)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description=f"Wrap redirect target '{url_arg}' in _plexSafeRedirect",
                    lineno=lno,
                    before=line,
                    after=fixed_line,
                )
            )

        if not changes:
            return source, []

        fixed_content = "".join(new_lines)
        if "_plexSafeRedirect" not in source:
            fixed_content = self.HELPER_CODE + fixed_content

        return fixed_content, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        if not is_jsts_file(target_file):
            return None

        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        diff = "".join(
            unified_diff(
                source.splitlines(keepends=True),
                fixed_source.splitlines(keepends=True),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback = "".join(
            unified_diff(
                fixed_source.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}",
            target_file=target_file,
            diff=diff,
            description="Enforce relative URL in res.redirect() in JavaScript/TypeScript",
            preconditions=("call is res.redirect",),
            generator="plex.repair.jsts.redirect",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback,
        )


class JsNoSQLInjectionFixer(BaseFixer):
    """Deterministic fixer filtering operator injection keys in NoSQL query filters."""

    rule_id = "xbnd.nosql-injection"
    name = "fix.js.nosql-injection"
    auto_apply = True

    HELPER_CODE = """function _plexRejectOperators(val) {
  if (val && typeof val === "object") {
    for (const k of Object.keys(val)) {
      if (k.startsWith("$")) throw new Error("Operator injection blocked: " + k);
      _plexRejectOperators(val[k]);
    }
  }
  return val;
}
"""

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        if not is_jsts_file(file_path):
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        new_lines: list[str] = []

        for lno, line in enumerate(lines, start=1):
            match = re.search(
                r'(\b\w+\.(?:find|findOne|updateMany|deleteMany))\(\s*([a-zA-Z0-9_\.]+)\s*\)',
                line,
            )
            if not match:
                new_lines.append(line)
                continue

            sink = match.group(1)
            filter_arg = match.group(2)

            rep = f"{sink}(_plexRejectOperators({filter_arg}))"
            fixed_line = line[: match.start()] + rep + line[match.end() :]
            new_lines.append(fixed_line)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description=f"Wrap NoSQL filter '{filter_arg}' in _plexRejectOperators",
                    lineno=lno,
                    before=line,
                    after=fixed_line,
                )
            )

        if not changes:
            return source, []

        fixed_content = "".join(new_lines)
        if "_plexRejectOperators" not in source:
            fixed_content = self.HELPER_CODE + fixed_content

        return fixed_content, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        if not is_jsts_file(target_file):
            return None

        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        diff = "".join(
            unified_diff(
                source.splitlines(keepends=True),
                fixed_source.splitlines(keepends=True),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback = "".join(
            unified_diff(
                fixed_source.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}",
            target_file=target_file,
            diff=diff,
            description="Filter MongoDB operator keys in JavaScript/TypeScript",
            preconditions=("call is NoSQL collection filter",),
            generator="plex.repair.jsts.nosql",
            generator_version="2.0.0",
            confidence="derived",
            risk="low",
            rollback_diff=rollback,
        )


class JsCodeEvalFixer(BaseFixer):
    """Proposal-only fixer for dynamic code evaluation in JavaScript and TypeScript."""

    rule_id = "xbnd.eval-injection"
    name = "fix.js.code-eval"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        if not is_jsts_file(file_path):
            return source, []

        lines = source.splitlines(keepends=True)
        changes: list[FixChange] = []
        new_lines: list[str] = []

        for lno, line in enumerate(lines, start=1):
            match = re.search(r'\beval\(\s*([a-zA-Z0-9_\.]+)\s*\)', line)
            if not match:
                new_lines.append(line)
                continue

            arg = match.group(1)
            rep = f"JSON.parse({arg})"
            fixed_line = line[: match.start()] + rep + line[match.end() :]
            new_lines.append(fixed_line)
            changes.append(
                FixChange(
                    rule_id=self.rule_id,
                    description=f"Replace dynamic eval with JSON.parse for '{arg}'",
                    lineno=lno,
                    before=line,
                    after=fixed_line,
                )
            )

        return "".join(new_lines), changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        if not is_jsts_file(target_file):
            return None

        fixed_source, changes = self.fix(source, target_file)
        if not changes or fixed_source == source:
            return None

        diff = "".join(
            unified_diff(
                source.splitlines(keepends=True),
                fixed_source.splitlines(keepends=True),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback = "".join(
            unified_diff(
                fixed_source.splitlines(keepends=True),
                source.splitlines(keepends=True),
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="xboundary",
            source_digest=f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}",
            target_file=target_file,
            diff=diff,
            description="Replace dynamic eval with JSON.parse in JavaScript/TypeScript",
            preconditions=("input must be valid JSON; proposal only",),
            generator="plex.repair.jsts.eval",
            generator_version="2.0.0",
            confidence="inferred",
            risk="medium",
            rollback_diff=rollback,
        )
