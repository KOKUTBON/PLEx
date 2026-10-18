"""Source and debug mapping for binary inspection findings.

In accordance with Section 7.2 of the PLEx 2.0 architecture:
When source code is available in the repository, map binary evidence back to
source files and lines, enabling unified remediation and rebuild comparison.
"""

from __future__ import annotations

import os
import re
from dataclasses import replace
from pathlib import Path

from plex.report.unified import AnalysisFinding

from .models import ArtifactDescriptor

SOURCE_EXTENSIONS = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".rs", ".go")


class SourceDebugMapper:
    """Correlates binary function symbols and call sites back to source tree files and lines."""

    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root.resolve()
        self._index_source_files()

    def _index_source_files(self) -> None:
        # Map function_name -> list of (relative_file_path, line_number)
        self.function_defs: dict[str, list[tuple[str, int]]] = {}
        # Map symbol_call -> list of (relative_file_path, line_number)
        self.symbol_calls: dict[str, list[tuple[str, int]]] = {}

        if not self.source_root.is_dir():
            return

        for root, dirs, files in os.walk(self.source_root):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("build", "target", "vendor", "node_modules")]
            for fname in files:
                if any(fname.endswith(ext) for ext in SOURCE_EXTENSIONS):
                    fpath = Path(root) / fname
                    rel_path = fpath.relative_to(self.source_root).as_posix()
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue

                    lines = content.splitlines()
                    for lno, line in enumerate(lines, start=1):
                        sline = line.strip()
                        if sline.startswith("//") or sline.startswith("/*") or sline.startswith("*"):
                            continue

                        # Function definition heuristic: void foo(...) or fn foo(...)
                        fn_match = re.search(r'\b(?:void|int|char|bool|size_t|ssize_t|auto|fn|func)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
                        if fn_match:
                            fn_name = fn_match.group(1)
                            self.function_defs.setdefault(fn_name, []).append((rel_path, lno))

                        # Call expression heuristic: name(...)
                        for call_match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line):
                            call_name = call_match.group(1)
                            self.symbol_calls.setdefault(call_name, []).append((rel_path, lno))

    def map_findings(
        self,
        findings: list[AnalysisFinding],
        descriptor: ArtifactDescriptor | None = None,
    ) -> list[AnalysisFinding]:
        """Correlate findings to source files and line numbers where matches exist."""
        mapped: list[AnalysisFinding] = []

        dwarf_sources: set[str] = set()
        if descriptor and descriptor.metadata:
            dwarf_sources = set(descriptor.metadata.get("source_files", []))

        for finding in findings:
            caller_fn = finding.engine_meta.get("caller_function")
            symbol = finding.engine_meta.get("symbol")
            if not symbol and finding.engine_meta.get("matched_symbols"):
                matched_syms = finding.engine_meta.get("matched_symbols") or []
                for s in matched_syms:
                    if s in self.symbol_calls:
                        symbol = s
                        break
                if not symbol and matched_syms:
                    symbol = matched_syms[0]

            source_file: str | None = None
            source_line: int | None = None

            # 1. Try matching the specific call within the caller function
            if symbol and symbol in self.symbol_calls:
                call_candidates = self.symbol_calls[symbol]
                if caller_fn and caller_fn in self.function_defs:
                    fn_defs = self.function_defs[caller_fn]
                    # Find a call candidate residing in the same file as the function definition
                    for fn_file, fn_line in fn_defs:
                        matching_call = next(
                            (c for c in call_candidates if c[0] == fn_file and c[1] >= fn_line),
                            None,
                        )
                        if matching_call:
                            source_file, source_line = matching_call
                            break
                if not source_file:
                    # Prefer candidate matching DWARF source files if available
                    if dwarf_sources:
                        dwarf_candidate = next(
                            (c for c in call_candidates if c[0] in dwarf_sources or Path(c[0]).name in dwarf_sources),
                            None,
                        )
                        if dwarf_candidate:
                            source_file, source_line = dwarf_candidate
                    if not source_file:
                        # Fallback: first candidate call site
                        source_file, source_line = call_candidates[0]

            # 2. Try matching the caller function definition directly
            elif caller_fn and caller_fn in self.function_defs:
                fn_candidates = self.function_defs[caller_fn]
                if dwarf_sources:
                    dwarf_fn = next(
                        (f for f in fn_candidates if f[0] in dwarf_sources or Path(f[0]).name in dwarf_sources),
                        None,
                    )
                    if dwarf_fn:
                        source_file, source_line = dwarf_fn
                if not source_file:
                    source_file, source_line = fn_candidates[0]

            if source_file and source_line is not None:
                updated_meta = dict(finding.engine_meta)
                updated_meta["source_mapped"] = True
                updated_meta["binary_path"] = finding.file
                updated_meta["source_file"] = source_file
                updated_meta["source_line"] = source_line
                if dwarf_sources and (source_file in dwarf_sources or Path(source_file).name in dwarf_sources):
                    updated_meta["debug_provenance"] = "dwarf"
                if descriptor and descriptor.metadata.get("pdb_path"):
                    updated_meta["pdb_path"] = descriptor.metadata["pdb_path"]

                mapped_finding = replace(
                    finding,
                    file=source_file,
                    lineno=source_line,
                    qualname=caller_fn or finding.qualname,
                    engine_meta=updated_meta,
                )
                mapped.append(mapped_finding)
            else:
                mapped.append(finding)

        return mapped
