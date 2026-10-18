"""Experimental path traversal rule (CWE-22)."""

from __future__ import annotations

from .injection import DataflowInjectionRule

PATH_LIMITATIONS = (
    "Path traversal rule checks file open, deletion, copy, and web send_file sinks",
    "os.path.basename, werkzeug secure_filename and the _plex_within_base containment helper inserted by fix.path-boundary are treated as path sanitizers",
    "Absolute paths and symlink resolution outside the model may still produce false negatives",
)

__all__ = ["PATH_LIMITATIONS", "PathTraversalRule"]


class PathTraversalRule(DataflowInjectionRule):
    id = "xbnd.path-traversal"
    name = "Untrusted input in file path"
    description = (
        "Untrusted input reaches filesystem path sink without directory traversal sanitation."
    )
    kind = "path"
    limitations = PATH_LIMITATIONS
    cwe = "CWE-22"
    owasp = ["A01:2025"]
    default_severity = "high"
    tags = ["security", "injection", "CWE-22", "A01:2025"]
    message = "Untrusted input reaches file path sink without basename or directory validation."
    remediation = "Use os.path.basename or secure_filename, and ensure paths resolve within an authorized root directory."
