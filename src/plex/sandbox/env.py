"""Environment scrubbing and secret allowlisting for subprocess isolation."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import Final

# Benign system and language runtime environment variables
SAFE_ENV_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        # Execution & Search paths
        "PATH",
        "PATHEXT",
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        # Locale & Internationalization
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "TZ",
        # User & Terminal context
        "USER",
        "LOGNAME",
        "USERNAME",
        "HOME",
        "USERPROFILE",
        "TERM",
        "TERMINFO",
        "SHELL",
        # Temporary directories
        "TMP",
        "TEMP",
        "TMPDIR",
        # Windows system paths
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "COMMONPROGRAMFILES",
        "SYSTEMDRIVE",
    }
)

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|AUTH|CREDENTIAL|CRED|AWS_|GITHUB_|GH_|STRIX_|OPENAI_|ANTHROPIC_|AZURE_|GCP_|PRIVATE)",
    re.IGNORECASE,
)


def is_sensitive_env_key(key: str) -> bool:
    """Return True if an environment key matches common credential or secret patterns."""
    return bool(_SENSITIVE_KEY_PATTERN.search(key))


def clean_env(
    base_env: Mapping[str, str] | None = None,
    extra_env: Mapping[str, str] | None = None,
    allowlist: frozenset[str] | set[str] | None = None,
    inherit_vars: tuple[str, ...] = (),
    scrub_sensitive: bool = True,
) -> dict[str, str]:
    """Produce a sanitized environment mapping containing only allowlisted, non-sensitive variables.

    Always enforces PYTHONHASHSEED=0 for deterministic Python execution.
    """
    source = os.environ if base_env is None else base_env
    allowed = SAFE_ENV_ALLOWLIST if allowlist is None else frozenset(allowlist)
    inherited = frozenset(inherit_vars)

    sanitized: dict[str, str] = {}
    for key, value in source.items():
        # Keep variable only if allowlisted or explicitly inherited
        if key in allowed or key in inherited:
            # Drop if sensitive pattern detected and scrubbing is enabled
            if scrub_sensitive and is_sensitive_env_key(key):
                continue
            sanitized[key] = value

    # Always enforce deterministic hash seed
    sanitized["PYTHONHASHSEED"] = "0"

    # Merge explicit caller overrides
    if extra_env:
        for key, value in extra_env.items():
            sanitized[key] = value

    return sanitized
