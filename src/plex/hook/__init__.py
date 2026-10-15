"""PLEx Git hook integration and pre-commit framework support."""

from __future__ import annotations

from .manager import (
    generate_hook_script,
    generate_pre_commit_config,
    install_hook,
    uninstall_hook,
)

__all__ = [
    "generate_hook_script",
    "generate_pre_commit_config",
    "install_hook",
    "uninstall_hook",
]
