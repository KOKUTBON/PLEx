"""Container execution boundary contract and runtime availability preflight."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from plex.report.unified import Isolation


@dataclass(frozen=True)
class ContainerSandbox:
    """Isolated container execution boundary for high-risk external engine inspection."""

    runtime: str = "docker"

    @property
    def isolation(self) -> Isolation:
        return "container"

    def supports(self, minimum: Isolation) -> bool:
        return minimum in ("none", "process", "container")

    def preflight(self) -> tuple[bool, list[str]]:
        """Verify that the required container runtime is installed and operational."""
        binary = shutil.which(self.runtime)
        if not binary:
            return False, [f"Container runtime '{self.runtime}' not found in PATH"]

        try:
            res = subprocess.run(
                [binary, "info"],
                capture_output=True,
                timeout=5.0,
                text=True,
            )
            if res.returncode != 0:
                return False, [f"Container daemon '{self.runtime}' is not running or accessible"]
        except Exception as exc:
            return False, [f"Failed to communicate with container runtime '{self.runtime}': {exc}"]

        return True, []
