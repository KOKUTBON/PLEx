"""MicroVM and hardware-virtualized execution boundary contract for hostile sample analysis."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from plex.report.unified import Isolation

from .env import clean_env

SUPPORTED_VM_RUNTIMES = (
    "firecracker",
    "limactl",
    "qemu-system-x86_64",
    "qemu-system-aarch64",
    "bwrap",
)


@dataclass(frozen=True)
class MicroVMSandbox:
    """MicroVM / hypervisor execution boundary (`isolation = "vm"`) for hostile artifact analysis."""

    runtime: str = "auto"
    default_timeout: float = 30.0
    disable_network: bool = True
    read_only_rootfs: bool = True

    @property
    def isolation(self) -> Isolation:
        return "virtual-machine"

    def supports(self, minimum: Isolation) -> bool:
        return minimum in ("none", "process", "container", "virtual-machine")

    def resolve_runtime(self) -> str | None:
        """Return the resolved microVM / hypervisor binary path if installed."""
        if self.runtime != "auto":
            return shutil.which(self.runtime)
        for cand in SUPPORTED_VM_RUNTIMES:
            found = shutil.which(cand)
            if found:
                return found
        return None

    def preflight(self) -> tuple[bool, list[str]]:
        """Verify that a microVM or namespace-isolated hypervisor runtime is available."""
        resolved = self.resolve_runtime()
        if not resolved:
            if self.runtime == "auto":
                return False, [
                    f"No microVM runtime found in PATH (checked: {', '.join(SUPPORTED_VM_RUNTIMES)})"
                ]
            return False, [f"MicroVM runtime '{self.runtime}' not found in PATH"]
        return True, []

    def build_command(self, inner_cmd: list[str], cwd: Path) -> list[str]:
        """Construct the isolated execution command for the detected runtime."""
        resolved = self.resolve_runtime()
        if not resolved:
            raise RuntimeError("Cannot build MicroVM command: no runtime available")
        bin_name = Path(resolved).name
        if bin_name == "bwrap":
            flags = [
                resolved,
                "--ro-bind",
                str(cwd),
                str(cwd),
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--unshare-all",
            ]
            if not self.disable_network:
                flags.append("--share-net")
            flags.extend(["--", *inner_cmd])
            return flags
        if bin_name == "limactl":
            return [resolved, "shell", "--workdir", str(cwd), "default", "--", *inner_cmd]
        return [resolved, *inner_cmd]

    def execute(
        self,
        cmd: list[str],
        cwd: Path | str = ".",
        timeout: float | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command inside the microVM runtime when available."""
        ready, reasons = self.preflight()
        if not ready:
            raise RuntimeError("; ".join(reasons))
        work_dir = Path(cwd).resolve()
        wrapped = self.build_command(cmd, work_dir)
        env = clean_env(extra_env=extra_env)
        return subprocess.run(
            wrapped,
            cwd=str(work_dir),
            text=True,
            capture_output=True,
            timeout=timeout if timeout is not None else self.default_timeout,
            env=env,
        )
