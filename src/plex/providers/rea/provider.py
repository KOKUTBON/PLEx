"""REA AnalysisProvider implementation for binary and artifact inspection."""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any

from plex.report.unified import EngineRun
from plex.sandbox import Sandbox
from plex.sandbox.disposable import disposable_workspace

from ..base import AnalysisTask, FindingSink, PreflightResult, ProviderEnv
from .capabilities import PINNED_REA_VERSION, REA_CAPABILITY
from .drift import DriftDetector, DriftError
from .evidence import map_rea_evidence
from .rules import evaluate_binary_rules
from .transport import (
    McpReaTransport,
    ReaExecutionError,
    ReaTransport,
)

log = logging.getLogger(__name__)


class ReaProvider:
    """Analysis provider orchestrating REA binary inspection and PLEx binary rules."""

    capability = REA_CAPABILITY
    version = PINNED_REA_VERSION

    def __init__(
        self,
        transport: ReaTransport | None = None,
        drift_detector: DriftDetector | None = None,
    ) -> None:
        self._transport = transport
        self._drift_detector = drift_detector or DriftDetector()

    @staticmethod
    def _options(raw: dict[str, Any] | Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            if "rea" in raw and isinstance(raw["rea"], dict):
                return raw["rea"]
            return raw
        return {}

    def preflight(self, env: ProviderEnv) -> PreflightResult:
        if env.task.target_kind not in self.capability.supports_targets:
            return PreflightResult(
                False, (f"Target kind '{env.task.target_kind}' not supported by REA",)
            )

        if not env.task.repo_root.exists():
            return PreflightResult(False, ("Target path does not exist",))

        if not shutil.which("node"):
            return PreflightResult(False, ("Node.js runtime not found in PATH (required by REA)",))

        if env.sandbox.isolation == "none":
            return PreflightResult(
                False, ("REA requires process or container isolation; cannot run in-process",)
            )

        return PreflightResult(True)

    def run(self, task: AnalysisTask, sink: FindingSink, sandbox: Sandbox) -> EngineRun:
        preflight = self.preflight(ProviderEnv(task, sandbox))
        if not preflight.ready:
            return EngineRun(
                "rea",
                self.version,
                "skipped",
                limitations=list(preflight.limitations),
                isolation=sandbox.isolation,
            )

        limitations: list[str] = []
        if sandbox.isolation != "container":
            limitations.append("Container sandbox unavailable; executed with process isolation")

        options = self._options(task.options)
        allow_dynamic = bool(options.get("allow_dynamic", False))
        if not allow_dynamic and options.get("dynamic_tools"):
            limitations.append("Dynamic inspection tools disabled: requires --allow-dynamic")

        target_root = task.repo_root.resolve()

        # Execute inspection in disposable sample copy to prevent modification
        transport = self._transport or McpReaTransport(drift_detector=self._drift_detector)

        try:
            if target_root.is_file():
                # For single-file artifacts, copy into isolated temp dir
                with tempfile.TemporaryDirectory(prefix="plex-rea-sample-") as tmp_dir:
                    sample_copy = Path(tmp_dir) / target_root.name
                    shutil.copy2(target_root, sample_copy)
                    bundle = transport.inspect(sample_copy, options)
            else:
                with disposable_workspace(target_root) as sample_copy:
                    bundle = transport.inspect(sample_copy, options)
        except DriftError as exc:
            limitations.append(str(exc))
            return EngineRun(
                "rea",
                self.version,
                "partial",
                limitations=limitations,
                isolation=sandbox.isolation,
            )
        except ReaExecutionError as exc:
            limitations.append(f"REA execution failed: {exc}")
            return EngineRun(
                "rea",
                self.version,
                "failed",
                limitations=limitations,
                isolation=sandbox.isolation,
            )
        except Exception as exc:
            limitations.append(f"REA provider failed ({type(exc).__name__})")
            return EngineRun(
                "rea",
                self.version,
                "failed",
                limitations=limitations,
                isolation=sandbox.isolation,
            )

        # Map evidence bundle into EvidenceRef and unknown findings
        evidence_ref, unknown_findings = map_rea_evidence(
            bundle, str(target_root), isolation=sandbox.isolation
        )
        for uf in unknown_findings:
            sink.emit(uf)

        # Interpret evidence via PLEx binary security rules
        binary_findings = evaluate_binary_rules(bundle, str(target_root), evidence_ref)
        for bf in binary_findings:
            sink.emit(bf)

        if evidence_ref.limitations:
            limitations.extend(evidence_ref.limitations)

        return EngineRun(
            "rea",
            self.version,
            "complete",
            limitations=limitations,
            isolation=sandbox.isolation,
        )
