"""Opt-in sandboxed runtime behavior tracing for PLEx Inspect."""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from plex.report.unified import AnalysisFinding, EvidenceRef, Isolation
from plex.sandbox import ContainerSandbox, SubprocessSandbox

from .models import ArtifactDescriptor

TraceEventKind = Literal[
    "syscall",
    "library_call",
    "file_access",
    "network_connect",
    "process_spawn",
]

_STRACE_LINE_RE = re.compile(
    r"^(?:\[pid\s+\d+\]\s+)?([a-zA-Z0-9_]+)\((.*)\)\s*=\s*(-?\d+|0x[0-9a-fA-F]+|\?)"
)


@dataclass(frozen=True)
class RuntimeTraceEvent:
    """A single runtime behavior event observed during sandboxed execution."""

    kind: TraceEventKind
    operation: str
    target: str
    return_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeTraceResult:
    """Structured result of an opt-in sandboxed binary runtime trace."""

    artifact_path: str
    executed: bool
    exit_code: int | None = None
    events: tuple[RuntimeTraceEvent, ...] = ()
    observed_symbols: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    isolation: Isolation = "process"
    stdout_preview: str = ""
    stderr_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_trace_output(
    raw_output: str,
    known_imports: tuple[str, ...] = (),
) -> tuple[list[RuntimeTraceEvent], list[str]]:
    """Parse strace/ltrace/runtime trace lines into structured RuntimeTraceEvent items."""
    events: list[RuntimeTraceEvent] = []
    observed_syms: list[str] = []

    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # 1. Explicit trace markers: PLEX_TRACE:<kind>:<operation>:<target>
        if "PLEX_TRACE:" in stripped:
            _, _, payload = stripped.partition("PLEX_TRACE:")
            parts = payload.split(":", 2)
            if len(parts) == 3:
                raw_kind, op, target = parts[0].strip(), parts[1].strip(), parts[2].strip()
                kind: TraceEventKind = (
                    raw_kind  # type: ignore[assignment]
                    if raw_kind
                    in (
                        "syscall",
                        "library_call",
                        "file_access",
                        "network_connect",
                        "process_spawn",
                    )
                    else "syscall"
                )
                events.append(RuntimeTraceEvent(kind=kind, operation=op, target=target, return_code=0))
                if op not in observed_syms:
                    observed_syms.append(op)
                continue

        # 2. strace-style syscall lines: openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
        m = _STRACE_LINE_RE.match(stripped)
        if m:
            syscall_name, args_str, ret_str = m.group(1), m.group(2), m.group(3)
            try:
                ret_val: int | None = int(ret_str, 0)
            except ValueError:
                ret_val = None

            ev_kind: TraceEventKind = "syscall"
            if syscall_name in ("open", "openat", "creat", "unlink", "unlinkat", "stat", "access"):
                ev_kind = "file_access"
            elif syscall_name in ("connect", "bind", "listen", "sendto", "socket"):
                ev_kind = "network_connect"
            elif syscall_name in ("execve", "fork", "vfork", "clone", "posix_spawn"):
                ev_kind = "process_spawn"

            quoted = re.findall(r'"([^"]*)"', args_str)
            target = quoted[0] if quoted else args_str[:64]
            events.append(
                RuntimeTraceEvent(
                    kind=ev_kind,
                    operation=syscall_name,
                    target=target,
                    return_code=ret_val,
                )
            )
            if syscall_name not in observed_syms:
                observed_syms.append(syscall_name)

        # 3. Match known imported symbols mentioned in trace output
        for sym in known_imports:
            if sym and sym in stripped and sym not in observed_syms:
                observed_syms.append(sym)
                events.append(
                    RuntimeTraceEvent(
                        kind="library_call",
                        operation=sym,
                        target=sym,
                        return_code=0,
                    )
                )

    return events, observed_syms


@dataclass
class RuntimeTracer:
    """Opt-in sandboxed runtime tracer for binary artifacts."""

    timeout: float = 10.0
    sandbox: Any = None

    def trace(
        self,
        descriptor: ArtifactDescriptor,
        *,
        allow_dynamic: bool = False,
        args: list[str] | None = None,
    ) -> RuntimeTraceResult:
        """Execute artifact in an isolated sandbox only when allow_dynamic=True."""
        if not allow_dynamic:
            return RuntimeTraceResult(
                artifact_path=descriptor.path,
                executed=False,
                limitations=(
                    "Dynamic runtime tracing skipped: --allow-dynamic was not enabled",
                ),
                isolation="none",
            )

        target_path = Path(descriptor.path).resolve()
        if not target_path.exists():
            return RuntimeTraceResult(
                artifact_path=descriptor.path,
                executed=False,
                limitations=(f"Artifact path does not exist: {descriptor.path}",),
                isolation="none",
            )

        isolation: Isolation = "process"
        runner = self.sandbox
        if runner is None:
            container = ContainerSandbox()
            ready, _ = container.preflight()
            if ready:
                runner = container
                isolation = "container"
            else:
                runner = SubprocessSandbox(default_timeout=self.timeout)
                isolation = "process"

        cmd: list[str] = []
        strace_bin = shutil.which("strace")
        if strace_bin:
            cmd = [strace_bin, "-f", "-e", "trace=file,process,network", str(target_path)]
        else:
            cmd = [str(target_path)]
        if args:
            cmd.extend(args)

        try:
            proc = runner.execute(cmd, cwd=target_path.parent)
        except Exception as exc:
            return RuntimeTraceResult(
                artifact_path=descriptor.path,
                executed=False,
                limitations=(f"Sandboxed runtime execution failed: {exc}",),
                isolation=isolation,
            )

        combined_output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
        events, observed_syms = parse_trace_output(
            combined_output,
            known_imports=descriptor.imported_symbols,
        )

        return RuntimeTraceResult(
            artifact_path=descriptor.path,
            executed=True,
            exit_code=proc.returncode,
            events=tuple(events),
            observed_symbols=tuple(observed_syms),
            limitations=(),
            isolation=isolation,
            stdout_preview=(proc.stdout or "")[:512],
            stderr_preview=(proc.stderr or "")[:512],
        )


def findings_from_runtime_trace(
    descriptor: ArtifactDescriptor,
    trace_result: RuntimeTraceResult,
    base_evidence: EvidenceRef,
) -> list[AnalysisFinding]:
    """Convert observed runtime trace events into verified AnalysisFinding records."""
    if not trace_result.executed or not trace_result.events:
        return []

    findings: list[AnalysisFinding] = []
    trace_digest = hashlib.sha256(
        repr([(e.kind, e.operation, e.target) for e in trace_result.events]).encode("utf-8")
    ).hexdigest()
    trace_ev = EvidenceRef(
        engine="inspect",
        kind="runtime_trace",
        ref=f"trace_{descriptor.sha256[:16]}",
        digest=f"sha256:{trace_digest}",
        isolation=trace_result.isolation,
    )

    spawn_events = [e for e in trace_result.events if e.kind == "process_spawn"]
    net_events = [e for e in trace_result.events if e.kind == "network_connect"]

    if spawn_events:
        targets = ", ".join(sorted({e.target for e in spawn_events})[:3])
        fid = hashlib.sha256(f"trace:spawn:{descriptor.path}:{targets}".encode()).hexdigest()[:16]
        findings.append(
            AnalysisFinding(
                id=f"bin.trace.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.trace.process-spawn",
                severity="high",
                title="Verified Runtime Capability: Subprocess / Shell Execution Observed",
                status="verified",
                confidence="observed",
                file=descriptor.path,
                message=f"Runtime trace confirmed process spawn activity ({spawn_events[0].operation}) targeting: {targets}.",
                suggestions=[
                    "Audit subprocess invocation arguments and restrict execution privileges via seccomp/AppArmor"
                ],
                cwe=["CWE-78"],
                evidence=[base_evidence, trace_ev],
                engine_meta={"runtime_events": [e.to_dict() for e in spawn_events]},
            )
        )

    if net_events:
        targets = ", ".join(sorted({e.target for e in net_events})[:3])
        fid = hashlib.sha256(f"trace:net:{descriptor.path}:{targets}".encode()).hexdigest()[:16]
        findings.append(
            AnalysisFinding(
                id=f"bin.trace.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.trace.network-activity",
                severity="medium",
                title="Verified Runtime Capability: Outbound Network Socket Activity Observed",
                status="verified",
                confidence="observed",
                file=descriptor.path,
                message=f"Runtime trace confirmed network socket operation ({net_events[0].operation}) targeting: {targets}.",
                suggestions=[
                    "Verify outbound destination endpoints against approved egress policy"
                ],
                evidence=[base_evidence, trace_ev],
                engine_meta={"runtime_events": [e.to_dict() for e in net_events]},
            )
        )

    return findings
