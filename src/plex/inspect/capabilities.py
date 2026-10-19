"""Native binary capability hypothesis and behavioral risk detection engine.

In accordance with Section 7.1 and 7.2 of the PLEx 2.0 architecture:
1. Capabilities are treated as testable hypotheses, not verified runtime facts.
2. Observations (symbols, call targets, strings) are separated from heuristic interpretation.
3. Every finding is emitted with status='suspected' and confidence='inferred'.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from plex.report.unified import AnalysisFinding, EvidenceRef

from .models import ArtifactDescriptor, ReconstructedCall

CAPABILITY_CATALOG: dict[str, dict[str, Any]] = {
    "network": {
        "rule_id": "bin.capability.network",
        "title": "Capability Hypothesis: Outbound Network Communication & Exfiltration",
        "severity": "medium",
        "cwe": ["CWE-200", "CWE-319"],
        "symbols": {
            "socket",
            "connect",
            "send",
            "sendto",
            "recv",
            "recvfrom",
            "WSAStartup",
            "WSASocketA",
            "WSASocketW",
            "InternetOpenA",
            "InternetOpenW",
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "getaddrinfo",
            "curl_easy_init",
            "curl_easy_perform",
        },
        "description": "Binary imports or invokes socket communications, HTTP protocols, or network request routines.",
        "remediation": "Audit network destinations and ensure all external communications use authenticated, encrypted endpoints.",
    },
    "process-injection": {
        "rule_id": "bin.capability.process-injection",
        "title": "Capability Hypothesis: Cross-Process Injection & Memory Manipulation",
        "severity": "high",
        "cwe": ["CWE-250", "CWE-749"],
        "symbols": {
            "ptrace",
            "process_vm_writev",
            "process_vm_readv",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetThreadContext",
            "QueueUserAPC",
            "ZwMapViewOfSection",
            "NtMapViewOfSection",
        },
        "description": "Binary imports low-level routines capable of writing to remote process memory or creating foreign threads.",
        "remediation": "Restrict process privilege delegation and eliminate cross-process memory manipulation APIs.",
    },
    "anti-analysis": {
        "rule_id": "bin.capability.anti-analysis",
        "title": "Capability Hypothesis: Debugger Detection & Anti-Analysis Evasion",
        "severity": "medium",
        "cwe": ["CWE-749", "CWE-693"],
        "symbols": {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "NtQueryInformationProcess",
        },
        "description": "Binary invokes debugger query APIs or environment checks indicative of anti-analysis or sandbox evasion.",
        "remediation": "Remove evasion logic from authorized software; review binary for unwanted obfuscation.",
    },
    "persistence": {
        "rule_id": "bin.capability.persistence",
        "title": "Capability Hypothesis: System Persistence & Autostart Installation",
        "severity": "medium",
        "cwe": ["CWE-250"],
        "symbols": {
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "CreateServiceA",
            "CreateServiceW",
            "OpenSCManagerA",
            "OpenSCManagerW",
        },
        "string_patterns": [
            r"/etc/init\.d",
            r"/etc/systemd/system",
            r"/etc/cron",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ],
        "description": "Binary contains API calls or path references associated with installing autostart services or persistence entries.",
        "remediation": "Verify authorized installation scripts and audit autostart registry or service registration logic.",
    },
    "dynamic-execution": {
        "rule_id": "bin.capability.dynamic-execution",
        "title": "Capability Hypothesis: Dynamic Symbol Loading & Executable Memory Modification",
        "severity": "medium",
        "cwe": ["CWE-749"],
        "symbols": {
            "dlopen",
            "dlsym",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "GetProcAddress",
            "mprotect",
            "VirtualProtect",
        },
        "description": "Binary allocates or modifies memory protections to execute code or resolves symbol addresses dynamically at runtime.",
        "remediation": "Use static symbol bindings where possible; enforce W^X memory protection policies.",
    },
    "command-execution": {
        "rule_id": "bin.capability.command-execution",
        "title": "Capability Hypothesis: Subprocess & Shell Command Spawning",
        "severity": "medium",
        "cwe": ["CWE-78"],
        "symbols": {
            "system",
            "popen",
            "execve",
            "execl",
            "execvp",
            "CreateProcessA",
            "CreateProcessW",
            "ShellExecuteA",
            "ShellExecuteW",
            "WinExec",
        },
        "description": "Binary imports or invokes shell execution APIs to spawn secondary programs or external commands.",
        "remediation": "Use direct parameter arrays without shell invocation; validate arguments against strict allowlists.",
    },
}


def _finding_id(rule_id: str, path: str, extra: str) -> str:
    return hashlib.sha256(f"{rule_id}:{path}:{extra}".encode()).hexdigest()[:16]


def detect_capabilities(
    descriptor: ArtifactDescriptor,
    evidence_ref: EvidenceRef,
) -> list[AnalysisFinding]:
    """Evaluate structural facts, symbols, and disassembly to formulate capability hypotheses."""
    findings: list[AnalysisFinding] = []
    path = descriptor.path

    # Gather all observed symbols: imported, exported, and call targets
    observed_symbols: set[str] = set(descriptor.imported_symbols) | set(descriptor.exported_symbols)
    call_by_target: dict[str, list[ReconstructedCall]] = {}
    for call in descriptor.calls:
        if call.target_symbol:
            observed_symbols.add(call.target_symbol)
            call_by_target.setdefault(call.target_symbol, []).append(call)

    # Check each capability family
    for cap_name, config in CAPABILITY_CATALOG.items():
        matched_symbols = observed_symbols & config["symbols"]
        matched_calls: list[ReconstructedCall] = []
        for sym in matched_symbols:
            if sym in call_by_target:
                matched_calls.extend(call_by_target[sym])

        matched_strings: list[str] = []
        string_patterns = config.get("string_patterns", [])
        if string_patterns:
            for s in descriptor.extracted_strings:
                for pat in string_patterns:
                    if re.search(pat, s, re.IGNORECASE):
                        matched_strings.append(s)
                        break

        # If evidence was observed, formulate the hypothesis
        if matched_symbols or matched_strings:
            fid = _finding_id(config["rule_id"], path, cap_name)
            evidence_summary: list[str] = []
            if matched_symbols:
                evidence_summary.append(f"Symbols: {', '.join(sorted(matched_symbols)[:8])}")
            if matched_calls:
                call_locs = [f"0x{c.caller_address:x}" for c in matched_calls[:4]]
                evidence_summary.append(f"Call sites: {', '.join(call_locs)}")
            if matched_strings:
                evidence_summary.append(f"Artifact strings: {', '.join(matched_strings[:3])}")

            findings.append(
                AnalysisFinding(
                    id=f"bin.{fid}",
                    engine="inspect",
                    category="binary",
                    rule_id=config["rule_id"],
                    severity=config["severity"],
                    title=config["title"],
                    status="suspected",
                    confidence="inferred",
                    file=path,
                    lineno=matched_calls[0].caller_address if matched_calls else 0,
                    cwe=config["cwe"],
                    message=(
                        f"{config['description']} "
                        f"Evidence: {'; '.join(evidence_summary)}."
                    ),
                    remediation=[config["remediation"]],
                    evidence=[evidence_ref],
                    engine_meta={
                        "capability": cap_name,
                        "matched_symbols": sorted(matched_symbols),
                        "matched_strings": matched_strings,
                        "call_count": len(matched_calls),
                    },
                )
            )

    # Check for Import Hash (imphash) capability
    if descriptor.metadata.get("imphash"):
        imphash = descriptor.metadata["imphash"]
        fid = _finding_id("bin.capability.imphash", path, imphash)
        sym_count = descriptor.metadata.get("imphash_symbols_count", 0)
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.capability.imphash",
                severity="info",
                title=f"Import Table Fingerprint (imphash): {imphash}",
                status="suspected",
                confidence="inferred",
                file=path,
                lineno=0,
                cwe=["CWE-699"],
                message=(
                    f"Binary import table yields standard PE import hash (imphash): {imphash} "
                    f"across {sym_count} ordered imported functions. Used for binary lineage, malware clustering, and static triage."
                ),
                remediation=["Track imphash across release builds to detect unexpected dynamic import dependencies."],
                evidence=[evidence_ref],
                engine_meta={"imphash": imphash, "symbol_count": sym_count},
            )
        )

    # Check for Compiler Provenance / Rich Header Fingerprint
    producer = descriptor.metadata.get("compiler_producer")
    rich_header = descriptor.metadata.get("rich_header")
    if producer or rich_header:
        fp_desc = []
        meta_payload: dict[str, Any] = {}
        if producer:
            fp_desc.append(f"DWARF Producer: {producer}")
            meta_payload["producer"] = producer
        if rich_header:
            r_hash = rich_header.get("hash", "")
            r_cnt = rich_header.get("record_count", 0)
            fp_desc.append(f"MSVC Rich Header Hash: {r_hash} ({r_cnt} build tool records)")
            meta_payload["rich_hash"] = r_hash
            meta_payload["tool_records"] = r_cnt

        fid = _finding_id("bin.capability.compiler-fingerprint", path, ";".join(fp_desc))
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.capability.compiler-fingerprint",
                severity="info",
                title="Compiler & Toolchain Provenance Fingerprint Identified",
                status="suspected",
                confidence="inferred",
                file=path,
                lineno=0,
                cwe=["CWE-699"],
                message=f"Artifact reveals compiler and linker build toolchain provenance. {'; '.join(fp_desc)}.",
                remediation=["Audit compiler toolchain versions against approved baseline compiler suites."],
                evidence=[evidence_ref],
                engine_meta=meta_payload,
            )
        )

    # Check for Code Signing / Cryptographic Identity Fingerprint
    cdhash = descriptor.metadata.get("cdhash")
    authenticode = descriptor.metadata.get("authenticode")
    if cdhash or authenticode:
        fp_parts: list[str] = []
        meta_payload = {}
        if cdhash:
            fp_parts.append(f"Mach-O CDHash: {cdhash}")
            meta_payload["cdhash"] = cdhash
            if descriptor.metadata.get("signing_id"):
                fp_parts.append(f"Signing ID: {descriptor.metadata['signing_id']}")
                meta_payload["signing_id"] = descriptor.metadata["signing_id"]
            if descriptor.metadata.get("team_id"):
                fp_parts.append(f"Team ID: {descriptor.metadata['team_id']}")
                meta_payload["team_id"] = descriptor.metadata["team_id"]
        if authenticode:
            algo = authenticode.get("digest_algorithm", "unknown")
            fp_parts.append(f"PE Authenticode Digest: {algo}")
            meta_payload["authenticode_digest"] = algo

        fid = _finding_id("bin.capability.codesign", path, ";".join(fp_parts))
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.capability.codesign",
                severity="info",
                title="Cryptographic Code Signature & Identity Provenance Identified",
                status="suspected",
                confidence="inferred",
                file=path,
                lineno=0,
                cwe=["CWE-699"],
                message=(
                    f"Binary contains cryptographic code signing identity and provenance metadata. {'; '.join(fp_parts)}. "
                    "Used for binary provenance, developer signature validation, and OS gatekeeper policy evaluation."
                ),
                remediation=["Track code signing identity and ensure production release certificates are applied."],
                evidence=[evidence_ref],
                engine_meta=meta_payload,
            )
        )

    return findings
