"""Native binary security rules evaluating structural facts and hardening mitigations."""

from __future__ import annotations

import hashlib
import re

from plex.report.unified import AnalysisFinding, EvidenceRef

from .models import ArtifactDescriptor

BANNED_APIS: dict[str, str] = {
    "gets": "Banned unbuffered standard input function vulnerable to trivial buffer overflow",
    "strcpy": "Unbounded string copy function subject to buffer overflow",
    "strcat": "Unbounded string concatenation function subject to buffer overflow",
    "sprintf": "Format string writing without buffer size bounds",
    "vsprintf": "Variadic format string writing without buffer size bounds",
}

DEPRECATED_CRYPTO: dict[str, str] = {
    "MD5_Init": "MD5 hash algorithm is collision-broken",
    "MD5_Update": "MD5 hash algorithm is collision-broken",
    "SHA1_Init": "SHA-1 hash algorithm has practical collision attacks",
    "SHA1_Update": "SHA-1 hash algorithm has practical collision attacks",
    "DES_encrypt": "DES 56-bit key length is insecure against modern brute force",
    "RC4": "RC4 stream cipher suffers from statistical keystream biases",
}

AWS_KEY_REGEX = re.compile(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)")
PRIVATE_KEY_MARKERS = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
]


def _finding_id(rule_id: str, path: str, extra: str) -> str:
    return hashlib.sha256(f"{rule_id}:{path}:{extra}".encode()).hexdigest()[:16]


def evaluate_artifact_rules(
    descriptor: ArtifactDescriptor,
    evidence_ref: EvidenceRef,
) -> list[AnalysisFinding]:
    """Execute native binary security rules over structural artifact facts."""
    findings: list[AnalysisFinding] = []
    path = descriptor.path
    h = descriptor.hardening

    # Rule 1: Weak compiler / linker hardening mitigations (CWE-693)
    if not h.nx:
        fid = _finding_id("bin.weak-hardening", path, "nx")
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.weak-hardening",
                severity="critical",
                title="Missing Non-Executable Stack (NX/DEP) protection",
                status="verified",
                confidence="observed",
                file=path,
                cwe=["CWE-693", "CWE-119"],
                message="Binary does not enforce non-executable stack (GNU_STACK segment missing or executable), enabling stack shellcode execution.",
                remediation=["Recompile with '-z noexecstack'."],
                evidence=[evidence_ref],
                engine_meta={"mitigation": "nx"},
            )
        )

    if not h.pie:
        fid = _finding_id("bin.weak-hardening", path, "pie")
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.weak-hardening",
                severity="medium",
                title="Missing Position Independent Executable (PIE) mitigation",
                status="verified",
                confidence="observed",
                file=path,
                cwe=["CWE-693"],
                message="Binary is compiled without Position Independent Executable (PIE) support, weakening ASLR effectiveness.",
                remediation=["Recompile with '-fPIE -pie'."],
                evidence=[evidence_ref],
                engine_meta={"mitigation": "pie"},
            )
        )

    if h.relro == "none":
        fid = _finding_id("bin.weak-hardening", path, "relro")
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.weak-hardening",
                severity="medium",
                title="Missing Relocation Read-Only (RELRO) protection",
                status="verified",
                confidence="observed",
                file=path,
                cwe=["CWE-693"],
                message="Binary lacks RELRO protection, leaving the Global Offset Table (GOT) writable and susceptible to overwrite attacks.",
                remediation=["Link with '-Wl,-z,relro,-z,now' for Full RELRO."],
                evidence=[evidence_ref],
                engine_meta={"mitigation": "relro"},
            )
        )

    if not h.canary:
        fid = _finding_id("bin.weak-hardening", path, "canary")
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.weak-hardening",
                severity="medium",
                title="Missing Stack Canary protector",
                status="verified",
                confidence="observed",
                file=path,
                cwe=["CWE-693", "CWE-121"],
                message="Binary does not import stack canary symbols (__stack_chk_fail), making buffer overflows easier to exploit.",
                remediation=["Recompile with '-fstack-protector-strong'."],
                evidence=[evidence_ref],
                engine_meta={"mitigation": "canary"},
            )
        )

    # Rule 2: Banned unsafe native C library functions (CWE-676)
    for sym, desc in sorted(BANNED_APIS.items()):
        if sym in descriptor.imported_symbols:
            fid = _finding_id("bin.banned-api", path, sym)
            findings.append(
                AnalysisFinding(
                    id=f"bin.{fid}",
                    engine="inspect",
                    category="binary",
                    rule_id="bin.banned-api",
                    severity="high",
                    title=f"Binary imports banned function '{sym}'",
                    status="verified",
                    confidence="observed",
                    file=path,
                    cwe=["CWE-676", "CWE-120"],
                    message=f"{desc} (symbol '{sym}' imported).",
                    remediation=[f"Replace '{sym}' with safe, size-bounded alternatives."],
                    evidence=[evidence_ref],
                    engine_meta={"symbol": sym},
                )
            )

    # Rule 3: Deprecated cryptographic primitives (CWE-327)
    for sym, desc in sorted(DEPRECATED_CRYPTO.items()):
        if sym in descriptor.imported_symbols:
            fid = _finding_id("bin.deprecated-crypto", path, sym)
            findings.append(
                AnalysisFinding(
                    id=f"bin.{fid}",
                    engine="inspect",
                    category="binary",
                    rule_id="bin.deprecated-crypto",
                    severity="medium",
                    title=f"Binary links broken cryptographic primitive '{sym}'",
                    status="verified",
                    confidence="observed",
                    file=path,
                    cwe=["CWE-327"],
                    message=f"{desc} (symbol '{sym}' detected).",
                    remediation=["Upgrade to modern cryptographic algorithms (SHA-256, AES-GCM)."],
                    evidence=[evidence_ref],
                    engine_meta={"symbol": sym},
                )
            )

    # Rule 4: Insecure relative RPATH / RUNPATH (CWE-426)
    for rpath_val, rpath_type in [(h.rpath, "RPATH"), (h.runpath, "RUNPATH")]:
        if rpath_val:
            entries = rpath_val.split(":")
            if "." in entries or "" in entries or any(e.startswith("./") for e in entries):
                fid = _finding_id("bin.insecure-rpath", path, rpath_val)
                findings.append(
                    AnalysisFinding(
                        id=f"bin.{fid}",
                        engine="inspect",
                        category="binary",
                        rule_id="bin.insecure-rpath",
                        severity="high",
                        title=f"Insecure relative {rpath_type} detected: '{rpath_val}'",
                        status="verified",
                        confidence="observed",
                        file=path,
                        cwe=["CWE-426"],
                        message=f"{rpath_type} contains relative directory entries, allowing DLL/shared library preloading hijacking.",
                        remediation=[
                            f"Remove relative paths from {rpath_type}; use secure system library paths."
                        ],
                        evidence=[evidence_ref],
                        engine_meta={"rpath": rpath_val},
                    )
                )

    # Rule 5: Hardcoded credentials or private keys in strings (CWE-798)
    seen_secrets: set[str] = set()
    for s in descriptor.extracted_strings:
        for marker in PRIVATE_KEY_MARKERS:
            if marker in s and marker not in seen_secrets:
                seen_secrets.add(marker)
                fid = _finding_id("bin.hardcoded-secret", path, marker)
                findings.append(
                    AnalysisFinding(
                        id=f"bin.{fid}",
                        engine="inspect",
                        category="binary",
                        rule_id="bin.hardcoded-secret",
                        severity="critical",
                        title="Embedded private cryptographic key header detected in binary data",
                        status="verified",
                        confidence="observed",
                        file=path,
                        cwe=["CWE-798"],
                        message=f"Binary artifact embeds private key marker: {marker}",
                        remediation=["Remove cryptographic keys from compiled binary data."],
                        evidence=[evidence_ref],
                        engine_meta={"marker": marker},
                    )
                )

        aws_match = AWS_KEY_REGEX.search(s)
        if aws_match:
            key_id = aws_match.group(1)
            if key_id not in seen_secrets:
                seen_secrets.add(key_id)
                fid = _finding_id("bin.hardcoded-secret", path, key_id)
                findings.append(
                    AnalysisFinding(
                        id=f"bin.{fid}",
                        engine="inspect",
                        category="binary",
                        rule_id="bin.hardcoded-secret",
                        severity="critical",
                        title="Embedded AWS Access Key ID detected in binary data",
                        status="verified",
                        confidence="observed",
                        file=path,
                        cwe=["CWE-798"],
                        message=f"Binary artifact embeds AWS Access Key ID: {key_id}",
                        remediation=[
                            "Revoke embedded credential and load via environment or vault."
                        ],
                        evidence=[evidence_ref],
                        engine_meta={"aws_key_id": key_id},
                    )
                )

    # Rule 6: Archive Path Traversal / Zip Slip (CWE-22)
    zip_slip_entries: list[str] = descriptor.metadata.get("zip_slip_entries", [])
    for entry in zip_slip_entries:
        fid = _finding_id("bin.archive.zip-slip", path, entry)
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.archive.zip-slip",
                severity="critical",
                title=f"Archive contains path traversal (Zip Slip) filename: '{entry}'",
                status="verified",
                confidence="observed",
                file=path,
                cwe=["CWE-22"],
                message=(
                    f"Archive entry '{entry}' contains directory traversal components ('..'), "
                    "enabling arbitrary file overwrites during extraction."
                ),
                remediation=[
                    "Sanitize archive entry paths prior to extraction; reject entries containing '..' or leading slashes."
                ],
                evidence=[evidence_ref],
                engine_meta={"entry": entry},
            )
        )

    # Rule 7: Bundled sensitive key or credential store file (CWE-798 / CWE-540)
    sensitive_files: list[str] = descriptor.metadata.get("sensitive_files", [])
    for sfile in sensitive_files:
        fid = _finding_id("bin.archive.sensitive-file", path, sfile)
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.archive.sensitive-file",
                severity="high",
                title=f"Archive packages sensitive key or credential file: '{sfile}'",
                status="verified",
                confidence="observed",
                file=path,
                cwe=["CWE-798", "CWE-540"],
                message=f"Archive bundles private key or credential store file '{sfile}', risking secret leakage.",
                remediation=["Exclude private keys, certificates, and environment files from package distributions."],
                evidence=[evidence_ref],
                engine_meta={"sensitive_file": sfile},
            )
        )

    # Rule 8: Dangerous Android permission requested (CWE-276)
    dangerous_perms: list[str] = descriptor.metadata.get("dangerous_permissions", [])
    for perm in dangerous_perms:
        fid = _finding_id("bin.archive.dangerous-permission", path, perm)
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.archive.dangerous-permission",
                severity="medium",
                title=f"Android package requests dangerous permission: '{perm}'",
                status="verified",
                confidence="observed",
                file=path,
                cwe=["CWE-276"],
                message=f"Application requests sensitive Android permission: android.permission.{perm}",
                remediation=["Verify that this high-privilege permission is strictly necessary and declare runtime user approval."],
                evidence=[evidence_ref],
                engine_meta={"permission": perm},
            )
        )

    # Rule 9: Direct calls to banned APIs reconstructed from disassembly (CWE-676)
    for call in descriptor.calls:
        if call.target_symbol and call.target_symbol in BANNED_APIS:
            sym = call.target_symbol
            desc = BANNED_APIS[sym]
            loc = f"0x{call.caller_address:x}"
            fid = _finding_id("bin.banned-api-call", path, f"{sym}:{loc}")
            fn_desc = f" in function '{call.caller_function}'" if call.caller_function else ""
            findings.append(
                AnalysisFinding(
                    id=f"bin.{fid}",
                    engine="inspect",
                    category="binary",
                    rule_id="bin.banned-api-call",
                    severity="critical",
                    title=f"Disassembly observes call to banned function '{sym}' at {loc}",
                    status="verified",
                    confidence="observed",
                    file=path,
                    lineno=0,
                    cwe=["CWE-676", "CWE-120"],
                    message=f"{desc}. Call site at instruction {loc}{fn_desc}: '{call.instruction}'.",
                    remediation=[f"Refactor caller to replace '{sym}' with safe, size-bounded alternatives."],
                    evidence=[evidence_ref],
                    engine_meta={
                        "symbol": sym,
                        "caller_address": loc,
                        "caller_function": call.caller_function,
                        "instruction": call.instruction,
                    },
                )
            )

    return findings

