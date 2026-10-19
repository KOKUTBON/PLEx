"""Native binary security rules evaluating structural facts and hardening mitigations."""

from __future__ import annotations

import hashlib
import re

from plex.report.unified import AnalysisFinding, EvidenceRef, Severity

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

    # Rule 10: Packed or encrypted executable code section (high entropy) (CWE-506 / CWE-693)
    for sec in descriptor.sections:
        is_exec = (
            "X" in sec.flags
            or sec.name in (".text", "CODE", "__text", "__TEXT.__text")
            or (sec.flags.startswith("0x") and bool(int(sec.flags, 16) & 0x20000000))
        )
        if is_exec and sec.entropy >= 7.2 and sec.size >= 512:
            fid = _finding_id("bin.packing.high-entropy", path, sec.name)
            findings.append(
                AnalysisFinding(
                    id=f"bin.{fid}",
                    engine="inspect",
                    category="binary",
                    rule_id="bin.packing.high-entropy",
                    severity="medium",
                    title=f"High entropy executable section '{sec.name}' indicates packed or encrypted code",
                    status="verified",
                    confidence="observed",
                    file=path,
                    cwe=["CWE-506", "CWE-693"],
                    message=(
                        f"Executable section '{sec.name}' has unusually high Shannon entropy "
                        f"({sec.entropy:.2f} / 8.00, size {sec.size} bytes). "
                        "High code entropy typically indicates software packing, runtime decompression, or crypter obfuscation."
                    ),
                    remediation=["Inspect binary for third-party packers, UPX compression, or unwanted code obfuscation."],
                    evidence=[evidence_ref],
                    engine_meta={"section": sec.name, "entropy": sec.entropy, "size": sec.size, "md5": sec.md5},
                )
            )

    # Rule 11: Internal build environment or debug path exposed in binary (CWE-200 / CWE-532)
    exposed_paths: list[str] = []
    if descriptor.metadata.get("pdb_path"):
        pdb = descriptor.metadata["pdb_path"]
        if any(marker in pdb for marker in ("\\Users\\", "\\home\\", "/Users/", "/home/", "\\build\\", "/build/")):
            exposed_paths.append(pdb)
    if descriptor.metadata.get("compilation_directory"):
        cdir = descriptor.metadata["compilation_directory"]
        if any(marker in cdir for marker in ("/Users/", "/home/", "\\Users\\", "\\home\\")):
            exposed_paths.append(cdir)

    for p in exposed_paths:
        fid = _finding_id("bin.debug.exposed-path", path, p)
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.debug.exposed-path",
                severity="low",
                title=f"Internal development path exposed in binary debug metadata: '{p}'",
                status="verified",
                confidence="observed",
                file=path,
                cwe=["CWE-200", "CWE-532"],
                message=(
                    f"Binary debug metadata contains internal filesystem path: '{p}'. "
                    "This leaks internal directory layouts, developer usernames, or build server environments."
                ),
                remediation=["Strip debug paths using linker flags, -fdebug-prefix-map, or /PDBALTPATH during release builds."],
                evidence=[evidence_ref],
                engine_meta={"exposed_path": p},
            )
        )

    # Rule 12: High-risk or dangerous Mach-O entitlements (CWE-250 / CWE-269 / CWE-732)
    entitlements = descriptor.metadata.get("entitlements", {})
    if isinstance(entitlements, dict):
        dangerous_spec: dict[str, tuple[str, str, str, Severity]] = {
            "com.apple.security.get-task-allow": (
                "Development debugging entitlement 'get-task-allow' enabled in binary",
                "CWE-250",
                "Allows external debuggers and hostile processes to attach and inject code into memory. Must be disabled in production release builds.",
                "high",
            ),
            "com.apple.security.cs.disable-library-validation": (
                "Library validation disabled via entitlement",
                "CWE-427",
                "Disables macOS dyld signature validation, allowing arbitrary unsigned or third-party dylibs to be loaded into the process.",
                "medium",
            ),
            "com.apple.security.cs.allow-dyld-environment-variables": (
                "DYLD environment variables allowed via entitlement",
                "CWE-426",
                "Permits DYLD_INSERT_LIBRARIES and related environment variables to alter dynamic linker behavior, enabling library injection.",
                "medium",
            ),
            "com.apple.security.cs.allow-unsigned-executable-memory": (
                "Unsigned executable memory allowed via entitlement",
                "CWE-693",
                "Bypasses kernel W^X protections, allowing pages to be both writable and executable, weakening memory corruption exploit mitigations.",
                "low",
            ),
        }
        for ent_key, (title, cwe_id, desc_msg, sev) in dangerous_spec.items():
            if entitlements.get(ent_key) is True:
                fid = _finding_id("bin.macho.dangerous-entitlement", path, ent_key)
                findings.append(
                    AnalysisFinding(
                        id=f"bin.{fid}",
                        engine="inspect",
                        category="binary",
                        rule_id="bin.macho.dangerous-entitlement",
                        severity=sev,
                        title=title,
                        status="verified",
                        confidence="observed",
                        file=path,
                        lineno=0,
                        cwe=[cwe_id, "CWE-250"],
                        message=(
                            f"Mach-O binary embeds dangerous entitlement '{ent_key}' = true. {desc_msg}"
                        ),
                        remediation=[f"Remove '{ent_key}' entitlement from production provisioning profile or Entitlements.plist."],
                        evidence=[evidence_ref],
                        engine_meta={"entitlement": ent_key, "value": True},
                    )
                )

    # Rule 13: Mach-O executable signed without Apple Hardened Runtime (CWE-693)
    if (
        descriptor.format == "macho"
        and descriptor.is_64bit
        and descriptor.metadata.get("has_code_signature")
        and not descriptor.metadata.get("has_hardened_runtime")
        and (descriptor.entry_point > 0 or descriptor.metadata.get("filetype") == 2)
    ):
        fid = _finding_id("bin.macho.unhardened-runtime", path, "missing_cs_runtime")
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.macho.unhardened-runtime",
                severity="low",
                title="Mach-O executable signed without Apple Hardened Runtime flag (CS_RUNTIME)",
                status="verified",
                confidence="observed",
                file=path,
                lineno=0,
                cwe=["CWE-693"],
                message=(
                    "64-bit Mach-O executable has a code signature but lacks the Apple Hardened Runtime flag (CS_RUNTIME). "
                    "Hardened Runtime enforces code signing integrity, memory protections, and dylib validation required by macOS Gatekeeper and notarization."
                ),
                remediation=["Sign binary with Hardened Runtime enabled using 'codesign --options runtime' during build packaging."],
                evidence=[evidence_ref],
                engine_meta={"format": "macho", "has_hardened_runtime": False},
            )
        )

    # Rule 14: Deprecated or weak code signature digest algorithm (CWE-327 / CWE-328)
    sig_digest = ""
    authenticode = descriptor.metadata.get("authenticode")
    if authenticode and isinstance(authenticode, dict):
        sig_digest = authenticode.get("digest_algorithm", "").lower()
    elif descriptor.metadata.get("cdhash_type"):
        sig_digest = descriptor.metadata.get("cdhash_type", "").lower()

    if sig_digest in ("sha1", "sha-1", "md5"):
        fid = _finding_id("bin.hardening.weak-signature-digest", path, sig_digest)
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.hardening.weak-signature-digest",
                severity="medium",
                title=f"Code signature uses deprecated or weak digest algorithm: '{sig_digest.upper()}'",
                status="verified",
                confidence="observed",
                file=path,
                lineno=0,
                cwe=["CWE-327", "CWE-328"],
                message=(
                    f"Binary signature was generated using collision-weakened hash algorithm '{sig_digest.upper()}'. "
                    "Modern operating systems deprecate SHA-1 and MD5 signatures, and modern code integrity policies reject them."
                ),
                remediation=["Re-sign binary using SHA-256 or stronger digest algorithm (/fd sha256 or codesign -s)."],
                evidence=[evidence_ref],
                engine_meta={"digest_algorithm": sig_digest},
            )
        )

    # Rule 15: Text relocations in dynamic ELF segment (DT_TEXTREL / DF_TEXTREL) (CWE-693 / CWE-119)
    if descriptor.format == "elf" and descriptor.metadata.get("has_text_relocations"):
        fid = _finding_id("bin.elf.text-relocation", path, "textrel")
        findings.append(
            AnalysisFinding(
                id=f"bin.{fid}",
                engine="inspect",
                category="binary",
                rule_id="bin.elf.text-relocation",
                severity="high",
                title="Text relocations detected in dynamic ELF segment (DT_TEXTREL)",
                status="verified",
                confidence="observed",
                file=path,
                lineno=0,
                cwe=["CWE-693", "CWE-119"],
                message=(
                    "Binary contains text relocations (DT_TEXTREL / DF_TEXTREL). "
                    "This forces the runtime dynamic linker to map the executable code segment (.text) with write permissions "
                    "during relocation processing, violating W^X (Write XOR Execute) memory protections and exposing the application "
                    "to code injection and runtime control-flow hijacking."
                ),
                remediation=["Recompile code with '-fPIC' (Position Independent Code) and link with '-Wl,-z,text'."],
                evidence=[evidence_ref],
                engine_meta={"has_text_relocations": True},
            )
        )

    return findings

