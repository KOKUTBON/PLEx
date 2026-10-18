"""Binary security rules that interpret REA evidence bundles and emit PLEx findings."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit

from plex.report.unified import AnalysisFinding, EvidenceRef

BANNED_APIS: dict[str, str] = {
    "gets": "Banned unbuffered input function subject to trivial buffer overflow",
    "strcpy": "Unbounded string copy function subject to buffer overflow",
    "strcat": "Unbounded string concatenation function subject to buffer overflow",
    "sprintf": "Format string writing without buffer size bounds",
    "vsprintf": "Variadic format string writing without buffer size bounds",
    "scanf": "Direct unbuffered standard input parsing",
    "sscanf": "Unbounded string scan format parsing",
}

DEPRECATED_CRYPTO_SYMBOLS: dict[str, str] = {
    "MD5_Init": "MD5 hash algorithm is collision-broken",
    "MD5_Update": "MD5 hash algorithm is collision-broken",
    "MD5_Final": "MD5 hash algorithm is collision-broken",
    "SHA1_Init": "SHA-1 hash algorithm has practical collision attacks",
    "SHA1_Update": "SHA-1 hash algorithm has practical collision attacks",
    "SHA1_Final": "SHA-1 hash algorithm has practical collision attacks",
    "DES_encrypt": "DES 56-bit encryption key size is insecure against modern brute force",
    "DES_decrypt": "DES 56-bit encryption key size is insecure against modern brute force",
    "RC4": "RC4 stream cipher suffers from severe statistical keystream biases",
    "RC4_set_key": "RC4 stream cipher suffers from severe statistical keystream biases",
}

DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
}

URL_REGEX = re.compile(r"https?://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[^\s\"'<>]*)?")
AWS_KEY_REGEX = re.compile(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)")
PRIVATE_KEY_MARKERS = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
]


def _hash_id(rule_id: str, file_path: str, detail: str) -> str:
    return hashlib.sha256(f"{rule_id}:{file_path}:{detail}".encode()).hexdigest()[:16]


def evaluate_binary_rules(
    bundle: dict[str, Any],
    artifact_path: str,
    evidence_ref: EvidenceRef,
) -> list[AnalysisFinding]:
    """Execute PLEx binary security rules over an REA evidence bundle."""
    findings: list[AnalysisFinding] = []

    imported_symbols = set()
    raw_symbols = bundle.get("imports") or bundle.get("imported_symbols") or []
    if isinstance(raw_symbols, list):
        for s in raw_symbols:
            if isinstance(s, str):
                imported_symbols.add(s)
            elif isinstance(s, dict) and "name" in s:
                imported_symbols.add(str(s["name"]))

    extracted_strings: list[str] = []
    raw_strings = bundle.get("strings") or bundle.get("extracted_strings") or []
    if isinstance(raw_strings, list):
        for s in raw_strings:
            if isinstance(s, str):
                extracted_strings.append(s)

    manifest = bundle.get("manifest", {})
    manifest_permissions: list[str] = []
    if isinstance(manifest, dict):
        perms = manifest.get("permissions", [])
        if isinstance(perms, list):
            manifest_permissions = [str(p) for p in perms]

    # Rule 1: Banned native APIs (CWE-676)
    for sym, desc in sorted(BANNED_APIS.items()):
        if sym in imported_symbols:
            fid = _hash_id("rea.banned-api", artifact_path, sym)
            findings.append(
                AnalysisFinding(
                    id=f"rea.bin.{fid}",
                    engine="rea",
                    category="binary",
                    rule_id="rea.banned-api",
                    severity="high",
                    title=f"Binary imports banned API '{sym}'",
                    status="verified",
                    confidence="observed",
                    file=artifact_path,
                    cwe=["CWE-676"],
                    message=f"{desc} (symbol '{sym}' imported).",
                    remediation=[f"Replace '{sym}' with safe, bounded alternatives."],
                    evidence=[evidence_ref],
                    engine_meta={"symbol": sym},
                )
            )

    # Rule 2: Deprecated cryptographic APIs (CWE-327)
    for sym, desc in sorted(DEPRECATED_CRYPTO_SYMBOLS.items()):
        if sym in imported_symbols:
            fid = _hash_id("rea.deprecated-crypto", artifact_path, sym)
            findings.append(
                AnalysisFinding(
                    id=f"rea.bin.{fid}",
                    engine="rea",
                    category="binary",
                    rule_id="rea.deprecated-crypto",
                    severity="medium",
                    title=f"Binary links deprecated cryptographic API '{sym}'",
                    status="verified",
                    confidence="observed",
                    file=artifact_path,
                    cwe=["CWE-327"],
                    message=f"{desc} (symbol '{sym}' detected).",
                    remediation=[
                        "Migrate to standard modern cryptographic primitives (e.g., SHA-256, AES-GCM, Ed25519)."
                    ],
                    evidence=[evidence_ref],
                    engine_meta={"symbol": sym},
                )
            )

    # Rule 3: Dangerous permission exfiltration (CWE-276 / CWE-200)
    def _is_standard_xml_namespace(target_url: str) -> bool:
        try:
            parsed = urlsplit(target_url)
            host = (parsed.hostname or "").lower()
            return host in {"schemas.android.com", "w3.org", "www.w3.org"} or host.endswith(".w3.org")
        except Exception:
            return False

    def _is_outbound_url_string(raw: str) -> bool:
        m = URL_REGEX.search(raw)
        if not m:
            return False
        return not _is_standard_xml_namespace(m.group(0))

    has_outbound_strings = any(_is_outbound_url_string(s) for s in extracted_strings)
    for perm in sorted(set(manifest_permissions)):
        if perm in DANGEROUS_PERMISSIONS and has_outbound_strings:
            fid = _hash_id("rea.dangerous-permission-exfil", artifact_path, perm)
            findings.append(
                AnalysisFinding(
                    id=f"rea.bin.{fid}",
                    engine="rea",
                    category="binary",
                    rule_id="rea.dangerous-permission-exfil",
                    severity="high",
                    title=f"Application requests sensitive permission '{perm}' with outbound network capability",
                    status="suspected",
                    confidence="derived",
                    file=artifact_path,
                    cwe=["CWE-276", "CWE-200"],
                    message=(
                        f"Permission '{perm}' grants access to sensitive private user data while "
                        "binary contains network communication endpoints."
                    ),
                    remediation=[
                        f"Ensure permission '{perm}' is strictly required and user data is never transmitted insecurely."
                    ],
                    evidence=[evidence_ref],
                    engine_meta={"permission": perm},
                )
            )

    # Rule 4: Cleartext HTTP endpoints (CWE-319)
    seen_urls: set[str] = set()
    for s in extracted_strings:
        match = URL_REGEX.search(s)
        if match:
            url = match.group(0)
            try:
                parsed_url = urlsplit(url)
                if parsed_url.scheme == "http" and not _is_standard_xml_namespace(url):
                    if url not in seen_urls:
                        seen_urls.add(url)
                        fid = _hash_id("rea.insecure-transport", artifact_path, url)
                        findings.append(
                            AnalysisFinding(
                                id=f"rea.bin.{fid}",
                                engine="rea",
                                category="binary",
                                rule_id="rea.insecure-transport",
                            severity="medium",
                            title=f"Cleartext HTTP endpoint detected: {url}",
                            status="verified",
                            confidence="observed",
                            file=artifact_path,
                            cwe=["CWE-319"],
                            message=f"Binary contains unencrypted HTTP endpoint '{url}'.",
                            remediation=["Enforce HTTPS/TLS for all external network endpoints."],
                            evidence=[evidence_ref],
                            engine_meta={"url": url},
                        )
                    )
            except Exception:
                pass

    # Rule 5: Hardcoded credentials or private keys (CWE-798)
    seen_secrets: set[str] = set()
    for s in extracted_strings:
        for marker in PRIVATE_KEY_MARKERS:
            if marker in s and marker not in seen_secrets:
                seen_secrets.add(marker)
                fid = _hash_id("rea.hardcoded-secret", artifact_path, marker)
                findings.append(
                    AnalysisFinding(
                        id=f"rea.bin.{fid}",
                        engine="rea",
                        category="binary",
                        rule_id="rea.hardcoded-secret",
                        severity="critical",
                        title="Hardcoded private cryptographic key detected",
                        status="verified",
                        confidence="observed",
                        file=artifact_path,
                        cwe=["CWE-798"],
                        message=f"Binary embeds private key header: {marker}",
                        remediation=["Extract private keys into external secure key stores."],
                        evidence=[evidence_ref],
                        engine_meta={"marker": marker},
                    )
                )

        aws_match = AWS_KEY_REGEX.search(s)
        if aws_match:
            key_id = aws_match.group(1)
            if key_id not in seen_secrets:
                seen_secrets.add(key_id)
                fid = _hash_id("rea.hardcoded-secret", artifact_path, key_id)
                findings.append(
                    AnalysisFinding(
                        id=f"rea.bin.{fid}",
                        engine="rea",
                        category="binary",
                        rule_id="rea.hardcoded-secret",
                        severity="critical",
                        title="Hardcoded AWS Access Key ID detected",
                        status="verified",
                        confidence="observed",
                        file=artifact_path,
                        cwe=["CWE-798"],
                        message=f"Binary embeds AWS Access Key ID: {key_id}",
                        remediation=[
                            "Revoke embedded credential and load from environment or IAM roles."
                        ],
                        evidence=[evidence_ref],
                        engine_meta={"aws_key_id": key_id},
                    )
                )

    return findings
