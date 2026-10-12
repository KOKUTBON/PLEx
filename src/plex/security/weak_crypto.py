"""Weak Cryptography and Insecure Hash Rule (CWE-327 / CWE-328 / OWASP A02:2025)."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable

from plex import __version__
from plex.report.unified import EvidenceRef, Severity, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

WEAK_CRYPTO_LIMITATIONS = (
    "Weak crypto rule detects broken hashes (MD5, SHA-1), deprecated ciphers (DES, RC4, Blowfish), and ECB mode",
    "Usage explicitly marked with 'usedforsecurity=False' is recognized as non-security hashing and exempted",
)

# Broken or deprecated hashing algorithms
BROKEN_HASHES: dict[str, tuple[str, Severity, str]] = {
    "md5": (
        "MD5",
        "high",
        "MD5 is cryptographically broken and vulnerable to practical collision attacks.",
    ),
    "md4": (
        "MD4",
        "critical",
        "MD4 is cryptographically broken and should never be used.",
    ),
    "sha1": (
        "SHA-1",
        "medium",
        "SHA-1 is deprecated and susceptible to theoretical and practical collision attacks.",
    ),
}

# Broken or deprecated symmetric ciphers
BROKEN_CIPHERS: dict[str, tuple[str, Severity, str]] = {
    "des": ("DES", "high", "DES uses an obsolete 56-bit key susceptible to brute-force recovery."),
    "des3": ("TripleDES", "high", "TripleDES is deprecated by NIST (SP 800-131A) due to Sweet32 64-bit block collisions."),
    "tripledes": ("TripleDES", "high", "TripleDES is deprecated by NIST (SP 800-131A) due to Sweet32 64-bit block collisions."),
    "arc4": ("RC4", "high", "RC4 (ARC4) has widespread keystream biases and plaintext recovery vulnerabilities."),
    "rc4": ("RC4", "high", "RC4 is insecure and prohibited across modern TLS/cryptographic standards."),
    "blowfish": ("Blowfish", "high", "Blowfish uses a 64-bit block size vulnerable to birthday attacks (Sweet32)."),
}

__all__ = ["WEAK_CRYPTO_LIMITATIONS", "WeakCryptoRule"]


def _resolve_callable_name(node: ast.AST) -> str:
    """Extract canonical dot-separated name from Call.func AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_callable_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_usedforsecurity_false(call: ast.Call) -> bool:
    """Return True if call explicitly specifies usedforsecurity=False."""
    for kw in call.keywords:
        if kw.arg == "usedforsecurity":
            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
    return False


class WeakCryptoRule(Rule):
    id = "xbnd.weak-crypto"
    name = "Weak Cryptography or Insecure Hash"
    description = (
        "Use of broken or deprecated cryptographic algorithm (MD5, SHA-1, DES, RC4, Blowfish, ECB mode) "
        "or insufficient key derivation iterations."
    )
    kind = "crypto"
    limitations = WEAK_CRYPTO_LIMITATIONS
    cwe = ["CWE-327", "CWE-328"]
    owasp = ["A02:2025"]
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "crypto", "CWE-327", "CWE-328", "A02:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file in sorted(context.sources):
            tree = context.ast_for_path(file)
            if tree is None:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func_name = _resolve_callable_name(node.func)
                func_parts = func_name.split(".")
                last_part = func_parts[-1].lower()

                finding_info: tuple[str, Severity, str, str, str] | None = None
                # Structure: (algorithm_name, severity, message, suggestion, issue_type)

                # 1. Direct hashlib calls: hashlib.md5(), hashlib.sha1(), md5(), sha1()
                if last_part in BROKEN_HASHES and (
                    func_name.startswith("hashlib.")
                    or func_name in ("md5", "sha1", "md4")
                    or "Crypto.Hash" in func_name
                    or "hashes." in func_name
                ):
                    if not _is_usedforsecurity_false(node):
                        algo, sev, reason = BROKEN_HASHES[last_part]
                        finding_info = (
                            algo,
                            sev,
                            f"Use of insecure or deprecated hash function '{algo}'. {reason}",
                            "Upgrade to SHA-256 ('hashlib.sha256'), SHA-3, or BLAKE2, or specify "
                            "'usedforsecurity=False' if calculating non-security checksums.",
                            "broken_hash",
                        )

                # 2. hashlib.new("md5", ...) / hashlib.new("sha1", ...)
                elif func_name.endswith(".new") or func_name == "new":
                    # Check first arg or name keyword
                    hash_name = ""
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        hash_name = node.args[0].value.lower()
                    for kw in node.keywords:
                        if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            hash_name = kw.value.value.lower()

                    if hash_name in BROKEN_HASHES and not _is_usedforsecurity_false(node):
                        algo, sev, reason = BROKEN_HASHES[hash_name]
                        finding_info = (
                            algo,
                            sev,
                            f"Use of insecure or deprecated hash function '{algo}' via hashlib.new(). {reason}",
                            "Upgrade to SHA-256 ('hashlib.sha256') or SHA-3, or specify 'usedforsecurity=False' "
                            "if calculating non-security checksums.",
                            "broken_hash",
                        )

                # 3. Broken symmetric ciphers: DES.new(), ARC4.new(), Blowfish.new(), TripleDES()
                if not finding_info:
                    cipher_target = ""
                    if len(func_parts) >= 2 and func_parts[-1] == "new":
                        cipher_target = func_parts[-2].lower()
                    elif last_part in BROKEN_CIPHERS:
                        cipher_target = last_part

                    if cipher_target in BROKEN_CIPHERS:
                        algo, sev, reason = BROKEN_CIPHERS[cipher_target]
                        finding_info = (
                            algo,
                            sev,
                            f"Use of insecure or broken cipher '{algo}'. {reason}",
                            "Upgrade to AES-256-GCM or ChaCha20-Poly1305 with authenticated encryption.",
                            "broken_cipher",
                        )

                # 4. Insecure cipher mode: ECB (Electronic Codebook)
                if not finding_info:
                    is_ecb = False
                    if last_part == "ecb" or func_name.endswith(".modes.ECB"):
                        is_ecb = True
                    else:
                        # Check args and keywords for MODE_ECB
                        for arg in node.args:
                            if isinstance(arg, ast.Attribute) and arg.attr == "MODE_ECB":
                                is_ecb = True
                                break
                            if isinstance(arg, ast.Name) and arg.id == "MODE_ECB":
                                is_ecb = True
                                break
                        for kw in node.keywords:
                            if isinstance(kw.value, ast.Attribute) and kw.value.attr == "MODE_ECB":
                                is_ecb = True
                                break
                            if isinstance(kw.value, ast.Name) and kw.value.id == "MODE_ECB":
                                is_ecb = True
                                break

                    if is_ecb:
                        finding_info = (
                            "AES-ECB",
                            "high",
                            "Use of insecure Electronic Codebook (ECB) cipher mode. ECB encrypts identical "
                            "plaintext blocks into identical ciphertext blocks, leaking structural patterns.",
                            "Use an authenticated cipher mode like GCM or CCM, or CBC mode with HMAC authentication.",
                            "ecb_mode",
                        )

                # 5. Insecure PBKDF2 parameters (weak hash or insufficient iteration count)
                if not finding_info and func_name in ("hashlib.pbkdf2_hmac", "pbkdf2_hmac"):
                    pbkdf_hash = ""
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        pbkdf_hash = node.args[0].value.lower()
                    for kw in node.keywords:
                        if kw.arg == "hash_name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            pbkdf_hash = kw.value.value.lower()

                    if pbkdf_hash in ("md5", "sha1"):
                        algo = pbkdf_hash.upper()
                        finding_info = (
                            f"PBKDF2-{algo}",
                            "high",
                            f"Use of deprecated hash algorithm '{algo}' in PBKDF2 password derivation.",
                            "Use 'sha256' or 'sha512' with PBKDF2, or migrate to modern password hashing like Argon2id.",
                            "weak_kdf_hash",
                        )
                    else:
                        # Check iteration count (4th argument or keyword 'iterations')
                        iterations = None
                        if len(node.args) >= 4 and isinstance(node.args[3], ast.Constant) and isinstance(node.args[3].value, int):
                            iterations = node.args[3].value
                        for kw in node.keywords:
                            if kw.arg == "iterations" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                                iterations = kw.value.value

                        if iterations is not None and iterations < 100_000:
                            finding_info = (
                                "PBKDF2-Iterations",
                                "medium",
                                f"PBKDF2 iteration count of {iterations:,} is below the NIST SP 800-63B minimum recommendation of 100,000.",
                                "Increase PBKDF2 iteration count to at least 100,000 iterations or migrate to Argon2id.",
                                "low_iterations",
                            )

                if not finding_info:
                    continue

                algo_name, severity, msg, remediation, issue_kind = finding_info

                identity = finding_id(
                    "xboundary", self.id, f"{file}:{node.lineno}:{algo_name}", self.name
                )
                ev_ref = EvidenceRef(
                    "xboundary",
                    "crypto_call",
                    f"crypto:{identity}",
                    f"sha256:{hashlib.sha256(f'{file}:{node.lineno}:{algo_name}'.encode()).hexdigest()}",
                    __version__,
                    "none",
                    list(self.limitations),
                )

                finding = RuleFinding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=severity,
                    message=msg,
                    file=file,
                    lineno=node.lineno,
                    end_lineno=node.end_lineno or node.lineno,
                    qualname=f"{func_name or algo_name}:{algo_name}",
                    function_id="",
                    body_hash="",
                    suggestions=[remediation],
                    category="security",
                    cwe=list(self.cwe),
                    owasp=list(self.owasp),
                    evidence=[ev_ref],
                    engine_meta={
                        "finding_id": identity,
                        "algorithm": algo_name,
                        "issue_kind": issue_kind,
                    },
                )

                if context.suppression_context:
                    suppressed, directive = context.suppression_context.is_suppressed(
                        file, node.lineno, self.id
                    )
                    if suppressed and directive:
                        context.suppressed_findings.append((finding, directive))
                        continue

                yield finding
