"""Deterministic fixer and patch candidate proposer for weak cryptography and hashes (CWE-327, CWE-328)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor
from plex.report.unified import Confidence, Severity

WEAK_HASH_NAMES = frozenset({"md5", "sha1", "md4"})

CRYPTOGRAPHIC_KEYWORDS = frozenset({
    "token",
    "signature",
    "sign",
    "verify",
    "auth",
    "password",
    "pwd",
    "secret",
    "mac",
    "hmac",
    "credential",
    "jwt",
    "session",
    "cipher",
    "crypto",
    "nonce",
    "salt",
})

NON_CRYPTO_KEYWORDS = frozenset({
    "cache",
    "etag",
    "checksum",
    "bucket",
    "sharding",
    "shard",
    "uuid",
    "fingerprint",
    "dedup",
    "partition",
    "metric",
    "content_hash",
})


def _is_usedforsecurity_false(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def _extract_context_identifiers(node: ast.Call, parents: dict[ast.AST, ast.AST]) -> set[str]:
    """Collect relevant names from arguments, parent assignments, and enclosing functions."""
    names: set[str] = set()

    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id.lower())
        elif isinstance(child, ast.Attribute):
            names.add(child.attr.lower())
        elif isinstance(child, ast.keyword) and child.arg:
            names.add(child.arg.lower())

    curr: ast.AST | None = node
    while curr is not None:
        curr = parents.get(curr)
        if isinstance(curr, ast.Assign):
            for t in curr.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id.lower())
                elif isinstance(t, ast.Attribute):
                    names.add(t.attr.lower())
        elif isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(curr.name.lower())
            for arg in curr.args.args:
                names.add(arg.arg.lower())
            break
        elif isinstance(curr, ast.ClassDef):
            names.add(curr.name.lower())

    return names


def _classify_hash_context(node: ast.Call, parents: dict[ast.AST, ast.AST]) -> str:
    """Classify call as 'crypto', 'non_crypto', or 'ambiguous'."""
    names = _extract_context_identifiers(node, parents)

    is_non_crypto = any(any(kw in n for kw in NON_CRYPTO_KEYWORDS) for n in names)
    is_crypto = any(any(kw in n for kw in CRYPTOGRAPHIC_KEYWORDS) for n in names)

    if is_crypto and not is_non_crypto:
        return "crypto"
    if is_non_crypto and not is_crypto:
        return "non_crypto"
    if is_crypto and is_non_crypto:
        return "crypto"
    return "ambiguous"


class WeakCryptoFixer(BaseFixer):
    """AST fixer that upgrades broken/deprecated hashes (MD5, SHA-1) to secure SHA-256 (CWE-327, CWE-328).

    - Auto-applies (``auto_apply = True``) when cryptographic signature, token, password, or auth
      keywords are detected in the enclosing context, safely upgrading to SHA-256.
    - Auto-applies (``auto_apply = True``) by adding ``usedforsecurity=False`` when non-cryptographic
      cache, etag, or checksum contexts are detected.
    - Proposes a manual review candidate (``auto_apply = False``) when hash usage context is ambiguous.
    """

    rule_id = "xbnd.weak-crypto"
    name = "weak_crypto"
    auto_apply = True

    def _fix_impl(self, source: str, file_path: str = "") -> tuple[str, list[FixChange], bool]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, [], False

        parents: dict[ast.AST, ast.AST] = {}
        for p in ast.walk(tree):
            for child in ast.iter_child_nodes(p):
                parents[child] = p

        editor = SourceEditor(source)
        changes: list[FixChange] = []
        change_auto_apply: list[bool] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # 1. hashlib.md5(...), hashlib.sha1(...), hashlib.md4(...)
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr.lower() in WEAK_HASH_NAMES
            ):
                if not _is_usedforsecurity_false(node):
                    old_algo = node.func.attr
                    ctx = _classify_hash_context(node, parents)

                    if ctx == "non_crypto":
                        if node.args or node.keywords:
                            last_item = node.keywords[-1] if node.keywords else node.args[-1]
                            last_seg = editor.segment(last_item)
                            editor.replace(last_item, f"{last_seg}, usedforsecurity=False")
                        else:
                            editor.replace(node, f"{editor.segment(node.func)}(usedforsecurity=False)")
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description=f"Add 'usedforsecurity=False' to non-cryptographic hash 'hashlib.{old_algo}' (CWE-327, CWE-328)",
                                lineno=node.func.lineno,
                                before=f"hashlib.{old_algo}",
                                after=f"hashlib.{old_algo}(..., usedforsecurity=False)",
                            )
                        )
                        change_auto_apply.append(True)
                    else:
                        receiver = editor.segment(node.func.value)
                        new_func_text = f"{receiver}.sha256"
                        editor.replace(node.func, new_func_text)
                        is_verified = (ctx == "crypto")
                        changes.append(
                            FixChange(
                                rule_id=self.rule_id,
                                description=f"Upgrade broken hash 'hashlib.{old_algo}' to 'hashlib.sha256' (CWE-327, CWE-328)",
                                lineno=node.func.lineno,
                                before=f"hashlib.{old_algo}",
                                after="hashlib.sha256",
                            )
                        )
                        change_auto_apply.append(is_verified)

            # 2. hashlib.new("md5", ...), hashlib.new(name="sha1", ...)
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr == "new"
            ):
                if not _is_usedforsecurity_false(node):
                    ctx = _classify_hash_context(node, parents)
                    if (
                        node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)
                        and node.args[0].value.lower() in WEAK_HASH_NAMES
                    ):
                        old_name = node.args[0].value
                        if ctx == "non_crypto":
                            last_item = node.keywords[-1] if node.keywords else node.args[-1]
                            last_seg = editor.segment(last_item)
                            editor.replace(last_item, f"{last_seg}, usedforsecurity=False")
                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description=f"Add 'usedforsecurity=False' to non-cryptographic 'hashlib.new(\"{old_name}\")' (CWE-327, CWE-328)",
                                    lineno=node.args[0].lineno,
                                    before=f'hashlib.new("{old_name}")',
                                    after=f'hashlib.new("{old_name}", ..., usedforsecurity=False)',
                                )
                            )
                            change_auto_apply.append(True)
                        else:
                            old_segment = editor.segment(node.args[0])
                            quote_char = old_segment[0] if old_segment and old_segment[0] in ("'", '"') else '"'
                            new_arg_text = f"{quote_char}sha256{quote_char}"
                            editor.replace(node.args[0], new_arg_text)
                            changes.append(
                                FixChange(
                                    rule_id=self.rule_id,
                                    description=f"Upgrade broken hash 'hashlib.new(\"{old_name}\")' to 'sha256' (CWE-327, CWE-328)",
                                    lineno=node.args[0].lineno,
                                    before=old_segment,
                                    after=new_arg_text,
                                )
                            )
                            change_auto_apply.append(ctx == "crypto")
                    else:
                        for kw in node.keywords:
                            if (
                                kw.arg == "name"
                                and isinstance(kw.value, ast.Constant)
                                and isinstance(kw.value.value, str)
                                and kw.value.value.lower() in WEAK_HASH_NAMES
                            ):
                                old_name = kw.value.value
                                old_segment = editor.segment(kw.value)
                                quote_char = old_segment[0] if old_segment and old_segment[0] in ("'", '"') else '"'
                                new_arg_text = f"{quote_char}sha256{quote_char}"
                                editor.replace(kw.value, new_arg_text)
                                changes.append(
                                    FixChange(
                                        rule_id=self.rule_id,
                                        description=f"Upgrade broken hash 'hashlib.new(name=\"{old_name}\")' to 'sha256' (CWE-327, CWE-328)",
                                        lineno=kw.value.lineno,
                                        before=old_segment,
                                        after=new_arg_text,
                                    )
                                )
                                change_auto_apply.append(ctx == "crypto")

            # 3. hashes.MD5(), hashes.SHA1() from cryptography
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashes"
                and node.func.attr.lower() in ("md5", "sha1", "md4")
            ):
                old_attr = node.func.attr
                receiver = editor.segment(node.func.value)
                new_func_text = f"{receiver}.SHA256"
                editor.replace(node.func, new_func_text)
                ctx = _classify_hash_context(node, parents)
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description=f"Upgrade 'hashes.{old_attr}()' to 'hashes.SHA256()' (CWE-327, CWE-328)",
                        lineno=node.func.lineno,
                        before=f"hashes.{old_attr}",
                        after="hashes.SHA256",
                    )
                )
                change_auto_apply.append(ctx == "crypto")

        if not changes:
            return source, [], False

        try:
            new_source = editor.result()
        except ValueError:
            return source, [], False

        all_verified = bool(change_auto_apply) and all(change_auto_apply)
        return new_source, changes, all_verified

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        new_source, changes, _ = self._fix_impl(source, file_path)
        return new_source, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform source and construct a versioned PatchCandidate contract."""
        fixed_source, changes, is_verified_auto_apply = self._fix_impl(source, target_file)
        if not changes or fixed_source == source:
            return None

        orig_lines = source.splitlines(keepends=True)
        fixed_lines = fixed_source.splitlines(keepends=True)

        diff = "".join(
            unified_diff(
                orig_lines,
                fixed_lines,
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
            )
        )
        rollback_diff = "".join(
            unified_diff(
                fixed_lines,
                orig_lines,
                fromfile=f"b/{target_file}",
                tofile=f"a/{target_file}",
            )
        )

        source_digest = f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"

        confidence: Confidence = "derived" if is_verified_auto_apply else "inferred"
        risk: Severity = "low" if is_verified_auto_apply else "medium"

        if is_verified_auto_apply:
            meta = {
                "auto_apply": True,
                "reason": "Cryptographic signature or token upgraded to SHA-256",
            }
        else:
            meta = {
                "auto_apply": False,
                "reason": "Hash upgrade alters output digest; manual data migration required",
            }

        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="security",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Upgrade weak cryptographic hash to SHA-256",
            generator="plex.repair.weak_crypto",
            generator_version="1.0.0",
            confidence=confidence,
            risk=risk,
            rollback_diff=rollback_diff,
            metadata=meta,
        )
