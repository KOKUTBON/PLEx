"""Deterministic fixer and patch candidate proposer for weak cryptography and hashes (CWE-327, CWE-328)."""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.repair.sourceedit import SourceEditor

WEAK_HASH_NAMES = frozenset({"md5", "sha1", "md4"})


def _is_usedforsecurity_false(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


class WeakCryptoFixer(BaseFixer):
    """AST fixer that upgrades broken/deprecated hashes (MD5, SHA-1) to secure SHA-256.

    This fixer is proposal-only (``auto_apply = False``) because upgrading hash algorithms
    changes the digest output, which breaks existing verification protocols, password databases,
    and external API contracts without a coordinated migration.
    """

    rule_id = "xbnd.weak-crypto"
    name = "weak_crypto"
    auto_apply = False

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        editor = SourceEditor(source)
        changes: list[FixChange] = []

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
                    receiver = editor.segment(node.func.value)
                    new_func_text = f"{receiver}.sha256"
                    editor.replace(node.func, new_func_text)
                    changes.append(
                        FixChange(
                            rule_id=self.rule_id,
                            description=f"Upgrade broken hash 'hashlib.{old_algo}' to 'hashlib.sha256' (CWE-327, CWE-328)",
                            lineno=node.func.lineno,
                            before=f"hashlib.{old_algo}",
                            after="hashlib.sha256",
                        )
                    )

            # 2. hashlib.new("md5", ...), hashlib.new(name="sha1", ...)
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr == "new"
            ):
                if not _is_usedforsecurity_false(node):
                    if (
                        node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)
                        and node.args[0].value.lower() in WEAK_HASH_NAMES
                    ):
                        old_name = node.args[0].value
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
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description=f"Upgrade 'hashes.{old_attr}()' to 'hashes.SHA256()' (CWE-327, CWE-328)",
                        lineno=node.func.lineno,
                        before=f"hashes.{old_attr}",
                        after="hashes.SHA256",
                    )
                )

        if not changes:
            return source, []

        try:
            new_source = editor.result()
        except ValueError:
            return source, []

        return new_source, changes

    def propose_patch(
        self,
        source: str,
        target_file: str,
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform source and construct a versioned PatchCandidate contract."""
        fixed_source, changes = self.fix(source, target_file)
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

        meta = {"auto_apply": False, "reason": "Hash upgrade alters output digest; manual data migration required"}
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
            confidence="inferred",
            risk="high",
            rollback_diff=rollback_diff,
            metadata=meta,
        )
