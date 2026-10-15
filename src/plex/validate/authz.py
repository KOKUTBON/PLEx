"""Authorization verification and scope parsing for PLEx Validate active testing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class AuthorizationError(Exception):
    """Raised when active validation is attempted without valid authorization."""


@dataclass(frozen=True)
class AuthorizationRecord:
    """Record defining explicit authorization for active testing on target endpoints."""

    authorized_by: str
    targets: tuple[str, ...]
    valid_until: str | None = None
    allowed_tests: tuple[str, ...] = ("all",)
    operator: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def parse_authorization(source: Path | str) -> AuthorizationRecord:
    """Parse an authorization document (Markdown with headers or key-value fields)."""
    text = source.read_text(encoding="utf-8") if isinstance(source, Path) else source

    authorized_by = ""
    targets: list[str] = []
    valid_until = None
    allowed_tests: list[str] = []
    operator = None
    meta: dict[str, Any] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip list bullets if present
        if line.startswith(("- ", "* ")):
            line = line[2:].strip()

        if ":" not in line:
            continue

        key, _, val = line.partition(":")
        k = key.strip().lower().replace(" ", "_").replace("-", "_")
        v = val.strip()

        if k in ("authorized_by", "approver", "authorizer"):
            authorized_by = v
        elif k in ("targets", "target", "target_urls", "scope"):
            items = [item.strip() for item in re.split(r"[,;]\s*", v) if item.strip()]
            targets.extend(items)
        elif k in ("valid_until", "expires", "expiration"):
            valid_until = v
        elif k in ("allowed_tests", "test_scope", "permitted_tests"):
            items = [item.strip() for item in re.split(r"[,;]\s*", v) if item.strip()]
            allowed_tests.extend(items)
        elif k in ("operator", "tester", "operator_id"):
            operator = v
        else:
            meta[k] = v

    if not authorized_by:
        raise AuthorizationError("Authorization document missing required 'Authorized By' field")
    if not targets:
        raise AuthorizationError("Authorization document contains no authorized targets")

    return AuthorizationRecord(
        authorized_by=authorized_by,
        targets=tuple(dict.fromkeys(targets)),
        valid_until=valid_until,
        allowed_tests=tuple(dict.fromkeys(allowed_tests or ["all"])),
        operator=operator,
        metadata=meta,
    )


def validate_authorization(
    record: AuthorizationRecord,
    target_url: str,
    operator: str | None = None,
) -> tuple[bool, str | None]:
    """Verify that a specific target URL and operator are authorized."""
    if not record.authorized_by:
        return False, "Missing authorizing party identity"

    # Check expiration if present
    if record.valid_until:
        try:
            exp_date = datetime.fromisoformat(record.valid_until.replace("Z", "+00:00"))
            if exp_date < datetime.now(timezone.utc):
                return False, f"Authorization expired at {record.valid_until}"
        except (ValueError, TypeError):
            pass

    target_parsed = urlparse(target_url)
    target_host_port = (
        target_parsed.netloc or f"{target_parsed.hostname}:{target_parsed.port or 80}"
    )

    # Check target match against authorized scope
    matched = False
    for authz_target in record.targets:
        authz_parsed = urlparse(authz_target if "://" in authz_target else f"http://{authz_target}")
        authz_host_port = (
            authz_parsed.netloc or f"{authz_parsed.hostname}:{authz_parsed.port or 80}"
        )

        if target_host_port == authz_host_port:
            # Host and port match; verify path prefix if specified in authz_target
            if not authz_parsed.path or authz_parsed.path == "/":
                matched = True
                break
            if target_parsed.path.startswith(authz_parsed.path):
                matched = True
                break

    if not matched:
        return (
            False,
            f"Target '{target_url}' is not within authorized scope: {list(record.targets)}",
        )

    # For non-local targets, require recorded operator identity
    is_local = (target_parsed.hostname or "").lower() in {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    }
    effective_operator = operator or record.operator
    if not is_local and not effective_operator:
        return (
            False,
            "Non-local testing requires explicit recorded operator identity (--operator)",
        )

    return True, None
