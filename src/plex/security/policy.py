"""Strict, additive security catalogs; declarations are trusted modeling assumptions."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

_PATTERN = re.compile(r"[A-Za-z_]\w*(?:\.(?:[A-Za-z_]\w*|\*))*", re.ASCII)
_IDENT = re.compile(r"[A-Za-z_]\w*", re.ASCII)
_DEST_PATTERN = re.compile(
    r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]{1,5})?",
    re.ASCII,
)

VALID_V2_FAMILIES: frozenset[str] = frozenset(
    {
        "sql",
        "command",
        "path",
        "eval",
        "deserialization",
        "ssrf",
        "data_leak",
        "log",
        "xss",
        "ssti",
        "nosql",
        "redirect",
        "xxe",
    }
)


class PolicyError(ValueError):
    """A policy could not be safely interpreted."""


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.MappingNode) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise PolicyError("Security policy keys must be unique strings")
        result[key] = loader.construct_object(value_node)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@dataclass(frozen=True)
class SecurityPolicy:
    sources: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    sinks: tuple[str, ...] = ()
    version: int = 1
    sanitizers_by_family: dict[str, tuple[str, ...]] = field(default_factory=dict)
    sinks_by_family: dict[str, tuple[str, ...]] = field(default_factory=dict)
    data_classes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    tenant_fields: tuple[str, ...] = ()
    tenant_guards: tuple[str, ...] = ()
    authorization_invariants: dict[str, tuple[str, ...]] = field(default_factory=dict)
    approved_destinations: tuple[str, ...] = ()

    @property
    def digest(self) -> str:
        if self.version == 1:
            payload = json.dumps(
                {
                    "version": 1,
                    "sources": self.sources,
                    "sanitizers": self.sanitizers,
                    "sinks": self.sinks,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()

        payload = json.dumps(
            {
                "version": self.version,
                "sources": self.sources,
                "sanitizers_by_family": self.sanitizers_by_family,
                "sinks_by_family": self.sinks_by_family,
                "data_classes": self.data_classes,
                "tenant_fields": self.tenant_fields,
                "tenant_guards": self.tenant_guards,
                "authorization_invariants": self.authorization_invariants,
                "approved_destinations": self.approved_destinations,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def matches(name: str, patterns: tuple[str, ...]) -> bool:
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)

    def sinks_for(self, family: str) -> tuple[str, ...]:
        if family == "data_leak":
            combined = set(self.sinks_by_family.get("data_leak", ())) | set(
                self.sinks_by_family.get("log", ())
            )
            return tuple(sorted(combined))
        if family in self.sinks_by_family:
            return self.sinks_by_family[family]
        if family == "sql":
            return self.sinks
        return ()

    def sanitizers_for(self, family: str) -> tuple[str, ...]:
        if family == "data_leak":
            combined = set(self.sanitizers_by_family.get("data_leak", ())) | set(
                self.sanitizers_by_family.get("log", ())
            )
            return tuple(sorted(combined))
        if family in self.sanitizers_by_family:
            return self.sanitizers_by_family[family]
        if family == "sql":
            return self.sanitizers
        return ()

    def is_classified_sensitive(self, name: str) -> bool:
        if not name or not self.data_classes:
            return False
        tail = name.split(".")[-1]
        for patterns in self.data_classes.values():
            if self.matches(name, patterns) or self.matches(tail, patterns):
                return True
        return False

    def is_approved_destination(self, url_or_host: str) -> bool:
        if not url_or_host or not self.approved_destinations:
            return False
        candidate = url_or_host.strip()
        if "://" in candidate:
            parsed = urlparse(candidate)
            host = parsed.netloc or ""
        else:
            host = candidate.split("/")[0]
        if not host:
            return False
        host_lower = host.lower()
        host_no_port = host_lower.split(":")[0]
        for pattern in self.approved_destinations:
            pat = pattern.lower()
            if fnmatch.fnmatchcase(host_lower, pat) or fnmatch.fnmatchcase(host_no_port, pat):
                return True
        return False


def _validate_pattern_list(values: object, section: str) -> tuple[str, ...]:
    if not isinstance(values, list) or any(
        not isinstance(value, str) or not _PATTERN.fullmatch(value) for value in values
    ):
        raise PolicyError(
            f"Security policy {section} entries must be lists of dotted names or wildcard segments"
        )
    if len(values) > 256:
        raise PolicyError("Security policy exceeds 256 patterns per section")
    return tuple(sorted(set(values)))


def migrate_policy_v1_to_v2(data: dict[str, object]) -> dict[str, object]:
    """Deterministically upgrade a v1 security policy mapping to v2 schema format."""
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise PolicyError("migrate_policy_v1_to_v2 requires a valid version 1 policy dict")
    if data.keys() - {"version", "sources", "sanitizers", "sinks"}:
        raise PolicyError("v1 policy contains unsupported top-level keys")
    upgraded: dict[str, object] = {"version": 2}
    for key in ("sources", "sanitizers", "sinks"):
        val = data.get(key)
        if isinstance(val, dict) and val:
            upgraded[key] = dict(val)
    if len(upgraded) == 1:
        upgraded["sources"] = {"default": []}
    return upgraded


def _load_v2_policy(data: dict[str, object]) -> SecurityPolicy:
    allowed_keys = {
        "version",
        "sources",
        "sanitizers",
        "sinks",
        "data_classes",
        "tenant_boundaries",
        "authorization_invariants",
        "approved_destinations",
    }
    if data.keys() - allowed_keys:
        raise PolicyError("Security policy v2 contains unknown top-level section")
    if len(data.keys() - {"version"}) == 0:
        raise PolicyError("Security policy v2 must declare at least one policy section")

    sources_set: set[str] = set()
    sources_raw = data.get("sources", {})
    if not isinstance(sources_raw, dict):
        raise PolicyError("Security policy sources must be a catalog mapping")
    for group, values in sources_raw.items():
        if not isinstance(group, str) or not _IDENT.fullmatch(group):
            raise PolicyError("Security policy catalog names must be identifiers")
        sources_set.update(_validate_pattern_list(values, "sources"))
    if len(sources_set) > 256:
        raise PolicyError("Security policy exceeds 256 patterns per section")

    sanitizers_by_family: dict[str, tuple[str, ...]] = {}
    sinks_by_family: dict[str, tuple[str, ...]] = {}
    for section, target_map in (
        ("sanitizers", sanitizers_by_family),
        ("sinks", sinks_by_family),
    ):
        groups = data.get(section, {})
        if not isinstance(groups, dict):
            raise PolicyError(f"Security policy {section} must be a family catalog mapping")
        total = 0
        for family, values in groups.items():
            if not isinstance(family, str) or family not in VALID_V2_FAMILIES:
                raise PolicyError(
                    f"Security policy v2 {section} family '{family}' is not supported"
                )
            validated = _validate_pattern_list(values, section)
            target_map[family] = validated
            total += len(validated)
        if total > 256:
            raise PolicyError("Security policy exceeds 256 patterns per section")

    data_classes: dict[str, tuple[str, ...]] = {}
    raw_classes = data.get("data_classes", {})
    if not isinstance(raw_classes, dict):
        raise PolicyError("Security policy data_classes must be a mapping")
    for cls_name, values in raw_classes.items():
        if not isinstance(cls_name, str) or not _IDENT.fullmatch(cls_name):
            raise PolicyError("Security policy data_classes keys must be identifiers")
        data_classes[cls_name] = _validate_pattern_list(values, "data_classes")

    raw_tenant = data.get("tenant_boundaries", {})
    if not isinstance(raw_tenant, dict) or raw_tenant.keys() - {"fields", "guards"}:
        raise PolicyError("Security policy tenant_boundaries must contain only fields and guards")
    tenant_fields = _validate_pattern_list(
        raw_tenant.get("fields", []), "tenant_boundaries.fields"
    )
    tenant_guards = _validate_pattern_list(
        raw_tenant.get("guards", []), "tenant_boundaries.guards"
    )

    raw_authz = data.get("authorization_invariants", {})
    if not isinstance(raw_authz, dict) or raw_authz.keys() - {
        "protected_decorators",
        "required_guards",
    }:
        raise PolicyError(
            "Security policy authorization_invariants must contain only protected_decorators and required_guards"
        )
    authz_invariants: dict[str, tuple[str, ...]] = {}
    if "protected_decorators" in raw_authz:
        authz_invariants["protected_decorators"] = _validate_pattern_list(
            raw_authz["protected_decorators"], "authorization_invariants.protected_decorators"
        )
    if "required_guards" in raw_authz:
        authz_invariants["required_guards"] = _validate_pattern_list(
            raw_authz["required_guards"], "authorization_invariants.required_guards"
        )

    raw_dests = data.get("approved_destinations", [])
    if not isinstance(raw_dests, list) or any(
        not isinstance(d, str) or not _DEST_PATTERN.fullmatch(d) for d in raw_dests
    ):
        raise PolicyError(
            "Security policy approved_destinations must be a list of hostname patterns"
        )
    if len(raw_dests) > 256:
        raise PolicyError("Security policy exceeds 256 patterns per section")

    return SecurityPolicy(
        version=2,
        sources=tuple(sorted(sources_set)),
        sanitizers=sanitizers_by_family.get("sql", ()),
        sinks=sinks_by_family.get("sql", ()),
        sanitizers_by_family=sanitizers_by_family,
        sinks_by_family=sinks_by_family,
        data_classes=data_classes,
        tenant_fields=tenant_fields,
        tenant_guards=tenant_guards,
        authorization_invariants=authz_invariants,
        approved_destinations=tuple(sorted(set(raw_dests))),
    )


def load_policy(root: Path, explicit: object = None) -> SecurityPolicy:
    if explicit is not None and (not isinstance(explicit, str) or not explicit):
        raise PolicyError("policy must be a nonempty path string")
    path = Path(explicit) if isinstance(explicit, str) else Path(".plex/security.yml")
    if not path.is_absolute():
        path = root / path
    if explicit is None and not path.exists() and not path.is_symlink():
        return SecurityPolicy()
    try:
        if path.stat().st_size > 65_536:
            raise PolicyError("Security policy exceeds 64 KiB limit")
        content = path.read_text(encoding="utf-8")
        data = yaml.load(content, Loader=_UniqueLoader)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise PolicyError(f"Could not read security policy ({type(exc).__name__})") from None
    if not isinstance(data, dict):
        raise PolicyError("Security policy must be a YAML mapping")
    version = data.get("version")
    if type(version) is not int or version not in (1, 2):
        raise PolicyError("Security policy version must be integer 1 or 2")
    if version == 2:
        return _load_v2_policy(data)
    if data.keys() - {"version", "sources", "sanitizers", "sinks"}:
        raise PolicyError(
            "Security policy must contain only version, sources, sanitizers and sinks"
        )
    catalogs: dict[str, tuple[str, ...]] = {}
    for section in ("sources", "sanitizers", "sinks"):
        groups = data.get(section, {})
        if not isinstance(groups, dict) or (section != "sources" and groups.keys() - {"sql"}):
            raise PolicyError(
                f"Security policy {section} must be a catalog mapping (SQL only for sinks/sanitizers)"
            )
        patterns: set[str] = set()
        for group, values in groups.items():
            if not isinstance(group, str) or not re.fullmatch(r"[A-Za-z_]\w*", group, re.ASCII):
                raise PolicyError("Security policy catalog names must be identifiers")
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not _PATTERN.fullmatch(value) for value in values
            ):
                raise PolicyError(
                    f"Security policy {section} entries must be lists of dotted names or wildcard segments"
                )
            patterns.update(values)
        if len(patterns) > 256:
            raise PolicyError("Security policy exceeds 256 patterns per section")
        catalogs[section] = tuple(sorted(patterns))
    return SecurityPolicy(
        sources=catalogs["sources"],
        sanitizers=catalogs["sanitizers"],
        sinks=catalogs["sinks"],
    )

