"""Strict, additive security catalogs; declarations are trusted modeling assumptions."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_PATTERN = re.compile(r"[A-Za-z_]\w*(?:\.(?:[A-Za-z_]\w*|\*))*", re.ASCII)


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
    command_sanitizers: tuple[str, ...] = ()
    command_sinks: tuple[str, ...] = ()

    @property
    def digest(self) -> str:
        data: dict[str, object] = {
            "version": 1,
            "sources": self.sources,
            "sanitizers": self.sanitizers,
            "sinks": self.sinks,
        }
        if self.command_sanitizers:
            data["command_sanitizers"] = self.command_sanitizers
        if self.command_sinks:
            data["command_sinks"] = self.command_sinks
        payload = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def matches(name: str, patterns: tuple[str, ...]) -> bool:
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


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
    if not isinstance(data, dict) or data.keys() - {"version", "sources", "sanitizers", "sinks"}:
        raise PolicyError(
            "Security policy must contain only version, sources, sanitizers and sinks"
        )
    if type(data.get("version")) is not int or data["version"] != 1:
        raise PolicyError("Security policy version must be integer 1")
    catalogs: dict[str, tuple[str, ...]] = {
        "sources": (),
        "sanitizers": (),
        "sinks": (),
        "command_sanitizers": (),
        "command_sinks": (),
    }
    for section in ("sources", "sanitizers", "sinks"):
        groups = data.get(section, {})
        if not isinstance(groups, dict) or (
            section != "sources" and groups.keys() - {"sql", "command"}
        ):
            raise PolicyError(
                f"Security policy {section} must be a catalog mapping (SQL or command only for sinks/sanitizers)"
            )
        if section == "sources":
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
            catalogs["sources"] = tuple(sorted(patterns))
        else:
            for category in ("sql", "command"):
                values = groups.get(category, [])
                if not isinstance(values, list) or any(
                    not isinstance(value, str) or not _PATTERN.fullmatch(value) for value in values
                ):
                    raise PolicyError(
                        f"Security policy {section} entries must be lists of dotted names or wildcard segments"
                    )
                if len(values) > 256:
                    raise PolicyError("Security policy exceeds 256 patterns per section")
                if category == "sql":
                    key = "sanitizers" if section == "sanitizers" else "sinks"
                else:
                    key = "command_sanitizers" if section == "sanitizers" else "command_sinks"
                catalogs[key] = tuple(sorted(set(values)))
    return SecurityPolicy(**catalogs)
