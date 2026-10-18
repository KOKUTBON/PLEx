"""Deterministic fixer and patch candidate proposer for Dockerfile floating base image tags (cfg.docker-latest-tag)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from plex.fix.base import BaseFixer, FixChange
from plex.repair.diffutil import unified_diff
from plex.repair.models import PatchCandidate
from plex.report.unified import Confidence, Severity

DEFAULT_PIN_MAP: dict[str, str] = {
    "python": "3.12-slim",
    "node": "20-alpine",
    "alpine": "3.19",
    "ubuntu": "22.04",
    "debian": "bookworm-slim",
    "golang": "1.22-alpine",
    "nginx": "1.25-alpine",
    "redis": "7.2-alpine",
    "postgres": "16-alpine",
}

FROM_PATTERN = re.compile(
    r"^(\s*FROM\s+)(--platform=\S+\s+)?([A-Za-z0-9_.\-\/]+)(?::([A-Za-z0-9_.\-]+))?(\s+AS\s+\w+)?(.*)$",
    re.IGNORECASE,
)

FROM_STAGE_DECL_PATTERN = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?([A-Za-z0-9_.\-\/:]+)\s+AS\s+([A-Za-z0-9_.\-]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RuntimeSpec:
    """Project-declared runtime requirement discovered from repository metadata."""

    ecosystem: str
    version: str
    source_file: str


def discover_project_runtimes(directory: Path) -> dict[str, RuntimeSpec]:
    """Scan directory for language runtime configuration files and extract declared versions."""
    runtimes: dict[str, RuntimeSpec] = {}

    if not directory.is_dir():
        return runtimes

    # 1. Python runtime detection
    py_ver_file = directory / ".python-version"
    if py_ver_file.is_file():
        try:
            content = py_ver_file.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    m = re.match(r"^(?:cpython-)?(\d+\.\d+)(?:\.\d+)?", line)
                    if m:
                        runtimes["python"] = RuntimeSpec("python", m.group(1), ".python-version")
                        break
        except (OSError, UnicodeDecodeError):
            pass

    if "python" not in runtimes:
        runtime_txt = directory / "runtime.txt"
        if runtime_txt.is_file():
            try:
                content = runtime_txt.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    m = re.match(r"^python-(\d+\.\d+)(?:\.\d+)?", line, re.IGNORECASE)
                    if m:
                        runtimes["python"] = RuntimeSpec("python", m.group(1), "runtime.txt")
                        break
            except (OSError, UnicodeDecodeError):
                pass

    if "python" not in runtimes:
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file():
            try:
                content = pyproject.read_text(encoding="utf-8")
                m = re.search(
                    r'(?:requires-python|python)\s*=\s*["\'](?:>=|~=|\^|==)?\s*(\d+\.\d+)',
                    content,
                )
                if m:
                    runtimes["python"] = RuntimeSpec("python", m.group(1), "pyproject.toml")
            except (OSError, UnicodeDecodeError):
                pass

    if "python" not in runtimes:
        pipfile = directory / "Pipfile"
        if pipfile.is_file():
            try:
                content = pipfile.read_text(encoding="utf-8")
                m = re.search(r'python_(?:version|full_version)\s*=\s*["\'](\d+\.\d+)', content)
                if m:
                    runtimes["python"] = RuntimeSpec("python", m.group(1), "Pipfile")
            except (OSError, UnicodeDecodeError):
                pass

    # 2. Node.js runtime detection
    nvmrc = directory / ".nvmrc"
    if nvmrc.is_file():
        try:
            content = nvmrc.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    m = re.match(r"^v?(\d+)", line)
                    if m:
                        runtimes["node"] = RuntimeSpec("node", m.group(1), ".nvmrc")
                        break
        except (OSError, UnicodeDecodeError):
            pass

    if "node" not in runtimes:
        node_version = directory / ".node-version"
        if node_version.is_file():
            try:
                content = node_version.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        m = re.match(r"^v?(\d+)", line)
                        if m:
                            runtimes["node"] = RuntimeSpec("node", m.group(1), ".node-version")
                            break
            except (OSError, UnicodeDecodeError):
                pass

    if "node" not in runtimes:
        pkg_json = directory / "package.json"
        if pkg_json.is_file():
            try:
                content = pkg_json.read_text(encoding="utf-8")
                m = re.search(r'"node"\s*:\s*["\'](?:>=|\^|~|v)?\s*(\d+)', content)
                if m:
                    runtimes["node"] = RuntimeSpec("node", m.group(1), "package.json")
            except (OSError, UnicodeDecodeError):
                pass

    # 3. Go runtime detection
    go_mod = directory / "go.mod"
    if go_mod.is_file():
        try:
            content = go_mod.read_text(encoding="utf-8")
            for line in content.splitlines():
                m = re.match(r"^\s*go\s+(\d+\.\d+)", line)
                if m:
                    runtimes["golang"] = RuntimeSpec("golang", m.group(1), "go.mod")
                    break
        except (OSError, UnicodeDecodeError):
            pass

    return runtimes


class DockerTagPinFixer(BaseFixer):
    """Container security fixer that pins unversioned or :latest Docker base images to explicit tags.

    Meets the Section 9 repair contract with strict preconditions:
    - Auto-applies (``auto_apply = True``) when base images match explicit project runtime
      declarations (e.g., Python version in ``.python-version``, ``runtime.txt``, ``pyproject.toml``;
      Node.js version in ``.nvmrc``, ``.node-version``, ``package.json``; Go in ``go.mod``).
    - Falls back to proposal-only (``candidate.metadata["auto_apply"] = False``) when no project runtime
      metadata is declared or image uses static fallback defaults.
    """

    rule_id = "cfg.docker-latest-tag"
    name = "docker_tag_pin"
    auto_apply = True

    def __init__(
        self,
        pin_map: dict[str, str] | None = None,
        default_tag: str = "stable",
        repo_root: Path | None = None,
    ) -> None:
        self.pin_map = pin_map or DEFAULT_PIN_MAP
        self.default_tag = default_tag
        self.repo_root = repo_root.resolve() if repo_root else None
        self.discovered_runtimes: dict[str, RuntimeSpec] = {}
        if self.repo_root:
            self.discovered_runtimes = discover_project_runtimes(self.repo_root)
        self.last_matched_specs: list[RuntimeSpec | None] = []

    def prepare(self, repo_root: Path) -> None:
        """Discover repository-wide runtime declarations."""
        self.repo_root = repo_root.resolve()
        self.discovered_runtimes = discover_project_runtimes(self.repo_root)

    def _get_active_runtimes(self, file_path: str = "") -> dict[str, RuntimeSpec]:
        """Combine repository runtimes with directory-local runtime metadata."""
        runtimes = dict(self.discovered_runtimes)
        if not file_path:
            return runtimes

        p = Path(file_path)
        if not p.is_absolute():
            if self.repo_root:
                p = (self.repo_root / p).resolve()
            else:
                if len(p.parts) > 1:
                    p = p.resolve()
                else:
                    return runtimes
        else:
            p = p.resolve()

        search_dir = p.parent if p.is_file() or not p.exists() else p
        curr: Path | None = search_dir
        stop_dir = self.repo_root

        while curr and curr != stop_dir:
            local_runtimes = discover_project_runtimes(curr)
            for k, v in local_runtimes.items():
                if k not in runtimes:
                    runtimes[k] = v
            if (curr / ".git").exists() or (stop_dir and curr == stop_dir):
                break
            parent = curr.parent
            if parent == curr:
                break
            curr = parent

        return runtimes

    def resolve_pin_with_metadata(
        self,
        image_ref: str,
        runtimes: dict[str, RuntimeSpec] | None = None,
    ) -> tuple[str, RuntimeSpec | None]:
        """Resolve a specific pinned tag and associated runtime provenance spec."""
        clean_img = image_ref.lower().strip()
        short_name = clean_img.split("/")[-1]

        active_runtimes = runtimes if runtimes is not None else self.discovered_runtimes

        # Check project runtime metadata matches
        if short_name in {"python", "python3"} and "python" in active_runtimes:
            spec = active_runtimes["python"]
            return f"{spec.version}-slim", spec

        if short_name in {"node", "nodejs"} and "node" in active_runtimes:
            spec = active_runtimes["node"]
            return f"{spec.version}-alpine", spec

        if short_name in {"golang", "go"} and "golang" in active_runtimes:
            spec = active_runtimes["golang"]
            return f"{spec.version}-alpine", spec

        # Direct match from default pin map
        if clean_img in self.pin_map:
            return self.pin_map[clean_img], None

        if short_name in self.pin_map:
            return self.pin_map[short_name], None

        return self.default_tag, None

    def resolve_pin(self, image_ref: str) -> str:
        """Resolve a specific pinned tag for an image repository."""
        tag, _ = self.resolve_pin_with_metadata(image_ref)
        return tag

    def fix(self, source: str, file_path: str = "") -> tuple[str, list[FixChange]]:
        lines = source.splitlines(keepends=True)
        if not lines:
            self.last_matched_specs = []
            return source, []

        active_runtimes = self._get_active_runtimes(file_path)
        self.last_matched_specs = []

        # Collect earlier declared stage names to avoid pinning multi-stage build references
        declared_stages: set[str] = set()
        for line in lines:
            stage_match = FROM_STAGE_DECL_PATTERN.match(line)
            if stage_match:
                declared_stages.add(stage_match.group(2).lower())

        new_lines: list[str] = []
        changes: list[FixChange] = []

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                new_lines.append(line)
                continue

            # If image is already digest-pinned with @sha256:, do not modify
            if "@" in stripped:
                new_lines.append(line)
                continue

            match = FROM_PATTERN.match(stripped)
            if not match:
                new_lines.append(line)
                continue

            prefix, platform, image, tag, as_clause, trailing = match.groups()

            # Skip 'scratch' base image and references to previous build stages
            if image.lower() == "scratch" or image.lower() in declared_stages:
                new_lines.append(line)
                continue

            platform_str = platform or ""
            as_str = as_clause or ""
            trailing_str = trailing or ""

            # Check if image uses floating :latest or lacks a version tag
            if tag is None or tag.lower() == "latest":
                pinned_version, spec = self.resolve_pin_with_metadata(image, active_runtimes)
                self.last_matched_specs.append(spec)

                line_ending = "\n"
                if line.endswith("\r\n"):
                    line_ending = "\r\n"

                new_line = (
                    f"{prefix}{platform_str}{image}:{pinned_version}{as_str}{trailing_str}{line_ending}"
                )
                new_lines.append(new_line)
                desc = (
                    f"Pin Docker image '{image}' from '{tag or 'unspecified'}' to '{pinned_version}' "
                    f"(derived from {spec.source_file})"
                    if spec
                    else f"Pin Docker image '{image}' from '{tag or 'unspecified'}' to '{pinned_version}'"
                )
                changes.append(
                    FixChange(
                        rule_id=self.rule_id,
                        description=desc,
                        lineno=lineno,
                        before=line,
                        after=new_line,
                    )
                )
            else:
                new_lines.append(line)

        fixed_source = "".join(new_lines)
        return fixed_source, changes

    def propose_patch(
        self,
        source: str,
        target_file: str = "Dockerfile",
        finding_ids: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> PatchCandidate | None:
        """Transform Dockerfile and construct a versioned PatchCandidate contract."""
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

        # Section 9 Auto-apply verification check:
        # Every modified FROM instruction must have a verified project runtime spec
        is_auto_applicable = (
            bool(self.last_matched_specs)
            and all(spec is not None for spec in self.last_matched_specs)
        )

        preconditions: tuple[str, ...]
        confidence: Confidence
        risk: Severity
        meta: dict[str, Any]

        if is_auto_applicable:
            specs = [s for s in self.last_matched_specs if s is not None]
            provenance_map = {s.ecosystem: s.source_file for s in specs}
            pinned_map = {s.ecosystem: s.version for s in specs}
            confidence = "derived"
            risk = "low"
            preconditions = (
                "Base image specifies floating :latest or lacks version tag",
                *(
                    f"Base image runtime matches explicit project requirement '{s.version}' from '{s.source_file}'"
                    for s in specs
                ),
            )
            meta = {
                "auto_apply": True,
                "runtime_provenance": provenance_map,
                "pinned_runtimes": pinned_map,
                "reason": "Base image pinned to explicit project-declared runtime version",
            }
        else:
            confidence = "inferred"
            risk = "medium"
            preconditions = ("Base image specifies floating :latest or lacks version tag",)
            meta = {
                "auto_apply": False,
                "reason": "Requires verifying pinned base image tag compatibility; no explicit project runtime metadata found",
            }

        if metadata:
            meta.update(metadata)

        return PatchCandidate.create(
            finding_ids=finding_ids,
            rule_id=self.rule_id,
            engine="supply_chain",
            source_digest=source_digest,
            target_file=target_file,
            diff=diff,
            description="Pin Docker base image to explicit version tag to avoid floating :latest",
            generator="plex.repair.docker_tag_pin",
            generator_version="2.0.0",
            confidence=confidence,
            risk=risk,
            rollback_diff=rollback_diff,
            preconditions=preconditions,
            metadata=meta,
        )
