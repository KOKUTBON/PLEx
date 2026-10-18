"""Models for dependency manifest parsing, supply chain tracking, and configuration security."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

ManifestKind = Literal[
    "requirements",
    "poetry_lock",
    "pipfile_lock",
    "package_lock_json",
    "package_json",
    "dockerfile",
    "env_file",
]


@dataclass(frozen=True)
class DependencyRecord:
    """A declared package dependency extracted from a manifest."""

    name: str
    specifier: str
    file: str
    lineno: int
    is_pinned: bool = False
    resolved_version: str | None = None
    hashes: tuple[str, ...] = ()
    index_url: str | None = None


@dataclass(frozen=True)
class AdvisoryRecord:
    """Known vulnerability advisory for a package within a version range."""

    cve_id: str
    package: str
    affected_specifier: str  # e.g. "< 1.26.18"
    fixed_version: str
    severity: str
    description: str
    cwe: tuple[str, ...] = ("CWE-1395",)
    vulnerable_symbols: tuple[str, ...] = ()


@dataclass
class AdvisoryFeed:
    """A declared feed of vulnerability advisories with provenance and freshness tracking."""

    feed_id: str
    updated_at: str  # ISO 8601 UTC timestamp
    freshness_max_age_days: int = 30
    source_url: str | None = None
    advisories: list[AdvisoryRecord] = field(default_factory=list)

    def is_stale(self, as_of: datetime | None = None) -> bool:
        """Check whether the advisory feed exceeds its declared freshness lifetime."""
        target_time = as_of or datetime.now(timezone.utc)
        try:
            feed_time = datetime.fromisoformat(self.updated_at.replace("Z", "+00:00"))
            if feed_time.tzinfo is None:
                feed_time = feed_time.replace(tzinfo=timezone.utc)
        except Exception:
            return True
        delta = target_time - feed_time
        return delta.total_seconds() > (self.freshness_max_age_days * 86400)

    def check_freshness(self, as_of: datetime | None = None) -> tuple[bool, str | None]:
        """Return (is_fresh, message)."""
        stale = self.is_stale(as_of)
        if stale:
            return False, (
                f"Advisory feed '{self.feed_id}' is stale: updated at {self.updated_at}, "
                f"exceeding max age of {self.freshness_max_age_days} day(s)."
            )
        return True, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "updated_at": self.updated_at,
            "freshness_max_age_days": self.freshness_max_age_days,
            "source_url": self.source_url,
            "advisories_count": len(self.advisories),
            "advisories": [
                {
                    "cve_id": a.cve_id,
                    "package": a.package,
                    "affected_specifier": a.affected_specifier,
                    "fixed_version": a.fixed_version,
                    "severity": a.severity,
                    "description": a.description,
                    "cwe": list(a.cwe),
                    "vulnerable_symbols": list(a.vulnerable_symbols),
                }
                for a in self.advisories
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdvisoryFeed:
        feed_id = str(data.get("feed_id", "custom"))
        updated_at = str(data.get("updated_at", ""))
        freshness_max_age_days = int(data.get("freshness_max_age_days", 30))
        source_url = data.get("source_url")
        raw_advs = data.get("advisories", [])
        advisories: list[AdvisoryRecord] = []
        for raw in raw_advs:
            advisories.append(
                AdvisoryRecord(
                    cve_id=str(raw.get("cve_id", "")),
                    package=str(raw.get("package", "")).lower(),
                    affected_specifier=str(raw.get("affected_specifier", "")),
                    fixed_version=str(raw.get("fixed_version", "")),
                    severity=str(raw.get("severity", "medium")),
                    description=str(raw.get("description", "")),
                    cwe=tuple(raw.get("cwe", ["CWE-1395"])),
                    vulnerable_symbols=tuple(raw.get("vulnerable_symbols", ())),
                )
            )
        return cls(
            feed_id=feed_id,
            updated_at=updated_at,
            freshness_max_age_days=freshness_max_age_days,
            source_url=source_url,
            advisories=advisories,
        )

    @classmethod
    def from_file(cls, path: Path) -> AdvisoryFeed:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            if data and "affected" in data[0]:
                return cls.from_osv(data, feed_id=path.stem)
            return cls(
                feed_id=path.stem,
                updated_at=datetime.now(timezone.utc).isoformat(),
                advisories=[
                    AdvisoryRecord(
                        cve_id=str(r.get("cve_id", "")),
                        package=str(r.get("package", "")).lower(),
                        affected_specifier=str(r.get("affected_specifier", "")),
                        fixed_version=str(r.get("fixed_version", "")),
                        severity=str(r.get("severity", "medium")),
                        description=str(r.get("description", "")),
                        cwe=tuple(r.get("cwe", ["CWE-1395"])),
                        vulnerable_symbols=tuple(r.get("vulnerable_symbols", ())),
                    )
                    for r in data
                ],
            )
        if "affected" in data:
            return cls.from_osv([data], feed_id=path.stem)
        return cls.from_dict(data)

    @classmethod
    def from_osv(
        cls,
        osv_entries: list[dict[str, Any]],
        feed_id: str = "osv",
        updated_at: str | None = None,
    ) -> AdvisoryFeed:
        """Parse standard Open Source Vulnerability (OSV) records."""
        latest_mod: str = ""
        advisories: list[AdvisoryRecord] = []
        for entry in osv_entries:
            cve_id = str(entry.get("id", ""))
            summary = entry.get("summary") or entry.get("details") or ""
            modified = str(entry.get("modified", ""))
            if modified > latest_mod:
                latest_mod = modified

            severity = "medium"
            db_spec = entry.get("database_specific", {})
            if isinstance(db_spec, dict) and "severity" in db_spec:
                severity = str(db_spec["severity"]).lower()

            cwes: list[str] = []
            if isinstance(db_spec, dict) and "cwe_ids" in db_spec:
                cwes = [str(c) for c in db_spec["cwe_ids"]]
            if not cwes:
                cwes = ["CWE-1395"]

            for aff in entry.get("affected", []):
                pkg_obj = aff.get("package", {})
                pkg_name = str(pkg_obj.get("name", "")).lower()
                if not pkg_name:
                    continue

                for rng in aff.get("ranges", []):
                    events = rng.get("events", [])
                    introduced = ""
                    fixed = ""
                    for ev in events:
                        if "introduced" in ev:
                            introduced = str(ev["introduced"])
                        if "fixed" in ev:
                            fixed = str(ev["fixed"])

                    spec_clauses: list[str] = []
                    if introduced and introduced != "0":
                        spec_clauses.append(f">={introduced}")
                    if fixed:
                        spec_clauses.append(f"<{fixed}")

                    specifier = ", ".join(spec_clauses) if spec_clauses else f"<{fixed}" if fixed else ""
                    if not fixed and not specifier:
                        continue

                    symbols: list[str] = []
                    eco = aff.get("ecosystem_specific", {})
                    if isinstance(eco, dict) and "affected_functions" in eco:
                        symbols = [str(fn) for fn in eco["affected_functions"]]

                    advisories.append(
                        AdvisoryRecord(
                            cve_id=cve_id,
                            package=pkg_name,
                            affected_specifier=specifier,
                            fixed_version=fixed,
                            severity=severity,
                            description=summary,
                            cwe=tuple(cwes),
                            vulnerable_symbols=tuple(symbols),
                        )
                    )

        up_at = updated_at or latest_mod or datetime.now(timezone.utc).isoformat()
        return cls(feed_id=feed_id, updated_at=up_at, advisories=advisories)

    def compute_digest(self) -> str:
        """Compute deterministic SHA-256 digest of the canonical advisory feed payload."""
        import hashlib
        import json

        canonical = json.dumps(self.to_dict(), sort_keys=True)
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        timeout: float = 10.0,
        expected_sha256: str | None = None,
    ) -> AdvisoryFeed:
        """Fetch and parse a JSON or OSV advisory feed from an HTTP/HTTPS mirror endpoint."""
        import hashlib
        import json
        from urllib.parse import urlparse
        from urllib.request import Request, urlopen

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Unsupported advisory feed URL scheme '{parsed.scheme}'; only http and https are allowed"
            )

        req = Request(url, headers={"Accept": "application/json", "User-Agent": "PLEx-SupplyChain/2.0"})
        with urlopen(req, timeout=timeout) as resp:
            raw_bytes = resp.read()

        if expected_sha256:
            clean_expected = expected_sha256.removeprefix("sha256:").strip().lower()
            actual_hex = hashlib.sha256(raw_bytes).hexdigest().lower()
            if actual_hex != clean_expected:
                raise ValueError(
                    f"Advisory feed SHA-256 mismatch: expected {clean_expected}, got {actual_hex}"
                )

        data = json.loads(raw_bytes.decode("utf-8"))
        if isinstance(data, list):
            if data and "affected" in data[0]:
                feed = cls.from_osv(data, feed_id="remote-osv")
                feed.source_url = url
                return feed
            feed = cls.from_dict(
                {
                    "feed_id": "remote-mirror",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "source_url": url,
                    "advisories": data,
                }
            )
            return feed
        if "affected" in data:
            feed = cls.from_osv([data], feed_id=str(data.get("id", "remote-osv")))
            feed.source_url = url
            return feed
        feed = cls.from_dict(data)
        if not feed.source_url:
            feed.source_url = url
        return feed


@dataclass
class FeedMirrorCache:
    """Local offline mirror cache for vulnerability advisory feeds with remote refresh fallback."""

    cache_dir: Path

    def _feed_path(self, feed_id: str) -> Path:
        safe_id = "".join(c if c.isalnum() or c in "-_." else "_" for c in feed_id)
        return self.cache_dir / f"{safe_id}.json"

    def save(self, feed: AdvisoryFeed) -> Path:
        """Persist an AdvisoryFeed to the local mirror cache directory."""
        import json

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        target = self._feed_path(feed.feed_id)
        payload = feed.to_dict()
        payload["digest"] = feed.compute_digest()
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return target

    def load(self, feed_id: str) -> AdvisoryFeed | None:
        """Load a cached AdvisoryFeed by feed_id if present."""
        target = self._feed_path(feed_id)
        if not target.exists():
            return None
        return AdvisoryFeed.from_file(target)

    def refresh_or_fallback(
        self,
        feed_id: str,
        *,
        source_url: str | None = None,
        fallback: AdvisoryFeed | None = None,
        timeout: float = 10.0,
        expected_sha256: str | None = None,
        force_refresh: bool = False,
    ) -> tuple[AdvisoryFeed, str]:
        """Return a fresh cached feed, refresh from remote mirror URL, or fall back cleanly."""
        cached = self.load(feed_id)
        if cached is not None and not cached.is_stale() and not force_refresh:
            return cached, "cached_fresh"

        target_url = source_url or (cached.source_url if cached else None)
        if target_url and target_url.startswith(("http://", "https://")):
            try:
                remote_feed = AdvisoryFeed.from_url(
                    target_url,
                    timeout=timeout,
                    expected_sha256=expected_sha256,
                )
                remote_feed.feed_id = feed_id
                self.save(remote_feed)
                return remote_feed, "refreshed_remote"
            except Exception:
                if cached is not None:
                    return cached, "cached_stale_fallback"

        if cached is not None:
            return cached, "cached_stale_fallback"

        if fallback is not None:
            return fallback, "builtin_fallback"

        from .scanner import BUILTIN_FEED

        return BUILTIN_FEED, "builtin_fallback"


ReachabilityStatus = Literal["reachable", "imported_uninvoked", "unreachable"]


@dataclass(frozen=True)
class CallSiteEvidence:
    """A concrete call site in project code invoking a dependency API."""

    package: str
    file: str
    lineno: int
    col_offset: int
    caller_symbol: str
    called_symbol: str
    source_line: str


@dataclass(frozen=True)
class DependencyReachability:
    """Reachability evaluation for a declared dependency and security advisory."""

    dependency: DependencyRecord
    advisory: AdvisoryRecord
    status: ReachabilityStatus
    import_sites: tuple[tuple[str, int], ...]
    call_sites: tuple[CallSiteEvidence, ...]
    reason: str


@dataclass(frozen=True)
class ConfigSecurityFinding:
    """A security issue detected in a configuration or container definition file."""

    rule_id: str
    severity: str
    file: str
    lineno: int
    title: str
    message: str
    remediation: str
    cwe: tuple[str, ...] = ("CWE-16",)
    details: dict[str, Any] = field(default_factory=dict)
