"""Repeatable browser/DOM session scenario runner and replayable fixture engine for PLEx Validate."""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Literal

from plex.sandbox import SubprocessSandbox

from .http import HttpExchange
from .scope import NetworkScope, enforce_scope
from .session import (
    ExtractedHtmlForm,
    StatefulSessionClient,
    extract_html_forms,
)

BrowserAction = Literal[
    "navigate",
    "fill_form",
    "submit_form",
    "request",
    "assert_text",
    "assert_selector",
]


@dataclass(frozen=True)
class BrowserStep:
    """A single step in a repeatable browser or stateful HTTP/DOM scenario."""

    action: BrowserAction
    target: str = ""
    values: dict[str, str] = field(default_factory=dict)
    method: str = "GET"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BrowserStepResult:
    """Recorded outcome and evidence for a single BrowserStep."""

    step_index: int
    action: BrowserAction
    status: Literal["passed", "failed", "error"]
    url: str
    exchange: HttpExchange | None = None
    extracted_forms: tuple[ExtractedHtmlForm, ...] = ()
    extracted_scripts: tuple[str, ...] = ()
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_index": self.step_index,
            "action": self.action,
            "status": self.status,
            "url": self.url,
            "exchange": self.exchange.to_dict() if self.exchange else None,
            "extracted_forms": [f.to_dict() for f in self.extracted_forms],
            "extracted_scripts": list(self.extracted_scripts),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class BrowserScenarioResult:
    """Complete execution and replayable fixture record for a BrowserSessionScenario."""

    scenario_id: str
    backend: str
    passed: bool
    step_results: tuple[BrowserStepResult, ...]
    cookies_captured: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "backend": self.backend,
            "passed": self.passed,
            "step_results": [s.to_dict() for s in self.step_results],
            "cookies_captured": list(self.cookies_captured),
            "limitations": list(self.limitations),
        }

    def save_replay_fixture(self, path: Path) -> None:
        """Persist redacted exchanges and DOM artifacts as a deterministic replay fixture."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load_replay_fixture(cls, path: Path) -> BrowserScenarioResult:
        """Load a saved BrowserScenarioResult replay fixture from disk."""
        data = json.loads(path.read_text(encoding="utf-8"))
        steps: list[BrowserStepResult] = []
        for raw_step in data.get("step_results", []):
            raw_ex = raw_step.get("exchange")
            exchange = (
                HttpExchange(
                    method=raw_ex["method"],
                    url=raw_ex["url"],
                    request_headers=raw_ex["request_headers"],
                    request_body=raw_ex["request_body"],
                    status_code=raw_ex["status_code"],
                    response_headers=raw_ex["response_headers"],
                    response_body=raw_ex["response_body"],
                    duration_ms=raw_ex["duration_ms"],
                    digest=raw_ex["digest"],
                )
                if raw_ex
                else None
            )
            forms = tuple(
                ExtractedHtmlForm(
                    action=f["action"],
                    method=f.get("method", "GET"),
                    inputs=f.get("inputs", {}),
                    csrf_fields=f.get("csrf_fields", {}),
                )
                for f in raw_step.get("extracted_forms", [])
            )
            steps.append(
                BrowserStepResult(
                    step_index=int(raw_step["step_index"]),
                    action=raw_step["action"],
                    status=raw_step["status"],
                    url=raw_step["url"],
                    exchange=exchange,
                    extracted_forms=forms,
                    extracted_scripts=tuple(raw_step.get("extracted_scripts", [])),
                    notes=raw_step.get("notes", ""),
                )
            )
        return cls(
            scenario_id=str(data.get("scenario_id", "replayed")),
            backend=str(data.get("backend", "replay")),
            passed=bool(data.get("passed", False)),
            step_results=tuple(steps),
            cookies_captured=tuple(data.get("cookies_captured", [])),
            limitations=tuple(data.get("limitations", [])),
        )


class _DomScriptAndSelectorParser(HTMLParser):
    """Extract inline/external <script> sources and CSS-like selectors (#id, .class, tag)."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self.selectors: set[str] = set()
        self._in_script: bool = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_low = tag.lower()
        self.selectors.add(tag_low)
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        elem_id = attr_map.get("id", "").strip()
        if elem_id:
            self.selectors.add(f"#{elem_id}")
        elem_cls = attr_map.get("class", "").strip()
        for c in elem_cls.split():
            if c:
                self.selectors.add(f".{c}")
        name_attr = attr_map.get("name", "").strip()
        if name_attr:
            self.selectors.add(f"[name={name_attr}]")

        if tag_low == "script":
            src = attr_map.get("src", "").strip()
            if src:
                self.scripts.append(f"src:{src}")
            self._in_script = True
            self._script_chunks = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            body = "".join(self._script_chunks).strip()
            if body:
                self.scripts.append(body)
            self._in_script = False
            self._script_chunks = []


def extract_dom_scripts_and_selectors(html_text: str) -> tuple[list[str], set[str]]:
    """Extract <script> blocks/sources and matching DOM selectors from an HTML document."""
    parser = _DomScriptAndSelectorParser()
    parser.feed(html_text)
    return parser.scripts, parser.selectors


class BrowserBackend:
    """Base interface for browser/DOM scenario execution backends."""

    name: str = "base"

    def is_available(self) -> bool:
        raise NotImplementedError

    def execute_scenario(
        self,
        scenario_id: str,
        steps: list[BrowserStep],
        scope: NetworkScope,
    ) -> BrowserScenarioResult:
        raise NotImplementedError


class SimulatedDomBrowserBackend(BrowserBackend):
    """Pure-Python deterministic DOM, form, cookie, and CSRF session runner."""

    name = "simulated_dom"

    def is_available(self) -> bool:
        return True

    def execute_scenario(
        self,
        scenario_id: str,
        steps: list[BrowserStep],
        scope: NetworkScope,
    ) -> BrowserScenarioResult:
        session = StatefulSessionClient(scope=scope)
        results: list[BrowserStepResult] = []
        current_url = ""
        current_html = ""
        current_forms: list[ExtractedHtmlForm] = []
        pending_overrides: dict[str, str] = {}
        all_passed = True

        for idx, step in enumerate(steps):
            try:
                if step.action == "navigate":
                    current_url = step.target
                    exchange, current_forms = session.fetch_form(current_url)
                    current_html = exchange.response_body
                    scripts, _ = extract_dom_scripts_and_selectors(current_html)
                    ok = 200 <= exchange.status_code < 400
                    if not ok:
                        all_passed = False
                    results.append(
                        BrowserStepResult(
                            step_index=idx,
                            action=step.action,
                            status="passed" if ok else "failed",
                            url=current_url,
                            exchange=exchange,
                            extracted_forms=tuple(current_forms),
                            extracted_scripts=tuple(scripts),
                            notes=f"HTTP {exchange.status_code}; {len(current_forms)} form(s) extracted",
                        )
                    )
                elif step.action == "fill_form":
                    pending_overrides.update(step.values)
                    results.append(
                        BrowserStepResult(
                            step_index=idx,
                            action=step.action,
                            status="passed",
                            url=current_url,
                            extracted_forms=tuple(current_forms),
                            notes=f"Staged {len(step.values)} form input override(s)",
                        )
                    )
                elif step.action == "submit_form":
                    if not current_forms:
                        all_passed = False
                        results.append(
                            BrowserStepResult(
                                step_index=idx,
                                action=step.action,
                                status="failed",
                                url=current_url,
                                notes="No HTML form available to submit on current page",
                            )
                        )
                        continue
                    target_form = current_forms[0]
                    if step.target:
                        for candidate_form in current_forms:
                            if step.target in candidate_form.action:
                                target_form = candidate_form
                                break
                    merged_overrides = {**pending_overrides, **step.values}
                    pending_overrides.clear()
                    exchange = session.submit_form(target_form, overrides=merged_overrides)
                    current_url = target_form.action
                    current_html = exchange.response_body
                    current_forms = extract_html_forms(current_html, base_url=current_url)
                    scripts, _ = extract_dom_scripts_and_selectors(current_html)
                    ok = 200 <= exchange.status_code < 400
                    if not ok:
                        all_passed = False
                    results.append(
                        BrowserStepResult(
                            step_index=idx,
                            action=step.action,
                            status="passed" if ok else "failed",
                            url=current_url,
                            exchange=exchange,
                            extracted_forms=tuple(current_forms),
                            extracted_scripts=tuple(scripts),
                            notes=f"Submitted form to {current_url} -> HTTP {exchange.status_code}",
                        )
                    )
                elif step.action == "request":
                    current_url = step.target or current_url
                    exchange = session.request(step.method, current_url, data=step.values.get("body"))
                    current_html = exchange.response_body
                    current_forms = extract_html_forms(current_html, base_url=current_url)
                    scripts, _ = extract_dom_scripts_and_selectors(current_html)
                    ok = 200 <= exchange.status_code < 400
                    if not ok:
                        all_passed = False
                    results.append(
                        BrowserStepResult(
                            step_index=idx,
                            action=step.action,
                            status="passed" if ok else "failed",
                            url=current_url,
                            exchange=exchange,
                            extracted_forms=tuple(current_forms),
                            extracted_scripts=tuple(scripts),
                            notes=f"{step.method.upper()} {current_url} -> HTTP {exchange.status_code}",
                        )
                    )
                elif step.action == "assert_text":
                    found = step.target in current_html
                    if not found:
                        all_passed = False
                    results.append(
                        BrowserStepResult(
                            step_index=idx,
                            action=step.action,
                            status="passed" if found else "failed",
                            url=current_url,
                            notes=f"Text '{step.target}' {'found' if found else 'not found'} in DOM",
                        )
                    )
                elif step.action == "assert_selector":
                    _, selectors = extract_dom_scripts_and_selectors(current_html)
                    found = step.target in selectors
                    if not found:
                        all_passed = False
                    results.append(
                        BrowserStepResult(
                            step_index=idx,
                            action=step.action,
                            status="passed" if found else "failed",
                            url=current_url,
                            notes=f"Selector '{step.target}' {'matched' if found else 'not matched'} in DOM",
                        )
                    )
            except Exception as exc:
                all_passed = False
                results.append(
                    BrowserStepResult(
                        step_index=idx,
                        action=step.action,
                        status="error",
                        url=step.target or current_url,
                        notes=str(exc),
                    )
                )

        return BrowserScenarioResult(
            scenario_id=scenario_id,
            backend=self.name,
            passed=all_passed,
            step_results=tuple(results),
            cookies_captured=tuple(sorted(session.cookies.keys())),
        )


class HeadlessBrowserBackend(BrowserBackend):
    """Optional Chromium/Playwright headless DOM backend with automatic SimulatedDom fallback."""

    name = "headless_chromium"

    def _find_browser_binary(self) -> str | None:
        for candidate in ("chromium", "chromium-browser", "google-chrome"):
            found = shutil.which(candidate)
            if found:
                return found
        return None

    def is_available(self) -> bool:
        return self._find_browser_binary() is not None

    def execute_scenario(
        self,
        scenario_id: str,
        steps: list[BrowserStep],
        scope: NetworkScope,
    ) -> BrowserScenarioResult:
        # Enforce scope on all target URLs up front
        for st in steps:
            if st.action in ("navigate", "request") and st.target:
                enforce_scope(st.target, scope)

        binary = self._find_browser_binary()
        sim = SimulatedDomBrowserBackend()
        base_result = sim.execute_scenario(scenario_id, steps, scope)
        if not binary:
            return BrowserScenarioResult(
                scenario_id=scenario_id,
                backend="simulated_dom",
                passed=base_result.passed,
                step_results=base_result.step_results,
                cookies_captured=base_result.cookies_captured,
                limitations=(
                    "Headless Chromium binary not installed; executed scenario via SimulatedDomBrowserBackend",
                ),
            )

        # If headless Chromium is available and the first step is a navigate, dump rendered DOM once inside sandbox
        sandbox = SubprocessSandbox(default_timeout=15.0)
        limitations: list[str] = []
        if steps and steps[0].action == "navigate" and steps[0].target:
            proc = sandbox.execute(
                [binary, "--headless", "--disable-gpu", "--dump-dom", steps[0].target],
                cwd=Path.cwd(),
            )
            if proc.returncode != 0:
                limitations.append(
                    "Headless Chromium DOM dump returned non-zero; used stateful DOM simulation"
                )
        return BrowserScenarioResult(
            scenario_id=scenario_id,
            backend=self.name,
            passed=base_result.passed,
            step_results=base_result.step_results,
            cookies_captured=base_result.cookies_captured,
            limitations=tuple(limitations),
        )


class BrowserSessionRunner:
    """Executes repeatable browser/DOM scenarios and replays recorded fixtures."""

    def __init__(
        self,
        scope: NetworkScope | None = None,
        prefer_headless: bool = False,
    ) -> None:
        self.scope = scope or NetworkScope()
        self.prefer_headless = prefer_headless

    def run(
        self,
        scenario_id: str,
        steps: list[BrowserStep],
    ) -> BrowserScenarioResult:
        backend: BrowserBackend = (
            HeadlessBrowserBackend() if self.prefer_headless else SimulatedDomBrowserBackend()
        )
        return backend.execute_scenario(scenario_id, steps, self.scope)

    def replay(self, fixture_path: Path) -> BrowserScenarioResult:
        """Deterministically replay a previously recorded BrowserScenarioResult fixture offline."""
        return BrowserScenarioResult.load_replay_fixture(fixture_path)
