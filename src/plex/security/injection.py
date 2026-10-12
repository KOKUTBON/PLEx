"""Shared evidence/report construction for experimental injection rules."""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict

from plex import __version__
from plex.report.unified import EvidenceRef, finding_id
from plex.rules.base import Rule, RuleContext, RuleFinding

from .dataflow import SQLDataflow, SQLFlow
from .modules import ModuleCatalog
from .policy import SecurityPolicy

SCOPE_LIMITATIONS = [
    "Bounded selected-project direct-call analysis; no dynamic imports or receiver type resolution",
    "Path-insensitive branches; one representative source path per modeled sink",
    "No heap/object alias tracking, deferred global-state modeling",
    "Built-in catalogs plus declared policy patterns; custom sanitizers are trusted assumptions",
]


class DataflowInjectionRule(Rule):
    kind = "sql"
    cwe = "CWE-89"
    message = ""
    remediation = ""
    limitations: tuple[str, ...] = ()
    default_severity = "high"
    stability = "experimental"
    tags = ["security", "injection", "CWE-89", "A05:2025"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        trees = {
            file: tree
            for file in sorted(context.sources)
            if (tree := context.ast_for_path(file)) is not None
        }
        project = ModuleCatalog(trees)
        configured = context.security_policy.get("catalog")
        policy = configured if isinstance(configured, SecurityPolicy) else SecurityPolicy()
        states: dict[str, SQLDataflow] = {}
        # Static preparation never resolves imported calls or executes target code.
        for file, tree in trees.items():
            state = SQLDataflow(file, policy, kind=self.kind)
            state.project = project
            state.allow_cross_module = False
            state.analyze(tree)
            states[file] = state
        flows: dict[tuple[str, str, int, int], SQLFlow] = {}
        for file, tree in trees.items():
            scanner = SQLDataflow(file, policy, kind=self.kind)
            scanner.project = project
            scanner.module_states = states
            context.dataflow[f"{self.id}:{file}"] = scanner
            for flow in scanner.analyze(tree):
                key = (flow.steps[-1].file, flow.qualname, flow.call.lineno, flow.call.col_offset)
                flows.setdefault(key, flow)
        occurrences: dict[tuple[str, str, str], int] = {}
        for flow in flows.values():
            file = flow.steps[-1].file
            call = flow.call
            signature = ast.dump(call, include_attributes=False)
            occurrence_key = (file, flow.qualname, signature)
            occurrence = occurrences.get(occurrence_key, 0)
            occurrences[occurrence_key] = occurrence + 1
            identity = finding_id(
                "xboundary",
                self.id,
                json.dumps([file, flow.qualname, signature, occurrence], separators=(",", ":")),
                self.name,
            )
            payload = {"steps": [asdict(step) for step in flow.steps]}
            digest = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            )
            ref = f"dataflow:{identity}"
            function = context.finding_for(file, flow.qualname)
            finding = RuleFinding(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.default_severity,
                message=self.message,
                file=file,
                lineno=call.lineno,
                end_lineno=call.end_lineno or call.lineno,
                qualname=flow.qualname,
                function_id=function.function_id if function else "",
                body_hash=function.body_hash if function else "",
                suggestions=[self.remediation],
                category="security",
                cwe=[self.cwe],
                owasp=["A05:2025"],
                evidence=[
                    EvidenceRef(
                        "xboundary",
                        "dataflow_path",
                        ref,
                        digest,
                        __version__,
                        "none",
                        [*SCOPE_LIMITATIONS, *self.limitations],
                    )
                ],
                engine_meta={
                    "finding_id": identity,
                    "stability": self.stability,
                    "policy_digest": policy.digest,
                    "dataflow_paths": {ref: payload},
                },
            )
            if context.suppression_context:
                suppressed, directive = context.suppression_context.is_suppressed(
                    file, call.lineno, self.id
                )
                if suppressed and directive:
                    context.suppressed_findings.append((finding, directive))
                    continue
            yield finding
