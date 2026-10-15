from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field

from plex.rules.base import Rule, RuleContext, RuleFinding
from plex.rules.builtin import BUILTIN_RULES

log = logging.getLogger(__name__)


@dataclass
class RuleRegistry:
    rules: list[Rule] = field(default_factory=list)

    def register(self, rule: Rule) -> None:
        self.rules.append(rule)

    def load_builtin(self) -> None:
        for rule in BUILTIN_RULES:
            self.register(rule)

    def load_plugins(
        self, plugin_modules: Iterable[str], failures: list[str] | None = None
    ) -> None:
        for module_path in plugin_modules:
            module_path = str(module_path).strip()
            if not module_path:
                continue
            try:
                module = importlib.import_module(module_path)
            except Exception as exc:
                log.warning("Failed to load rule plugin %s (%s)", module_path, exc)
                if failures is not None:
                    failures.append(f"Rule plugin unavailable: {module_path}")
                continue
            if hasattr(module, "register"):
                try:
                    module.register(self)
                    continue
                except Exception as exc:
                    log.warning("Rule plugin register() failed for %s (%s)", module_path, exc)
                    if failures is not None:
                        failures.append(f"Rule plugin registration failed: {module_path}")
                    continue
            rules = getattr(module, "RULES", None)
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, Rule):
                        self.register(rule)
            else:
                log.warning("Rule plugin %s has no RULES or register()", module_path)
                if failures is not None:
                    failures.append(f"Rule plugin has no registration interface: {module_path}")


def run_rules(
    context: RuleContext,
    enabled_rules: list[str] | None = None,
    disabled_rules: list[str] | None = None,
    severity_overrides: dict[str, str] | None = None,
    plugin_modules: list[str] | None = None,
    stability: str | None = None,
    failures: list[str] | None = None,
) -> list[RuleFinding]:
    registry = RuleRegistry()
    registry.load_builtin()
    if plugin_modules:
        registry.load_plugins(plugin_modules, failures)

    enabled_set = {r.strip() for r in (enabled_rules or []) if str(r).strip()}
    disabled_set = {r.strip() for r in (disabled_rules or []) if str(r).strip()}
    overrides = severity_overrides or {}
    stability_filter = stability.strip() if stability else None

    findings: list[RuleFinding] = []
    for rule in registry.rules:
        if stability_filter and stability_filter != "all" and rule.stability != stability_filter:
            continue
        if enabled_set and rule.id not in enabled_set:
            continue
        if rule.id in disabled_set:
            continue
        try:
            results = list(rule.apply(context))
        except Exception as exc:
            log.warning("Rule %s failed: %s", rule.id, exc)
            if failures is not None:
                failures.append(f"Rule execution failed: {rule.id}")
            continue
        suppression_ctx = getattr(context, "suppression_context", None)
        for finding in results:
            if suppression_ctx is not None:
                is_suppressed, directive = suppression_ctx.is_suppressed(
                    finding.file, finding.lineno, finding.rule_id
                )
                if is_suppressed:
                    if hasattr(context, "suppressed_findings") and directive is not None:
                        context.suppressed_findings.append((finding, directive))
                    continue

            if finding.rule_id in overrides:
                findings.append(
                    RuleFinding(
                        **{
                            **finding.__dict__,
                            "severity": overrides[finding.rule_id],
                        }
                    )
                )
            else:
                findings.append(finding)
    return findings
