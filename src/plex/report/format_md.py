from __future__ import annotations

from .models import PLExReport
from .severity import severity_rank


def to_markdown(report: PLExReport, top_n: int = 10) -> str:
    lines: list[str] = []
    lines.append("# PLEx report")
    lines.append("")
    lines.append(f"- Generated: `{report.generated_at}`")
    lines.append(f"- Mode: `{'changed-only' if report.changed_only else 'full-scan'}`")
    lines.append(f"- Base ref: `{report.base_ref}`")
    lines.append(f"- Baseline compare: `{'enabled' if report.regression_mode else 'disabled'}`")
    lines.append(f"- Schema: `v{report.schema_version}`")
    if report.suppressions:
        lines.append(f"- Suppressions: `{len(report.suppressions)}`")
    if report.stats:
        lines.append(f"- Findings: `{report.stats.findings_total}`")
        if report.regression_mode:
            lines.append(f"- Regressions: `{report.stats.regressions_total}`")
        if report.stats.severity_counts:
            severity_ordered = sorted(
                report.stats.severity_counts.items(),
                key=lambda item: severity_rank(item[0]),
                reverse=True,
            )
            severity_str = ", ".join(f"{key}:{value}" for key, value in severity_ordered)
            lines.append(f"- Findings by severity: `{severity_str}`")
    lines.append("")

    if report.regression_mode:
        if report.regressions:
            lines.append("## Regressions vs base")
            lines.append("")
            has_dynamic = any(r.dynamic for r in report.regressions)
            if has_dynamic:
                lines.append(
                    "| Severity | Risk Δ | Hint Δ | Dynamic | Base | Head | Location | Why |"
                )
                lines.append("|---|---:|---:|---|---|---|---|---|")
            else:
                lines.append("| Severity | Risk Δ | Hint Δ | Base | Head | Location | Why |")
                lines.append("|---|---:|---:|---|---|---|---|")
            for r in report.regressions:
                loc = f"{r.file}:{r.lineno} `{r.qualname}`"
                hint_delta = f"{r.hint_delta:+d}" if r.hint_delta is not None else "n/a"
                base = f"{r.base_risk_score:.3f} / {r.base_hint}"
                head = f"{r.head_risk_score:.3f} / {r.head_hint}"
                severity = r.regression_severity or "low"
                why = r.explanation or "Risk score increased."
                if has_dynamic:
                    reg_dynamic = r.dynamic
                    if reg_dynamic:
                        if reg_dynamic.status in {"confirmed", "downgraded"}:
                            dyn = f"{reg_dynamic.status} ({reg_dynamic.ratio:.2f}x)"
                        else:
                            dyn = reg_dynamic.status
                    else:
                        dyn = "n/a"
                    lines.append(
                        f"| {severity} | {r.risk_delta:+.3f} | {hint_delta} | {dyn} | {base} | {head} | {loc} | {why} |"
                    )
                else:
                    lines.append(
                        f"| {severity} | {r.risk_delta:+.3f} | {hint_delta} | {base} | {head} | {loc} | {why} |"
                    )
            lines.append("")
            regression_suggestions = [
                (r, r.suggestions) for r in report.regressions if r.suggestions
            ]
            if regression_suggestions:
                lines.append("### Fix suggestions")
                lines.append("")
                for r, items in regression_suggestions:
                    loc = f"{r.file}:{r.lineno} `{r.qualname}`"
                    joined = "; ".join(items)
                    lines.append(f"- {loc}: {joined}")
                lines.append("")
        else:
            lines.append("✅ No regressions vs base.")
            lines.append("")

    if report.diffs:
        added = sum(1 for d in report.diffs if d.change_type == "added")
        removed = sum(1 for d in report.diffs if d.change_type == "removed")
        changed = sum(1 for d in report.diffs if d.change_type == "changed")
        lines.append("## Change summary (base -> head)")
        lines.append("")
        lines.append(f"- Added: `{added}`  Removed: `{removed}`  Changed: `{changed}`")
        lines.append("")
        lines.append("| Type | Trend | Risk (base -> head) | Hint (base -> head) | Location |")
        lines.append("|---|---|---|---|---|")
        diffs_ordered = sorted(
            report.diffs,
            key=lambda d: (
                0
                if d.trend == "worse"
                else 1
                if d.trend == "new"
                else 2
                if d.trend == "better"
                else 3,
                d.file,
                d.lineno,
            ),
        )
        for d in diffs_ordered[:top_n]:
            risk = (
                f"{d.base_risk_score:.3f} -> {d.head_risk_score:.3f}"
                if d.base_risk_score is not None and d.head_risk_score is not None
                else "n/a"
            )
            hint = (
                f"{d.base_hint} -> {d.head_hint}"
                if d.base_hint is not None and d.head_hint is not None
                else "n/a"
            )
            loc = f"{d.file}:{d.lineno} `{d.qualname}`"
            lines.append(f"| {d.change_type} | {d.trend} | {risk} | {hint} | {loc} |")
        if len(report.diffs) > top_n:
            lines.append("")
            lines.append(f"_+{len(report.diffs) - top_n} more changes_")
        lines.append("")

    if report.suppressions:
        lines.append("## Suppressions")
        lines.append("")
        lines.append("| Location | Reason | Ticket | Comment |")
        lines.append("|---|---|---|---|")
        for s in report.suppressions[:top_n]:
            loc = f"{s.file}:{s.lineno} `{s.qualname}`"
            reason = s.reason or "n/a"
            ticket = s.ticket or "n/a"
            comment = s.comment or "plex: ignore"
            lines.append(f"| {loc} | {reason} | {ticket} | {comment} |")
        if len(report.suppressions) > top_n:
            lines.append("")
            lines.append(f"_+{len(report.suppressions) - top_n} more suppressions_")
        lines.append("")

    security_findings = [
        f
        for f in report.findings_unified
        if f.engine == "xboundary" or (f.category == "security" and f.engine != "supply_chain")
    ]
    supply_chain_findings = [
        f for f in report.findings_unified if f.engine == "supply_chain"
    ]
    reliability_findings = [
        f for f in report.findings_unified if f.engine == "reliability" or f.category == "quality"
    ]
    has_security_engine = any(e.engine == "xboundary" for e in report.engines)
    has_supply_chain_engine = any(e.engine == "supply_chain" for e in report.engines)
    has_reliability_engine = any(e.engine == "reliability" for e in report.engines)
    has_non_perf = bool(
        has_security_engine
        or security_findings
        or has_supply_chain_engine
        or supply_chain_findings
        or has_reliability_engine
        or reliability_findings
        or report.repairs
    )

    if not report.findings and not has_non_perf:
        lines.append("✅ No findings (or no analyzable functions found).")
        return "\n".join(lines)

    if not report.findings and has_non_perf:
        lines.append("✅ No performance findings (or no analyzable functions found).")
    else:
        lines.append("## Top hotspots (heuristic)")
        lines.append("")
        has_dynamic = any(f.dynamic for f in report.findings[:top_n])
        if has_dynamic:
            lines.append("| Severity | Risk | Confidence | Dynamic | Hint | Location |")
            lines.append("|---|---:|---:|---|---|---|")
        else:
            lines.append("| Severity | Risk | Confidence | Hint | Location |")
            lines.append("|---|---:|---:|---|---|")
        for f in report.findings[:top_n]:
            loc = f"{f.file}:{f.lineno} `{f.qualname}`"
            if has_dynamic:
                finding_dynamic = f.dynamic
                dyn = (
                    f"{finding_dynamic.status} ({finding_dynamic.label})"
                    if finding_dynamic
                    else "n/a"
                )
                lines.append(
                    f"| {f.severity} | {f.risk_score:.3f} | {f.confidence:.2f} | {dyn} | {f.complexity_hint} | {loc} |"
                )
            else:
                lines.append(
                    f"| {f.severity} | {f.risk_score:.3f} | {f.confidence:.2f} | {f.complexity_hint} | {loc} |"
                )

        lines.append("")
        finding_suggestions = [(f, f.suggestions) for f in report.findings[:top_n] if f.suggestions]
        if finding_suggestions:
            lines.append("### Fix suggestions")
            lines.append("")
            for f, items in finding_suggestions:
                loc = f"{f.file}:{f.lineno} `{f.qualname}`"
                joined = "; ".join(items)
                lines.append(f"- {loc}: {joined}")
            lines.append("")

    if has_security_engine or security_findings:
        lines.append("")
        lines.append("## Security findings (xBOUNDARY)")
        lines.append("")
        if security_findings:
            lines.append("| Severity | Rule | Location | Description |")
            lines.append("|---|---|---|---|")
            for sec in security_findings[:top_n]:
                loc = f"{sec.file}:{sec.lineno}" if sec.file else "n/a"
                desc = sec.message or sec.title
                lines.append(f"| {sec.severity} | {sec.rule_id} | {loc} | {desc} |")
            if len(security_findings) > top_n:
                lines.append("")
                lines.append(f"_+{len(security_findings) - top_n} more security findings_")
        else:
            lines.append("✅ No security findings detected.")
        lines.append("")

    if has_supply_chain_engine or supply_chain_findings:
        lines.append("")
        lines.append("## Supply chain & configuration findings")
        lines.append("")
        if supply_chain_findings:
            lines.append("| Severity | Rule | Location | Description |")
            lines.append("|---|---|---|---|")
            for sc in supply_chain_findings[:top_n]:
                loc = f"{sc.file}:{sc.lineno}" if sc.file else "n/a"
                desc = sc.message or sc.title
                lines.append(f"| {sc.severity} | {sc.rule_id} | {loc} | {desc} |")
            if len(supply_chain_findings) > top_n:
                lines.append("")
                lines.append(f"_+{len(supply_chain_findings) - top_n} more supply chain findings_")
        else:
            lines.append("✅ No supply chain or configuration findings detected.")
        lines.append("")

    if has_reliability_engine or reliability_findings:
        lines.append("")
        lines.append("## Reliability & architecture findings")
        lines.append("")
        if reliability_findings:
            lines.append("| Severity | Rule | Location | Description |")
            lines.append("|---|---|---|---|")
            for rel in reliability_findings[:top_n]:
                loc = f"{rel.file}:{rel.lineno}" if rel.file else "n/a"
                desc = rel.message or rel.title
                lines.append(f"| {rel.severity} | {rel.rule_id} | {loc} | {desc} |")
            if len(reliability_findings) > top_n:
                lines.append("")
                lines.append(f"_+{len(reliability_findings) - top_n} more reliability findings_")
        else:
            lines.append("✅ No reliability or architecture findings detected.")
        lines.append("")

    if report.repairs:
        lines.append("")
        lines.append("## Repairs & verification")
        lines.append("")
        lines.append("| Candidate | Rule | Status |")
        lines.append("|---|---|---|")
        for rep in report.repairs[:top_n]:
            cand = rep.get("candidate", {}) if isinstance(rep, dict) else {}
            cid = cand.get("id", "n/a") if isinstance(cand, dict) else "n/a"
            rid = cand.get("rule_id", "n/a") if isinstance(cand, dict) else "n/a"
            rstatus = rep.get("status", "n/a") if isinstance(rep, dict) else "n/a"
            lines.append(f"| {cid} | {rid} | {rstatus} |")
        lines.append("")

    lines.append(
        "> Notes: PLEx uses static AST heuristics; dynamic verification is optional and best-effort."
    )
    return "\n".join(lines)
