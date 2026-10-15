from __future__ import annotations

from html import escape
from pathlib import Path

from .models import PLExReport
from .severity import severity_rank


def _get_fixable_rules() -> set[str]:
    try:
        from plex.fix.engine import DEFAULT_FIXERS

        return {f.rule_id for f in DEFAULT_FIXERS}
    except Exception:
        return {
            "plex.string-concat-in-loop",
            "plex.linear-search-in-loop",
            "plex.uncompiled-regex-in-loop",
            "plex.redundant-comprehension",
            "plex.unnecessary-dict-keys",
            "plex.sync-io-in-async",
            "plex.unnecessary-len",
            "plex.math-pow-vs-operator",
            "plex.dict-get-fallback",
            "plex.mutable-default-arg",
            "plex.manual-list-extend",
            "plex.short-circuit-comprehension",
            "plex.sorted-min-max",
            "plex.unnecessary-comprehension-in-call",
            "plex.membership-in-literal-list",
            "plex.unnecessary-lambda",
            "plex.dict-get-default-none",
            "plex.unnecessary-async-def",
            "plex.unnecessary-enumerate",
            "plex.dict-items-value-unused",
            "plex.dict-items-comprehension-to-copy",
            "plex.redundant-collection-call",
            "plex.redundant-fstring",
            "plex.str-startswith-tuple",
            "plex.dict-fromkeys",
            "plex.itertools-chain-from-iterable",
        }


FIXABLE_RULES = _get_fixable_rules()


def _severity_class(severity: str) -> str:
    value = severity.lower()
    if value in {"critical", "high"}:
        return "sev-high"
    if value == "medium":
        return "sev-medium"
    if value == "low":
        return "sev-low"
    return "sev-info"


def _row(cells: list[str]) -> str:
    inner = "".join(f"<td>{cell}</td>" for cell in cells)
    return f"<tr>{inner}</tr>"


def _to_legacy_html(report: PLExReport, top_n: int = 10) -> str:
    lines: list[str] = []
    lines.append("<!doctype html>")
    lines.append('<html lang="en">')
    lines.append("<head>")
    lines.append('<meta charset="utf-8">')
    lines.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    lines.append("<title>PLEx report</title>")
    lines.append(
        "<style>"
        "body{font-family:'IBM Plex Sans','Segoe UI',sans-serif;background:#f6f3ee;color:#1f2a2e;"
        "margin:0;padding:24px;}h1{margin:0 0 12px;}h2{margin-top:28px;}"
        ".meta{list-style:none;padding:0;margin:0 0 18px;display:grid;grid-template-columns:"
        "repeat(auto-fit,minmax(220px,1fr));gap:6px;} .card{background:#ffffff;border-radius:14px;"
        "padding:16px 18px;box-shadow:0 8px 24px rgba(31,42,46,0.08);margin-bottom:18px;}"
        "table{width:100%;border-collapse:collapse;margin-top:8px;font-size:14px;}"
        "th,td{padding:8px 10px;border-bottom:1px solid #e7e2d9;text-align:left;vertical-align:top;}"
        "th{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#5b666a;}"
        ".sev-high{color:#8c1d18;font-weight:600;}"
        ".sev-medium{color:#a35a00;font-weight:600;}"
        ".sev-low{color:#2b5f8a;font-weight:600;}"
        ".sev-info{color:#4b5563;font-weight:600;}"
        ".tag{display:inline-block;padding:2px 8px;border-radius:999px;background:#edf2f7;font-size:12px;}"
        ".note{color:#586069;font-size:13px;}"
        "</style>"
    )
    lines.append("</head>")
    lines.append("<body>")
    lines.append("<h1>PLEx report</h1>")
    lines.append('<div class="card">')
    lines.append('<ul class="meta">')
    lines.append(f'<li><span class="tag">Generated</span> {escape(report.generated_at)}</li>')
    lines.append(
        f'<li><span class="tag">Mode</span> '
        f"{'changed-only' if report.changed_only else 'full-scan'}</li>"
    )
    lines.append(f'<li><span class="tag">Base ref</span> {escape(report.base_ref)}</li>')
    lines.append(
        f'<li><span class="tag">Baseline compare</span> '
        f"{'enabled' if report.regression_mode else 'disabled'}</li>"
    )
    lines.append(f'<li><span class="tag">Schema</span> v{report.schema_version}</li>')
    if report.suppressions:
        lines.append(f'<li><span class="tag">Suppressions</span> {len(report.suppressions)}</li>')
    if report.stats:
        lines.append(f'<li><span class="tag">Findings</span> {report.stats.findings_total}</li>')
        if report.regression_mode:
            lines.append(
                f'<li><span class="tag">Regressions</span> {report.stats.regressions_total}</li>'
            )
        if report.stats.severity_counts:
            severity_ordered = sorted(
                report.stats.severity_counts.items(),
                key=lambda item: severity_rank(item[0]),
                reverse=True,
            )
            severity_str = ", ".join(f"{key}:{value}" for key, value in severity_ordered)
            lines.append(f'<li><span class="tag">By severity</span> {escape(severity_str)}</li>')
    lines.append("</ul>")
    lines.append("</div>")

    if report.regression_mode:
        lines.append('<div class="card">')
        lines.append("<h2>Regressions vs base</h2>")
        if report.regressions:
            has_dynamic = any(r.dynamic for r in report.regressions)
            headers = [
                "Severity",
                "Risk Delta",
                "Hint Delta",
                "Dynamic" if has_dynamic else None,
                "Base",
                "Head",
                "Location",
                "Why",
            ]
            lines.append("<table><thead><tr>")
            for header in headers:
                if header:
                    lines.append(f"<th>{escape(header)}</th>")
            lines.append("</tr></thead><tbody>")
            for r in report.regressions[:top_n]:
                hint_delta = f"{r.hint_delta:+d}" if r.hint_delta is not None else "n/a"
                base = f"{r.base_risk_score:.3f} / {escape(r.base_hint)}"
                head = f"{r.head_risk_score:.3f} / {escape(r.head_hint)}"
                loc = f"{escape(r.file)}:{r.lineno} {escape(r.qualname)}"
                severity = r.regression_severity or "low"
                why = escape(r.explanation or "Risk score increased.")
                dynamic = ""
                if has_dynamic:
                    if r.dynamic:
                        if r.dynamic.status in {"confirmed", "downgraded"}:
                            dynamic = f"{r.dynamic.status} ({r.dynamic.ratio:.2f}x)"
                        else:
                            dynamic = r.dynamic.status
                    else:
                        dynamic = "n/a"
                cells = [
                    f'<span class="{_severity_class(severity)}">{escape(severity)}</span>',
                    f"{r.risk_delta:+.3f}",
                    hint_delta,
                ]
                if has_dynamic:
                    cells.append(escape(dynamic))
                cells.extend([base, head, loc, why])
                lines.append(
                    _row(
                        [escape(cell) if idx in {1, 2} else cell for idx, cell in enumerate(cells)]
                    )
                )
            lines.append("</tbody></table>")
            if len(report.regressions) > top_n:
                lines.append(
                    f'<p class="note">+{len(report.regressions) - top_n} more regressions</p>'
                )
            regression_suggestions = [
                (r, r.suggestions) for r in report.regressions[:top_n] if r.suggestions
            ]
            if regression_suggestions:
                lines.append("<h3>Fix suggestions</h3>")
                lines.append("<ul>")
                for r, items in regression_suggestions:
                    loc = f"{escape(r.file)}:{r.lineno} {escape(r.qualname)}"
                    joined = escape("; ".join(items))
                    lines.append(f"<li><strong>{loc}</strong>: {joined}</li>")
                lines.append("</ul>")
        else:
            lines.append('<p class="note">No regressions vs base.</p>')
        lines.append("</div>")

    if report.findings:
        lines.append('<div class="card">')
        lines.append("<h2>Top hotspots</h2>")
        has_dynamic = any(f.dynamic for f in report.findings[:top_n])
        headers = [
            "Severity",
            "Risk",
            "Confidence",
            "Dynamic" if has_dynamic else None,
            "Hint",
            "Location",
        ]
        lines.append("<table><thead><tr>")
        for header in headers:
            if header:
                lines.append(f"<th>{escape(header)}</th>")
        lines.append("</tr></thead><tbody>")
        for f in report.findings[:top_n]:
            loc = f"{escape(f.file)}:{f.lineno} {escape(f.qualname)}"
            dynamic = ""
            if has_dynamic:
                if f.dynamic:
                    dynamic = f"{f.dynamic.status} ({f.dynamic.label})"
                else:
                    dynamic = "n/a"
            cells = [
                f'<span class="{_severity_class(f.severity)}">{escape(f.severity)}</span>',
                f"{f.risk_score:.3f}",
                f"{f.confidence:.2f}",
            ]
            if has_dynamic:
                cells.append(escape(dynamic))
            cells.extend([escape(f.complexity_hint), loc])
            lines.append(
                _row([escape(cell) if idx in {1, 2} else cell for idx, cell in enumerate(cells)])
            )
        lines.append("</tbody></table>")
        finding_suggestions = [(f, f.suggestions) for f in report.findings[:top_n] if f.suggestions]
        if finding_suggestions:
            lines.append("<h3>Fix suggestions</h3>")
            lines.append("<ul>")
            for f, items in finding_suggestions:
                loc = f"{escape(f.file)}:{f.lineno} {escape(f.qualname)}"
                joined = escape("; ".join(items))
                lines.append(f"<li><strong>{loc}</strong>: {joined}</li>")
            lines.append("</ul>")
        lines.append("</div>")
    else:
        lines.append('<div class="card"><p class="note">No findings.</p></div>')

    if report.suppressions:
        lines.append('<div class="card">')
        lines.append("<h2>Suppressions</h2>")
        lines.append("<table><thead><tr>")
        for header in ["Location", "Reason", "Ticket", "Comment"]:
            lines.append(f"<th>{escape(header)}</th>")
        lines.append("</tr></thead><tbody>")
        for s in report.suppressions[:top_n]:
            loc = f"{escape(s.file)}:{s.lineno} {escape(s.qualname)}"
            reason = escape(s.reason or "n/a")
            ticket = escape(s.ticket or "n/a")
            comment = escape(s.comment or "plex: ignore")
            lines.append(_row([loc, reason, ticket, comment]))
        lines.append("</tbody></table>")
        if len(report.suppressions) > top_n:
            lines.append(
                f'<p class="note">+{len(report.suppressions) - top_n} more suppressions</p>'
            )
        lines.append("</div>")

    lines.append(
        '<p class="note">PLEx uses static heuristics; dynamic verification is optional.</p>'
    )
    lines.append("</body></html>")
    return "\n".join(lines)


def _to_interactive_html(report: PLExReport, top_n: int = 50) -> str:
    # Compute counts and stats
    findings = report.findings or []
    regressions = report.regressions or []
    suppressions = report.suppressions or []

    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    fixable_count = 0
    for f in findings:
        s = f.severity.lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
        if f.rule_id in FIXABLE_RULES:
            fixable_count += 1

    total_findings = len(findings)
    total_regressions = len(regressions)
    max_risk = max((f.risk_score for f in findings), default=0.0)
    avg_conf = (sum(f.confidence for f in findings) / total_findings) if total_findings else 0.0

    # Severity bar percentages
    denom = max(1, total_findings)
    p_crit = (sev_counts.get("critical", 0) / denom) * 100.0
    p_high = (sev_counts.get("high", 0) / denom) * 100.0
    p_med = (sev_counts.get("medium", 0) / denom) * 100.0
    p_low = (sev_counts.get("low", 0) / denom) * 100.0
    p_info = (sev_counts.get("info", 0) / denom) * 100.0

    lines: list[str] = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>PLEx Performance Dashboard</title>",
        "<style>",
        ":root {",
        "  --bg: #f8fafc;",
        "  --card-bg: #ffffff;",
        "  --text: #0f172a;",
        "  --text-muted: #64748b;",
        "  --border: #e2e8f0;",
        "  --accent: #0284c7;",
        "  --sev-critical: #dc2626;",
        "  --sev-high: #ea580c;",
        "  --sev-medium: #d97706;",
        "  --sev-low: #2563eb;",
        "  --sev-info: #64748b;",
        "  --badge-bg: #f1f5f9;",
        "  --hover: #f8fafc;",
        "  --fixable: #059669;",
        "  --fixable-bg: #ecfdf5;",
        "}",
        "@media (prefers-color-scheme: dark) {",
        "  :root {",
        "    --bg: #0f172a;",
        "    --card-bg: #1e293b;",
        "    --text: #f8fafc;",
        "    --text-muted: #94a3b8;",
        "    --border: #334155;",
        "    --accent: #38bdf8;",
        "    --badge-bg: #334155;",
        "    --hover: #273549;",
        "    --fixable: #34d399;",
        "    --fixable-bg: #064e3b;",
        "  }",
        "}",
        "[data-theme='dark'] {",
        "  --bg: #0f172a;",
        "  --card-bg: #1e293b;",
        "  --text: #f8fafc;",
        "  --text-muted: #94a3b8;",
        "  --border: #334155;",
        "  --accent: #38bdf8;",
        "  --badge-bg: #334155;",
        "  --hover: #273549;",
        "  --fixable: #34d399;",
        "  --fixable-bg: #064e3b;",
        "}",
        "[data-theme='light'] {",
        "  --bg: #f8fafc;",
        "  --card-bg: #ffffff;",
        "  --text: #0f172a;",
        "  --text-muted: #64748b;",
        "  --border: #e2e8f0;",
        "  --accent: #0284c7;",
        "  --badge-bg: #f1f5f9;",
        "  --hover: #f8fafc;",
        "  --fixable: #059669;",
        "  --fixable-bg: #ecfdf5;",
        "}",
        "* { box-sizing: border-box; }",
        "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; transition: background .2s, color .2s; }",
        ".header-container { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; flex-wrap: wrap; gap: 16px; }",
        ".brand-title { margin: 0; font-size: 26px; font-weight: 700; display: flex; align-items: center; gap: 10px; }",
        ".brand-badge { font-size: 13px; font-weight: 600; padding: 3px 10px; border-radius: 999px; background: var(--accent); color: #ffffff; }",
        ".theme-toggle-btn { background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 500; }",
        ".theme-toggle-btn:hover { background: var(--hover); }",
        ".meta-bar { font-size: 13px; color: var(--text-muted); margin-top: 6px; display: flex; gap: 14px; flex-wrap: wrap; }",
        ".stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }",
        ".stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }",
        ".stat-label { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--text-muted); margin-bottom: 6px; }",
        ".stat-val { font-size: 28px; font-weight: 700; }",
        ".stat-sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; }",
        ".card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }",
        ".card h2 { margin-top: 0; font-size: 18px; margin-bottom: 16px; }",
        ".ratio-bar-container { margin: 12px 0 18px; }",
        ".ratio-bar { display: flex; height: 14px; border-radius: 999px; overflow: hidden; background: var(--border); }",
        ".ratio-seg { height: 100%; transition: width .3s; }",
        ".ratio-legend { display: flex; gap: 18px; flex-wrap: wrap; margin-top: 10px; font-size: 13px; }",
        ".legend-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; }",
        ".controls-bar { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; justify-content: space-between; }",
        ".search-input { background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 14px; border-radius: 8px; font-size: 14px; min-width: 260px; outline: none; }",
        ".search-input:focus { border-color: var(--accent); }",
        ".filter-group { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }",
        ".filter-btn { background: var(--badge-bg); border: 1px solid transparent; color: var(--text); padding: 6px 12px; border-radius: 8px; font-size: 13px; cursor: pointer; }",
        ".filter-btn.active { background: var(--accent); color: #ffffff; font-weight: 600; }",
        ".fix-checkbox-label { display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer; color: var(--fixable); font-weight: 600; margin-left: 8px; }",
        "table { width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 8px; }",
        "th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }",
        "th { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--text-muted); font-weight: 600; }",
        "tr.finding-row:hover { background: var(--hover); }",
        ".badge-sev { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; text-transform: capitalize; }",
        ".badge-sev.high { background: rgba(234, 88, 12, 0.15); color: var(--sev-high); }",
        ".badge-sev.critical { background: rgba(220, 38, 38, 0.15); color: var(--sev-critical); }",
        ".badge-sev.medium { background: rgba(217, 119, 6, 0.15); color: var(--sev-medium); }",
        ".badge-sev.low { background: rgba(37, 99, 235, 0.15); color: var(--sev-low); }",
        ".badge-sev.info { background: var(--badge-bg); color: var(--sev-info); }",
        ".badge-fix { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; background: var(--fixable-bg); color: var(--fixable); margin-left: 6px; }",
        ".loc-cell { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; }",
        ".rule-tag { display: inline-block; padding: 2px 6px; border-radius: 4px; background: var(--badge-bg); font-family: monospace; font-size: 12px; color: var(--text-muted); }",
        ".suggestions-box { margin-top: 6px; font-size: 13px; color: var(--text-muted); }",
        ".suggestions-box ul { margin: 4px 0 0 16px; padding: 0; }",
        ".footer { text-align: center; font-size: 13px; color: var(--text-muted); margin-top: 32px; }",
        "</style>",
        "</head>",
        "<body>",
        '<div class="header-container">',
        "  <div>",
        '    <h1 class="brand-title">PLEx <span class="brand-badge">Performance Dashboard</span></h1>',
        '    <div class="meta-bar">',
        f"      <span><strong>Generated:</strong> {escape(report.generated_at)}</span>",
        f"      <span><strong>Mode:</strong> {'changed-only' if report.changed_only else 'full-scan'}</span>",
        f"      <span><strong>Base Ref:</strong> {escape(report.base_ref)}</span>",
        f"      <span><strong>Schema:</strong> v{report.schema_version}</span>",
        "    </div>",
        "  </div>",
        '  <button class="theme-toggle-btn" id="theme-btn" onclick="toggleTheme()">🌓 Toggle Theme</button>',
        "</div>",
        "",
        '<div class="stats-grid">',
        '  <div class="stat-card">',
        '    <div class="stat-label">Total Findings</div>',
        f'    <div class="stat-val" style="color:var(--sev-high);">{total_findings}</div>',
        f'    <div class="stat-sub">{sev_counts.get("high", 0)} High &bull; {sev_counts.get("medium", 0)} Medium</div>',
        "  </div>",
        '  <div class="stat-card">',
        '    <div class="stat-label">Regressions</div>',
        f'    <div class="stat-val" style="color:{"#dc2626" if total_regressions else "var(--text)"};">{total_regressions}</div>',
        f'    <div class="stat-sub">{"Degraded vs base ref" if total_regressions else "Clean vs base ref"}</div>',
        "  </div>",
        '  <div class="stat-card">',
        '    <div class="stat-label">Auto-Fixable</div>',
        f'    <div class="stat-val" style="color:var(--fixable);">{fixable_count}</div>',
        '    <div class="stat-sub">Remediable with <code>plex fix</code></div>',
        "  </div>",
        '  <div class="stat-card">',
        '    <div class="stat-label">Peak Risk / Confidence</div>',
        f'    <div class="stat-val">{max_risk:.2f}</div>',
        f'    <div class="stat-sub">Avg Confidence: {avg_conf:.0%}</div>',
        "  </div>",
        "</div>",
        "",
        '<div class="card">',
        "  <h2>Severity Distribution</h2>",
        '  <div class="ratio-bar-container">',
        '    <div class="ratio-bar">',
        f'      <div class="ratio-seg" style="width:{p_crit}%;background:var(--sev-critical);"></div>',
        f'      <div class="ratio-seg" style="width:{p_high}%;background:var(--sev-high);"></div>',
        f'      <div class="ratio-seg" style="width:{p_med}%;background:var(--sev-medium);"></div>',
        f'      <div class="ratio-seg" style="width:{p_low}%;background:var(--sev-low);"></div>',
        f'      <div class="ratio-seg" style="width:{p_info}%;background:var(--sev-info);"></div>',
        "    </div>",
        '    <div class="ratio-legend">',
        f'      <span><span class="legend-dot" style="background:var(--sev-critical);"></span>Critical: {sev_counts.get("critical", 0)}</span>',
        f'      <span><span class="legend-dot" style="background:var(--sev-high);"></span>High: {sev_counts.get("high", 0)}</span>',
        f'      <span><span class="legend-dot" style="background:var(--sev-medium);"></span>Medium: {sev_counts.get("medium", 0)}</span>',
        f'      <span><span class="legend-dot" style="background:var(--sev-low);"></span>Low: {sev_counts.get("low", 0)}</span>',
        f'      <span><span class="legend-dot" style="background:var(--sev-info);"></span>Info: {sev_counts.get("info", 0)}</span>',
        "    </div>",
        "  </div>",
        "</div>",
    ]

    # Regressions card (if regression mode)
    if report.regression_mode:
        lines.append('<div class="card">')
        lines.append(f"<h2>Performance Regressions ({len(regressions)})</h2>")
        if regressions:
            lines.append("<table><thead><tr>")
            lines.append(
                "<th>Severity</th><th>Risk Delta</th><th>Hint Delta</th><th>Base / Head</th><th>Location</th><th>Explanation</th>"
            )
            lines.append("</tr></thead><tbody>")
            for r in regressions[:top_n]:
                h_delta = f"{r.hint_delta:+d}" if r.hint_delta is not None else "n/a"
                loc = f"{escape(r.file)}:{r.lineno} <br><strong>{escape(r.qualname)}</strong>"
                sev = r.regression_severity or "low"
                lines.append(
                    f'<tr class="finding-row" data-severity="{sev.lower()}">'
                    f'<td><span class="badge-sev {sev.lower()}">{escape(sev)}</span></td>'
                    f'<td style="font-weight:700;color:var(--sev-high);">{r.risk_delta:+.3f}</td>'
                    f"<td>{h_delta}</td>"
                    f"<td>{r.base_risk_score:.2f} ({escape(r.base_hint)}) &rarr;<br>{r.head_risk_score:.2f} ({escape(r.head_hint)})</td>"
                    f'<td class="loc-cell">{loc}</td>'
                    f"<td>{escape(r.explanation or 'Risk increased')}</td>"
                    f"</tr>"
                )
            lines.append("</tbody></table>")
        else:
            lines.append(
                '<p style="color:var(--text-muted);">No regressions detected against base ref.</p>'
            )
        lines.append("</div>")

    # Findings card
    lines.append('<div class="card">')
    lines.append(
        f'<h2>Hotspots & Findings (<span id="visible-count">{len(findings[:top_n])}</span> of {total_findings})</h2>'
    )
    lines.append('<div class="controls-bar">')
    lines.append(
        '  <input type="text" id="search-input" class="search-input" placeholder="Search function, file, rule ID, or hint..." oninput="filterItems()">'
    )
    lines.append('  <div class="filter-group">')
    lines.append(
        '    <button class="filter-btn active" onclick="setSeverityFilter(\'all\', this)">All</button>'
    )
    for level in ("critical", "high", "medium", "low", "info"):
        count = sev_counts.get(level, 0)
        if level in ("critical", "info") and not count:
            continue
        lines.append(
            f'    <button class="filter-btn" onclick="setSeverityFilter(\'{level}\', this)">'
            f"{level.capitalize()} ({count})</button>"
        )
    lines.append(
        '    <label class="fix-checkbox-label"><input type="checkbox" id="fixable-toggle" onchange="filterItems()"> ⚡ Auto-Fixable Only</label>'
    )
    lines.append("  </div>")
    lines.append("</div>")

    if findings:
        lines.append('<table id="findings-table"><thead><tr>')
        lines.append(
            "<th>Severity</th><th>Location</th><th>Complexity Hint</th><th>Risk / Conf</th><th>Rule ID / Remediation</th>"
        )
        lines.append("</tr></thead><tbody>")
        for f in findings[:top_n]:
            is_fixable = f.rule_id in FIXABLE_RULES
            sev = f.severity.lower()
            loc = f"{escape(f.file)}:{f.lineno} <br><strong>{escape(f.qualname)}</strong>"
            fix_badge = '<span class="badge-fix">⚡ Auto-Fixable</span>' if is_fixable else ""
            rule_badge = f'<span class="rule-tag">{escape(f.rule_id)}</span>' if f.rule_id else ""
            search_str = (
                f"{f.file} {f.qualname} {f.rule_id} {f.complexity_hint} {f.explanation}".lower()
            )

            suggestions_html = ""
            if f.suggestions:
                items_str = "".join(f"<li>{escape(s)}</li>" for s in f.suggestions)
                suggestions_html = f'<div class="suggestions-box"><ul>{items_str}</ul></div>'

            lines.append(
                f'<tr class="finding-row" data-severity="{sev}" data-fixable="{"true" if is_fixable else "false"}" data-search="{escape(search_str)}">'
                f'<td><span class="badge-sev {sev}">{escape(sev)}</span>{fix_badge}</td>'
                f'<td class="loc-cell">{loc}</td>'
                f"<td><strong>{escape(f.complexity_hint)}</strong></td>"
                f'<td>{f.risk_score:.2f} <span style="color:var(--text-muted);font-size:12px;">({f.confidence:.0%})</span></td>'
                f"<td>{rule_badge}{suggestions_html}</td>"
                f"</tr>"
            )
        lines.append("</tbody></table>")
        lines.append(
            '<div id="no-matches" style="display:none;padding:24px;text-align:center;color:var(--text-muted);">No findings match the current search or filters.</div>'
        )
    else:
        lines.append('<p style="color:var(--text-muted);">No performance findings identified.</p>')
    lines.append("</div>")

    # Suppressions card
    if suppressions:
        lines.append('<div class="card">')
        lines.append(f"<h2>Suppressions ({len(suppressions)})</h2>")
        lines.append(
            "<table><thead><tr><th>Location</th><th>Reason</th><th>Ticket</th><th>Comment</th></tr></thead><tbody>"
        )
        for supp in suppressions[:top_n]:
            loc = f"{escape(supp.file)}:{supp.lineno} <strong>{escape(supp.qualname)}</strong>"
            reason = escape(supp.reason or "n/a")
            ticket = escape(supp.ticket or "n/a")
            comment = escape(supp.comment or "plex: ignore")
            lines.append(
                f'<tr><td class="loc-cell">{loc}</td><td>{reason}</td><td>{ticket}</td><td><code>{comment}</code></td></tr>'
            )
        lines.append("</tbody></table>")
        lines.append("</div>")

    # Embedded Javascript
    lines.append("<script>")
    lines.append("window.currentSeverityFilter = 'all';")
    lines.append("function setSeverityFilter(sev, btn) {")
    lines.append("  window.currentSeverityFilter = sev;")
    lines.append(
        "  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));"
    )
    lines.append("  btn.classList.add('active');")
    lines.append("  filterItems();")
    lines.append("}")
    lines.append("function filterItems() {")
    lines.append(
        "  const q = (document.getElementById('search-input').value || '').toLowerCase().trim();"
    )
    lines.append("  const activeSev = window.currentSeverityFilter || 'all';")
    lines.append("  const fixOnly = document.getElementById('fixable-toggle')?.checked || false;")
    lines.append("  const rows = document.querySelectorAll('#findings-table tr.finding-row');")
    lines.append("  let visible = 0;")
    lines.append("  rows.forEach(r => {")
    lines.append("    const text = (r.getAttribute('data-search') || '').toLowerCase();")
    lines.append("    const sev = r.getAttribute('data-severity');")
    lines.append("    const fixable = r.getAttribute('data-fixable') === 'true';")
    lines.append("    const matchQ = !q || text.includes(q);")
    lines.append("    const matchSev = activeSev === 'all' || sev === activeSev;")
    lines.append("    const matchFix = !fixOnly || fixable;")
    lines.append("    if (matchQ && matchSev && matchFix) {")
    lines.append("      r.style.display = '';")
    lines.append("      visible++;")
    lines.append("    } else {")
    lines.append("      r.style.display = 'none';")
    lines.append("    }")
    lines.append("  });")
    lines.append("  const counter = document.getElementById('visible-count');")
    lines.append("  if (counter) counter.innerText = visible;")
    lines.append("  const noMatches = document.getElementById('no-matches');")
    lines.append("  if (noMatches) noMatches.style.display = visible === 0 ? 'block' : 'none';")
    lines.append("}")
    lines.append("function toggleTheme() {")
    lines.append(
        "  const cur = document.documentElement.getAttribute('data-theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');"
    )
    lines.append("  const next = cur === 'dark' ? 'light' : 'dark';")
    lines.append("  document.documentElement.setAttribute('data-theme', next);")
    lines.append("  try { localStorage.setItem('plex-theme', next); } catch(e) {}")
    lines.append("}")
    lines.append("(function() {")
    lines.append("  try {")
    lines.append("    const saved = localStorage.getItem('plex-theme');")
    lines.append("    if (saved) document.documentElement.setAttribute('data-theme', saved);")
    lines.append("  } catch(e) {}")
    lines.append("})();")
    lines.append("</script>")

    lines.append(
        '<div class="footer"><p>Generated by PLEx &bull; Automated Static Performance Engineering Engine</p></div>'
    )
    lines.append("</body></html>")
    return "\n".join(lines)


def to_html(report: PLExReport, top_n: int = 10, interactive: bool = True) -> str:
    if not interactive:
        return _to_legacy_html(report, top_n=top_n)
    return _to_interactive_html(report, top_n=top_n)


def write_html(report: PLExReport, path: Path, top_n: int = 10, interactive: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_html(report, top_n=top_n, interactive=interactive), encoding="utf-8")
