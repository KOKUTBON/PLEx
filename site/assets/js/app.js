// PLEx report explorer — renders a real `plex analyze` report bundle.
import {
  $,
  $$,
  esc,
  ICONS,
  SEVERITIES,
  GATING_PRESETS,
  copyText,
  download,
  evaluateGate,
  findingKey,
  findingTitle,
  formatHint,
  highlightLines,
  initTheme,
  isRule,
  loadBundle,
  policyToFlags,
  renderDiff,
  renderMarkdown,
  sevRank,
  toast,
} from "./core.js";

const VIEWS = ["findings", "pr", "hotspots", "fixes", "outputs"];
const VIEW_LABELS = { findings: "Findings", pr: "Pull request", hotspots: "Hotspots", fixes: "Auto-fix", outputs: "Raw outputs" };
const SIGNAL_LABELS = {
  loops: "Loops",
  max_loop_depth: "Max loop depth",
  sort_calls: "Sort calls",
  recursion: "Recursion",
  comprehension: "Comprehensions",
};

const state = {
  bundle: null,
  demo: null,
  custom: false,
  findings: [],
  view: "findings",
  selected: null,
  inspTab: "overview",
  outTab: "comment",
  outMode: "rendered",
  sort: "risk",
  filters: { q: "", sev: new Set(SEVERITIES), kinds: new Set(["rule", "hint"]), fixable: false, regression: false, file: null, rule: null },
  preset: "balanced",
  policy: { ...GATING_PRESETS.balanced, fail_on_finding_severity: null, max_findings: null, max_risk_score: null },
  policyOpen: false,
};

/* ----------------------------------------------------------------- model */

function hydrate(bundle) {
  const report = bundle.report;
  const rules = new Map((bundle.rules || []).map((r) => [r.id, r]));
  const fixable = new Set(bundle.fixable_rules || []);
  const regressed = new Set((report.regressions || []).map((r) => r.function_id));
  state.bundle = bundle;
  state.rules = rules;
  state.fixable = fixable;
  state.findings = (report.findings || []).map((f, i) => ({
    ...f,
    key: findingKey(f),
    order: i,
    kind: isRule(f) ? "rule" : "hint",
    title: findingTitle(f),
    rule: rules.get(f.rule_id),
    fix: bundle.fixes?.[`${f.file}::${f.rule_id}`] || null,
    canFix: Boolean(f.rule_id && fixable.has(f.rule_id)),
    regression: regressed.has(f.function_id) && !isRule(f),
  }));
  // Duplicate keys (same function, same hint) are disambiguated by order.
  const seen = new Map();
  for (const f of state.findings) {
    const n = seen.get(f.key) || 0;
    seen.set(f.key, n + 1);
    if (n) f.key += `~${n}`;
  }
}

const source = (file, side = "head") => state.bundle.sources?.[side]?.[file] ?? null;

function filtered() {
  const { q, sev, kinds, fixable, regression, file, rule } = state.filters;
  const needle = q.trim().toLowerCase();
  const out = state.findings.filter(
    (f) =>
      sev.has(f.severity) &&
      kinds.has(f.kind) &&
      (!fixable || f.canFix) &&
      (!regression || f.regression) &&
      (!file || f.file === file) &&
      (!rule || f.rule_id === rule) &&
      (!needle ||
        [f.title, f.qualname, f.file, f.rule_id, f.explanation, f.complexity_hint]
          .join(" ")
          .toLowerCase()
          .includes(needle)),
  );
  const by = {
    risk: (a, b) => b.risk_score - a.risk_score || sevRank(b.severity) - sevRank(a.severity) || a.order - b.order,
    confidence: (a, b) => b.confidence - a.confidence || b.risk_score - a.risk_score,
    location: (a, b) => a.file.localeCompare(b.file) || a.lineno - b.lineno,
  }[state.sort];
  return out.sort(by);
}

const current = () => state.findings.find((f) => f.key === state.selected) || null;

/* ------------------------------------------------------------------ hash */

function writeHash() {
  const parts = [state.view];
  if (state.view === "findings" && state.selected) parts.push(encodeURIComponent(state.selected));
  history.replaceState(null, "", `#${parts.join("/")}`);
}

function readHash() {
  const [view, key] = location.hash.slice(1).split("/");
  if (VIEWS.includes(view)) state.view = view;
  if (key) {
    const k = decodeURIComponent(key);
    if (state.findings.some((f) => f.key === k)) state.selected = k;
  }
}

/* --------------------------------------------------------------- chrome */

function renderCrumb() {
  const meta = state.bundle.meta || {};
  const pr = meta.pull_request;
  $("#crumb").innerHTML = `
    <span class="crumb-title">${esc(meta.project || "Your report")}</span>
    ${
      pr
        ? `<span class="chip">${ICONS.branch}${esc(pr.head)} → ${esc(pr.base)}</span>`
        : `<span class="chip">${ICONS.file}local file</span>`
    }`;
}

function renderGate() {
  const report = state.bundle.report;
  const { failed, reasons } = evaluateGate(report, state.policy);
  const flags = policyToFlags(state.policy, state.preset);
  const base = report.regression_mode ? ` --compare-base --base-ref ${esc(report.base_ref || "origin/main")}` : "";
  const cmd = `plex analyze .${base}${flags.length ? " " : ""}${flags.map((f) => `<b>${esc(f)}</b>`).join(" ")}`;
  const plainCmd = cmd.replace(/<\/?b>/g, "").replace(/&gt;/g, ">");
  const el = $("#gate");
  el.className = `gate ${failed ? "failed" : "passed"}`;
  const presetBtn = (p, label) =>
    `<button type="button" data-preset="${p}" aria-pressed="${state.preset === p}">${label}</button>`;
  const num = (key, label, step = 1) => `
    <label class="field"><span>${label}</span>
      <input type="number" min="0" step="${step}" data-policy="${key}" value="${state.policy[key] ?? ""}" placeholder="off" />
      <code>${key}</code></label>`;
  const sevSelect = (key, label) => `
    <label class="field"><span>${label}</span>
      <select data-policy="${key}">
        <option value="">off</option>
        ${["high", "medium", "low", "info"].map((s) => `<option ${state.policy[key] === s ? "selected" : ""}>${s}</option>`).join("")}
      </select><code>${key}</code></label>`;

  el.innerHTML = `
    <div class="gate-icon" aria-hidden="true">${failed ? ICONS.x : ICONS.check}</div>
    <div>
      <h2 class="gate-title">${failed ? "CI gate would fail this pull request" : "CI gate passes"}
        <small>${failed ? `exit code 1 · ${reasons.length} policy violation${reasons.length > 1 ? "s" : ""}` : "exit code 0 · no policy violations"}</small></h2>
      <ul class="gate-reasons">${
        failed
          ? reasons.map((r) => `<li>${esc(r)}</li>`).join("")
          : `<li>${report.findings.length} findings reported, none blocking under this policy</li>`
      }</ul>
      <div class="gate-cmd"><span aria-hidden="true">$</span><code>${cmd}</code>
        <button class="icon-btn" type="button" data-copy-cmd aria-label="Copy command">${ICONS.copy}</button></div>
    </div>
    <div class="policy">
      <span class="policy-label">Gate policy</span>
      <div class="segmented" role="group" aria-label="Gating preset">
        ${presetBtn("strict", "Strict")}${presetBtn("balanced", "Balanced")}${presetBtn("relaxed", "Relaxed")}${presetBtn("custom", "Custom")}${presetBtn("off", "Off")}
      </div>
      <button class="policy-toggle" type="button" aria-expanded="${state.policyOpen}" data-policy-toggle>${
        state.policyOpen ? "Hide thresholds" : "Tune thresholds"
      }</button>
    </div>
    <div class="policy-grid" ${state.policyOpen ? "" : "hidden"}>
      <label class="field check"><input type="checkbox" data-policy="fail_on_regressions" ${
        state.policy.fail_on_regressions ? "checked" : ""
      } /><span>Fail on any regression<br /><code>fail_on_regressions</code></span></label>
      ${sevSelect("fail_on_severity", "Fail on regression severity ≥")}
      ${num("max_regressions", "Max regressions")}
      ${num("max_high_regressions", "Max high regressions")}
      ${num("max_risk_delta", "Max risk delta", 0.1)}
      ${num("risk_delta_budget", "Risk delta budget", 0.1)}
      ${sevSelect("fail_on_finding_severity", "Fail on finding severity ≥")}
      ${num("max_findings", "Max findings")}
      ${num("max_risk_score", "Max risk score", 0.1)}
    </div>`;
  el.querySelector("[data-copy-cmd]").onclick = () => copyText(plainCmd, "Command copied");
}

function bindGate() {
  const el = $("#gate");
  el.addEventListener("click", (e) => {
    const preset = e.target.closest("[data-preset]")?.dataset.preset;
    if (preset) {
      state.preset = preset;
      const keep = {
        fail_on_finding_severity: state.policy.fail_on_finding_severity,
        max_findings: state.policy.max_findings,
        max_risk_score: state.policy.max_risk_score,
      };
      if (preset === "off") {
        state.policy = { ...keep, fail_on_finding_severity: null, max_findings: null, max_risk_score: null };
      } else if (preset !== "custom") state.policy = { ...GATING_PRESETS[preset], ...keep };
      else state.policyOpen = true;
      renderGate();
    }
    if (e.target.closest("[data-policy-toggle]")) {
      state.policyOpen = !state.policyOpen;
      renderGate();
    }
  });
  el.addEventListener("change", (e) => {
    const key = e.target.dataset.policy;
    if (!key) return;
    const v = e.target.type === "checkbox" ? e.target.checked : e.target.value;
    state.policy[key] = v === "" ? null : e.target.type === "number" ? Number(v) : v;
    if (!["fail_on_finding_severity", "max_findings", "max_risk_score"].includes(key)) state.preset = "custom";
    renderGate();
    $(`#gate [data-policy="${key}"]`)?.focus();
  });
}

function renderKpis() {
  const { report, meta = {} } = state.bundle;
  const fs = state.findings;
  const regs = report.regressions || [];
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, fs.filter((f) => f.severity === s).length]));
  const files = new Set(fs.map((f) => f.file)).size;
  const fns = new Set(fs.map((f) => f.function_id)).size;
  const fixCount = fs.filter((f) => f.canFix).length;
  const rulesHit = new Set(fs.filter((f) => f.rule_id).map((f) => f.rule_id)).size;
  const maxRisk = Math.max(0, ...fs.map((f) => f.risk_score || 0));
  const tile = (label, value, sub, cls = "") =>
    `<div class="kpi"><div class="kpi-label">${label}</div><div class="kpi-value">${value}</div><div class="kpi-sub ${cls}">${sub}</div></div>`;
  $("#kpis").innerHTML = `
    ${tile("Findings", fs.length, `${files} files · ${fns} functions`)}
    ${tile("Regressions", regs.length, report.regression_mode ? `vs <code>${esc(report.base_ref)}</code>` : "baseline compare off", regs.length ? "bad" : "")}
    ${tile("Max risk score", maxRisk.toFixed(2), `avg ${(report.stats?.avg_risk_score ?? 0).toFixed(2)}`)}
    ${tile("Auto-fixable", fixCount, `${rulesHit} distinct rules fired`)}
    ${tile(
      "Analysis time",
      meta.analysis_ms ? `${Math.round(meta.analysis_ms)}<small style="font-size:14px;font-weight:600"> ms</small>` : "—",
      meta.analysis_ms ? `incl. base compare · ${esc(meta.python ? `Py ${meta.python}` : "")}` : "not recorded",
    )}
    <div class="kpi kpi-dist">
      <div class="kpi-label">Severity distribution · click to filter</div>
      <div class="dist-bar" role="img" aria-label="${SEVERITIES.map((s) => `${counts[s]} ${s}`).join(", ")}">
        ${SEVERITIES.filter((s) => counts[s])
          .map((s) => `<span data-sev="${s}" style="flex-grow:${counts[s]};--c:var(--sev-${s})" title="${counts[s]} ${s}"></span>`)
          .join("")}
      </div>
      <div class="dist-legend">${SEVERITIES.map((s) => `<span class="sev sev-${s}">${s}<b>${counts[s]}</b></span>`).join("")}</div>
    </div>`;
  $$("#kpis .dist-bar span").forEach((seg) =>
    seg.addEventListener("click", () => {
      state.filters.sev = new Set([seg.dataset.sev]);
      setView("findings");
      renderFindings();
    }),
  );
}

function renderCounts() {
  const regs = state.bundle.report.regressions?.length || 0;
  $('[data-count="findings"]').textContent = state.findings.length;
  const pr = $('[data-count="pr"]');
  pr.textContent = regs || "";
  pr.classList.toggle("bad", regs > 0);
  $('[data-count="fixes"]').textContent = Object.keys(state.bundle.fixes || {}).length || "";
}

function setView(view) {
  state.view = view;
  $$("#tabs [role=tab]").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.view === view)));
  $$(".view").forEach((v) => (v.hidden = v.dataset.view !== view));
  const panel = $(`.view[data-view="${view}"]`);
  if (view === "pr") renderPR(panel);
  if (view === "hotspots") renderHotspots(panel);
  if (view === "fixes") renderFixes(panel);
  if (view === "outputs") renderOutputs(panel);
  writeHash();
}

/* -------------------------------------------------------------- findings */

function renderFilters() {
  const fs = state.findings;
  const f = state.filters;
  const opt = (attr, value, label, n, pressed, extra = "") =>
    `<button type="button" class="opt ${extra}" data-${attr}="${esc(value)}" aria-pressed="${pressed}"><span class="box"></span>${label}<span class="n">${n}</span></button>`;
  const fileOpt = (file, n) =>
    `<button type="button" class="opt file" data-file="${esc(file)}" aria-current="${f.file === file}">${ICONS.file}<span>${esc(
      file.split("/").pop(),
    )}</span><span class="n">${n}</span></button>`;
  const files = [...new Set(fs.map((x) => x.file))].sort();
  const rules = [...new Set(fs.filter((x) => x.rule_id).map((x) => x.rule_id))].sort();

  $("#filters").innerHTML = `
    <div class="filter-group" style="flex:1 1 220px">
      <label class="search">${ICONS.search}<span class="sr-only">Filter findings</span>
        <input id="q" type="search" placeholder="Filter findings" value="${esc(f.q)}" autocomplete="off" /><kbd>/</kbd></label>
    </div>
    <div class="filter-group">
      <div class="filter-title">Severity</div>
      <div class="opts">${SEVERITIES.map((s) =>
        opt("sev", s, `<span class="sev sev-${s}">${s}</span>`, fs.filter((x) => x.severity === s).length, f.sev.has(s)),
      ).join("")}</div>
    </div>
    <div class="filter-group">
      <div class="filter-title">Type</div>
      <div class="opts">
        ${opt("kind", "rule", "Rule findings", fs.filter((x) => x.kind === "rule").length, f.kinds.has("rule"))}
        ${opt("kind", "hint", "Complexity hints", fs.filter((x) => x.kind === "hint").length, f.kinds.has("hint"))}
      </div>
    </div>
    <div class="filter-group">
      <div class="filter-title">Only</div>
      <div class="opts">
        ${opt("only", "fixable", "Auto-fixable", fs.filter((x) => x.canFix).length, f.fixable)}
        ${opt("only", "regression", "In a regression", fs.filter((x) => x.regression).length, f.regression)}
      </div>
    </div>
    <div class="filter-group files">
      <div class="filter-title">Files ${f.file ? '<button type="button" data-clear="file">clear</button>' : ""}</div>
      ${files.map((file) => fileOpt(file, fs.filter((x) => x.file === file).length)).join("")}
    </div>
    <div class="filter-group rules">
      <div class="filter-title">Rules ${f.rule ? '<button type="button" data-clear="rule">clear</button>' : ""}</div>
      ${rules
        .map(
          (r) =>
            `<button type="button" class="opt file" data-rule="${esc(r)}" aria-current="${f.rule === r}"><span>${esc(
              r.replace(/^plex\./, ""),
            )}</span><span class="n">${fs.filter((x) => x.rule_id === r).length}</span></button>`,
        )
        .join("")}
    </div>`;
}

function bindFilters() {
  const el = $("#filters");
  el.addEventListener("input", (e) => {
    if (e.target.id !== "q") return;
    state.filters.q = e.target.value;
    renderList();
  });
  el.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    const f = state.filters;
    const toggle = (set, v) => (set.has(v) ? set.size > 1 && set.delete(v) : set.add(v));
    if (b.dataset.sev) toggle(f.sev, b.dataset.sev);
    if (b.dataset.kind) toggle(f.kinds, b.dataset.kind);
    if (b.dataset.only === "fixable") f.fixable = !f.fixable;
    if (b.dataset.only === "regression") f.regression = !f.regression;
    if (b.dataset.file) f.file = f.file === b.dataset.file ? null : b.dataset.file;
    if (b.dataset.rule) f.rule = f.rule === b.dataset.rule ? null : b.dataset.rule;
    if (b.dataset.clear) f[b.dataset.clear] = null;
    renderFindings();
  });
  $("#sort").addEventListener("change", (e) => {
    state.sort = e.target.value;
    renderList();
  });
}

function renderFindings() {
  renderFilters();
  renderList();
}

function renderList() {
  const items = filtered();
  const list = $("#finding-list");
  const f = state.filters;
  const active = [f.file && f.file.split("/").pop(), f.rule, f.fixable && "auto-fixable", f.regression && "regression"].filter(Boolean);
  $("#list-meta").innerHTML = `<b>${items.length}</b> of ${state.findings.length}${
    active.length ? ` · ${esc(active.join(", "))}` : ""
  }`;
  if (!items.length) {
    list.innerHTML = `<li class="empty">${ICONS.filter}<span>No findings match these filters.</span>
      <button class="btn btn-sm" type="button" data-reset>Reset filters</button></li>`;
    list.querySelector("[data-reset]").onclick = resetFilters;
    renderInspector();
    return;
  }
  if (!items.some((x) => x.key === state.selected)) state.selected = items[0].key;
  list.innerHTML = items
    .map(
      (x) => `
    <li class="finding" role="option" tabindex="-1" data-key="${esc(x.key)}" aria-selected="${x.key === state.selected}">
      <div class="finding-top">
        <span class="sev sev-${x.severity}">${x.severity}</span>
        ${x.regression ? '<span class="tag reg">Regression</span>' : ""}
        ${x.canFix ? `<span class="tag fix">${ICONS.wand}Fix</span>` : ""}
        ${x.rule?.stability === "experimental" ? '<span class="tag exp">Exp</span>' : ""}
        <span class="risk" title="Risk score">${x.risk_score.toFixed(2)}</span>
      </div>
      <div class="finding-title">${esc(formatHint(x.title))}</div>
      <div class="finding-loc"><span class="fn">${esc(x.qualname)}</span><span>${esc(x.file)}:${x.lineno}</span></div>
    </li>`,
    )
    .join("");
  renderInspector();
}

function resetFilters() {
  state.filters = { q: "", sev: new Set(SEVERITIES), kinds: new Set(["rule", "hint"]), fixable: false, regression: false, file: null, rule: null };
  renderFindings();
}

function select(key, { scroll = true, focusList = false } = {}) {
  state.selected = key;
  $$("#finding-list .finding").forEach((li) => li.setAttribute("aria-selected", String(li.dataset.key === key)));
  const li = $(`#finding-list .finding[data-key="${CSS.escape(key)}"]`);
  if (scroll) li?.scrollIntoView({ block: "nearest" });
  if (focusList) li?.focus({ preventScroll: true });
  renderInspector();
  writeHash();
}

function step(dir) {
  const items = filtered();
  if (!items.length) return;
  const i = items.findIndex((x) => x.key === state.selected);
  const next = items[Math.min(items.length - 1, Math.max(0, i + dir))];
  select(next.key, { focusList: true });
}

/** Render a source file with gutter markers, a highlighted range, and an inline peek. */
function codeView(f, { compact = false } = {}) {
  const text = source(f.file);
  if (text == null)
    return `<div class="empty">${ICONS.file}<span>Source isn't bundled with this report.<br/><code>${esc(f.file)}:${
      f.lineno
    }</code></span></div>`;
  const lines = highlightLines(text);
  const start = f.lineno;
  const rangeStart = f.kind === "rule" ? enclosingDef(text, f.lineno) : start;
  const rangeEnd = f.kind === "rule" ? functionEnd(text, rangeStart) : functionEnd(text, start);
  const marks = new Map();
  for (const o of state.findings.filter((o) => o.file === f.file && o.kind === "rule")) {
    if (!marks.has(o.lineno) || sevRank(o.severity) > sevRank(marks.get(o.lineno).severity)) marks.set(o.lineno, o);
  }
  const hitLine = f.kind === "rule" ? start : null;
  const peekAt = start;
  const from = compact ? Math.max(1, rangeStart - 2) : 1;
  const to = compact ? Math.min(lines.length, rangeEnd + 2) : lines.length;
  let html = "";
  for (let n = from; n <= to; n++) {
    const m = marks.get(n);
    const cls = [n >= rangeStart && n <= rangeEnd && "in-range", n === hitLine && "hit"].filter(Boolean).join(" ");
    html += `<div class="cl ${cls}" data-line="${n}" style="--c:var(--sev-${f.severity})"><span class="gut">${
      m
        ? `<i class="dot" style="--c:var(--sev-${m.severity})" data-jump="${esc(m.key)}" data-tip="${esc(
            `${m.title} · line ${m.lineno}`,
          )}"></i>`
        : ""
    }</span><span class="no">${n}</span><span class="src">${lines[n - 1] || " "}</span></div>`;
    if (n === peekAt && !compact) {
      html += `<div class="peek" style="--c:var(--sev-${f.severity})"><strong>${esc(formatHint(f.title))}</strong><span>${esc(
        f.explanation || "",
      )}</span></div>`;
    }
  }
  return `<div class="codeview" data-scroll-to="${rangeStart}">
    <div class="codeview-head">${ICONS.file}<span>${esc(f.file)}</span><span class="spacer"></span><span>lines ${rangeStart}–${rangeEnd}</span></div>
    ${html}</div>`;
}

const indentOf = (line) => line.match(/^\s*/)[0].length;

function enclosingDef(text, line) {
  const lines = text.split("\n");
  const ind = indentOf(lines[line - 1] || "");
  for (let i = line - 1; i >= 0; i--) {
    if (/^\s*(async\s+)?def\s/.test(lines[i]) && indentOf(lines[i]) < ind) return i + 1;
  }
  return line;
}

function functionEnd(text, defLine) {
  const lines = text.split("\n");
  const head = lines[defLine - 1] || "";
  if (!/^\s*(async\s+)?(def|class)\s/.test(head)) return defLine;
  const ind = indentOf(head);
  let last = defLine;
  for (let i = defLine; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    if (indentOf(lines[i]) <= ind) break;
    last = i + 1;
  }
  return last;
}

function sliceFunction(text, name) {
  if (!text) return null;
  const lines = text.split("\n");
  const idx = lines.findIndex((l) => new RegExp(`^\\s*(async\\s+)?def\\s+${name}\\b`).test(l));
  if (idx < 0) return null;
  const end = functionEnd(text, idx + 1);
  return { start: idx + 1, lines: lines.slice(idx, end) };
}

function renderInspector() {
  const el = $("#inspector");
  const f = current();
  if (!f) {
    el.innerHTML = `<div class="empty" style="height:100%">Select a finding to inspect it.</div>`;
    return;
  }
  const rule = f.rule;
  const regression = f.regression ? state.bundle.report.regressions.find((r) => r.function_id === f.function_id) : null;
  const tab = (id, label, disabled = false) =>
    `<button type="button" role="tab" data-insp="${id}" aria-selected="${state.inspTab === id}" ${disabled ? "disabled" : ""}>${label}</button>`;
  if (state.inspTab === "fix" && !f.canFix) state.inspTab = "overview";

  el.innerHTML = `
    <div class="insp-head">
      <div class="insp-kicker">
        <span class="sev sev-${f.severity}">${f.severity}</span>
        <code>${esc(f.rule_id || "plex.hotspot")}</code>
        ${rule ? `<span class="chip">${esc(rule.stability)}</span>` : '<span class="chip">heuristic</span>'}
        ${f.canFix ? `<span class="tag fix">${ICONS.wand}Auto-fix available</span>` : ""}
        ${regression ? '<span class="tag reg">Regression vs base</span>' : ""}
      </div>
      <h2 class="insp-title">${esc(formatHint(f.title))}</h2>
      <p class="insp-expl">${esc(f.explanation || rule?.description || "")}</p>
    </div>
    <div class="insp-tabs" role="tablist">
      ${tab("overview", "Overview")}${tab("fix", "Fix preview", !f.canFix)}${tab("json", "JSON")}
    </div>
    <div class="insp-body" id="insp-body"></div>`;
  const body = $("#insp-body");

  if (state.inspTab === "overview") {
    body.innerHTML = `
      ${codeView(f)}
      ${
        f.suggestions?.length
          ? `<div class="insp-section"><h4>Suggestions</h4><ul class="suggestions">${f.suggestions
              .map((s) => `<li>${esc(s).replace(/`([^`]+)`/g, "<code>$1</code>")}</li>`)
              .join("")}</ul></div>`
          : ""
      }
      <div class="insp-section"><h4>Scores</h4>
        <div class="meters">
          <div><div class="meter-label">Risk score <b>${f.risk_score.toFixed(2)}</b></div><div class="meter"><i style="width:${Math.min(
            100,
            (f.risk_score / 3) * 100,
          )}%"></i></div></div>
          <div><div class="meter-label">Confidence <b>${Math.round(f.confidence * 100)}%</b></div><div class="meter"><i style="width:${
            f.confidence * 100
          }%"></i></div></div>
        </div>
      </div>
      <div class="insp-section"><h4>Static signals · ${esc(formatHint(f.complexity_hint))}</h4>
        <div class="signals">${Object.entries(f.signals || {})
          .map(([k, v]) => `<div class="signal"><span>${esc(k)}</span><b>${v === true ? "yes" : v === false ? "no" : esc(v)}</b></div>`)
          .join("")}</div>
      </div>
      ${
        regression
          ? `<div class="insp-section"><h4>Regression</h4><p style="margin:0 0 10px;font-size:13.5px">${esc(
              regression.explanation,
            )} Risk ${regression.base_risk_score.toFixed(2)} → ${regression.head_risk_score.toFixed(2)}.</p>
            <button class="btn btn-sm" type="button" data-goto="pr">Open pull request view ${ICONS.arrow}</button></div>`
          : ""
      }`;
    const cv = body.querySelector(".codeview");
    if (cv) {
      const target = cv.querySelector(`[data-line="${Math.max(1, +cv.dataset.scrollTo - 3)}"]`);
      body.scrollTop = 0;
      if (target) body.scrollTop = target.offsetTop - 36;
    }
  } else if (state.inspTab === "fix") {
    const cmd = `plex fix --rule ${f.rule_id} ${f.file}`;
    body.innerHTML = f.fix
      ? `<div class="insp-section">
          <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;margin-bottom:12px">
            <span class="cmd"><span>$ ${esc(cmd)}</span><button class="icon-btn" type="button" data-copy="${esc(cmd)}" aria-label="Copy">${ICONS.copy}</button></span>
            <button class="btn btn-sm" type="button" data-goto="fixes">All fixes ${ICONS.arrow}</button>
          </div>
          <div class="card">${renderDiff(f.fix.diff, { numbers: false })}</div>
          <p class="kpi-sub" style="margin-top:10px">Output of the real fixer for <code>${esc(f.rule_id)}</code>, diffed against the AST-normalized original so only the rewrite shows.</p>
        </div>`
      : `<div class="insp-section"><div class="note">${ICONS.wand}<span>A fixer is registered for <code>${esc(
          f.rule_id,
        )}</code>, but no preview is bundled for this report. Run <code>${esc(cmd)} --diff --dry-run</code> locally.</span></div></div>`;
  } else {
    const sarif = sarifFor(f);
    body.innerHTML = `
      <div class="insp-section"><h4>Finding (plex.json)</h4><div class="card"><pre class="raw" style="max-height:none">${jsonHtml(
        stripFinding(f),
      )}</pre></div></div>
      ${sarif ? `<div class="insp-section"><h4>SARIF result</h4><div class="card"><pre class="raw" style="max-height:none">${jsonHtml(sarif)}</pre></div></div>` : ""}`;
  }
}

function stripFinding(f) {
  const { key, order, kind, title, rule, fix, canFix, regression, ...raw } = f;
  return raw;
}

function sarifFor(f) {
  const results = state.bundle.outputs?.sarif?.runs?.[0]?.results || [];
  return (
    results.find((r) => {
      const loc = r.locations?.[0]?.physicalLocation;
      return loc?.artifactLocation?.uri?.endsWith(f.file) && loc?.region?.startLine === f.lineno && (r.ruleId === f.rule_id || !f.rule_id);
    }) || null
  );
}

function jsonHtml(value) {
  return esc(JSON.stringify(value, null, 2)).replace(
    /(&quot;(?:\\.|[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)/g,
    (m, str, colon, lit, num) => {
      if (str) return colon ? `<span class="json-key">${str}</span>${colon}` : `<span class="json-str">${str}</span>`;
      if (lit) return `<span class="json-lit">${lit}</span>`;
      return `<span class="json-num">${num}</span>`;
    },
  );
}

/* -------------------------------------------------------------------- PR */

function renderPR(panel) {
  const { report, meta = {}, outputs = {} } = state.bundle;
  const regs = report.regressions || [];
  const diffs = report.diffs || [];
  if (!report.regression_mode) {
    panel.innerHTML = `<div class="card"><div class="empty">${ICONS.branch}<span>This report was generated without <code>--compare-base</code>, so there's no base-vs-head comparison.</span></div></div>`;
    return;
  }
  const pr = meta.pull_request || { title: "Pull request", base: report.base_ref, head: "HEAD" };
  const added = diffs.filter((d) => d.change_type === "added").length;
  const changed = diffs.filter((d) => d.change_type === "changed").length;
  const removed = diffs.filter((d) => d.change_type === "removed").length;

  const regCards = regs
    .map((r) => {
      const base = sliceFunction(source(r.file, "base"), r.qualname.split(".").pop());
      const head = sliceFunction(source(r.file, "head"), r.qualname.split(".").pop());
      const max = Math.max(3, r.head_risk_score, r.base_risk_score);
      const pos = (v) => `${(v / max) * 100}%`;
      const baseSet = new Set(base?.lines.map((l) => l.trim()) || []);
      const headSet = new Set(head?.lines.map((l) => l.trim()) || []);
      const side = (fn, other, cls) =>
        fn
          ? `<div class="codeview">${highlightLines(fn.lines.join("\n"))
              .map(
                (h, i) =>
                  `<div class="cl ${other.has(fn.lines[i].trim()) ? "" : cls}"><span class="gut"></span><span class="no">${
                    fn.start + i
                  }</span><span class="src">${h || " "}</span></div>`,
              )
              .join("")}</div>`
          : `<div class="empty">Source not bundled</div>`;
      const sig = Object.keys({ ...r.base_signals, ...r.head_signals })
        .map((k) => {
          const a = r.base_signals?.[k];
          const b = r.head_signals?.[k];
          const fmt = (v) => (v === true ? "yes" : v === false ? "no" : v);
          const d = typeof a === "number" && typeof b === "number" ? b - a : a === b ? 0 : null;
          return `<div class="delta"><span>${esc(SIGNAL_LABELS[k] || k)}</span><b>${fmt(a)} → ${fmt(b)} <small class="${
            d ? "" : "same"
          }">${d ? (d > 0 ? `+${d}` : d) : d === 0 ? "no change" : "changed"}</small></b></div>`;
        })
        .join("");
      return `
      <article class="card">
        <div class="card-head">
          <span class="sev sev-${r.regression_severity}">${r.regression_severity}</span>
          <h3><code>${esc(r.qualname)}</code> · ${esc(formatHint(r.base_hint))} → ${esc(formatHint(r.head_hint))}</h3>
          <span class="spacer"></span>
          <code style="color:var(--muted);font-size:12px">${esc(r.file)}:${r.lineno}</code>
        </div>
        <div class="card-body">
          <p style="margin:0 0 6px">${esc(r.explanation)}</p>
          <div class="risk-track" role="img" aria-label="Risk score ${r.base_risk_score} to ${r.head_risk_score}">
            <div class="rail"></div>
            <div class="arrow" style="left:${pos(r.base_risk_score)};width:calc(${pos(r.head_risk_score)} - ${pos(r.base_risk_score)})"></div>
            <div class="pt" style="left:${pos(r.base_risk_score)}">base ${r.base_risk_score.toFixed(2)}</div>
            <div class="pt head" style="left:${pos(r.head_risk_score)}">head ${r.head_risk_score.toFixed(2)}</div>
          </div>
          <div class="risk-scale"><span>0</span><span>risk score · Δ +${r.risk_delta.toFixed(2)} · hint Δ +${r.hint_delta}</span><span>${max}</span></div>
          <div class="delta-strip" style="margin-top:16px">${sig}</div>
        </div>
        <div class="compare">
          <div><div class="compare-label"><span>base</span><b>${esc(pr.base)}</b></div>${side(base, headSet, "removed")}</div>
          <div><div class="compare-label"><span>head</span><b>${esc(pr.head)}</b></div>${side(head, baseSet, "changed")}</div>
        </div>
        <div class="card-body" style="border-top:1px solid var(--border)">
          <h4 style="margin:0 0 8px;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)">Fix ideas</h4>
          <ul class="suggestions">${(r.suggestions || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ul>
        </div>
      </article>`;
    })
    .join("");

  const annotations = outputs.check_run?.annotations || [];
  panel.innerHTML = `
    <div class="view-grid">
      <div class="card pr-hero">
        <div style="flex:1;min-width:260px">
          <h2>${esc(pr.title)} <span>· demo PR</span></h2>
          <div class="pr-branches" style="margin-top:6px"><code>${esc(pr.head)}</code>${ICONS.arrow}<code>${esc(pr.base)}</code></div>
        </div>
        <span class="chip">${changed} changed</span><span class="chip">${added} added</span>${removed ? `<span class="chip">${removed} removed</span>` : ""}
        <span class="chip" style="color:var(--bad)">${regs.length} regression${regs.length === 1 ? "" : "s"}</span>
      </div>
      <div class="two-col">
        <div class="view-grid">${regCards || `<div class="card"><div class="empty">${ICONS.check}<span>No regressions vs base.</span></div></div>`}
          <div class="card">
            <div class="card-head"><h3>Function changes</h3><p>base → head, from <code>diffs</code></p></div>
            <div style="overflow-x:auto"><table class="change-table">
              <thead><tr><th>Function</th><th>Type</th><th>Trend</th><th>Risk</th><th>Hint</th></tr></thead>
              <tbody>${diffs
                .map(
                  (d) => `<tr>
                  <td class="mono">${esc(d.qualname)} <span style="color:var(--muted)">${esc(d.file)}:${d.lineno}</span></td>
                  <td>${esc(d.change_type)}</td>
                  <td><span class="trend ${esc(d.trend)}">${d.trend === "worse" ? "▲ worse" : d.trend === "new" ? "● new" : esc(d.trend)}</span></td>
                  <td class="mono">${d.base_risk_score == null ? "—" : d.base_risk_score.toFixed(2)} → ${d.head_risk_score?.toFixed(2) ?? "—"}</td>
                  <td class="mono">${esc(formatHint(d.base_hint || "—"))} → ${esc(formatHint(d.head_hint || "—"))}</td></tr>`,
                )
                .join("")}</tbody></table></div>
          </div>
        </div>
        <div class="view-grid">
          ${
            outputs.comment
              ? `<div class="card"><div class="card-head"><h3>Sticky PR comment</h3><p><code>--comment</code> · posted by the Action</p></div>
                <div class="card-body"><div class="gh-comment"><div class="gh-comment-head"><img src="../assets/img/logo.svg" alt="" /><b>plex-bot</b> commented</div>
                <div class="md">${renderMarkdown(outputs.comment)}</div></div></div></div>`
              : ""
          }
          ${
            annotations.length
              ? `<div class="card"><div class="card-head"><h3>Check run annotations</h3><p><code>--check-run</code></p></div><div class="card-body view-grid">${annotations
                  .map(
                    (a) =>
                      `<div class="annotation">${ICONS.shield}<div><b>${esc(a.title)}</b><div>${esc(a.message)}</div><code>${esc(a.path)}:${
                        a.start_line
                      } · ${esc(a.annotation_level)}</code></div></div>`,
                  )
                  .join("")}</div></div>`
              : ""
          }
        </div>
      </div>
    </div>`;
}

/* -------------------------------------------------------------- hotspots */

function renderHotspots(panel) {
  const byFn = new Map();
  for (const f of state.findings) {
    const k = `${f.file}::${f.qualname}`;
    const e = byFn.get(k) || { file: f.file, qualname: f.qualname, lineno: f.lineno, items: [] };
    e.items.push(f);
    e.lineno = Math.min(e.lineno, f.lineno);
    byFn.set(k, e);
  }
  const rows = [...byFn.values()]
    .map((e) => {
      const top = [...e.items].sort((a, b) => b.risk_score - a.risk_score || sevRank(b.severity) - sevRank(a.severity))[0];
      return { ...e, top, risk: top.risk_score };
    })
    .sort((a, b) => b.risk - a.risk || a.qualname.localeCompare(b.qualname));
  const max = Math.max(3, Math.ceil(Math.max(...rows.map((r) => r.risk))));
  const files = [...new Set(state.findings.map((f) => f.file))].sort();
  const counts = (file) => Object.fromEntries(SEVERITIES.map((s) => [s, state.findings.filter((f) => f.file === file && f.severity === s).length]));
  panel.innerHTML = `
    <div class="two-col">
      <div class="card">
        <div class="card-head"><h3>Risk by function</h3><p>Highest risk score per function · click a bar to inspect</p><span class="spacer"></span>
          <div class="legend">${SEVERITIES.map((s) => `<span class="sev sev-${s}">${s}</span>`).join("")}</div></div>
        <div class="card-body">
          <div class="bars">${rows
            .map(
              (r, i) => `<div class="bar-row" tabindex="0" role="button" data-jump="${esc(r.top.key)}"
                data-tip="${esc(`${r.qualname} · ${r.file}:${r.lineno}|${r.items.length} finding${r.items.length > 1 ? "s" : ""}: ${r.items.map((x) => formatHint(x.title)).join(", ")}`)}">
                <div class="bar-name">${esc(r.qualname)} <small>${esc(r.file.split("/").pop())}</small></div>
                <div class="bar-track"><i style="width:${Math.max(0.6, (r.risk / max) * 100)}%;--c:var(--sev-${r.top.severity});animation-delay:${i * 25}ms"></i></div>
                <div class="bar-val">${r.risk.toFixed(2)}</div></div>`,
            )
            .join("")}</div>
          <div class="axis"><span></span><div>${Array.from({ length: max + 1 }, (_, i) => `<span>${i}</span>`).join("")}</div><span></span></div>
        </div>
      </div>
      <div class="view-grid">
        <div class="card"><div class="card-head"><h3>Findings by file</h3><p>Stacked by severity</p></div>
          <div class="card-body file-heat">${files
            .map((file) => {
              const c = counts(file);
              const total = Object.values(c).reduce((a, b) => a + b, 0);
              return `<div class="file-heat-row"><header><b>${esc(file)}</b><span>${total} · ${SEVERITIES.filter((s) => c[s])
                .map((s) => `${c[s]} ${s}`)
                .join(", ")}</span></header>
                <div class="stack" role="img" aria-label="${esc(file)}: ${SEVERITIES.map((s) => `${c[s]} ${s}`).join(", ")}">${SEVERITIES.filter((s) => c[s])
                  .map((s) => `<i style="flex-grow:${c[s]};--c:var(--sev-${s})"></i>`)
                  .join("")}</div></div>`;
            })
            .join("")}</div></div>
        <div class="card"><div class="card-head"><h3>Complexity hints</h3><p>Static estimate per function</p></div>
          <div class="card-body"><table class="change-table" style="margin:-16px -18px;width:calc(100% + 36px)"><thead><tr><th>Hint</th><th>Functions</th></tr></thead><tbody>${Object.entries(
            state.bundle.report.stats?.hint_counts || {},
          )
            .filter(([k]) => !k.startsWith("Rule:"))
            .map(([k, v]) => `<tr><td class="mono">${esc(formatHint(k))}</td><td>${v}</td></tr>`)
            .join("")}</tbody></table></div></div>
      </div>
    </div>`;
}

/* ----------------------------------------------------------------- fixes */

function renderFixes(panel) {
  const fixes = Object.values(state.bundle.fixes || {});
  if (!fixes.length) {
    panel.innerHTML = `<div class="card"><div class="empty">${ICONS.wand}<span>No fix previews are bundled with this report.<br/>Run <code>plex fix --diff --dry-run .</code> locally.</span></div></div>`;
    return;
  }
  const byRule = (id) => state.findings.find((f) => f.rule_id === id && fixes.some((x) => x.rule_id === id));
  panel.innerHTML = `
    <div class="view-grid">
      <div class="note">${ICONS.wand}<span><b>${esc(state.bundle.fix_summary || `${fixes.length} fixes`)}</b> Each preview is the
        real output of <code>plex fix --rule &lt;id&gt;</code>, diffed against the AST-normalized original so only the semantic rewrite shows.
        Review with <code>plex fix --diff --dry-run</code> before applying.</span></div>
      ${fixes
        .map((x) => {
          const f = state.findings.find((f) => f.rule_id === x.rule_id && f.file === x.file) || byRule(x.rule_id);
          const cmd = `plex fix --rule ${x.rule_id} ${x.file}`;
          return `<article class="card fix-card">
            <div class="card-head">
              ${f ? `<span class="sev sev-${f.severity}">${f.severity}</span>` : ""}
              <h3>${esc(f ? formatHint(f.title) : x.rule_id)}</h3><code>${esc(x.rule_id)}</code>
              <span class="spacer"></span>
              <span class="cmd"><span>$ ${esc(cmd)}</span><button class="icon-btn" type="button" data-copy="${esc(cmd)}" aria-label="Copy command">${ICONS.copy}</button></span>
              ${f ? `<button class="btn btn-sm" type="button" data-jump="${esc(f.key)}">Inspect</button>` : ""}
            </div>
            ${renderDiff(x.diff, { numbers: false })}
          </article>`;
        })
        .join("")}
    </div>`;
}

/* --------------------------------------------------------------- outputs */

function outputsList() {
  const o = state.bundle.outputs || {};
  return [
    o.comment && { id: "comment", label: "PR comment", file: "plex.comment.md", flag: "--comment", md: o.comment },
    o.markdown && { id: "markdown", label: "Markdown report", file: "plex.md", flag: "--md", md: o.markdown },
    { id: "json", label: "JSON report", file: "plex.json", flag: "--json", json: state.bundle.report },
    o.sarif && { id: "sarif", label: "SARIF 2.1.0", file: "plex.sarif", flag: "--sarif", json: o.sarif },
    o.check_run && { id: "check_run", label: "Check run", file: "plex.check_run.json", flag: "--check-run", json: o.check_run },
  ].filter(Boolean);
}

function renderOutputs(panel) {
  const list = outputsList();
  if (!list.some((x) => x.id === state.outTab)) state.outTab = list[0].id;
  const cur = list.find((x) => x.id === state.outTab);
  const text = cur.md ?? JSON.stringify(cur.json, null, 2);
  const meta = state.bundle.meta || {};
  panel.innerHTML = `
    <div class="out-layout">
      <nav class="card out-nav" aria-label="Output formats">${list
        .map((x) => `<button type="button" data-out="${x.id}" aria-current="${x.id === cur.id}"><span>${x.label}</span><small>${x.flag} ${x.file}</small></button>`)
        .join("")}</nav>
      <div class="card">
        <div class="card-head">
          <h3>${cur.label}</h3><code style="color:var(--muted);font-size:12px">out/${cur.file}</code>
          <span class="spacer"></span>
          ${cur.md ? `<div class="segmented"><button type="button" data-mode="rendered" aria-pressed="${state.outMode === "rendered"}">Rendered</button><button type="button" data-mode="source" aria-pressed="${state.outMode === "source"}">Source</button></div>` : ""}
          <button class="btn btn-sm" type="button" data-copy-out>${ICONS.copy}Copy</button>
          <button class="btn btn-sm" type="button" data-download-out>${ICONS.download}Download</button>
        </div>
        ${
          cur.md && state.outMode === "rendered"
            ? `<div class="card-body md">${renderMarkdown(cur.md)}</div>`
            : `<pre class="raw">${cur.json ? jsonHtml(cur.json) : esc(text)}</pre>`
        }
        ${meta.command ? `<div class="card-body" style="border-top:1px solid var(--border)"><div class="kpi-sub">Generated by <code>${esc(meta.command)}</code> · ${esc(meta.plex_version || "")}</div></div>` : ""}
      </div>
    </div>`;
  panel.querySelector("[data-copy-out]").onclick = () => copyText(text, `${cur.label} copied`);
  panel.querySelector("[data-download-out]").onclick = () => download(cur.file, text, cur.md ? "text/markdown" : "application/json");
}

/* --------------------------------------------------------------- palette */

function paletteItems() {
  const items = [];
  VIEWS.forEach((v, i) => items.push({ group: "View", label: VIEW_LABELS[v], sub: `${i + 1}`, run: () => setView(v) }));
  for (const f of state.findings)
    items.push({
      group: "Finding",
      label: `${formatHint(f.title)} — ${f.qualname}`,
      sub: `${f.file.split("/").pop()}:${f.lineno}`,
      sev: f.severity,
      run: () => {
        setView("findings");
        if (!filtered().some((x) => x.key === f.key)) resetFilters();
        select(f.key);
      },
    });
  for (const file of new Set(state.findings.map((f) => f.file)))
    items.push({
      group: "File",
      label: file,
      run: () => {
        state.filters.file = file;
        setView("findings");
        renderFindings();
      },
    });
  for (const id of new Set(state.findings.filter((f) => f.rule_id).map((f) => f.rule_id)))
    items.push({
      group: "Rule",
      label: id,
      sub: state.rules.get(id)?.name,
      run: () => {
        state.filters.rule = id;
        setView("findings");
        renderFindings();
      },
    });
  for (const p of ["strict", "balanced", "relaxed", "off"])
    items.push({ group: "Gate", label: `Use ${p} gate policy`, run: () => $(`#gate [data-preset="${p}"]`).click() });
  items.push(
    { group: "Action", label: "Toggle light / dark theme", run: () => $("#theme-toggle").click() },
    { group: "Action", label: "Download plex.json", run: () => download("plex.json", JSON.stringify(state.bundle.report, null, 2)) },
    { group: "Action", label: "Open a local plex.json…", run: () => $("#file-input").click() },
    { group: "Action", label: "Reset filters", run: () => (setView("findings"), resetFilters()) },
  );
  if (state.custom) items.push({ group: "Action", label: "Back to the demo report", run: () => useBundle(state.demo, false) });
  return items;
}

function fuzzy(q, text) {
  const t = text.toLowerCase();
  const i = t.indexOf(q);
  if (i >= 0) return { score: 100 - i, html: `${esc(text.slice(0, i))}<mark>${esc(text.slice(i, i + q.length))}</mark>${esc(text.slice(i + q.length))}` };
  let j = 0;
  for (const c of t) if (c === q[j]) j++;
  return j === q.length ? { score: 10, html: esc(text) } : null;
}

function initPalette() {
  const dlg = $("#palette");
  const input = $("#palette-q");
  const ul = $("#palette-results");
  let results = [];
  let idx = 0;
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    results = paletteItems()
      .map((it) => {
        if (!q) return { it, score: 0, html: esc(it.label) };
        const m = fuzzy(q, `${it.label}`) || (it.sub && fuzzy(q, it.sub) && { score: 5, html: esc(it.label) });
        return m && { it, ...m };
      })
      .filter(Boolean)
      .sort((a, b) => b.score - a.score)
      .slice(0, 40);
    idx = Math.min(idx, Math.max(0, results.length - 1));
    ul.innerHTML = results.length
      ? results
          .map(
            (r, i) =>
              `<li role="option" data-i="${i}" aria-selected="${i === idx}"><span class="group">${r.it.group}</span>${
                r.it.sev ? `<span class="sev sev-${r.it.sev}"></span>` : ""
              }<span>${r.html}</span>${r.it.sub ? `<span class="sub">${esc(r.it.sub)}</span>` : ""}</li>`,
          )
          .join("")
      : `<li class="empty">No matches</li>`;
    ul.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
  };
  const open = () => {
    input.value = "";
    idx = 0;
    draw();
    dlg.showModal();
    input.focus();
  };
  const run = (i) => {
    const r = results[i];
    if (!r) return;
    dlg.close();
    r.it.run();
  };
  input.addEventListener("input", () => ((idx = 0), draw()));
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") (idx = Math.min(results.length - 1, idx + 1)), draw(), e.preventDefault();
    if (e.key === "ArrowUp") (idx = Math.max(0, idx - 1)), draw(), e.preventDefault();
    if (e.key === "Enter") run(idx);
  });
  ul.addEventListener("click", (e) => {
    const li = e.target.closest("[data-i]");
    if (li) run(+li.dataset.i);
  });
  dlg.addEventListener("click", (e) => e.target === dlg && dlg.close());
  $("#palette-open").addEventListener("click", open);
  if (!/Mac|iPhone|iPad/.test(navigator.platform)) $("#palette-kbd").textContent = "Ctrl K";
  return { open, isOpen: () => dlg.open };
}

/* ------------------------------------------------------- user reports */

async function loadFile(file) {
  try {
    const report = JSON.parse(await file.text());
    if (!Array.isArray(report.findings)) throw new Error("missing a findings array");
    if (report.schema_version && report.schema_version !== 7)
      toast(`Schema v${report.schema_version} — this viewer targets v7; some fields may be missing`);
    useBundle(
      {
        meta: { project: file.name },
        report: { regressions: [], diffs: [], stats: {}, ...report },
        rules: state.demo.rules,
        fixable_rules: state.demo.fixable_rules,
        fixes: {},
        sources: null,
        outputs: {},
      },
      true,
    );
    toast(`Loaded ${file.name} · ${report.findings.length} findings`);
  } catch (err) {
    toast(`Couldn't read ${file.name}: ${err.message}`);
  }
}

function initDrop() {
  const overlay = $("#drop-overlay");
  let depth = 0;
  addEventListener("dragenter", (e) => {
    if (![...(e.dataTransfer?.types || [])].includes("Files")) return;
    depth++;
    overlay.hidden = false;
  });
  addEventListener("dragleave", () => {
    if (--depth <= 0) (depth = 0), (overlay.hidden = true);
  });
  addEventListener("dragover", (e) => e.preventDefault());
  addEventListener("drop", (e) => {
    e.preventDefault();
    depth = 0;
    overlay.hidden = true;
    const file = e.dataTransfer?.files?.[0];
    if (file) loadFile(file);
  });
  $("#file-input").addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (file) loadFile(file);
    e.target.value = "";
  });
}

function renderBanner() {
  $(".app > .banner")?.remove();
  if (!state.custom) return;
  const b = document.createElement("div");
  b.className = "banner";
  b.innerHTML = `${ICONS.file}<span>Viewing <b>${esc(state.bundle.meta.project)}</b> from your machine. It was parsed locally and never uploaded; source code isn't included in plex.json, so code views are hidden.</span><span class="spacer"></span><button class="btn btn-sm" type="button">Back to demo</button>`;
  b.querySelector("button").onclick = () => useBundle(state.demo, false);
  $("#gate").before(b);
}

/* ------------------------------------------------------------------ boot */

function useBundle(bundle, custom) {
  state.custom = custom;
  hydrate(bundle);
  state.selected = null;
  state.inspTab = "overview";
  state.filters = { q: "", sev: new Set(SEVERITIES), kinds: new Set(["rule", "hint"]), fixable: false, regression: false, file: null, rule: null };
  renderAll();
}

function renderAll() {
  renderBanner();
  renderCrumb();
  renderGate();
  renderKpis();
  renderCounts();
  renderFindings();
  setView(state.view);
}

function bindGlobal(palette) {
  $("#tabs").addEventListener("click", (e) => {
    const t = e.target.closest("[role=tab]");
    if (t) setView(t.dataset.view);
  });
  $("#tabs").addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
    const i = VIEWS.indexOf(state.view) + (e.key === "ArrowRight" ? 1 : -1);
    setView(VIEWS[(i + VIEWS.length) % VIEWS.length]);
    $(`#tabs [data-view="${state.view}"]`).focus();
  });
  $("#finding-list").addEventListener("click", (e) => {
    const li = e.target.closest(".finding");
    if (li) select(li.dataset.key, { scroll: false });
  });
  $("#inspector").addEventListener("click", (e) => {
    const t = e.target.closest("[data-insp]");
    if (t && !t.disabled) {
      state.inspTab = t.dataset.insp;
      renderInspector();
    }
  });

  document.addEventListener("click", (e) => {
    const jump = e.target.closest("[data-jump]")?.dataset.jump;
    if (jump) {
      hideTip();
      setView("findings");
      if (!filtered().some((x) => x.key === jump)) resetFilters();
      state.inspTab = "overview";
      select(jump);
      return;
    }
    const go = e.target.closest("[data-goto]")?.dataset.goto;
    if (go) setView(go);
    const cp = e.target.closest("[data-copy]")?.dataset.copy;
    if (cp) copyText(cp, "Command copied");
    const out = e.target.closest("[data-out]")?.dataset.out;
    if (out) (state.outTab = out), renderOutputs($('.view[data-view="outputs"]'));
    const mode = e.target.closest("[data-mode]")?.dataset.mode;
    if (mode) (state.outMode = mode), renderOutputs($('.view[data-view="outputs"]'));
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.matches?.(".bar-row")) e.target.click();
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      palette.open();
      return;
    }
    if (palette.isOpen() || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.target.matches?.("input, select, textarea")) {
      if (e.key === "Escape") e.target.blur();
      return;
    }
    if (e.key === "/") {
      e.preventDefault();
      setView("findings");
      $("#q")?.focus();
    } else if (e.key === "j" || (e.key === "ArrowDown" && e.target.closest?.(".finding"))) {
      e.preventDefault();
      if (state.view !== "findings") setView("findings");
      step(1);
    } else if (e.key === "k" || (e.key === "ArrowUp" && e.target.closest?.(".finding"))) {
      e.preventDefault();
      if (state.view !== "findings") setView("findings");
      step(-1);
    } else if (/^[1-5]$/.test(e.key)) setView(VIEWS[+e.key - 1]);
  });
}

const tip = $("#tooltip");
function hideTip() {
  tip.hidden = true;
}
function initTooltips() {
  document.addEventListener("pointerover", (e) => {
    const t = e.target.closest("[data-tip]");
    if (!t) return hideTip();
    const [head, rest] = t.dataset.tip.split("|");
    tip.innerHTML = `<b>${esc(head)}</b>${rest ? `<span>${esc(rest)}</span>` : ""}`;
    tip.hidden = false;
  });
  document.addEventListener("pointermove", (e) => {
    if (tip.hidden) return;
    const pad = 14;
    const w = tip.offsetWidth;
    const h = tip.offsetHeight;
    tip.style.left = `${Math.min(innerWidth - w - 8, e.clientX + pad)}px`;
    tip.style.top = `${e.clientY + pad + h > innerHeight ? e.clientY - h - pad : e.clientY + pad}px`;
  });
  document.addEventListener("pointerout", (e) => {
    if (e.target.closest("[data-tip]") && !e.relatedTarget?.closest?.("[data-tip]")) hideTip();
  });
}

async function main() {
  initTheme($("#theme-toggle"));
  try {
    const bundle = await loadBundle("../");
    state.demo = bundle;
    hydrate(bundle);
    readHash();
    bindGate();
    bindFilters();
    bindGlobal(initPalette());
    initDrop();
    initTooltips();
    renderAll();
    if (state.selected) select(state.selected);
    addEventListener("hashchange", () => {
      const prev = state.selected;
      readHash();
      setView(state.view);
      if (state.selected !== prev) select(state.selected);
    });
  } catch (err) {
    $("#main").innerHTML = `<div class="card"><div class="empty">${ICONS.x}<span>${esc(err.message)}</span></div></div>`;
  } finally {
    $("#main").removeAttribute("aria-busy");
  }
}

main();
