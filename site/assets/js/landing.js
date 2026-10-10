// PLEx landing page — every number and finding comes from assets/data/demo.json.
import {
  $,
  $$,
  esc,
  ICONS,
  GATING_PRESETS,
  copyText,
  evaluateGate,
  findingKey,
  findingTitle,
  formatHint,
  highlightLine,
  initTheme,
  loadBundle,
  parseDiff,
  renderMarkdown,
  sevRank,
} from "./core.js";

const PLAYGROUND_RULES = [
  "plex.string-concat-in-loop",
  "plex.sync-io-in-async",
  "plex.db-in-loop",
  "plex.uncompiled-regex-in-loop",
  "plex.sorted-min-max",
  "plex.mutable-default-arg",
];
const CASE_LABELS = {
  "plex.string-concat-in-loop": ["Quadratic string build", "n²"],
  "plex.sync-io-in-async": ["Blocking call in async", "io"],
  "plex.db-in-loop": ["N+1 database query", "N+1"],
  "plex.uncompiled-regex-in-loop": ["Regex compiled per item", "re"],
  "plex.sorted-min-max": ["Sorting to find a minimum", "min"],
  "plex.mutable-default-arg": ["Mutable default argument", "[]"],
};

/* ---------------------------------------------------------------- chrome */

initTheme($("#theme-toggle"));

const nav = $("#nav");
const onScroll = () => nav.classList.toggle("scrolled", scrollY > 8);
addEventListener("scroll", onScroll, { passive: true });
onScroll();

document.addEventListener("click", (e) => {
  const c = e.target.closest("[data-copy]");
  if (c) copyText(c.dataset.copy);
});

const io =
  "IntersectionObserver" in window
    ? new IntersectionObserver(
        (entries) =>
          entries.forEach((en) => {
            if (en.isIntersecting) {
              en.target.classList.add("in");
              io.unobserve(en.target);
            }
          }),
        { rootMargin: "0px 0px -8% 0px" },
      )
    : null;
for (const el of $$(".section-head, .playground, .pipeline li, .pr-grid > *, .int-grid > *, .cta")) {
  if (!io) break;
  el.classList.add("reveal");
  io.observe(el);
}
$$(".pipeline li").forEach((li, i) => (li.style.transitionDelay = `${i * 70}ms`));

/* ----------------------------------------------------------------- utils */

const indentOf = (l) => l.match(/^\s*/)[0].length;

function functionAt(text, line) {
  const lines = text.split("\n");
  let start = line - 1;
  const ind = indentOf(lines[start] || "");
  if (!/^\s*(async\s+)?def\s/.test(lines[start])) {
    for (let i = start; i >= 0; i--)
      if (/^\s*(async\s+)?def\s/.test(lines[i]) && indentOf(lines[i]) < ind) {
        start = i;
        break;
      }
  }
  const base = indentOf(lines[start]);
  let end = start;
  for (let i = start + 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    if (indentOf(lines[i]) <= base) break;
    end = i;
  }
  return { start: start + 1, lines: lines.slice(start, end + 1) };
}

const row = (no, html, cls = "", delay = 0) =>
  `<div class="ln-row ${cls}" style="animation-delay:${delay}ms"><span class="no">${no}</span><span>${html || " "}</span></div>`;

/* ------------------------------------------------------------------ hero */

function renderHero(bundle) {
  const { report, sources, meta } = bundle;
  const reg = report.regressions?.[0];
  if (meta?.plex_version) $("#hero-version").textContent = `${meta.plex_version.replace(/^plex\s*/, "v")} · Open source · Apache-2.0`;
  if (!reg) return;
  const head = sources.head[reg.file];
  const base = new Set(sources.base[reg.file].split("\n").map((l) => l.trim()));
  const fn = functionAt(head, reg.lineno);
  $("#hero-file").textContent = reg.file;
  $("#hero-branch").textContent = meta?.pull_request?.head || "HEAD";
  $("#hero-code").innerHTML = fn.lines
    .map((l, i) => row(fn.start + i, highlightLine(l), l.trim() && !base.has(l.trim()) ? "add" : ""))
    .join("");

  const gate = evaluateGate(report, { ...GATING_PRESETS.balanced });
  $("#hero-reg").innerHTML = `
    <div class="reg-head"><span class="sev sev-${reg.regression_severity}">${reg.regression_severity} regression</span><code>${esc(
      reg.qualname,
    )}</code></div>
    <div class="reg-big"><span class="from">${esc(formatHint(reg.base_hint).replace(" candidate", ""))}</span>${ICONS.arrow}<span class="to">${esc(
      formatHint(reg.head_hint).replace(" candidate", ""),
    )}</span></div>
    <div class="reg-meta"><span>risk <b>${reg.base_risk_score.toFixed(2)} → ${reg.head_risk_score.toFixed(2)}</b></span><span>${esc(
      reg.explanation,
    )}</span></div>`;
  $("#hero-check").innerHTML = `<span class="check-ico">${gate.failed ? ICONS.x : ICONS.check}</span>
    <div><b>PLEx / analyze</b><div class="muted">${gate.failed ? "Gate failed" : "Passed"} · ${report.regressions.length} regression · ${
      report.findings.length
    } findings</div></div>`;
}

/* ------------------------------------------------------------ playground */

function renderPlayground(bundle) {
  const { report, sources, fixes } = bundle;
  const rules = new Map(bundle.rules.map((r) => [r.id, r]));
  const cases = PLAYGROUND_RULES.map((id) => report.findings.find((f) => f.rule_id === id)).filter(Boolean);
  let idx = 0;
  let mode = "before";

  $("#pg-cases").innerHTML = cases
    .map((f, i) => {
      const [label, ico] = CASE_LABELS[f.rule_id] || [findingTitle(f), "•"];
      return `<button class="pg-case" role="tab" type="button" data-i="${i}" aria-selected="${i === 0}">
        <span class="ico">${esc(ico)}</span><b>${esc(label)}</b><small>${esc(f.rule_id.replace("plex.", ""))}</small></button>`;
    })
    .join("");

  const draw = () => {
    const f = cases[idx];
    const fix = fixes[`${f.file}::${f.rule_id}`];
    const rule = rules.get(f.rule_id);
    if (!fix) mode = "before";
    $$("#pg-cases .pg-case").forEach((b, i) => b.setAttribute("aria-selected", String(i === idx)));
    $$("[data-pg-mode]").forEach((b) => {
      b.setAttribute("aria-pressed", String(b.dataset.pgMode === mode));
      b.disabled = b.dataset.pgMode === "after" && !fix;
    });
    $("#pg-file").textContent = `${f.file} · ${f.qualname}()`;

    const fn = functionAt(sources.head[f.file], f.lineno);
    if (mode === "before") {
      $("#pg-code").innerHTML = fn.lines
        .map((l, i) => row(fn.start + i, highlightLine(l), fn.start + i === f.lineno ? "hot" : "", i * 25))
        .join("");
    } else {
      const lines = parseDiff(fix.diff).filter((l) => l.type !== "hunk");
      $("#pg-code").innerHTML = lines
        .map((l, i) =>
          row(l.type === "add" ? "+" : l.type === "del" ? "−" : "", highlightLine(l.text), l.type === "ctx" ? "" : l.type, i * 25),
        )
        .join("");
    }

    const href = `demo/#findings/${encodeURIComponent(findingKey(f))}`;
    const cmd = fix ? `plex fix --rule ${f.rule_id} ${f.file}` : `plex analyze . --rule ${f.rule_id}`;
    $("#pg-finding").innerHTML = `
      <div class="pg-meta"><span class="sev sev-${f.severity}">${f.severity}</span><code>${esc(f.rule_id)}</code>
        <span class="badge ${rule?.stability === "experimental" ? "exp" : ""}">${esc(rule?.stability || "rule")}</span>
        ${fix ? '<span class="badge fix">auto-fix</span>' : ""}</div>
      <h3>${esc(formatHint(findingTitle(f)))}</h3>
      <p>${esc(f.explanation)}</p>
      <div class="pg-bars">
        <div class="pg-bar"><span>Risk <b>${f.risk_score.toFixed(2)}</b></span><div><i style="width:${Math.min(100, (f.risk_score / 3) * 100)}%"></i></div></div>
        <div class="pg-bar"><span>Confidence <b>${Math.round(f.confidence * 100)}%</b></span><div><i style="width:${f.confidence * 100}%"></i></div></div>
      </div>
      <ul class="pg-sugg">${(f.suggestions || [])
        .map((s) => `<li><span>${esc(s).replace(/`([^`]+)`/g, "<code>$1</code>")}</span></li>`)
        .join("")}</ul>
      <div class="pg-cmd">${esc(cmd)}</div>
      <div class="pg-action">
        ${
          fix
            ? `<button class="btn btn-sm btn-primary" type="button" data-pg-apply>${ICONS.wand}${mode === "after" ? "Show original" : "Apply fix"}</button>`
            : '<span class="badge">No safe automatic rewrite — refactor manually</span>'
        }
        <a class="btn btn-sm" href="${href}">Inspect in explorer ${ICONS.arrow}</a>
      </div>`;
  };

  $("#pg-cases").addEventListener("click", (e) => {
    const b = e.target.closest("[data-i]");
    if (!b) return;
    idx = +b.dataset.i;
    mode = "before";
    draw();
  });
  $("#pg-cases").addEventListener("keydown", (e) => {
    if (!["ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight"].includes(e.key)) return;
    e.preventDefault();
    idx = (idx + (e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : -1) + cases.length) % cases.length;
    mode = "before";
    draw();
    $(`#pg-cases [data-i="${idx}"]`).focus();
  });
  $("#playground").addEventListener("click", (e) => {
    const m = e.target.closest("[data-pg-mode]");
    if (m && !m.disabled) {
      mode = m.dataset.pgMode;
      draw();
    }
    if (e.target.closest("[data-pg-apply]")) {
      mode = mode === "after" ? "before" : "after";
      draw();
    }
  });
  draw();
}

/* -------------------------------------------------------------------- PR */

function renderPR(bundle) {
  const { report, outputs } = bundle;
  const gate = evaluateGate(report, { ...GATING_PRESETS.balanced });
  const sarifCount = outputs.sarif?.runs?.[0]?.results?.length ?? 0;
  const fixable = new Set(bundle.fixable_rules);
  const fixCount = report.findings.filter((f) => fixable.has(f.rule_id)).length;
  $("#pr-mock").innerHTML = `
    <div class="pr-status">
      <div class="pr-status-row"><span class="s ${gate.failed ? "fail" : "ok"}">${gate.failed ? ICONS.x : ICONS.check}</span>
        <b>PLEx / analyze</b><span>${gate.failed ? esc(gate.reasons[0]) : "passed"}</span></div>
      <div class="pr-status-row"><span class="s ok">${ICONS.check}</span><b>Code scanning / PLEx</b><span>${sarifCount} SARIF results uploaded</span></div>
      <div class="pr-status-row"><span class="s ok">${ICONS.check}</span><b>PLEx / fix --check</b><span>${fixCount} findings auto-fixable</span></div>
    </div>
    <div class="gh-comment">
      <div class="gh-comment-head"><img src="assets/img/logo.svg" alt="" /><b>plex-bot</b> commented · sticky comment, updated on every push</div>
      <div class="md">${renderMarkdown(outputs.comment)}</div>
    </div>`;
}

/* ----------------------------------------------------------------- rules */

function renderRules(bundle) {
  const fixable = new Set(bundle.fixable_rules);
  const rules = [...bundle.rules].sort(
    (a, b) => (a.stability === b.stability ? 0 : a.stability === "stable" ? -1 : 1) || sevRank(b.severity) - sevRank(a.severity),
  );
  $$('[data-stat="rules"]').forEach((el) => (el.textContent = rules.length));
  $$('[data-stat="fixers"]').forEach((el) => (el.textContent = fixable.size));
  let filter = "all";
  let expanded = false;
  const LIMIT = 12;

  const draw = () => {
    const q = $("#rule-q").value.trim().toLowerCase();
    const list = rules.filter(
      (r) =>
        (filter === "all" ||
          (filter === "fix" && fixable.has(r.id)) ||
          (filter === "high" && r.severity === "high") ||
          r.stability === filter) &&
        (!q || [r.id, r.name, r.description, ...(r.tags || [])].join(" ").toLowerCase().includes(q)),
    );
    const shown = expanded || q ? list : list.slice(0, LIMIT);
    $("#rule-grid").innerHTML = shown.length
      ? shown
          .map(
            (r) => `<article class="rule">
        <div class="rule-top"><span class="sev sev-${r.severity}">${r.severity}</span><div class="badges">
          ${fixable.has(r.id) ? '<span class="badge fix">auto-fix</span>' : ""}
          <span class="badge ${r.stability === "experimental" ? "exp" : ""}">${r.stability}</span></div></div>
        <code>${esc(r.id)}</code>
        <h3>${esc(r.name)}</h3>
        <p>${esc(r.description)}</p>
        <div class="rule-tags">${(r.tags || [])
          .filter((t) => t !== "performance")
          .map((t) => `<span>${esc(t)}</span>`)
          .join("")}</div>
      </article>`,
          )
          .join("")
      : `<div class="rule-empty">No rules match “${esc(q)}”.</div>`;
    const more = $("#rule-more");
    more.hidden = Boolean(q) || list.length <= LIMIT;
    more.textContent = expanded ? "Show fewer" : `Show all ${list.length} rules`;
  };

  $("#rule-q").addEventListener("input", draw);
  $("#rule-filter").addEventListener("click", (e) => {
    const b = e.target.closest("[data-rf]");
    if (!b) return;
    filter = b.dataset.rf;
    $$("#rule-filter [data-rf]").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    draw();
  });
  $("#rule-more").addEventListener("click", () => {
    expanded = !expanded;
    draw();
    if (!expanded) $("#rules").scrollIntoView({ behavior: "smooth" });
  });
  draw();
}

/* ---------------------------------------------------------- integrations */

const SNIPPETS = {
  action: {
    file: ".github/workflows/plex.yml",
    lang: "yaml",
    text: `name: PLEx Performance Check

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write   # sticky PR comment
  checks: write          # check run + annotations
  security-events: write # SARIF code scanning

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # history for base comparison

      - name: Run PLEx
        uses: KOKUTBON/PLEx/action@main
        with:
          install: "true"
          stability: "stable"
          changed_only: "true"
          compare_base: "true"
          post_comment: "true"
          comment_out: "out/plex.comment.md"
          upload_sarif: "true"
          sarif_out: "out/plex.sarif"`,
  },
  precommit: {
    file: ".pre-commit-config.yaml",
    lang: "yaml",
    text: `repos:
  - repo: https://github.com/KOKUTBON/PLEx
    rev: v0.1.0  # use the latest release tag or a commit SHA
    hooks:
      # Rewrite safe performance issues in staged files
      - id: plex-fix

      # Validate .plex.yml when it changes
      - id: plex-config-validate

      # Gate on stable rules only
      - id: plex
        args: ["--stability", "stable", "--max-findings", "20"]`,
  },
  cli: {
    file: "terminal",
    lang: "sh",
    text: `# Scaffold a config and analyze the repository
plex init --preset minimal
plex analyze . --json out/plex.json --sarif out/plex.sarif

# Compare against main and fail on regressions
plex analyze . --compare-base --base-ref origin/main --gating balanced

# Preview, then apply, safe rewrites
plex fix --diff --dry-run .
plex fix --rule plex.string-concat-in-loop src/

# Turn a JSON report into an HTML dashboard
plex report out/plex.json --format html --open

# Measure analysis throughput on this machine
plex benchmark . --iterations 3`,
  },
  config: {
    file: ".plex.yml",
    lang: "yaml",
    text: `include:
  - "src"
languages: ["python"]
rule_stability: "stable"

# Gate pull requests
compare_base: true
gating_preset: "balanced"
fail_on_finding_severity: "high"

# Stricter budgets for the hot path
risk_delta_budgets:
  - pattern: "src/core/**"
    budget: 0.5
loop_depth_fail_paths:
  - "src/core/**"

rule_severity_overrides:
  - rule_id: "plex.db-in-loop"
    severity: "high"`,
  },
  editor: {
    file: "settings.json",
    lang: "json",
    text: `{
  // VS Code extension (vscode/ in the repo)
  "plex.executablePath": "plex",
  "plex.analyzeOnSave": true,
  "plex.enableQuickFixes": true,
  "plex.extraArgs": ["--changed-only"]
}

// Any LSP client: run the language server over stdio
// $ plex lsp`,
  },
};

function hlSnippet({ text, lang }) {
  return text
    .split("\n")
    .map((line) => {
      if (lang === "sh") {
        if (/^\s*#/.test(line)) return `<span class="y-com">${esc(line)}</span>`;
        return esc(line)
          .replace(/^(\s*)(plex)\b/, '$1<span class="sh-cmd">$2</span>')
          .replace(/(\s)(--?[\w-]+)/g, '$1<span class="sh-flag">$2</span>');
      }
      if (lang === "json") {
        if (/^\s*\/\//.test(line)) return `<span class="y-com">${esc(line)}</span>`;
        return esc(line)
          .replace(/(&quot;[^&]*?&quot;)(\s*:)/g, '<span class="y-key">$1</span>$2')
          .replace(/:\s*(&quot;[^&]*?&quot;)/g, ': <span class="y-str">$1</span>')
          .replace(/\b(true|false)\b/g, '<span class="tk-kw">$1</span>');
      }
      const m = line.match(/^(\s*-?\s*)([\w.-]+)(:)(.*)$/);
      const comment = (s) => esc(s).replace(/(\s#.*)$/, '<span class="y-com">$1</span>');
      if (/^\s*#/.test(line)) return `<span class="y-com">${esc(line)}</span>`;
      if (m)
        return `${esc(m[1])}<span class="y-key">${esc(m[2])}</span><span class="y-pun">:</span>${comment(m[4]).replace(
          /(&quot;[^&]*?&quot;|\bv\d[\w.]*)/g,
          '<span class="y-str">$1</span>',
        )}`;
      return comment(line).replace(/(&quot;[^&]*?&quot;)/g, '<span class="y-str">$1</span>');
    })
    .join("\n");
}

function initIntegrations() {
  let current = "action";
  const draw = () => {
    const s = SNIPPETS[current];
    $("#int-file").textContent = s.file;
    $("#int-pre").innerHTML = hlSnippet(s);
    $$("#int-tabs [data-int]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.int === current)));
  };
  $("#int-tabs").addEventListener("click", (e) => {
    const b = e.target.closest("[data-int]");
    if (!b) return;
    current = b.dataset.int;
    draw();
  });
  $("#int-copy").addEventListener("click", () => copyText(SNIPPETS[current].text, "Snippet copied"));
  draw();
}

/* ------------------------------------------------------------------ boot */

initIntegrations();
loadBundle("")
  .then((bundle) => {
    renderHero(bundle);
    renderPlayground(bundle);
    renderPR(bundle);
    renderRules(bundle);
  })
  .catch((err) => {
    console.error(err);
    $("#pg-finding").textContent = "Demo data failed to load.";
  });
