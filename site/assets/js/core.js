// PLEx site — shared helpers (no dependencies).

export const SEVERITIES = ["high", "medium", "low", "info"];
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export const sevRank = (s) => SEV_RANK[String(s || "info").toLowerCase()] ?? 0;

export const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/* ------------------------------------------------------------------ data */

let bundlePromise;
export function loadBundle(base = "") {
  bundlePromise ??= fetch(`${base}assets/data/demo.json`, { cache: "no-cache" }).then((r) => {
    if (!r.ok) throw new Error(`Failed to load demo data (${r.status})`);
    return r.json();
  });
  return bundlePromise;
}

export const findingKey = (f) => `${f.function_id || `${f.file}:${f.lineno}`}~${f.rule_id || "hint"}`;

export const isRule = (f) => Boolean(f.rule_id);

export function findingTitle(f) {
  if (f.rule_name) return f.rule_name;
  return (f.complexity_hint || "Complexity hotspot").replace(/^Rule:\s*/, "");
}

export const formatHint = (hint) =>
  String(hint || "")
    .replace(/\^2/g, "²")
    .replace(/\^3/g, "³");

/* ------------------------------------------------------------- highlight */

const PY_KW = new Set(
  "False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case".split(
    " ",
  ),
);
const PY_BI = new Set(
  "abs all any bool bytes dict enumerate filter float frozenset getattr hasattr int isinstance iter len list map max min next object open print range repr reversed round set sorted str sum super tuple type zip".split(
    " ",
  ),
);

const TOKEN_RE =
  /(#.*$)|([rRbBuUfF]{0,2}(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'))|(@[\w.]+)|(\b\d[\d_]*(?:\.\d+)?(?:e[+-]?\d+)?\b)|([A-Za-z_]\w*)|(==|!=|<=|>=|\*\*|\/\/|->|:=|[+\-*/%<>=&|^~])/gm;

/** Highlight one line of Python, returning HTML. */
export function highlightLine(line) {
  let out = "";
  let last = 0;
  let prevWord = "";
  TOKEN_RE.lastIndex = 0;
  for (const m of line.matchAll(TOKEN_RE)) {
    out += esc(line.slice(last, m.index));
    last = m.index + m[0].length;
    const [tok, com, str, dec, num, word, op] = m;
    if (com) out += `<span class="tk-com">${esc(tok)}</span>`;
    else if (str) out += `<span class="tk-str">${esc(tok)}</span>`;
    else if (dec) out += `<span class="tk-dec">${esc(tok)}</span>`;
    else if (num) out += `<span class="tk-num">${esc(tok)}</span>`;
    else if (word) {
      const next = line.slice(last).trimStart()[0];
      if (PY_KW.has(word)) out += `<span class="tk-kw">${tok}</span>`;
      else if (prevWord === "def" || prevWord === "class") out += `<span class="tk-fn">${tok}</span>`;
      else if (word === "self" || word === "cls") out += `<span class="tk-self">${tok}</span>`;
      else if (PY_BI.has(word) && next === "(") out += `<span class="tk-bi">${tok}</span>`;
      else if (next === "(") out += `<span class="tk-fn">${tok}</span>`;
      else out += tok;
      prevWord = word;
      continue;
    } else if (op) out += `<span class="tk-op">${esc(tok)}</span>`;
    prevWord = "";
  }
  return out + esc(line.slice(last));
}

export const highlightLines = (source) => String(source ?? "").replace(/\n$/, "").split("\n").map(highlightLine);

/* ------------------------------------------------------------------ diff */

export function parseDiff(text) {
  const lines = [];
  let a = 0;
  let b = 0;
  for (const raw of String(text).split("\n")) {
    if (raw.startsWith("---") || raw.startsWith("+++")) continue;
    const h = raw.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (h) {
      a = +h[1];
      b = +h[2];
      lines.push({ type: "hunk", text: raw });
    } else if (raw.startsWith("+")) lines.push({ type: "add", b: b++, text: raw.slice(1) });
    else if (raw.startsWith("-")) lines.push({ type: "del", a: a++, text: raw.slice(1) });
    else if (raw.startsWith(" ")) lines.push({ type: "ctx", a: a++, b: b++, text: raw.slice(1) });
  }
  return lines;
}

export function renderDiff(text, { hunks = true, numbers = true } = {}) {
  const rows = parseDiff(text)
    .filter((l) => hunks || l.type !== "hunk")
    .map((l) => {
      if (l.type === "hunk") return `<div class="diff-line hunk">${numbers ? esc(l.text) : "⋯"}</div>`;
      const mk = l.type === "add" ? "+" : l.type === "del" ? "−" : " ";
      return `<div class="diff-line ${l.type}"><span class="ln">${l.a ?? ""}</span><span class="ln">${
        l.b ?? ""
      }</span><span class="mk">${mk}</span><span>${highlightLine(l.text)}</span></div>`;
    });
  return `<div class="diff${numbers ? "" : " no-ln"}" role="region" aria-label="Unified diff">${rows.join("")}</div>`;
}

/* -------------------------------------------------------------- markdown */

function inlineMd(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<a href="$2" rel="noopener">$1</a>');
}

/** A deliberately small Markdown renderer covering what PLEx reports emit. */
export function renderMarkdown(md) {
  const lines = String(md).replace(/<!--[\s\S]*?-->/g, "").split("\n");
  const html = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      html.push(`<h${h[1].length}>${inlineMd(h[2])}</h${h[1].length}>`);
      i++;
      continue;
    }
    if (line.trim().startsWith("|")) {
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) rows.push(lines[i++]);
      const cells = (r) => r.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const [head, , ...body] = rows;
      html.push(
        `<div class="table-wrap"><table><thead><tr>${cells(head)
          .map((c) => `<th>${inlineMd(c)}</th>`)
          .join("")}</tr></thead><tbody>${body
          .map((r) => `<tr>${cells(r).map((c) => `<td>${inlineMd(c)}</td>`).join("")}</tr>`)
          .join("")}</tbody></table></div>`,
      );
      continue;
    }
    if (/^\s*[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*[-*]\s+/, ""));
      html.push(`<ul>${items.map((t) => `<li>${inlineMd(t)}</li>`).join("")}</ul>`);
      continue;
    }
    if (line.startsWith(">")) {
      const quote = [];
      while (i < lines.length && lines[i].startsWith(">")) quote.push(lines[i++].replace(/^>\s?/, ""));
      html.push(`<blockquote>${inlineMd(quote.join(" "))}</blockquote>`);
      continue;
    }
    const para = [];
    while (i < lines.length && lines[i].trim() && !/^(#|\||>|\s*[-*]\s)/.test(lines[i])) para.push(lines[i++]);
    html.push(`<p>${inlineMd(para.join(" "))}</p>`);
  }
  return html.join("");
}

/* ---------------------------------------------------------------- gating */

// Mirrors plex.cli._GATING_PRESETS and the gate evaluators in src/plex/cli.py.
export const GATING_PRESETS = {
  strict: {
    fail_on_regressions: true,
    fail_on_severity: "medium",
    max_regressions: 0,
    max_high_regressions: 0,
    max_risk_delta: 0.2,
    risk_delta_budget: 0.5,
  },
  balanced: {
    fail_on_regressions: false,
    fail_on_severity: "high",
    max_regressions: 1,
    max_high_regressions: 0,
    max_risk_delta: 0.5,
    risk_delta_budget: 1.0,
  },
  relaxed: {
    fail_on_regressions: false,
    fail_on_severity: null,
    max_regressions: 3,
    max_high_regressions: 1,
    max_risk_delta: 1.0,
    risk_delta_budget: 3.0,
  },
};

export function evaluateGate(report, policy) {
  const reasons = [];
  const regs = report.regressions || [];
  const findings = report.findings || [];
  const regSev = regs.map((r) => r.regression_severity || "info");
  const fmt = (n) => Number(n).toFixed(3);

  if (report.regression_mode && regs.length) {
    if (policy.fail_on_regressions) reasons.push(`regressions detected (${regs.length})`);
    if (policy.max_regressions != null && regs.length > policy.max_regressions)
      reasons.push(`regressions ${regs.length} > max_regressions ${policy.max_regressions}`);
    if (policy.fail_on_severity && regSev.some((s) => sevRank(s) >= sevRank(policy.fail_on_severity)))
      reasons.push(`regressions at or above severity ${policy.fail_on_severity}`);
    const high = regSev.filter((s) => sevRank(s) >= sevRank("high")).length;
    if (policy.max_high_regressions != null && high > policy.max_high_regressions)
      reasons.push(`high regressions ${high} > max_high_regressions ${policy.max_high_regressions}`);
    const worst = Math.max(...regs.map((r) => r.risk_delta || 0));
    if (policy.max_risk_delta != null && worst > policy.max_risk_delta)
      reasons.push(`max risk_delta ${fmt(worst)} > ${fmt(policy.max_risk_delta)}`);
    const total = regs.reduce((t, r) => t + Math.max(0, r.risk_delta || 0), 0);
    if (policy.risk_delta_budget != null && total > policy.risk_delta_budget)
      reasons.push(`risk_delta budget ${fmt(total)} > ${fmt(policy.risk_delta_budget)}`);
  }
  if (policy.max_findings != null && findings.length > policy.max_findings)
    reasons.push(`findings ${findings.length} > max_findings ${policy.max_findings}`);
  if (policy.fail_on_finding_severity && findings.some((f) => sevRank(f.severity) >= sevRank(policy.fail_on_finding_severity)))
    reasons.push(`findings at or above severity ${policy.fail_on_finding_severity}`);
  if (policy.max_risk_score != null && findings.length) {
    const worst = Math.max(...findings.map((f) => f.risk_score || 0));
    if (worst > policy.max_risk_score) reasons.push(`max risk_score ${fmt(worst)} > ${fmt(policy.max_risk_score)}`);
  }
  return { failed: reasons.length > 0, reasons };
}

export function policyToFlags(policy, preset) {
  const flags = [];
  if (preset && preset !== "custom" && preset !== "off") flags.push(`--gating ${preset}`);
  else if (preset === "custom") {
    if (policy.fail_on_regressions) flags.push("--fail-on-regressions");
    if (policy.fail_on_severity) flags.push(`--fail-on-severity ${policy.fail_on_severity}`);
    if (policy.max_regressions != null) flags.push(`--max-regressions ${policy.max_regressions}`);
    if (policy.max_high_regressions != null) flags.push(`--max-high-regressions ${policy.max_high_regressions}`);
    if (policy.max_risk_delta != null) flags.push(`--max-risk-delta ${policy.max_risk_delta}`);
    if (policy.risk_delta_budget != null) flags.push(`--risk-delta-budget ${policy.risk_delta_budget}`);
  }
  if (policy.fail_on_finding_severity) flags.push(`--fail-on-finding-severity ${policy.fail_on_finding_severity}`);
  if (policy.max_findings != null) flags.push(`--max-findings ${policy.max_findings}`);
  if (policy.max_risk_score != null) flags.push(`--max-risk-score ${policy.max_risk_score}`);
  return flags;
}

/* ------------------------------------------------------------- utilities */

export function toast(message) {
  let el = document.querySelector(".toast");
  if (!el) {
    el = document.createElement("div");
    el.className = "toast";
    el.setAttribute("role", "status");
    document.body.append(el);
  }
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove("show"), 1800);
}

export async function copyText(text, label = "Copied to clipboard") {
  try {
    await navigator.clipboard.writeText(text);
    toast(label);
  } catch {
    toast("Copy failed — select the text manually");
  }
}

export function download(filename, content, type = "application/json") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const THEME_KEY = "plex-theme";
export function initTheme(button) {
  const root = document.documentElement;
  let saved = null;
  try {
    saved = localStorage.getItem(THEME_KEY);
  } catch {}
  if (saved) root.dataset.theme = saved;
  const current = () =>
    root.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const sync = () => button?.setAttribute("aria-label", `Switch to ${current() === "dark" ? "light" : "dark"} theme`);
  sync();
  button?.addEventListener("click", () => {
    root.dataset.theme = current() === "dark" ? "light" : "dark";
    try {
      localStorage.setItem(THEME_KEY, root.dataset.theme);
    } catch {}
    sync();
  });
  return { toggle: () => button?.click() };
}

export const ICONS = {
  github:
    '<svg class="icon" viewBox="0 0 24 24" style="fill:currentColor;stroke:none"><path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.87-1.37-3.87-1.37-.53-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.04 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.58.23 2.75.11 3.04.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.38-5.26 5.67.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z"/></svg>',
  theme:
    '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9Z"/></svg>',
  copy: '<svg class="icon" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>',
  search: '<svg class="icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>',
  arrow: '<svg class="icon" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  check: '<svg class="icon" viewBox="0 0 24 24"><path d="m5 12 5 5 9-10"/></svg>',
  x: '<svg class="icon" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg>',
  upload: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 16V4m0 0-5 5m5-5 5 5M4 20h16"/></svg>',
  download: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 4v12m0 0 5-5m-5 5-5-5M4 20h16"/></svg>',
  file: '<svg class="icon" viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>',
  wand: '<svg class="icon" viewBox="0 0 24 24"><path d="m15 4 1 2 2 1-2 1-1 2-1-2-2-1 2-1zM4 20 14 10"/></svg>',
  bolt: '<svg class="icon" viewBox="0 0 24 24"><path d="M13 2 4 14h7l-1 8 9-12h-7z"/></svg>',
  filter: '<svg class="icon" viewBox="0 0 24 24"><path d="M4 5h16l-6 8v6l-4-2v-4z"/></svg>',
  shield: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6z"/></svg>',
  branch:
    '<svg class="icon" viewBox="0 0 24 24"><circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="8" r="2"/><path d="M6 7v10M18 10c0 4-6 3-11 7"/></svg>',
};
