import * as cp from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

export type PLExFinding = {

  file?: string;
  lineno?: number;
  end_lineno?: number;
  severity?: string;
  risk_score?: number;
  complexity_hint?: string;
  explanation?: string;
  rule_id?: string;
  rule_name?: string;
  suggestions?: string[];
};

export type PLExRegression = {

  file?: string;
  lineno?: number;
  regression_severity?: string;
  risk_delta?: number;
  base_hint?: string;
  head_hint?: string;
  explanation?: string;
};

export type PLExReport = {
  findings?: PLExFinding[];
  regressions?: PLExRegression[];
};

export const FIXABLE_RULES = new Set([
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
  "plex.try-except-dict-get",
  "plex.try-except-pop-default",
  "plex.if-pass-else-invert",
  "plex.isinstance-tuple",
  "plex.itertools-islice",
  "plex.re-sub-literal",
  "plex.str-removeprefix-suffix",
  "plex.math-log-base",
  "plex.try-except-next-default",
  "plex.str-split-maxsplit",
  "plex.filter-truthy",
  "plex.all-in-superset",
]);

export function getDiagnosticRuleId(diagnostic: vscode.Diagnostic): string {
  if (!diagnostic.code) {
    return "";
  }
  if (typeof diagnostic.code === "object" && "value" in diagnostic.code) {
    return String(diagnostic.code.value);
  }
  return String(diagnostic.code);
}

function toLine(value: unknown): number {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    return 1;
  }
  return Math.floor(num);
}

function toRisk(value: unknown): string {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return "n/a";
  }
  return num.toFixed(3);
}

function toDelta(value: unknown): string {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return "n/a";
  }
  return num.toFixed(3);
}

function toSeverity(value: unknown): vscode.DiagnosticSeverity {
  const level = String(value || "").toLowerCase();
  if (level === "critical" || level === "high") {
    return vscode.DiagnosticSeverity.Error;
  }
  if (level === "medium") {
    return vscode.DiagnosticSeverity.Warning;
  }
  return vscode.DiagnosticSeverity.Information;
}

function resolveReportPath(): string | undefined {
  const config = vscode.workspace.getConfiguration("plex");
  const reportPath = config.get<string>("reportPath", "out/plex.json");
  if (!reportPath) {
    return undefined;
  }
  if (path.isAbsolute(reportPath)) {
    return reportPath;
  }
  const folders = vscode.workspace.workspaceFolders || [];
  for (const folder of folders) {
    const candidate = path.join(folder.uri.fsPath, reportPath);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  if (folders.length > 0) {
    return path.join(folders[0].uri.fsPath, reportPath);
  }
  return undefined;
}

function resolveSourcePath(filePath: string, folders: readonly vscode.WorkspaceFolder[]): string | undefined {
  if (!filePath) {
    return undefined;
  }
  if (path.isAbsolute(filePath)) {
    return filePath;
  }
  for (const folder of folders) {
    const candidate = path.join(folder.uri.fsPath, filePath);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  if (folders.length > 0) {
    return path.join(folders[0].uri.fsPath, filePath);
  }
  return undefined;
}

const RULES_DOC_URL = "https://github.com/KOKUTBON/PLEx/blob/main/docs/RULES.md";

function parseReport(raw: string): PLExReport {
  try {
    return JSON.parse(raw) as PLExReport;
  } catch (err) {
    throw new Error("Invalid PLEx JSON report.");
  }
}

function getWorkspaceRoot(uri?: vscode.Uri): string | undefined {
  if (uri) {
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    if (folder) {
      return folder.uri.fsPath;
    }
  }
  const folders = vscode.workspace.workspaceFolders || [];
  return folders.length > 0 ? folders[0].uri.fsPath : undefined;
}

function getExecutable(): string {
  const config = vscode.workspace.getConfiguration("plex");
  return config.get<string>("executablePath", "plex") || "plex";
}

export function buildDiagnostics(report: PLExReport): Map<string, vscode.Diagnostic[]> {
  const diagnosticsByFile = new Map<string, vscode.Diagnostic[]>();
  const folders = vscode.workspace.workspaceFolders || [];

  const add = (filePath: string | undefined, diagnostic: vscode.Diagnostic) => {
    if (!filePath) {
      return;
    }
    const list = diagnosticsByFile.get(filePath) || [];
    list.push(diagnostic);
    diagnosticsByFile.set(filePath, list);
  };

  for (const finding of report.findings || []) {
    const filePath = resolveSourcePath(String(finding.file || ""), folders);
    const line = toLine(finding.lineno);
    const endLine = toLine(finding.end_lineno ?? finding.lineno);
    const range = new vscode.Range(line - 1, 0, Math.max(line, endLine) - 1, 0);
    const hint = finding.complexity_hint || "Complexity hotspot";
    const risk = toRisk(finding.risk_score);
    let message = `PLEx hotspot: ${hint} (risk ${risk})`;
    if (finding.explanation) {
      message += `: ${finding.explanation}`;
    }
    const diagnostic = new vscode.Diagnostic(range, message, toSeverity(finding.severity));
    diagnostic.source = "plex";
    if (finding.rule_id) {
      diagnostic.code = {
        value: finding.rule_id,
        target: vscode.Uri.parse(RULES_DOC_URL),
      };
    }
    add(filePath, diagnostic);
  }

  for (const regression of report.regressions || []) {
    const filePath = resolveSourcePath(String(regression.file || ""), folders);
    const line = toLine(regression.lineno);
    const range = new vscode.Range(line - 1, 0, line - 1, 0);
    const baseHint = regression.base_hint || "n/a";
    const headHint = regression.head_hint || "n/a";
    const delta = toDelta(regression.risk_delta);
    let message = `PLEx regression: ${baseHint} -> ${headHint} (risk +${delta})`;
    if (regression.explanation) {
      message += `: ${regression.explanation}`;
    }
    const diagnostic = new vscode.Diagnostic(
      range,
      message,
      toSeverity(regression.regression_severity),
    );
    diagnostic.source = "plex";
    add(filePath, diagnostic);
  }

  return diagnosticsByFile;
}

function applyReport(collection: vscode.DiagnosticCollection, reportFile: string): void {
  const report = parseReport(fs.readFileSync(reportFile, "utf-8"));
  collection.clear();
  for (const [filePath, diagnostics] of buildDiagnostics(report)) {
    collection.set(vscode.Uri.file(filePath), diagnostics);
  }
}

/**
 * Load diagnostics from the configured report. When `interactive` is true and the
 * report does not exist, the user is asked to pick a report file; background loads
 * (startup, after analysis, configuration changes) never open dialogs.
 */
async function loadReport(collection: vscode.DiagnosticCollection, interactive: boolean): Promise<boolean> {
  const reportPath = resolveReportPath();
  if (!reportPath) {
    if (interactive) {
      vscode.window.showErrorMessage("PLEx: no workspace folder or report path configured.");
    }
    return false;
  }
  let reportFile: string | undefined = reportPath;
  if (!fs.existsSync(reportPath)) {
    if (!interactive) {
      return false;
    }
    const pick = await vscode.window.showOpenDialog({
      title: "Select PLEx JSON report",
      canSelectMany: false,
      filters: { "PLEx report": ["json"] },
    });
    reportFile = pick && pick.length > 0 ? pick[0].fsPath : undefined;
    if (!reportFile) {
      return false;
    }
  }
  try {
    applyReport(collection, reportFile);
    return true;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`PLEx: failed to load report ${reportFile}: ${message}`);
    return false;
  }
}

function runCli(executable: string, args: string[], cwd: string | undefined): Promise<{ error: cp.ExecFileException | null; stdout: string; stderr: string }> {
  return new Promise(resolve => {
    cp.execFile(executable, args, { cwd, maxBuffer: 32 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({ error, stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

function describeCliError(error: cp.ExecFileException, stderr: string): string {
  if ((error as NodeJS.ErrnoException).code === "ENOENT") {
    return `could not find the PLEx CLI ("${error.path || getExecutable()}"). Install it with "pip install git+https://github.com/KOKUTBON/PLEx.git" or set "plex.executablePath".`;
  }
  const detail = stderr.trim().split(/\r?\n/).filter(Boolean).pop();
  return detail || error.message;
}

const SUPPORTED_EXTENSIONS = new Set([
  ".py",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".go",
  ".java",
  ".kt",
]);

export class PLExQuickFixProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
    vscode.CodeActionKind.SourceFixAll,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const config = vscode.workspace.getConfiguration("plex");
    const enableQuickFixes = config.get<boolean>("enableQuickFixes", true);

    const fixableDiagnostics: vscode.Diagnostic[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "plex") {
        continue;
      }

      const ruleId = getDiagnosticRuleId(diagnostic);

      // 1. Automated AST Quick-Fix if rule is fixable
      if (enableQuickFixes && ruleId && FIXABLE_RULES.has(ruleId)) {
        fixableDiagnostics.push(diagnostic);
        const autoFix = new vscode.CodeAction(
          `PLEx: Automatically fix '${ruleId}'`,
          vscode.CodeActionKind.QuickFix
        );
        autoFix.diagnostics = [diagnostic];
        autoFix.isPreferred = true;
        autoFix.command = {
          command: "plex.applyFix",
          title: `PLEx: Fix '${ruleId}'`,
          arguments: [document.uri, ruleId],
        };
        actions.push(autoFix);
      }

      // 2. Inline ignore comment
      const ignoreFix = new vscode.CodeAction(
        ruleId ? `PLEx: Add inline ignore comment for ${ruleId}` : "PLEx: Add inline ignore comment",
        vscode.CodeActionKind.QuickFix
      );
      ignoreFix.diagnostics = [diagnostic];
      const edit = new vscode.WorkspaceEdit();
      const line = document.lineAt(diagnostic.range.start.line);
      const indent = line.text.match(/^\s*/)?.[0] || "";
      const commentPrefix = document.languageId === "python" ? "#" : "//";
      const ruleSpec = ruleId ? `[${ruleId}]` : "";
      const text = `${indent}${commentPrefix} plex: ignore${ruleSpec} reason="reviewed"\n`;
      edit.insert(document.uri, new vscode.Position(diagnostic.range.start.line, 0), text);
      ignoreFix.edit = edit;
      actions.push(ignoreFix);
    }

    // 3. Fix all issues in this file action
    if (enableQuickFixes && fixableDiagnostics.length > 0) {
      const fixAll = new vscode.CodeAction(
        "PLEx: Fix all auto-fixable issues in this file",
        vscode.CodeActionKind.SourceFixAll
      );
      fixAll.diagnostics = fixableDiagnostics;
      fixAll.command = {
        command: "plex.fixCurrentFile",
        title: "PLEx: Fix All Violations in Current File",
        arguments: [document.uri],
      };
      actions.push(fixAll);
    }

    return actions;
  }
}

let analysisRunning = false;
let analysisQueued = false;

export async function runAnalysis(collection: vscode.DiagnosticCollection): Promise<void> {
  const root = getWorkspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("PLEx: No workspace folder open.");
    return;
  }
  // Coalesce overlapping requests (e.g. several quick saves) into one follow-up run.
  if (analysisRunning) {
    analysisQueued = true;
    return;
  }
  analysisRunning = true;
  try {
    do {
      analysisQueued = false;
      await runAnalysisOnce(collection, root);
    } while (analysisQueued);
  } finally {
    analysisRunning = false;
  }
}

async function runAnalysisOnce(collection: vscode.DiagnosticCollection, root: string): Promise<void> {
  const config = vscode.workspace.getConfiguration("plex");
  const reportRelPath = config.get<string>("reportPath", "out/plex.json") || "out/plex.json";
  const extraArgs = config.get<string[]>("extraArgs", ["--changed-only"]) || [];
  const reportFile = path.isAbsolute(reportRelPath) ? reportRelPath : path.join(root, reportRelPath);
  const args = ["analyze", ".", "--json", reportFile, ...extraArgs];
  const startedAt = Date.now();

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: "PLEx: Running analysis..." },
    async () => {
      const { error, stderr } = await runCli(getExecutable(), args, root);
      // A non-zero exit code is expected when quality gates fail; the report is still written.
      const fresh = fs.existsSync(reportFile) && fs.statSync(reportFile).mtimeMs >= startedAt - 1000;
      if (fresh) {
        try {
          applyReport(collection, reportFile);
          vscode.window.setStatusBarMessage("PLEx: Analysis completed.", 4000);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          vscode.window.showErrorMessage(`PLEx: failed to load report: ${message}`);
        }
        return;
      }
      if (error) {
        vscode.window.showErrorMessage(`PLEx analysis error: ${describeCliError(error, stderr)}`);
      }
    }
  );
}

export async function applyFix(
  collection: vscode.DiagnosticCollection,
  fileUri?: vscode.Uri,
  ruleId?: string
): Promise<void> {
  const targetUri = fileUri || vscode.window.activeTextEditor?.document.uri;
  if (!targetUri) {
    vscode.window.showWarningMessage("PLEx: No target file to fix.");
    return;
  }

  // Save document if dirty so the CLI sees the latest contents.
  const doc = vscode.workspace.textDocuments.find(d => d.uri.fsPath === targetUri.fsPath);
  if (doc && doc.isDirty) {
    await doc.save();
  }

  const args = ["fix", targetUri.fsPath];
  if (ruleId) {
    args.push("--rule", ruleId);
  }

  const title = ruleId ? `PLEx: Applying fix for ${ruleId}...` : "PLEx: Applying fixes...";
  const { error, stdout, stderr } = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title },
    () => runCli(getExecutable(), args, getWorkspaceRoot(targetUri))
  );
  if (error) {
    vscode.window.showErrorMessage(`PLEx fix error: ${describeCliError(error, stderr)}`);
    return;
  }
  const msg = stdout.trim() || `PLEx: Completed fixes on ${path.basename(targetUri.fsPath)}.`;
  vscode.window.showInformationMessage(msg);
  await runAnalysis(collection);
}

export async function fixWorkspace(collection: vscode.DiagnosticCollection): Promise<void> {
  const root = getWorkspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("PLEx: No workspace folder open.");
    return;
  }
  const choice = await vscode.window.showWarningMessage(
    "PLEx will rewrite files across the workspace to apply all automated fixes. Continue?",
    { modal: true },
    "Fix Workspace"
  );
  if (choice !== "Fix Workspace") {
    return;
  }
  await vscode.workspace.saveAll(false);

  const { error, stdout, stderr } = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: "PLEx: Applying fixes across workspace..." },
    () => runCli(getExecutable(), ["fix", "."], root)
  );
  if (error) {
    vscode.window.showErrorMessage(`PLEx workspace fix error: ${describeCliError(error, stderr)}`);
    return;
  }
  const msg = stdout.trim() || "PLEx: Completed workspace fixes.";
  vscode.window.showInformationMessage(msg);
  await runAnalysis(collection);
}

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection("plex");
  context.subscriptions.push(collection);

  context.subscriptions.push(
    vscode.commands.registerCommand("plex.loadReport", async () => {
      await loadReport(collection, true);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("plex.clearDiagnostics", () => {
      collection.clear();
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("plex.runAnalysis", async () => {
      await runAnalysis(collection);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("plex.applyFix", async (uri?: vscode.Uri, ruleId?: string) => {
      await applyFix(collection, uri, ruleId);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("plex.fixCurrentFile", async (uri?: vscode.Uri) => {
      await applyFix(collection, uri);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("plex.fixWorkspace", async () => {
      await fixWorkspace(collection);
    }),
  );

  const filter: vscode.DocumentFilter[] = [
    { language: "python" },
    { language: "javascript" },
    { language: "typescript" },
    { language: "javascriptreact" },
    { language: "typescriptreact" },
    { language: "go" },
    { language: "java" },
    { language: "kotlin" },
  ];

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(filter, new PLExQuickFixProvider(), {
      providedCodeActionKinds: PLExQuickFixProvider.providedCodeActionKinds,
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async doc => {
      const config = vscode.workspace.getConfiguration("plex");
      if (!config.get<boolean>("analyzeOnSave", true)) {
        return;
      }
      const ext = path.extname(doc.uri.fsPath);
      if (SUPPORTED_EXTENSIONS.has(ext)) {
        await runAnalysis(collection);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(event => {
      if (event.affectsConfiguration("plex")) {
        const config = vscode.workspace.getConfiguration("plex");
        if (config.get<boolean>("autoLoad", true)) {
          void loadReport(collection, false);
        }
      }
    }),
  );

  const config = vscode.workspace.getConfiguration("plex");
  if (config.get<boolean>("autoLoad", true)) {
    void loadReport(collection, false);
  }
}

export function deactivate(): void {
  // VS Code disposes subscriptions automatically on deactivate.
}
