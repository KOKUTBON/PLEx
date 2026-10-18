"""Comprehensive unit and integration tests for JavaScript & TypeScript taint analysis and repair.

Covers:
1. Pure-Python lexical tokenizer (JsTsLexer).
2. Taint analysis across 8 vulnerability families:
   - SQL Injection (xbnd.sql-injection)
   - Command Injection (xbnd.command-injection)
   - Path Traversal (xbnd.path-traversal)
   - Code Eval (xbnd.eval-injection)
   - NoSQL Injection (xbnd.nosql-injection)
   - Open Redirect (xbnd.open-redirect)
   - Cross-Site Scripting (xbnd.xss)
   - Server-Side Request Forgery (xbnd.ssrf)
3. Safe patterns and false-positive prevention.
4. Deterministic repair fixers complying with Section 9 contracts:
   - JsSQLParameterizeFixer (auto_apply=True)
   - JsCommandArrayFixer (auto_apply=True)
   - JsPathBoundaryFixer (auto_apply=True)
   - JsOpenRedirectFixer (auto_apply=True)
   - JsNoSQLInjectionFixer (auto_apply=True)
   - JsCodeEvalFixer (auto_apply=False, proposal-only)
5. Repair verification runner and pure-Python JS/TS syntax checking.
6. RemediationCoordinator end-to-end integration for JS/TS projects.
"""

from __future__ import annotations

from pathlib import Path

from plex.repair.coordinator import RemediationCoordinator
from plex.repair.jsts import (
    JsCodeEvalFixer,
    JsCommandArrayFixer,
    JsNoSQLInjectionFixer,
    JsOpenRedirectFixer,
    JsPathBoundaryFixer,
    JsSQLParameterizeFixer,
    is_jsts_file,
)
from plex.repair.runner import RepairVerificationRunner, validate_jsts_syntax
from plex.security.jsts_taint import JsTsLexer, analyze_jsts_source

# ==============================================================================
# 1. Lexical Tokenizer Tests
# ==============================================================================


def test_jsts_lexer_basic_tokens() -> None:
    source = """
    // Line comment
    /* Multi-line
       comment */
    const greeting = "Hello world";
    let count = 42;
    `template ${user.name}`
    """
    tokens = JsTsLexer(source).tokenize()
    types = [t.type for t in tokens]
    assert "comment" in types
    assert "string" in types
    assert "number" in types
    assert "ident" in types
    assert "template" in types

    template_tokens = [t for t in tokens if t.type == "template"]
    assert len(template_tokens) == 1
    assert "user.name" in template_tokens[0].value


# ==============================================================================
# 2. Taint Analysis - All 8 Vulnerability Families
# ==============================================================================


def test_jsts_taint_sql_injection() -> None:
    src_concat = 'const q = "SELECT * FROM users WHERE id = " + req.query.id;\ndb.query(q);\n'
    findings_concat = analyze_jsts_source("app.js", src_concat)
    assert any(f.rule_id == "xbnd.sql-injection" for f in findings_concat)

    src_template = "db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);\n"
    findings_template = analyze_jsts_source("app.ts", src_template)
    assert any(f.rule_id == "xbnd.sql-injection" for f in findings_template)


def test_jsts_taint_command_injection() -> None:
    src = """
    const cp = require("child_process");
    app.get("/ping", (req, res) => {
        cp.exec("ping -c 1 " + req.query.host, (err, stdout) => {
            res.send(stdout);
        });
    });
    """
    findings = analyze_jsts_source("server.js", src)
    cmd_findings = [f for f in findings if f.rule_id == "xbnd.command-injection"]
    assert len(cmd_findings) >= 1
    assert cmd_findings[0].cwe == ["CWE-78"]
    assert cmd_findings[0].severity in ("critical", "high")


def test_jsts_taint_path_traversal() -> None:
    src_readfile = """
    const fs = require("fs");
    app.get("/download", (req, res) => {
        const file = req.query.file;
        fs.readFile(file, "utf8", (err, data) => res.send(data));
    });
    """
    findings = analyze_jsts_source("routes.js", src_readfile)
    assert any(f.rule_id == "xbnd.path-traversal" for f in findings)

    src_sendfile = "res.sendFile(req.query.path);\n"
    findings_send = analyze_jsts_source("routes.ts", src_sendfile)
    assert any(f.rule_id == "xbnd.path-traversal" for f in findings_send)


def test_jsts_taint_eval_injection() -> None:
    src = "const result = eval(req.query.formula);\n"
    findings = analyze_jsts_source("calc.js", src)
    eval_findings = [f for f in findings if f.rule_id == "xbnd.eval-injection"]
    assert len(eval_findings) >= 1
    assert eval_findings[0].cwe == ["CWE-95"]
    assert eval_findings[0].severity == "critical"


def test_jsts_taint_nosql_injection() -> None:
    src = """
    app.post("/login", async (req, res) => {
        const user = await db.collection("users").findOne(req.body);
        res.json(user);
    });
    """
    findings = analyze_jsts_source("auth.ts", src)
    nosql_findings = [f for f in findings if f.rule_id == "xbnd.nosql-injection"]
    assert len(nosql_findings) >= 1
    assert nosql_findings[0].cwe == ["CWE-943"]


def test_jsts_taint_open_redirect() -> None:
    src = """
    app.get("/logout", (req, res) => {
        const nextUrl = req.query.next;
        res.redirect(nextUrl);
    });
    """
    findings = analyze_jsts_source("auth.js", src)
    redir_findings = [f for f in findings if f.rule_id == "xbnd.open-redirect"]
    assert len(redir_findings) >= 1
    assert redir_findings[0].cwe == ["CWE-601"]


def test_jsts_taint_xss() -> None:
    src_send = "res.send('<h1>Welcome ' + req.query.name + '</h1>');\n"
    findings_send = analyze_jsts_source("view.js", src_send)
    assert any(f.rule_id == "xbnd.xss" for f in findings_send)

    src_innerhtml = "document.getElementById('content').innerHTML = req.query.html;\n"
    findings_html = analyze_jsts_source("client.tsx", src_innerhtml)
    assert any(f.rule_id == "xbnd.xss" for f in findings_html)


def test_jsts_taint_ssrf() -> None:
    src_fetch = "fetch(req.query.targetUrl);\n"
    findings_fetch = analyze_jsts_source("proxy.ts", src_fetch)
    assert any(f.rule_id == "xbnd.ssrf" for f in findings_fetch)

    src_axios = "axios.get(req.query.url);\n"
    findings_axios = analyze_jsts_source("proxy.js", src_axios)
    assert any(f.rule_id == "xbnd.ssrf" for f in findings_axios)


def test_jsts_taint_safe_patterns_no_false_positives() -> None:
    safe_src = """
    // Completely safe operations with literals and no untrusted inputs
    const sql = "SELECT id, name FROM users";
    db.query(sql);

    const safePath = "/static/styles.css";
    fs.readFile(safePath, "utf8", cb);

    res.redirect("/dashboard");

    res.send("<h1>Static Header</h1>");

    fetch("https://api.example.com/status");
    """
    findings = analyze_jsts_source("safe.js", safe_src)
    assert len(findings) == 0


# ==============================================================================
# 3. Deterministic Fixers Tests
# ==============================================================================


def test_is_jsts_file() -> None:
    assert is_jsts_file("foo.js") is True
    assert is_jsts_file("bar.ts") is True
    assert is_jsts_file("baz.tsx") is True
    assert is_jsts_file("qux.jsx") is True
    assert is_jsts_file("pkg.mjs") is True
    assert is_jsts_file("pkg.cjs") is True
    assert is_jsts_file("app.py") is False
    assert is_jsts_file("Dockerfile") is False


def test_js_sql_parameterize_fixer() -> None:
    fixer = JsSQLParameterizeFixer()
    src = 'db.query("SELECT * FROM users WHERE id = " + userId);\n'
    fixed, changes = fixer.fix(src, "db.js")
    assert len(changes) == 1
    assert 'db.query("SELECT * FROM users WHERE id = $1", [userId])' in fixed

    # Template literal in MySQL context
    src_mysql = '// mysql connection\ndb.query(`SELECT * FROM items WHERE code = ${itemCode}`);\n'
    fixed_mysql, changes_mysql = fixer.fix(src_mysql, "db.ts")
    assert len(changes_mysql) == 1
    assert 'db.query("SELECT * FROM items WHERE code = ?", [itemCode])' in fixed_mysql

    # Propose patch
    cand = fixer.propose_patch(src, "db.js", ("f-sql-1",))
    assert cand is not None
    assert cand.target_file == "db.js"
    assert cand.rule_id == "xbnd.sql-injection"
    assert "+db.query" in cand.diff
    assert "-db.query" in cand.diff


def test_js_command_array_fixer() -> None:
    fixer = JsCommandArrayFixer()
    src = 'const cp = require("child_process");\ncp.exec("git status " + target);\n'
    fixed, changes = fixer.fix(src, "deploy.js")
    assert len(changes) == 1
    assert 'cp.execFile("git", ["status", target]' in fixed

    cand = fixer.propose_patch(src, "deploy.js", ("f-cmd-1",))
    assert cand is not None
    assert cand.target_file == "deploy.js"
    assert cand.rule_id == "xbnd.command-injection"


def test_js_path_boundary_fixer() -> None:
    fixer = JsPathBoundaryFixer()
    src = 'const fs = require("fs");\nfs.readFile(filePath, "utf8", cb);\n'
    fixed, changes = fixer.fix(src, "reader.js")
    assert len(changes) == 1
    assert "_plexWithinBase" in fixed
    assert "fs.readFile(_plexWithinBase(__dirname, filePath), \"utf8\", cb)" in fixed

    cand = fixer.propose_patch(src, "reader.js", ("f-path-1",))
    assert cand is not None
    assert cand.target_file == "reader.js"
    assert cand.rule_id == "xbnd.path-traversal"


def test_js_open_redirect_fixer() -> None:
    fixer = JsOpenRedirectFixer()
    src = 'app.get("/go", (req, res) => {\n    res.redirect(targetUrl);\n});\n'
    fixed, changes = fixer.fix(src, "routes.js")
    assert len(changes) == 1
    assert "_plexSafeRedirect" in fixed
    assert "res.redirect(_plexSafeRedirect(targetUrl))" in fixed

    cand = fixer.propose_patch(src, "routes.js", ("f-redir-1",))
    assert cand is not None
    assert cand.target_file == "routes.js"


def test_js_nosql_injection_fixer() -> None:
    fixer = JsNoSQLInjectionFixer()
    src = 'const user = await users.findOne(filterQuery);\n'
    fixed, changes = fixer.fix(src, "repo.ts")
    assert len(changes) == 1
    assert "_plexRejectOperators" in fixed
    assert "users.findOne(_plexRejectOperators(filterQuery))" in fixed

    cand = fixer.propose_patch(src, "repo.ts", ("f-nosql-1",))
    assert cand is not None
    assert cand.target_file == "repo.ts"


def test_js_code_eval_fixer_is_proposal_only() -> None:
    fixer = JsCodeEvalFixer()
    assert fixer.auto_apply is False

    src = 'const data = eval(rawJsonString);\n'
    fixed, changes = fixer.fix(src, "parser.js")
    assert len(changes) == 1
    assert "JSON.parse(rawJsonString)" in fixed

    cand = fixer.propose_patch(src, "parser.js", ("f-eval-1",))
    assert cand is not None
    assert cand.confidence == "inferred"
    assert cand.risk == "medium"
    assert cand.preconditions == ("input must be valid JSON; proposal only",)


# ==============================================================================
# 4. Syntax Validation and Runner Tests
# ==============================================================================


def test_validate_jsts_syntax_valid() -> None:
    valid_js = """
    function greet(name) {
        const message = `Hello, ${name}!`;
        console.log(message);
        return { success: true, count: [1, 2, 3] };
    }
    """
    valid, err = validate_jsts_syntax(valid_js)
    assert valid is True
    assert err == ""


def test_validate_jsts_syntax_invalid_delimiters() -> None:
    # Unclosed bracket
    invalid_js = "const arr = [1, 2, 3;\n"
    valid, err = validate_jsts_syntax(invalid_js)
    assert valid is False
    assert "Mismatched" in err or "Unclosed" in err

    # Unclosed string
    unclosed_str = 'const s = "hello\n'
    valid_str, _ = validate_jsts_syntax(unclosed_str)
    assert valid_str is False


def test_repair_verification_runner_verifies_js_patch(tmp_path: Path) -> None:
    import sys

    target_file = tmp_path / "server.js"
    orig_src = 'db.query("SELECT * FROM users WHERE id = " + userId);\n'
    target_file.write_text(orig_src, encoding="utf-8")

    fixer = JsSQLParameterizeFixer()
    candidate = fixer.propose_patch(orig_src, "server.js", ("finding-1",))
    assert candidate is not None

    runner = RepairVerificationRunner()
    # Without test command: inconclusive
    rec_inconclusive = runner.verify(candidate, tmp_path)
    assert rec_inconclusive.status == "inconclusive"

    # With test command: verified
    record = runner.verify(
        candidate,
        tmp_path,
        test_command=[sys.executable, "-c", "pass"],
        check_performance=False,
    )
    assert record.status == "verified"
    syntax_check = next((c for c in record.verification.checks if c.name == "syntax_valid"), None)
    assert syntax_check is not None
    assert syntax_check.passed is True


# ==============================================================================
# 5. RemediationCoordinator End-to-End Integration for JS/TS Projects
# ==============================================================================


def test_remediation_coordinator_e2e_jsts(tmp_path: Path) -> None:
    import sys

    js_file = tmp_path / "app.js"
    js_file.write_text(
        """
        const cp = require("child_process");
        const express = require("express");
        const app = express();

        app.get("/ping", (req, res) => {
            cp.exec("ping -c 1 " + req.query.host, (err, out) => {
                res.send(out);
            });
        });
        """,
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(
        tmp_path,
        test_command=[sys.executable, "-c", "pass"],
        check_performance=False,
    )

    assert len(plan.findings) >= 1
    assert any(f.rule_id == "xbnd.command-injection" for f in plan.findings)

    # Candidate should be proposed and verified
    assert len(plan.candidates) >= 1
    assert any(c.target_file == "app.js" for c in plan.candidates)
    assert len(plan.repairs) >= 1
    assert any(r.status == "verified" for r in plan.repairs)
    assert len(plan.applicable_repairs) >= 1
