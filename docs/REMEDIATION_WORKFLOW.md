# PLEx Remediation & Verification Workflow

PLEx integrates static code intelligence, API route discovery, active runtime validation, and verified remediation into a unified workflow.

## The Section 3 Integrated Lifecycle

```
[Source Repository]
        │
        ▼ (xBOUNDARY)
[Static Findings] ──────────► [AST Route Discovery]
        │                               │
        │                               ▼
        │                      [Reachable Endpoints]
        │                               │
        │                               ▼ (PLEx Validate)
        └─────────────────────► [Active Reproduction]
                                        │
                                        ▼ (PLEx Repair)
                                [Patch Candidate]
                                        │
                                        ▼ (Verification Runner)
                        ┌───────────────────────────────┐
                        │ 1. Syntax Valid (py_compile)  │
                        │ 2. Security Cleared (rescan)  │
                        │ 3. Active Exploit Blocked     │
                        │ 4. No Perf Regressions        │
                        │ 5. Functional Tests Pass      │
                        └───────────────┬───────────────┘
                                        ▼
                        [Verified Patch Applied / Graph]
```

## CLI Usage

### 1. Dry Run / Inspection of Remediation Plan

Inspect detected vulnerabilities, mapped routes, proposed patch candidates, and verification status:

```bash
plex remediate path/to/repo --diff
```

### 2. Output Full Audit Trail to JSON & ProjectGraph

```bash
plex remediate path/to/repo --json --out-graph graph.json
```

### 3. Verification with Functional Tests

Run project test suites inside the isolated verification workspace:

```bash
plex remediate path/to/repo --test-cmd "pytest tests/test_app.py"
```

### 4. Applying Verified Patches

Transactionally apply all verified patches to the repository:

```bash
plex remediate path/to/repo --apply
```

Note: If any verification check fails, `--apply` refuses to modify the repository and leaves the working tree untouched.

---

## Supported Native Automated Fixers

PLEx includes deterministic AST-based repair fixers that produce exact, syntax-checked patch candidates without probabilistic LLM hallucination:

1. **`SQLParameterizeFixer` (`xbnd.sql-injection` / CWE-89)**:
   - Detects dynamic SQL string formatting (f-strings, `.format()`, `%` formatting, concatenations) passed to DB-API execution methods (`execute`, `executemany`, `raw`).
   - Converts strings into parameterized query structures with parameter tuples or dictionaries.

2. **`CommandArrayFixer` (`xbnd.command-injection` / CWE-78)**:
   - Identifies dynamic command strings invoked via `subprocess.run`, `Popen`, `call`, `check_call`, and `check_output`.
   - Parses tokens and variables into safe argument lists (using constant tokens and variable references), disabling or removing `shell=True`.

3. **`PathBoundaryFixer` (`xbnd.path-traversal` / CWE-22)**:
   - Detects untrusted user-controlled paths flowing into file opening and filesystem APIs (`open`, `Path`, `send_file`, `rmtree`, `copy`, `remove`, `unlink`).
   - Inserts boundary sanitization via `os.path.basename(...)`, automatically ensuring `import os` is present and preventing redundant wrapping.

