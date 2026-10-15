# PLEx Validate Guide (Native Active Application Testing)

PLEx Validate is PLEx 2.0's native active testing and vulnerability reproduction engine.
It confirms or refutes security hypotheses by executing scoped, repeatable HTTP test recipes
against authorized local or staging targets.

```
┌─────────────────────────────────┐
│  xBOUNDARY Source Findings      │
│  (SQLi, Cmd Injection, Path Tr) │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│     Static Route Discovery      │  Discovers endpoints from Flask, FastAPI,
│      (src/plex/validate/routes) │  and Django source code
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│      Validation Hypotheses      │  Links findings to reachable HTTP routes
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│   Technical Scope Guardrails    │  - Destination allowlist
│     (ScopedHttpClient)          │  - Cloud metadata blocked (169.254.169.254)
└────────────────┬────────────────┘  - Rate limits & request budgets
                 │
                 ▼
┌─────────────────────────────────┐
│ Deterministic Test Recipes      │  - SQLInjectionRecipe
│ (src/plex/validate/recipes/)    │  - CommandInjectionRecipe
└────────────────┬────────────────┘  - PathTraversalRecipe / RoleMatrixRecipe
                 │
                 ▼
┌─────────────────────────────────┐
│ PLExReport (v8 JSON / SARIF)    │  Findings upgraded to status="verified"
│  + Redacted HttpExchange Proof  │  with content-addressed EvidenceRef
└─────────────────────────────────┘
```

## Core Security Invariants

1. **Hard Technical Scope Enforcement:**
   Requests cannot stray outside authorized hosts and ports. Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`), multicast, and reserved ranges are strictly blocked by `ScopedHttpClient`.
2. **Hard Authorization Gate:**
   Tests refuse to run without an explicit `--authorize <AUTHORIZATION.md>` file.
3. **Zero Mandatory LLM:**
   Supported test recipes (SQLi, command injection, path traversal, access control) are deterministic, repeatable, and fast.
4. **Credential & Evidence Hygiene:**
   All HTTP request/response headers (`Authorization`, `Cookie`, `X-Api-Key`) are redacted before evidence is stored.

## Usage

### 1. Creating an Authorization Document
Create an `AUTHORIZATION.md` file in your repository:
```markdown
# Scope Authorization
- Authorized By: security-auditor@example.com
- Targets: http://127.0.0.1:5000, http://localhost:8000
- Allowed Tests: all
- Operator: local-dev
```

### 2. Running Active Validation
Run active tests against a local test instance:
```bash
plex validate --target http://127.0.0.1:5000 --authorize ./AUTHORIZATION.md
```

### 3. Correlating with Source Code Routes
Pass `--repo .` to automatically discover Flask, FastAPI, and Django routes from source:
```bash
plex validate --target http://127.0.0.1:5000 --authorize ./AUTHORIZATION.md --repo .
```

### 4. CI/CD Gate on Verified Vulnerabilities
Fail the build if any vulnerability is actively reproduced:
```bash
plex validate --target http://127.0.0.1:5000 --authorize ./AUTHORIZATION.md --fail-on-verified
```

### 5. Report Formats
Export findings and evidence to JSON or SARIF:
```bash
plex validate --target http://127.0.0.1:5000 --authorize ./AUTHORIZATION.md --format json -o validation.json
plex validate --target http://127.0.0.1:5000 --authorize ./AUTHORIZATION.md --format sarif -o validation.sarif
```
