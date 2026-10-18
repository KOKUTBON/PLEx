# 0006 Native active application testing (PLEx Validate)

- Status: accepted
- Date: 2026-10-16
- Plan: [PLEx 2.0, section 8](../PLEx-2.0-PLAN.md)
- Related: [Native platform ownership](0003-native-platform-ownership.md), [Engine isolation model](0002-engine-isolation-model.md)

## Context

Previous proposals envisioned wrapping external dynamic security scanners (such as Strix).
However, a detailed architectural review revealed critical security weaknesses in external wrappers:
- Prompt-only scoping without technical runtime network boundaries.
- Writable target mounts and arbitrary host egress permissions (`NET_ADMIN/NET_RAW`).
- Credential leaks via persisted config files (`~/.strix/cli-config.json`).
- Non-deterministic agent loops without source-to-route correlation or verifiable replayability.

Per ADR 0003, PLEx owns active application testing natively within the project: **PLEx Validate**.
The goal is to provide a capability comparable to and significantly better than Strix, built with
hard technical scope enforcement, deterministic reproduction recipes, and verifiable evidence.

## Decision

Introduce the PLEx Validate subsystem (`src/plex/validate/`) with the following architectural invariants:

### 1. Hard Technical Scope Guardrails
- Network egress is enforced technically by `ScopedHttpClient`, not by LLM prompts.
- All requests are strictly constrained by `NetworkScope`:
  - Allowed destination hostnames and ports.
  - Automatic blocking of cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`), multicast, and reserved ranges.
  - Strict requests-per-second rate limiter (`rate_limit_rps`).
  - Request budget ceiling (`max_requests`) and wall-clock execution watchdog (`max_wall_time_seconds`).

### 2. Authorization Verification
- Active testing refuses execution without an explicit `AuthorizationRecord` (e.g., `AUTHORIZATION.md`).
- Authorization mandates approving party identity, authorized target URLs/paths, and expiration.
- Non-local endpoints additionally require a recorded operator identity (`--operator`).

### 3. Static Route Discovery, OpenAPI/Swagger Intake, and JS/TS Support
- Native AST visitors discover routes and HTTP methods across major Python web frameworks:
  - Flask: `@app.route()`, `@blueprint.route()`.
  - FastAPI: `@app.get()`, `@app.post()`, `@router.*`.
  - Django: `urlpatterns = [path(), re_path()]`.
- JavaScript & TypeScript route discovery:
  - Express.js and Fastify: `app.get()`, `router.post()`, `fastify.get()`.
  - Next.js: App Router (`app/**/route.ts`) and Pages Router (`pages/api/**/*.ts`).
- OpenAPI / Swagger specification intake (`parse_openapi_spec`):
  - Direct ingestion of OpenAPI 3.0/3.1 and Swagger 2.0 specifications in JSON or YAML.
  - Automatic parameter extraction (`parameters`) for route-guided probe synthesis.
- Source findings (such as xBOUNDARY SQL injection, command injection, and path traversal) are
  automatically linked to reachable endpoints via file and line proximity.

### 4. Deterministic Reproduction Recipes (Zero Mandatory LLM)
- Build repeatable, zero-LLM reproduction recipes that run reliably in CI/CD:
  - `SQLInjectionRecipe`: Compares baseline responses against syntax-breaking quotes and boolean truth/false probes (`' OR '1'='1` vs `' AND '1'='2`). Detects database error patterns.
  - `CommandInjectionRecipe`: Verifies benign test canary reflections across command separators.
  - `PathTraversalRecipe`: Verifies directory traversal signatures (`root:x:`, `/bin/sh`).
  - `RoleMatrixRecipe`: Verifies authentication and tenant isolation boundaries against unauthenticated and forged roles.
  - `TenantIsolationRecipe`: Verifies broken object-level access boundaries between distinct tenants.

### 5. Content-Addressed HTTP Evidence
- Every probe and response is captured as an `HttpExchange` with automatic header redaction (`Authorization`, `Cookie`, tokens).
- Content-addressed SHA-256 digests attach to `EvidenceRef(kind="http_exchange")` and store into `EvidenceStore`.
- Hypotheses that reproduce successfully become `AnalysisFinding(status="verified", confidence="observed")`.
- Hypotheses that do not reproduce retain counterevidence with `status="inconclusive"` or `status="refuted"`.

### 6. CLI Integration
- Accessible via:
  ```bash
  plex validate --target <url> --authorize <file> [--repo <path>] [--spec <file>] [--operator <id>] [--fail-on-verified]
  ```

## Consequences

- Full dynamic verification is achieved without external dependencies, Node, Docker sockets, or third-party agent packages.
- CI/CD can run deterministic active reproduction recipes against local fixture apps in safe, disposable environments.
- High-confidence verification links source taint flows to observable HTTP exploitability.
- Multi-framework support covers Python, Express, Fastify, Next.js, and standard OpenAPI/Swagger specifications.
