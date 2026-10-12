# 0002 Engine isolation and execution boundaries

- Status: proposed
- Date: 2026-10-11
- Issue: [#1](https://github.com/KOKUTBON/PLEx/issues/1)
- Plan: [PLEx 2.0, sections 5, 7, 8 and 13](../PLEx-2.0-PLAN.md)
- Related: [Unified finding schema](0001-unified-finding-schema.md)

## Context

PLEx performs static analysis by default. Its opt-in dynamic verifier currently
uses a subprocess with time and resource controls but inherits `os.environ`.
That can expose CI credentials to target code. A subprocess and resource limits
do not restrict filesystem or network access and are not a security sandbox.

The plan proposes external REA and Strix providers. Their reviewed versions have
different execution and persistence behaviors; recheck those assumptions when
implementing each adapter. Static binary parsers also process hostile inputs.
No external provider may gain trust just because it produces structured output.

This ADR defines requirements; it does not implement or claim containment today.

## Decision

Separate native analysis, target execution and external-tool execution behind a
`Sandbox` contract. Providers declare minimum capabilities and orchestrators
may strengthen controls but must refuse configurations that weaken required
boundaries. Isolation names describe mechanisms, not a guarantee of safety.

| Workload | Execution mode | Required boundary |
| --- | --- | --- |
| Bundled performance and xBOUNDARY static analysis | In process | Parse source without importing or executing target code |
| Existing opt-in dynamic verifier | Subprocess | Trusted targets only; explicit opt-in, timeout/resource limits, filtered environment |
| REA binary parsing | Container by default | Disposable sample directory, restricted filesystem, no target execution/network tools by default |
| Strix active testing | Container | Explicit authorization, disposable target copy, enforced target network scope and resource limits |

Rule/provider plugins are trusted executable Python code. Entry-point discovery
does not isolate them; loading a plugin requires explicit configuration and must
be documented as code execution. An in-process plugin must not claim container
isolation on the basis of a declaration.

### Preflight and failure behavior

Before execution, validate engine/version availability, required isolation,
authorization and budgets. Missing prerequisites produce a recorded skip and
limitation. Missing required containment or authorization prevents execution;
there is no fallback to unrestricted execution. Execution errors, cancellation,
timeouts and budget stops preserve any available findings and mark the engine
partial or failed, as defined by ADR 0001. Exit code zero alone does not establish
completion. Record applied controls and residual limitations in EngineRun and
evidence metadata; unsupported operating-system controls must be visible.

### Filesystem, credentials and artifacts

- External engines receive a disposable copy or sample directory, never the live
  checkout, host home directory, Git credentials or host Docker socket. Resolve
  symlinks and validate copy boundaries so copying cannot expose external files.
- Use an explicit environment allowlist for every child. Runtime necessities
  are selected per backend; dedicated credentials are passed only to the provider
  component that needs them. Scrub inherited tokens, proxy settings and config
  paths. Dynamic target code receives no LLM credentials.
- Redirect engine configuration, caches and credential persistence to an owned
  ephemeral directory with restrictive permissions. Retain only selected,
  sanitized evidence; redact secrets before logs, reports or PR output.
- Treat artifact paths and imported reports as untrusted. Reject traversal and
  symlink escapes, enforce size limits, and never execute imported PoCs or fetch
  remote evidence automatically. A hash verifies bytes, not truth or safety.
- Clean up owned processes, containers, networks and temporary credentials after
  success, failure, timeout and interruption. Cleanup must not delete caller-owned
  resources. Report cleanup failures without printing credentials.

### Network and active testing

REA tools that execute samples, launch additional programs or access networks
remain disabled unless their effects are understood and specifically allowed.
Dynamic target execution additionally requires explicit authorization. Pin engine
versions and detect incompatible tool catalogs before parsing their output.

Strix requires an explicit target and authorization scope, operator identity,
wall-clock limit, turn limit and spending cap. Non-local tests also require the
interactive confirmation specified in the plan; unattended execution must use a
separately documented pre-approved CI scope. `plex analyze` never starts active
testing.

A named Docker network alone is insufficient containment. Enforce egress at the
network/proxy/firewall boundary, restrict destinations and ports to authorized
targets, and address DNS rebinding, redirects, IPv6 and access to host/metadata
services. Separate model-provider access from target-testing traffic so an LLM
egress exception cannot become arbitrary agent egress. Enforce request-rate
limits outside model instructions. If the deployment cannot enforce these
controls, preflight refuses active testing.

Use least privilege: non-root where supported, drop unnecessary capabilities,
avoid privileged/host networking, and apply CPU, memory and PID limits. If an
engine requires elevated capabilities, document and validate the specific need
before enabling it. Containers share a host kernel; hostile native execution may
require a dedicated runner or virtual machine instead.

Enforce time/turn limits independently where supported. Use a provider-supported
hard spend cap or an enforcing metered gateway for a claimed hard monetary cap;
token estimates and a kill timer cannot guarantee a dollar limit. Refuse a hard
budget configuration that the selected backend cannot enforce. Disable telemetry
and update checks by default, while documenting any unavoidable provider traffic.

## Alternatives Considered

1. Trust each engine's defaults and prompt scope: cannot enforce PLEx's boundaries.
2. Use subprocesses for all engines: useful for lifecycle control, insufficient
   for hostile samples or active testing.
3. Require virtual machines for all workloads: stronger separation but unnecessary
   overhead for bundled static analysis; retain as an option for hostile execution.

## Consequences

- Positive: explicit boundaries protect working copies and credentials, and
  incomplete scans remain visible.
- Negative: external engines require infrastructure and can be unavailable on
  systems that cannot enforce their controls.
- Risks: container escape, engine drift and incomplete cleanup remain possible;
  limitations must be reported rather than described as proven safety.

## Rollout and Migration

Keep static analysis available without Docker, Node or an LLM. Implement the
provider lifecycle with the performance wrapper first. Harden the existing
dynamic-verification environment before the 2.0 release and document trusted-code
constraints. Add restricted external workers with mocked contract tests before
connecting real REA or Strix engines. Do not enable active testing as part of
the schema migration. No runtime behavior changes in this design-only commit.

## Follow-up Tasks

- [ ] Define Sandbox capability checks and mandatory preflight outcomes.
- [ ] Replace inherited subprocess environments with tested allowlists.
- [ ] Test disposable-copy boundaries, secret exclusion and artifact path checks.
- [ ] Test cleanup on failures, interruption, timeout and budget exhaustion.
- [ ] Test actual egress/rate enforcement and deny-by-default authorization.
- [ ] Revalidate pinned engine behavior and credential persistence during adapter
  implementation; record unsupported controls as blockers.
