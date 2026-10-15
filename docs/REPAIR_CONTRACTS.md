# PLEx 2.0 — Repair, Target, and Evidence Contracts

This document specifies the contracts, storage structures, and lifecycle states for **targets**, **content-addressed evidence**, the **project graph**, and **patch candidate verification** in PLEx 2.0.

---

## 1. Overview and Design Principles

1. **Deterministic Identity:** Every target, node, evidence bundle, and patch candidate has a stable, content-derived identifier (prefixed by its entity type, e.g. `target:`, `node:`, `patch:`, `verif:`).
2. **Finding vs. Repair Separation:** A finding records an issue observed in code (`suspected`, `verified`, `inconclusive`, `false_positive`). A repair represents a proposed remedy with its own distinct lifecycle (`proposed`, `applied-in-workspace`, `verified`, `failed`, `inconclusive`, `reverted`).
3. **Content-Addressed Evidence:** Supporting artifacts (taint traces, PoC payloads, logs, disassemblies) are stored under SHA-256 addresses (`.plex/evidence/objects/xx/yy.dat`) with explicit metadata and provenance, never mixed with live source files.
4. **Graph-Connected Relationships:** The `ProjectGraph` connects source files, symbols, findings, patches, and verification runs into a queryable, versioned graph model.

---

## 2. Target Descriptors (`plex.target`)

Targets define the boundary of an analysis or verification session:

```python
from plex.target import TargetDescriptor, TargetScope

# Describe a source repository or directory
desc = TargetDescriptor(
    kind="source_tree",
    path="src/plex",
    snapshot_digest="sha256:...",
)

# Constrain the exploration scope
scope = TargetScope(
    target=desc,
    include_patterns=("**/*.py",),
    exclude_patterns=("**/*_test.py",),
    max_files=500,
    network_restricted=True,
)
```

### Entity Fields

- `TargetDescriptor`:
  - `schema_version`: integer schema version (`1`).
  - `id`: deterministic ID (`target:<sha256[:16]>`).
  - `kind`: `"source_tree" | "artifact" | "endpoint"`.
  - `path`: local filesystem path (if local).
  - `url`: remote target URL (if applicable).
  - `snapshot_digest`: Git commit SHA or file archive digest.
  - `metadata`: dictionary of arbitrary target properties.
- `TargetScope`:
  - `target`: `TargetDescriptor`.
  - `include_patterns`: glob patterns to include (default `("**/*",)`).
  - `exclude_patterns`: glob patterns to exclude.
  - `max_files`: maximum file traversal budget (default `200`).
  - `network_restricted`: whether external network calls are forbidden during inspection (default `True`).

---

## 3. Evidence Artifacts and Storage (`plex.evidence`)

### Storage Layout

Artifacts are persisted in a sharded content-addressed object directory:

```
.plex/evidence/
  objects/
    a1/
      b2c3d4e5...dat         # Raw binary or text payload
      b2c3d4e5...meta.json    # Provenance, MIME type, creation time
```

### Methods

- `EvidenceArtifact.create(kind, content, provenance, redacted, content_type)`: Ingests text, JSON, or bytes, computes `sha256:<hex>`, and packages provenance.
- `artifact.to_ref(engine, isolation, limitations)`: Produces an `EvidenceRef` consumable by `PLExReport` v8 findings.
- `store.put(artifact) -> str`: Writes the payload and metadata atomically.
- `store.get(digest) -> EvidenceArtifact | None`: Reads and deserializes the artifact.
- `store.verify(digest) -> bool`: Re-hashes payload on disk and verifies that it strictly matches `digest`.

---

## 4. Versioned Project Graph (`plex.graph`)

Schema: `schema/project-graph-v1.schema.json`.

The project graph represents software entities and analysis deductions:

### Node Kinds
`file`, `symbol`, `call_site`, `source`, `sink`, `data_class`, `route`, `service`, `dependency`, `artifact`, `finding`, `hypothesis`, `patch_candidate`, `verification_run`.

### Edge Kinds
`contains`, `calls`, `flows_to`, `reaches`, `authenticates`, `depends_on`, `maps_to`, `detects`, `repairs`, `verifies`, `correlates`.

### Example Usage

```python
from plex.graph import ProjectGraph

graph = ProjectGraph(target_digest="sha256:abc")
src_node = graph.add_node(kind="source", label="user_input")
sink_node = graph.add_node(kind="sink", label="cursor.execute")

graph.add_edge(
    source=src_node.id,
    target=sink_node.id,
    kind="flows_to",
    producer="xboundary",
    confidence=1.0,
    evidence_ref="sha256:...",
)

# Traverse outgoing flow edges
for edge in graph.outgoing(src_node.id, kind="flows_to"):
    print(f"Flows to node: {edge.target}")
```

---

## 5. Repair and Verification Lifecycle (`plex.repair`)

Schema: `schema/repair-candidate-v1.schema.json`.

### Lifecycle State Machine

```
              ┌─────────────────────────────┐
              │          proposed           │◄────────────┐
              └──────┬───────────────┬──────┘             │
                     │               │                    │
          apply into │               │ direct pass        │
           workspace │               │ or failure         │
                     ▼               ▼                    │
      ┌────────────────────┐   ┌───────────┐              │
      │applied-in-workspace│   │  failed   ├──────────────┤
      └──────┬─────────────┘   └───────────┘              │
             │                       ▲                    │
             ├──────────────┬────────┤                    │
             │ pass         │ fail   │                    │
             ▼              ▼        │                    │
       ┌───────────┐   ┌────────────┐│                    │
       │ verified  │   │inconclusive├┘                    │
       └─────┬─────┘   └─────┬──────┘                     │
             │ revert        │ revert                     │
             └───────┬───────┴────────────────────────────┘
                     ▼
               ┌───────────┐
               │ reverted  │──────────────────────────────┘
               └───────────┘          re-propose
```

### State Transitions

- **`proposed`**: Patch candidate generated; not yet tested in a workspace.
- **`applied-in-workspace`**: Temporarily applied to an isolated working tree or scratch branch for verification checks.
- **`verified`**: Every required check ran and passed (syntax check for the file type and the behavioral test command), and no optional check failed.
- **`failed`**: Verification checks failed (e.g. syntax error or test regression).
- **`inconclusive`**: Executed checks passed but a required check could not run (no test command, no syntax validator for the file type). The missing checks are listed in `VerificationRecord.limitations`.
- **`reverted`**: Workspace was rolled back to original state.

### Patch Candidate Contract

```python
from plex.repair import PatchCandidate, VerificationCheck, VerificationRecord, RepairRecord

# Deterministic patch creation
candidate = PatchCandidate.create(
    finding_ids=("find:890abc",),
    rule_id="xbnd.sql-injection",
    engine="xboundary",
    source_digest="sha256:...",
    target_file="src/gateway.py",
    diff="--- a/src/gateway.py\n+++ b/src/gateway.py\n@@ -10,1 +10,1 @@\n-cursor.execute(query)\n+cursor.execute(query, params)",
    description="Parameterize dynamic SQL query",
    rollback_diff="--- b/src/gateway.py\n+++ a/src/gateway.py\n@@ -10,1 +10,1 @@\n+cursor.execute(query)\n-cursor.execute(query, params)",
)

# Verification execution record
verification = VerificationRecord.create(
    patch_id=candidate.id,
    finding_id="find:890abc",
    status="verified",
    verifier="plex.worker.subprocess",
    checks=(
        VerificationCheck(name="syntax_check", passed=True, duration_ms=12.0),
        VerificationCheck(name="regression_test", passed=True, duration_ms=450.0),
    ),
    environment_digest="sha256:...",
)

# Repair lifecycle tracking
repair = RepairRecord(candidate=candidate)
repair.transition("applied-in-workspace", reason="Running verification suite")
repair.transition("verified", reason="All tests passed successfully")
```
