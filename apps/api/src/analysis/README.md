# Supply-Chain Analysis Subsystem

This directory contains HydraSCOPE's pure, read-only software supply-chain
security analysis.

## Ownership boundary

Pratik owns the complete `apps/api/src/analysis/` subtree.

Analysis code may import shared domain types, but it must not independently
modify the canonical domain schema, ingestion pipeline, database adapters,
API routes, contracts, or dashboard.

Changes outside this subtree require approval from the relevant owner.

## Architectural invariants

All analysis modules must follow these rules:

1. Analysis reads graph facts but never mutates the source graph.
2. Analysis functions receive an injected, read-only graph interface.
3. Analysis must work without a running HydraDB instance.
4. Network-free fixtures must produce deterministic results.
5. Canonical graph evidence must be preserved in every returned path.
6. Traversal must enforce maximum-depth and result limits.
7. Cycles must terminate safely.
8. Input nodes and edges must remain unchanged after analysis.
9. Confidence, evidence stage, security conclusion, and severity are separate
   concepts.
10. Missing canonical relationships must be raised for schema-owner approval
    rather than invented inside analysis.

## Canonical dependency semantics

`DEPENDS_ON` is the canonical dependency relationship.

If package version A depends on package version B, the canonical direction is:

```text
A -[:DEPENDS_ON]-> B
