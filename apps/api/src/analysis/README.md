# Supply-Chain Analysis Subsystem

This directory contains HydraSCOPE's deterministic, read-only software
supply-chain security analysis.

## Ownership boundary

Pratik owns the complete `apps/api/src/analysis/` subtree.

Analysis may import shared domain, graph-batch, and persistence contracts, but
it must not independently modify the canonical schema, ingestion pipeline,
database writer, API routes, contracts, or dashboard.

Changes outside this subtree require approval from the relevant owner. The
`validate:analysis` package script is the approved exception required for
automated analysis validation.

## Production persistence boundary

Production analysis cannot run directly against an unpersisted graph batch.

The public entry point is:

```typescript
runBlastRadius(
  persisted,
  reader,
  affectedVersionIds,
  options,
)
