import assert from "node:assert/strict";

import type {
  Driver,
} from "neo4j-driver";

import {
  deserializeHydraNode,
} from "../../db/hydra-deserializer.js";

import {
  NODE_PROPERTY_KEYS,
  serializeHydraNode,
} from "../../db/hydra-serializer.js";

import type {
  GraphNode,
} from "../../domain/schema.js";

import type {
  GraphBatch,
} from "../../ingest/graph-batch.js";

import {
  collectPackageLock,
} from "../../ingest/lockfile/collector.js";

import {
  TyposquattingService,
  TyposquattingServiceError,
} from "../service.js";

const observedAt = 1_755_216_000_000;
const collected = collectPackageLock(
  {
    name: "lifecycle-smoke",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "": {
        name: "lifecycle-smoke",
        version: "1.0.0",
        dependencies: { lodahs: "1.0.0" },
      },
      "node_modules/lodahs": {
        version: "1.0.0",
      },
    },
  },
  {
    serviceLogicalId: "service:typo-lifecycle",
    serviceName: "typo-lifecycle",
    serviceCriticality: "critical",
    sourceUri: "file:///fixtures/lifecycle-lock.json",
    observedAt,
    confidence: 1,
    synthetic: false,
  },
);

function plain(value: unknown): unknown {
  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    return value.toNumber();
  }
  if (Array.isArray(value)) return value.map(plain);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, plain(entry)]),
    );
  }
  return value;
}

class RecordValue {
  constructor(private readonly values: Readonly<Record<string, unknown>>) {}
  get(key: string): unknown {
    return this.values[key];
  }
}

function projectedNode(node: GraphNode, prefix: string): RecordValue {
  const row = serializeHydraNode(node);
  const values: Record<string, unknown> = {
    [`${prefix}_vertex`]: node.id,
  };
  for (const [key, value] of Object.entries(row)) {
    if (key !== "vertex") values[`${prefix}_${key}`] = value;
  }
  return new RecordValue(values);
}

interface MemoryState {
  readonly nodes: Map<number, GraphNode>;
  readonly candidateId: number;
  readonly targetId: number;
}

function createDriver(state: MemoryState): Driver {
  return {
    session: () => ({
      run: async (query: string, rawParameters: unknown) => {
        const parameters = plain(rawParameters) as Record<string, unknown>;

        if (query.includes("expected_payload_hash")) {
          const current = state.nodes.get(parameters.finding_id as number);
          if (
            current?.kind !== "Finding" ||
            current.status !== parameters.expected_status ||
            serializeHydraNode(current).payload_hash !== parameters.expected_payload_hash
          ) {
            return { records: [] };
          }
          const properties = Object.fromEntries(
            NODE_PROPERTY_KEYS.Finding.map((key) => [key, parameters[key]]),
          );
          const updated = deserializeHydraNode({
            vertex: current.id,
            properties,
            expectedKind: "Finding",
          });
          state.nodes.set(updated.id, updated);
          return {
            records: [new RecordValue({
              finding_id: updated.id,
              payload_hash: serializeHydraNode(updated).payload_hash,
            })],
          };
        }

        if (query.includes("-[:TARGETS]->(candidate:Package)")) {
          return {
            records: [new RecordValue({
              candidate_id: state.candidateId,
              target_id: state.targetId,
            })],
          };
        }

        if (query.includes("-[:HAS_VERSION]->(v:PackageVersion)")) {
          const candidate = state.nodes.get(state.candidateId);
          const versions = [...state.nodes.values()]
            .filter((node) =>
              node.kind === "PackageVersion" &&
              candidate?.kind === "Package" &&
              node.packageName === candidate.name,
            )
            .sort((left, right) => left.id - right.id)
            .map((node) => new RecordValue({ version_id: node.id }));
          return { records: versions };
        }

        if (query.includes("UNWIND $rows AS row") && query.includes("MATCH (n:Evidence")) {
          const rows = parameters.rows as readonly { readonly vertex: number }[];
          return {
            records: rows.flatMap(({ vertex }) => {
              const node = state.nodes.get(vertex);
              return node?.kind === "Evidence" ? [projectedNode(node, "evidence")] : [];
            }),
          };
        }

        if (query.includes("MATCH (f:Finding {id: $finding_id})")) {
          const node = state.nodes.get(parameters.finding_id as number);
          return {
            records: node?.kind === "Finding" ? [projectedNode(node, "finding")] : [],
          };
        }

        if (query.includes("MATCH (n {id: $node_id})")) {
          const node = state.nodes.get(parameters.node_id as number);
          return { records: node === undefined ? [] : [projectedNode(node, "node")] };
        }

        throw new Error(`Unexpected lifecycle smoke query: ${query}`);
      },
      close: async () => undefined,
    }),
  } as unknown as Driver;
}

async function createFixture() {
  const scanBatches: GraphBatch[] = [];
  const scanPersistence = {
    persist: async (batch: GraphBatch) => {
      scanBatches.push(batch);
      return Object.freeze({});
    },
  };
  const scan = new TyposquattingService(
    { session: () => { throw new Error("unexpected scan read"); } } as unknown as Driver,
    scanPersistence as never,
  );
  const scanResult = await scan.scanLockfile({
    collected,
    observedAt,
    persistenceIdempotencyKey: "hg-lifecycle-scan-0001",
    correlationId: "hg-lifecycle-scan-correlation",
  });
  assert.equal(scanResult.findingCount, 1);
  const batch = scanBatches[0]!;
  const finding = batch.nodes.find((node) => node.kind === "Finding");
  const candidateEdge = batch.edges.find((edge) => edge.kind === "TARGETS");
  const targetEdge = batch.edges.find((edge) => edge.kind === "IMITATES");
  assert.ok(finding?.kind === "Finding" && candidateEdge && targetEdge);
  const nodes = new Map<number, GraphNode>();
  for (const node of [...collected.nodes, ...batch.nodes]) nodes.set(node.id, node);
  return {
    findingId: finding.id,
    state: {
      nodes,
      candidateId: candidateEdge.targetId,
      targetId: targetEdge.targetId,
    },
  };
}

function lifecycleService(
  state: MemoryState,
  options: {
    readonly failLifecycleOnce?: boolean;
  } = {},
) {
  const persisted: GraphBatch[] = [];
  let failLifecycle =
    options.failLifecycleOnce === true;
  const persistence = {
    persist: async (batch: GraphBatch) => {
      if (
        failLifecycle &&
        batch.edges.some(
          (edge) => edge.kind === "AFFECTS",
        )
      ) {
        failLifecycle = false;
        throw new Error(
          "simulated lifecycle graph failure",
        );
      }

      persisted.push(batch);
      for (const node of batch.nodes) state.nodes.set(node.id, node);
      return Object.freeze({});
    },
  };
  return {
    service: new TyposquattingService(createDriver(state), persistence as never),
    persisted,
  };
}

const promoteFixture = await createFixture();
const promoteRuntime = lifecycleService(promoteFixture.state);
const promoteCommand = {
  findingId: promoteFixture.findingId,
  action: "promote" as const,
  reason: "Analyst confirmed the exact lockfile-resolved package.",
  reviewer: "lifecycle-smoke",
  decidedAt: observedAt + 1_000,
  idempotencyKey: "lifecycle-promote-0001",
  requestFingerprint: "a".repeat(64),
};
const promoted = await promoteRuntime.service.reviewFinding(promoteCommand);
assert.equal(promoted.finding.status, "confirmed");
assert.ok(promoted.incidentId !== undefined);
assert.equal(
  [...promoteFixture.state.nodes.values()].some((node) => node.kind === "Incident"),
  true,
);
assert.equal(
  promoteRuntime.persisted.some((batch) => batch.edges.some((edge) => edge.kind === "AFFECTS")),
  true,
  "promotion must link only exact persisted PackageVersion evidence",
);

const replay = await promoteRuntime.service.reviewFinding({
  ...promoteCommand,
  decidedAt: observedAt + 9_000,
});
assert.equal(replay.replayed, true);
assert.equal(replay.finding.decidedAt, observedAt + 1_000);
assert.equal(replay.incidentId, promoted.incidentId);

const repairFixture = await createFixture();
const repairRuntime = lifecycleService(
  repairFixture.state,
  { failLifecycleOnce: true },
);
const originalRepairCommand = {
  findingId: repairFixture.findingId,
  action: "promote" as const,
  reason: "Original confirmation survives graph persistence failure.",
  reviewer: "lifecycle-original-analyst",
  decidedAt: observedAt + 1_500,
  idempotencyKey: "lifecycle-repair-original-001",
  requestFingerprint: "d".repeat(64),
};
await assert.rejects(
  () => repairRuntime.service.reviewFinding(originalRepairCommand),
  (error: unknown) =>
    error instanceof TyposquattingServiceError &&
    error.code === "PERSISTENCE_FAILED",
);
const partiallyConfirmed =
  repairFixture.state.nodes.get(
    repairFixture.findingId,
  );
assert.equal(
  partiallyConfirmed?.kind === "Finding"
    ? partiallyConfirmed.status
    : undefined,
  "confirmed",
  "the fixture must reproduce CAS success followed by lifecycle persistence failure",
);
assert.equal(
  [...repairFixture.state.nodes.values()].some(
    (node) => node.kind === "Incident",
  ),
  false,
);

const repaired =
  await repairRuntime.service.reviewFinding({
    ...originalRepairCommand,
    reason: "Authorized repair request with a new idempotency key.",
    reviewer: "lifecycle-repair-analyst",
    decidedAt: observedAt + 8_000,
    idempotencyKey: "lifecycle-repair-new-0001",
    requestFingerprint: "e".repeat(64),
  });
assert.equal(repaired.replayed, true);
assert.equal(
  repaired.finding.decidedAt,
  originalRepairCommand.decidedAt,
);
const repairedIncident =
  [...repairFixture.state.nodes.values()]
    .find((node) => node.kind === "Incident");
assert.ok(repairedIncident?.kind === "Incident");
const originalReviewEvidence =
  [...repairFixture.state.nodes.values()]
    .find((node) =>
      node.kind === "Evidence" &&
      node.sourceType === "analyst-review" &&
      node.observedAt ===
        originalRepairCommand.decidedAt,
    );
assert.ok(originalReviewEvidence?.kind === "Evidence");
assert.deepEqual(
  repairedIncident.evidenceIds,
  [originalReviewEvidence.id],
  "repair must retain the original confirmation provenance",
);

const mismatchedEvidenceFixture =
  await createFixture();
const mismatchedFinding =
  mismatchedEvidenceFixture.state.nodes.get(
    mismatchedEvidenceFixture.findingId,
  );
assert.ok(mismatchedFinding?.kind === "Finding");
const detectorEvidenceId =
  mismatchedFinding.evidenceIds.find(
    (evidenceId) => {
      const node =
        mismatchedEvidenceFixture.state.nodes.get(
          evidenceId,
        );
      return (
        node?.kind === "Evidence" &&
        node.sourceType ===
          "typosquat-detector"
      );
    },
  );
assert.ok(detectorEvidenceId !== undefined);
const mismatchedVersion =
  [...mismatchedEvidenceFixture.state.nodes.values()]
    .find((node) =>
      node.kind === "PackageVersion" &&
      node.packageName === "lodahs",
    );
assert.ok(mismatchedVersion?.kind === "PackageVersion");
mismatchedEvidenceFixture.state.nodes.set(
  mismatchedVersion.id,
  {
    ...mismatchedVersion,
    evidenceIds: [detectorEvidenceId],
  },
);
const mismatchedRuntime =
  lifecycleService(
    mismatchedEvidenceFixture.state,
  );
await assert.rejects(
  () => mismatchedRuntime.service.reviewFinding({
    findingId:
      mismatchedEvidenceFixture.findingId,
    action: "promote",
    reason: "A detector evidence intersection is not an exact lockfile resolution.",
    reviewer: "lifecycle-smoke",
    decidedAt: observedAt + 1_750,
    idempotencyKey: "lifecycle-mismatched-evidence-001",
    requestFingerprint: "f".repeat(64),
  }),
  (error: unknown) =>
    error instanceof TyposquattingServiceError &&
    error.code ===
      "PROMOTION_REQUIRES_EXACT_EXPOSURE",
);

const dismissFixture = await createFixture();
const dismissRuntime = lifecycleService(dismissFixture.state);
const dismissed = await dismissRuntime.service.reviewFinding({
  findingId: dismissFixture.findingId,
  action: "dismiss",
  reason: "Analyst determined this is an approved package name.",
  reviewer: "lifecycle-smoke",
  decidedAt: observedAt + 2_000,
  idempotencyKey: "lifecycle-dismiss-0001",
  requestFingerprint: "b".repeat(64),
});
assert.equal(dismissed.finding.status, "dismissed");
assert.equal(dismissed.incidentId, undefined);

await assert.rejects(
  () => dismissRuntime.service.reviewFinding({
    findingId: dismissFixture.findingId,
    action: "promote",
    reason: "Conflicting terminal transition.",
    reviewer: "lifecycle-smoke",
    decidedAt: observedAt + 3_000,
    idempotencyKey: "lifecycle-conflict-0001",
    requestFingerprint: "c".repeat(64),
  }),
  (error: unknown) =>
    error instanceof TyposquattingServiceError &&
    error.code === "FINDING_ALREADY_DECIDED",
);

console.log("Typosquatting lifecycle smoke passed");
console.log("- explicit promotion created one evidence-backed Incident for exact versions");
console.log("- idempotent replay retained the original analyst decision timestamp");
console.log("- a new authorized promotion repaired partial confirmation with original provenance");
console.log("- non-lockfile evidence intersections could not satisfy exact exposure");
console.log("- dismissal stayed terminal and rejected conflicting promotion");
