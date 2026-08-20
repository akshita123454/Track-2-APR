import assert from "node:assert/strict";

import type {
  Driver,
} from "neo4j-driver";

import {
  collectPackageLock,
} from "../../ingest/lockfile/collector.js";

import {
  serializeGraphBatch,
} from "../../db/hydra-serializer.js";

import type {
  GraphBatch,
} from "../../ingest/graph-batch.js";

import {
  TyposquattingService,
} from "../service.js";

const observedAt = 1_755_216_000_000;

const collected = collectPackageLock(
  {
    name: "typosquat-smoke",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": {
        name: "typosquat-smoke",
        version: "1.0.0",
        dependencies: {
          lodahs: "1.0.0",
        },
      },
      "node_modules/lodahs": {
        version: "1.0.0",
        integrity: "sha512-fixture",
      },
    },
  },
  {
    serviceLogicalId:
      "service:typosquat-smoke",
    serviceName: "typosquat-smoke",
    serviceCriticality: "high",
    sourceUri:
      "file:///fixtures/package-lock.json",
    observedAt,
    confidence: 1,
    synthetic: false,
    maxPackages: 100,
  },
);

const persisted: GraphBatch[] = [];
const persistence = {
  persist: async (batch: GraphBatch) => {
    persisted.push(batch);
    return Object.freeze({});
  },
};
const fakeDriver = {
  session: () => {
    throw new Error(
      "scan orchestration must not read HydraDB before producing findings",
    );
  },
} as unknown as Driver;

const service = new TyposquattingService(
  fakeDriver,
  persistence as never,
);

const input = {
  collected,
  observedAt,
  persistenceIdempotencyKey:
    "hg-typosquat-smoke-0001",
  correlationId:
    "hg-typosquat-smoke-correlation",
} as const;

const first = await service.scanLockfile(input);
const second = await service.scanLockfile(input);

assert.equal(first.findingCount, 1);
assert.deepEqual(second, first);
assert.equal(persisted.length, 2);

const firstSerialized =
  serializeGraphBatch(persisted[0]!);
const secondSerialized =
  serializeGraphBatch(persisted[1]!);
assert.equal(
  firstSerialized.batchHash,
  secondSerialized.batchHash,
  "repeated scans must produce the same graph batch",
);

const finding = persisted[0]!.nodes.find(
  (node) => node.kind === "Finding",
);
assert.ok(
  finding?.kind === "Finding",
  "scan must persist a Finding",
);
assert.equal(finding.status, "suspicious");
assert.equal(
  finding.candidatePackageName,
  "lodahs",
);
assert.equal(
  finding.targetPackageName,
  "lodash",
);
assert.notEqual(
  (finding as { readonly status: string }).status,
  "confirmed",
  "detector must never auto-confirm",
);
assert.equal(
  persisted[0]!.nodes.some(
    (node) => node.kind === "Incident",
  ),
  false,
  "inferred scans must not create incidents",
);

const relationKinds = new Set(
  persisted[0]!.edges.map(
    (edge) => edge.kind,
  ),
);
for (const kind of [
  "LOOKALIKE_OF",
  "TARGETS",
  "IMITATES",
  "SUPPORTS",
]) {
  assert.equal(
    relationKinds.has(kind as never),
    true,
    `scan graph must include ${kind}`,
  );
}

assert.equal(
  persisted[0]!.validation.valid,
  true,
);
assert.equal(
  first.diagnostics.truncated,
  false,
);

console.log(
  "Typosquatting orchestration smoke passed",
);
console.log(
  "- exact lockfile observation produced one deterministic inferred finding",
);
console.log(
  "- repeated scans produced an identical verified graph batch",
);
console.log(
  "- no automatic confirmation or Incident creation occurred",
);
