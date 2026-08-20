import assert from "node:assert/strict";

import {
  collectPackageLock,
} from "./collector.js";
import {
  HydraLockfileSnapshotStore,
  LockfileSnapshotStoreError,
} from "./snapshot-store.js";
import {
  EDGE_PROPERTY_KEYS,
  NODE_PROPERTY_KEYS,
  serializeHydraEdge,
  serializeHydraNode,
} from "../../db/hydra-serializer.js";

import type {
  HydraScalar,
} from "../../db/hydra-serializer.js";
import type {
  DependencyEdge,
  LockfileSnapshotNode,
} from "../../domain/schema.js";

const hour = 3_600_000;
const firstObservedAt = 1_735_689_600_000;
const secondObservedAt = firstObservedAt + 6 * hour;

function lockfile(badVersion: string): unknown {
  return {
    name: "checkout-api",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "": {
        name: "checkout-api",
        version: "1.0.0",
        dependencies: {
          "bad-lib": `^${badVersion}`,
        },
      },
      "node_modules/bad-lib": {
        version: badVersion,
        integrity: `sha512-${badVersion}`,
      },
    },
  };
}

const collectorOptions = {
  serviceLogicalId:
    "service:demo-org:checkout-api",
  serviceName: "checkout-api",
  serviceCriticality: "critical" as const,
  sourceUri:
    "fixture://snapshot-history/package-lock.json",
  synthetic: true,
};

/* 1. The collector emits a current, content-addressed snapshot. */
const first = collectPackageLock(
  lockfile("1.2.3"),
  {
    ...collectorOptions,
    observedAt: firstObservedAt,
  },
);

const firstSnapshot = first.nodes.find(
  (node) => node.kind === "LockfileSnapshot",
) as LockfileSnapshotNode | undefined;

assert.ok(
  firstSnapshot !== undefined,
  "Collector must emit a LockfileSnapshot",
);

assert.equal(
  firstSnapshot.validUntil,
  null,
  "A newly collected snapshot must be current",
);

assert.equal(
  firstSnapshot.validFrom,
  firstObservedAt,
);

assert.equal(
  firstSnapshot.serviceId,
  first.serviceId,
);

/* Resolutions inherit the snapshot identity and its opening instant. */
const firstResolutions = first.edges.filter(
  (edge): edge is DependencyEdge =>
    edge.kind === "DEPENDS_ON",
);

assert.ok(firstResolutions.length > 0);

for (const edge of firstResolutions) {
  assert.equal(
    edge.snapshotId,
    firstSnapshot.id,
  );
  assert.equal(edge.validFrom, firstObservedAt);
  assert.equal(edge.validUntil, undefined);
}

/* RESOLVED_IN links the snapshot to each exact resolved version. */
assert.ok(
  first.edges.some(
    (edge) => edge.kind === "RESOLVED_IN",
  ),
);

/* 2. validFrom may differ from observation time. */
const backdated = collectPackageLock(
  lockfile("1.2.3"),
  {
    ...collectorOptions,
    observedAt: secondObservedAt,
    validFrom: firstObservedAt,
    commitSha: "abc123def456",
  },
);

const backdatedSnapshot = backdated.nodes.find(
  (node) => node.kind === "LockfileSnapshot",
) as LockfileSnapshotNode;

assert.equal(
  backdatedSnapshot.validFrom,
  firstObservedAt,
  "validFrom must record when the state was true, not when it was scanned",
);

assert.equal(
  backdatedSnapshot.commitSha,
  "abc123def456",
);

/* Identical content yields identical snapshot identity, so re-ingest is idempotent. */
assert.equal(
  backdatedSnapshot.id,
  firstSnapshot.id,
);

/* 3. Different content yields a different snapshot. */
const second = collectPackageLock(
  lockfile("1.2.4"),
  {
    ...collectorOptions,
    observedAt: secondObservedAt,
  },
);

const secondSnapshot = second.nodes.find(
  (node) => node.kind === "LockfileSnapshot",
) as LockfileSnapshotNode;

assert.notEqual(
  secondSnapshot.id,
  firstSnapshot.id,
  "Changed lockfile content must produce a new snapshot",
);

/* 4. Closing the superseded snapshot writes real history. */
interface Statement {
  readonly query: string;
  readonly parameters: Readonly<
    Record<string, unknown>
  >;
}

/**
 * Parameters pass through toHydraParameters, which converts numbers into Bolt
 * Integer values, so numeric assertions normalize before comparing.
 */
function paramNumber(value: unknown): number {
  if (typeof value === "number") {
    return value;
  }

  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    return (
      value.toNumber as () => number
    )();
  }

  throw new Error(
    "Expected a numeric Bolt parameter",
  );
}

function nodeRow(
  node: LockfileSnapshotNode,
): Record<string, unknown> {
  const {
    vertex: _vertex,
    ...properties
  } = serializeHydraNode(node);

  const row: Record<string, unknown> = {
    snapshot_vertex: node.id,
  };

  for (const key of NODE_PROPERTY_KEYS.LockfileSnapshot) {
    row[`snapshot_${key}`] = (
      properties as Record<string, HydraScalar>
    )[key];
  }

  return row;
}

function edgeRow(
  edge: DependencyEdge,
): Record<string, unknown> {
  const {
    relationship_vertex: _relationshipVertex,
    source_vertex: _sourceVertex,
    destination_vertex: _destinationVertex,
    ...properties
  } = serializeHydraEdge(edge);

  const row: Record<string, unknown> = {
    edge_vertex: edge.id,
    source_vertex: edge.sourceId,
    target_vertex: edge.targetId,
    source_logical_id:
      "service:demo-org:checkout-api",
    target_logical_id:
      "pkgver:npm:bad-lib@1.2.3",
  };

  for (const key of EDGE_PROPERTY_KEYS.DEPENDS_ON) {
    row[`edge_${key}`] = (
      properties as Record<string, HydraScalar>
    )[key];
  }

  return row;
}

/*
 * The first snapshot's own dependency edge is rebuilt with matching endpoint
 * logical IDs so the deserializer's identity check passes inside the fake.
 */
const openResolution = firstResolutions.find(
  (edge) =>
    edge.sourceId === first.serviceId,
);

assert.ok(openResolution !== undefined);

function createFakeSession(
  statements: Statement[],
  rows: {
    readonly snapshots: readonly Record<
      string,
      unknown
    >[];
    readonly resolutions: readonly Record<
      string,
      unknown
    >[];
  },
) {
  let closed = 0;

  const session = {
    run: async (
      query: string,
      parameters: Readonly<
        Record<string, unknown>
      >,
    ) => {
      statements.push({ query, parameters });

      if (
        query.includes(
          "MATCH (snapshot:LockfileSnapshot {service_id:",
        )
      ) {
        return {
          records: rows.snapshots.map(
            (row) => ({
              get: (key: string) => row[key],
            }),
          ),
        };
      }

      if (
        query.includes("[edge:DEPENDS_ON]->")
      ) {
        return {
          records: rows.resolutions.map(
            (row) => ({
              get: (key: string) => row[key],
            }),
          ),
        };
      }

      return { records: [] };
    },

    close: async () => {
      closed += 1;
    },
  };

  return {
    session,
    closedCount: () => closed,
  };
}

const statements: Statement[] = [];
const fake = createFakeSession(statements, {
  snapshots: [nodeRow(firstSnapshot)],
  resolutions: [edgeRow(openResolution)],
});

const store = new HydraLockfileSnapshotStore(
  undefined as never,
  {
    sessionFactory: () =>
      fake.session as never,
  },
);

const closeResult =
  await store.closeSupersededSnapshots({
    serviceId: second.serviceId,
    currentSnapshotId: secondSnapshot.id,
    closedAt: second.validFrom,
  });

assert.deepEqual(
  closeResult.closedSnapshotIds,
  [firstSnapshot.id],
);

assert.equal(
  closeResult.closedResolutionCount,
  1,
);

assert.equal(closeResult.truncated, false);

/* The new snapshot is excluded from its own sweep. */
const findStatement = statements.find(
  (statement) =>
    statement.query.includes(
      "snapshot.id <> $current_snapshot_id",
    ),
);

assert.ok(
  findStatement !== undefined,
  "The sweep must exclude the newly persisted snapshot",
);

assert.equal(
  paramNumber(
    findStatement.parameters
      .current_snapshot_id,
  ),
  secondSnapshot.id,
);

/*
 * The close must rewrite payload_hash. Persisting valid_until without
 * rehashing would make the row fail its own integrity check on the next read.
 */
const snapshotClose = statements.find(
  (statement) =>
    statement.query.includes(
      "SET snapshot.valid_until",
    ),
);

assert.ok(snapshotClose !== undefined);

assert.equal(
  paramNumber(
    snapshotClose.parameters.valid_until,
  ),
  secondObservedAt,
);

const expectedSnapshotHash =
  serializeHydraNode({
    ...firstSnapshot,
    validUntil: secondObservedAt,
  }).payload_hash;

assert.equal(
  snapshotClose.parameters.payload_hash,
  expectedSnapshotHash,
  "Closing a snapshot must recompute its payload hash",
);

assert.notEqual(
  snapshotClose.parameters.payload_hash,
  serializeHydraNode(firstSnapshot)
    .payload_hash,
);

const resolutionClose = statements.find(
  (statement) =>
    statement.query.includes(
      "SET edge.valid_until",
    ),
);

assert.ok(resolutionClose !== undefined);

assert.equal(
  resolutionClose.parameters.payload_hash,
  serializeHydraEdge({
    ...openResolution,
    validUntil: secondObservedAt,
  }).payload_hash,
  "Closing a resolution must recompute its payload hash",
);

/* Every session the store opened must be closed. */
assert.equal(
  fake.closedCount(),
  statements.length,
);

/* 5. Closing before a snapshot opened is rejected, not written. */
const invalidStatements: Statement[] = [];
const invalidFake = createFakeSession(
  invalidStatements,
  {
    snapshots: [nodeRow(firstSnapshot)],
    resolutions: [],
  },
);

const invalidStore =
  new HydraLockfileSnapshotStore(
    undefined as never,
    {
      sessionFactory: () =>
        invalidFake.session as never,
    },
  );

await assert.rejects(
  () =>
    invalidStore.closeSupersededSnapshots({
      serviceId: first.serviceId,
      currentSnapshotId: secondSnapshot.id,
      closedAt: firstObservedAt - hour,
    }),
  (error: unknown) =>
    error instanceof
      LockfileSnapshotStoreError &&
    error.code === "INVALID_CLOSE_TIME",
);

assert.equal(
  invalidStatements.some((statement) =>
    statement.query.includes(
      "SET snapshot.valid_until",
    ),
  ),
  false,
  "An incoherent close must not write history",
);

/* A negative close time is rejected before any query runs. */
await assert.rejects(
  () =>
    invalidStore.closeSupersededSnapshots({
      serviceId: first.serviceId,
      currentSnapshotId: secondSnapshot.id,
      closedAt: -1,
    }),
  (error: unknown) =>
    error instanceof
      LockfileSnapshotStoreError &&
    error.code === "INVALID_CLOSE_TIME",
);

console.log("Lockfile snapshot history smoke passed");
console.log(
  "- collector emits a current content-addressed snapshot with RESOLVED_IN edges",
);
console.log(
  "- resolutions inherit the snapshot identity and opening instant",
);
console.log(
  "- identical content is idempotent; changed content creates a new snapshot",
);
console.log(
  "- superseding closes the prior snapshot and its resolutions with rehashed payloads",
);
console.log(
  "- incoherent close times fail closed without writing history",
);
