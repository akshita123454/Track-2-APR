import assert from "node:assert/strict";

import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../../domain/identity.js";
import { createDependencyPair } from "../../domain/factories.js";
import { validateGraph } from "../../domain/validator.js";
import {
  deserializeHydraEdge,
  deserializeHydraNode,
} from "../../db/hydra-deserializer.js";
import {
  serializeHydraEdge,
  serializeHydraNode,
} from "../../db/hydra-serializer.js";
import {
  classifyWindowOverlap,
  partitionByWindow,
  TemporalWindowError,
} from "../core/temporal-window.js";
import {
  buildTemporalWindow,
} from "../core/temporal-projection.js";

import type {
  EvidenceNode,
  GraphEdge,
  GraphNode,
  LockfileSnapshotNode,
  PackageVersionNode,
  ServiceNode,
  StandardCanonicalEdge,
} from "../../domain/schema.js";

const observedAt = 1_735_689_600_000;
const hour = 3_600_000;

const evidence: EvidenceNode = {
  ...createEntityIdentity(
    "evidence:temporal:lockfile-snapshot-v1",
  ),
  kind: "Evidence",
  evidenceIds: [],
  synthetic: true,
  observedAt,
  sourceType: "package-lock",
  sourceUri: "fixture://temporal/package-lock.json",
  collectorVersion: "temporal-fixture-1.0.0",
  confidence: 1,
  detail:
    "Synthetic lockfile evidence for temporal validity coverage",
};

const service: ServiceNode = {
  ...createEntityIdentity(
    "service:demo-org:checkout-api",
  ),
  kind: "Service",
  evidenceIds: [evidence.id],
  synthetic: true,
  observedAt,
  name: "checkout-api",
  criticality: "critical",
  internetExposed: true,
  dataSensitivity: "high",
};

const badVersion: PackageVersionNode = {
  ...createEntityIdentity(
    "pkgver:npm:bad-lib@1.2.4",
  ),
  kind: "PackageVersion",
  evidenceIds: [evidence.id],
  synthetic: true,
  observedAt,
  ecosystem: "npm",
  packageName: "bad-lib",
  version: "1.2.4",
};

const contentSha256 = "a".repeat(64);

const currentSnapshot: LockfileSnapshotNode = {
  ...createEntityIdentity(
    `lockfile-snapshot:${service.logicalId}:${contentSha256}`,
  ),
  kind: "LockfileSnapshot",
  evidenceIds: [evidence.id],
  synthetic: true,
  observedAt,
  serviceId: service.id,
  contentSha256,
  lockfileVersion: 3,
  validFrom: observedAt,
  validUntil: null,
  commitSha: "0f1e2d3c4b5a6978",
};

function resolvedInEdge(
  snapshot: LockfileSnapshotNode,
  version: PackageVersionNode,
): StandardCanonicalEdge {
  const discriminator = "package-lock:node_modules/bad-lib";

  return {
    ...createEdgeIdentity({
      kind: "RESOLVED_IN",
      sourceLogicalId: snapshot.logicalId,
      targetLogicalId: version.logicalId,
      discriminator,
    }),
    kind: "RESOLVED_IN",
    sourceId: snapshot.id,
    targetId: version.id,
    observedAt,
    derived: false,
    identityDiscriminator: discriminator,
    evidenceIds: [evidence.id],
  };
}

/**
 * The deserializer materializes absent optional fields as explicit undefined,
 * while factories omit the key entirely. Both mean "not present", so equality
 * is compared after dropping undefined-valued keys.
 */
function stripUndefined<T extends object>(
  value: T,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(
      ([, entry]) => entry !== undefined,
    ),
  );
}

function roundTripNode(node: GraphNode): GraphNode {
  const {
    vertex: _vertex,
    ...properties
  } = serializeHydraNode(node);

  return deserializeHydraNode({
    vertex: node.id,
    properties,
    expectedKind: node.kind,
  });
}

function roundTripEdge(
  edge: GraphEdge,
  source: GraphNode,
  target: GraphNode,
): GraphEdge {
  const {
    relationship_vertex: _relationshipVertex,
    source_vertex: _sourceVertex,
    destination_vertex: _destinationVertex,
    ...properties
  } = serializeHydraEdge(edge);

  return deserializeHydraEdge({
    relationshipVertex: edge.id,
    sourceVertex: edge.sourceId,
    destinationVertex: edge.targetId,
    sourceLogicalId: source.logicalId,
    destinationLogicalId: target.logicalId,
    properties,
    expectedKind: edge.kind,
  });
}

/* 1. LockfileSnapshot survives an exact serialization round trip. */
assert.deepEqual(
  stripUndefined(roundTripNode(currentSnapshot)),
  stripUndefined(currentSnapshot),
);

/* A closed snapshot round-trips its validUntil rather than losing it. */
const closedSnapshot: LockfileSnapshotNode = {
  ...currentSnapshot,
  validUntil: observedAt + 6 * hour,
};

assert.deepEqual(
  stripUndefined(roundTripNode(closedSnapshot)),
  stripUndefined(closedSnapshot),
);

/* An absent commitSha must stay absent, not become an empty string. */
const snapshotWithoutCommit:
  LockfileSnapshotNode = {
    ...currentSnapshot,
    commitSha: undefined,
  };

assert.deepEqual(
  stripUndefined(roundTripNode(snapshotWithoutCommit)),
  stripUndefined(snapshotWithoutCommit),
);

/* 2. RESOLVED_IN survives an exact round trip. */
const resolved = resolvedInEdge(
  currentSnapshot,
  badVersion,
);

assert.deepEqual(
  stripUndefined(
    roundTripEdge(
      resolved,
      currentSnapshot,
      badVersion,
    ),
  ),
  stripUndefined(resolved),
);

/* 3. DEPENDS_ON carries and round-trips its temporal validity. */
const temporalPair = createDependencyPair({
  source: service,
  target: badVersion,
  discriminator:
    "package-lock:root>node_modules/bad-lib",
  dependencyType: "production",
  evidenceIds: [evidence.id],
  observedAt,
  generatorVersion: "1.0.0",
  declaredRange: "^1.2.0",
  lockfilePath: "node_modules/bad-lib",
  snapshotId: currentSnapshot.id,
  validFrom: observedAt,
  validUntil: observedAt + 6 * hour,
});

assert.equal(
  temporalPair.canonical.validFrom,
  observedAt,
);

assert.deepEqual(
  stripUndefined(
    roundTripEdge(
      temporalPair.canonical,
      service,
      badVersion,
    ),
  ),
  stripUndefined(temporalPair.canonical),
);

/* A dependency with no temporal fields still round-trips unchanged. */
const untimedPair = createDependencyPair({
  source: service,
  target: badVersion,
  discriminator:
    "package-lock:root>node_modules/bad-lib",
  dependencyType: "production",
  evidenceIds: [evidence.id],
  observedAt,
  generatorVersion: "1.0.0",
});

assert.equal(
  untimedPair.canonical.validFrom,
  undefined,
);

assert.deepEqual(
  stripUndefined(
    roundTripEdge(
      untimedPair.canonical,
      service,
      badVersion,
    ),
  ),
  stripUndefined(untimedPair.canonical),
);

/* 4. The complete temporal graph passes validation. */
const temporalGraph = validateGraph(
  [
    evidence,
    service,
    badVersion,
    currentSnapshot,
  ],
  [
    resolved,
    temporalPair.canonical,
    temporalPair.reverseIndex,
  ],
);

assert.equal(
  temporalGraph.valid,
  true,
  `Temporal graph must validate: ${temporalGraph.errors.join(", ")}`,
);

/* 5. Fail-closed graph cases. */

/* RESOLVED_IN cannot originate from a Service. */
const misroutedResolved: StandardCanonicalEdge = {
  ...createEdgeIdentity({
    kind: "RESOLVED_IN",
    sourceLogicalId: service.logicalId,
    targetLogicalId: badVersion.logicalId,
    discriminator: "misrouted",
  }),
  kind: "RESOLVED_IN",
  sourceId: service.id,
  targetId: badVersion.id,
  observedAt,
  derived: false,
  identityDiscriminator: "misrouted",
  evidenceIds: [evidence.id],
};

assert.equal(
  validateGraph(
    [evidence, service, badVersion],
    [misroutedResolved],
  ).valid,
  false,
);

/* A snapshot reference must point at a LockfileSnapshot. */
const wrongSnapshotKind = createDependencyPair({
  source: service,
  target: badVersion,
  discriminator: "wrong-snapshot-kind",
  dependencyType: "production",
  evidenceIds: [evidence.id],
  observedAt,
  generatorVersion: "1.0.0",
  validFrom: observedAt,
  snapshotId: service.id,
});

assert.equal(
  validateGraph(
    [evidence, service, badVersion],
    [
      wrongSnapshotKind.canonical,
      wrongSnapshotKind.reverseIndex,
    ],
  ).valid,
  false,
);

/* An unparseable content hash fails closed. */
assert.equal(
  validateGraph(
    [
      evidence,
      service,
      {
        ...currentSnapshot,
        contentSha256: "NOT-A-SHA",
      },
    ],
    [],
  ).valid,
  false,
);

/* An unsupported lockfile version fails closed. */
assert.equal(
  validateGraph(
    [
      evidence,
      service,
      {
        ...currentSnapshot,
        lockfileVersion: 9 as unknown as 3,
      },
    ],
    [],
  ).valid,
  false,
);

/* A snapshot closing before it opens fails closed. */
assert.equal(
  validateGraph(
    [
      evidence,
      service,
      {
        ...currentSnapshot,
        validUntil: observedAt - hour,
      },
    ],
    [],
  ).valid,
  false,
);

/* The factory rejects a closing timestamp with no opening timestamp. */
assert.throws(
  () =>
    createDependencyPair({
      source: service,
      target: badVersion,
      discriminator: "dangling-valid-until",
      dependencyType: "production",
      evidenceIds: [evidence.id],
      observedAt,
      generatorVersion: "1.0.0",
      validUntil: observedAt,
    }),
  /validUntil requires validFrom/,
);

/* The serializer refuses an inverted dependency validity window. */
assert.throws(
  () =>
    serializeHydraEdge({
      ...temporalPair.canonical,
      validFrom: observedAt,
      validUntil: observedAt - hour,
    }),
  /validUntil precedes validFrom/,
);

/* 6. Window classification. */
const incidentWindow = {
  intervalStart: observedAt + hour,
  intervalEnd: observedAt + 3 * hour,
};

/* A resolution spanning the incident overlaps it. */
assert.equal(
  classifyWindowOverlap(
    {
      validFrom: observedAt,
      validUntil: observedAt + 6 * hour,
    },
    incidentWindow,
    [evidence.id],
  ).overlap,
  "resolved-during-window",
);

/* A resolution closed before the incident opened does not overlap. */
assert.equal(
  classifyWindowOverlap(
    {
      validFrom: observedAt,
      validUntil: observedAt + 30 * 60_000,
    },
    incidentWindow,
  ).overlap,
  "resolved-outside-window",
);

/* A resolution opened after the incident closed does not overlap. */
assert.equal(
  classifyWindowOverlap(
    {
      validFrom: observedAt + 5 * hour,
    },
    incidentWindow,
  ).overlap,
  "resolved-outside-window",
);

/* A still-current resolution overlaps an open-ended incident. */
assert.equal(
  classifyWindowOverlap(
    { validFrom: observedAt },
    {
      intervalStart: observedAt + hour,
      intervalEnd: null,
    },
  ).overlap,
  "resolved-during-window",
);

/* A missing validFrom is unknown, never "outside". */
const unknown = classifyWindowOverlap(
  {},
  incidentWindow,
  [evidence.id],
);

assert.equal(unknown.overlap, "unknown-window");
assert.deepEqual(unknown.evidenceIds, []);
assert.match(unknown.reason, /cannot be placed/);

/* Touching exactly at the incident boundary reports overlap. */
assert.equal(
  classifyWindowOverlap(
    {
      validFrom: observedAt,
      validUntil: incidentWindow.intervalStart,
    },
    incidentWindow,
  ).overlap,
  "resolved-during-window",
);

/* Evidence IDs are deduplicated and sorted. */
assert.deepEqual(
  classifyWindowOverlap(
    { validFrom: observedAt },
    incidentWindow,
    [9, 3, 9, 1],
  ).evidenceIds,
  [1, 3, 9],
);

/* Invalid windows fail closed rather than silently classifying. */
assert.throws(
  () =>
    classifyWindowOverlap({}, {
      intervalStart: observedAt + hour,
      intervalEnd: observedAt,
    }),
  (error: unknown) =>
    error instanceof TemporalWindowError &&
    error.code === "INVALID_INCIDENT_WINDOW",
);

assert.throws(
  () =>
    classifyWindowOverlap(
      { validUntil: observedAt },
      incidentWindow,
    ),
  (error: unknown) =>
    error instanceof TemporalWindowError &&
    error.code === "INVALID_RESOLUTION_WINDOW",
);

assert.throws(
  () =>
    classifyWindowOverlap(
      {
        validFrom: observedAt,
        validUntil: observedAt - 1,
      },
      incidentWindow,
    ),
  (error: unknown) =>
    error instanceof TemporalWindowError &&
    error.code === "INVALID_RESOLUTION_WINDOW",
);

/* 7. Partitioning keeps unknown visible. */
const partition = partitionByWindow(
  [
    { name: "during", validFrom: observedAt },
    {
      name: "outside",
      validFrom: observedAt + 5 * hour,
    },
    { name: "unknown" },
  ] as readonly {
    readonly name: string;
    readonly validFrom?: number;
  }[],
  incidentWindow,
  (subject) => ({
    resolution:
      subject.validFrom === undefined
        ? {}
        : { validFrom: subject.validFrom },
    evidenceIds: [evidence.id],
  }),
);

assert.deepEqual(
  partition.resolvedDuringWindow.map(
    (entry) => entry.subject.name,
  ),
  ["during"],
);

assert.deepEqual(
  partition.resolvedOutsideWindow.map(
    (entry) => entry.subject.name,
  ),
  ["outside"],
);

assert.deepEqual(
  partition.unknownWindow.map(
    (entry) => entry.subject.name,
  ),
  ["unknown"],
);

assert.equal(partition.hasUnknown, true);

/* 8. Blast-radius projection partitions services and keeps unknown visible. */
function candidate(
  serviceName: string,
  serviceId: number,
  edges: readonly {
    readonly validFrom?: number;
    readonly validUntil?: number;
  }[],
) {
  return {
    service: {
      ...service,
      id: serviceId,
      name: serviceName,
    },
    minimumDepth: 1,
    paths: [
      {
        pathKey: `path:${serviceName}`,
        affectedVersionId: badVersion.id,
        serviceId,
        nodes: [badVersion, service],
        canonicalEdges: edges.map(
          (edge) => ({
            ...temporalPair.canonical,
            ...(edge.validFrom === undefined
              ? { validFrom: undefined }
              : { validFrom: edge.validFrom }),
            ...(edge.validUntil === undefined
              ? { validUntil: undefined }
              : {
                  validUntil: edge.validUntil,
                }),
          }),
        ),
        depth: 1,
      },
    ],
  };
}

const projection = buildTemporalWindow(
  {
    affectedVersionIds: [badVersion.id],
    services: [
      /* Still current, so it overlaps an open incident. */
      candidate("live-service", 101, [
        { validFrom: observedAt },
      ]),

      /* Closed before the incident opened. */
      candidate("stale-service", 102, [
        {
          validFrom: observedAt,
          validUntil: observedAt + 30 * 60_000,
        },
      ]),

      /* No recorded validity at all. */
      candidate("unrecorded-service", 103, [
        {},
      ]),
    ],
    totalPathCount: 3,
    truncated: false,
    limits: {
      maxDepth: 8,
      maxServices: 100,
      maxPathsPerService: 10,
      maxTotalPaths: 100,
      maxTraversalStates: 1_000,
      maxDependentsPerNode: 100,
      maxWarnings: 50,
    },
    warnings: [],
  } as never,
  incidentWindow,
  { asOf: observedAt + 2 * hour },
);

assert.deepEqual(
  projection.resolvedDuringWindow.map(
    (entry) => entry.serviceName,
  ),
  ["live-service"],
);

assert.deepEqual(
  projection.resolvedOutsideWindow.map(
    (entry) => entry.serviceName,
  ),
  ["stale-service"],
);

assert.deepEqual(
  projection.unknownWindow.map(
    (entry) => entry.serviceName,
  ),
  ["unrecorded-service"],
);

assert.equal(projection.hasUnknown, true);
assert.equal(projection.complete, false);
assert.equal(
  projection.asOf,
  observedAt + 2 * hour,
);

assert.deepEqual(
  projection.incidentInterval,
  incidentWindow,
);

assert.ok(
  projection.limitations.some((entry) =>
    entry.includes("Unknown is not safe"),
  ),
  "The projection must state that unknown is not safe",
);

/* A fully recorded, non-truncated projection reports completeness. */
const completeProjection =
  buildTemporalWindow(
    {
      affectedVersionIds: [badVersion.id],
      services: [
        candidate("live-service", 101, [
          { validFrom: observedAt },
        ]),
      ],
      totalPathCount: 1,
      truncated: false,
      limits: {
        maxDepth: 8,
        maxServices: 100,
        maxPathsPerService: 10,
        maxTotalPaths: 100,
        maxTraversalStates: 1_000,
        maxDependentsPerNode: 100,
        maxWarnings: 50,
      },
      warnings: [],
    } as never,
    incidentWindow,
  );

assert.equal(completeProjection.complete, true);
assert.equal(completeProjection.asOf, null);
assert.deepEqual(
  completeProjection.limitations,
  [],
);

/* Truncated traversal can never claim completeness. */
const truncatedProjection =
  buildTemporalWindow(
    {
      affectedVersionIds: [badVersion.id],
      services: [
        candidate("live-service", 101, [
          { validFrom: observedAt },
        ]),
      ],
      totalPathCount: 1,
      truncated: true,
      limits: {
        maxDepth: 8,
        maxServices: 100,
        maxPathsPerService: 10,
        maxTotalPaths: 100,
        maxTraversalStates: 1_000,
        maxDependentsPerNode: 100,
        maxWarnings: 50,
      },
      warnings: [],
    } as never,
    incidentWindow,
  );

assert.equal(
  truncatedProjection.complete,
  false,
);

console.log("Temporal validity smoke passed");
console.log(
  "- LockfileSnapshot, RESOLVED_IN, and timed DEPENDS_ON round-trip exactly",
);
console.log(
  "- absent temporal fields stay absent instead of becoming sentinels",
);
console.log(
  "- misrouted endpoints, bad hashes, bad versions, and inverted windows fail closed",
);
console.log(
  "- missing resolution validity classifies as unknown, never as outside",
);
console.log(
  "- boundary-touching resolutions resolve toward reporting exposure",
);
console.log(
  "- blast-radius services partition into during/outside/unknown windows",
);
console.log(
  "- truncated traversal and missing history can never claim completeness",
);
