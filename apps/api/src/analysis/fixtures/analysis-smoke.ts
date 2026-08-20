import assert from "node:assert/strict";

import type {
  Driver,
  Session,
} from "neo4j-driver";
import {
  GraphBatchReader,
} from "../readers/graph-batch-reader.js";

import {
  HydraPersistenceService,
} from "../../db/persistence-service.js";
import type {
  PersistenceServiceOptions,
} from "../../db/persistence-service.js";

import {
  createDependencyPair,
} from "../../domain/factories.js";
import type {
  DependencyPair,
} from "../../domain/factories.js";
import {
  createEntityIdentity,
} from "../../domain/identity.js";
import type {
  DependencyEdge,
  EvidenceNode,
  GraphEdge,
  GraphNode,
  NodeId,
  PackageVersionNode,
  ServiceNode,
} from "../../domain/schema.js";


import {
  mergeGraphFragments,
} from "../../ingest/graph-batch.js";
import type {
  GraphBatch,
} from "../../ingest/graph-batch.js";

import {
  analyzeBlastRadius,
} from "../core/blast-radius.js";
import {
  classifyExposureWithValidatedEvidence,
  ExposureEvidenceValidationError,
} from "../core/exposure-ladder.js";
import type {
  DependencyHop,
  ExposureEvidenceSignals,
  ReadonlyGraphReader,
} from "../core/analysis-types.js";
import {
  runBlastRadius,
} from "../persisted-analysis.js";

type UnknownRecord = Record<string, unknown>;

type MutationKind =
  | "node"
  | "canonical"
  | "derived";

interface StoredNode extends UnknownRecord {
  vertex: number;
  logical_id: string;
  kind: string;
}

interface StoredRelationship extends UnknownRecord {
  relationship_vertex: number;
  source_vertex: number;
  destination_vertex: number;
  logical_id: string;
  kind: string;
  relationshipType: string;
}

interface FakeResult {
  readonly records: readonly FakeRecord[];
}

interface AnalysisFixture {
  readonly batch: GraphBatch;
  readonly affectedVersion: PackageVersionNode;
  readonly bridgeVersion: PackageVersionNode;
  readonly alphaService: ServiceNode;
  readonly betaService: ServiceNode;
  readonly resolutionEvidence: EvidenceNode;
  readonly buildEvidence: EvidenceNode;
  readonly deploymentEvidence: EvidenceNode;
  readonly reachabilityEvidence: EvidenceNode;
  readonly executionEvidence: EvidenceNode;
  readonly alphaDirectPair: DependencyPair;
}

const OBSERVED_AT = 1_700_000_000_000;

class FakeRecord {
  public constructor(
    private readonly values: Readonly<UnknownRecord>,
  ) {}

  public get(key: string): unknown {
    return this.values[key];
  }
}

function isRecord(
  value: unknown,
): value is UnknownRecord {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function requireRecord(
  value: unknown,
  description: string,
): UnknownRecord {
  assert.ok(
    isRecord(value),
    `${description} must be a record`,
  );

  return value;
}

function requireString(
  value: unknown,
  description: string,
): string {
  if (typeof value !== "string") {
    throw new TypeError(
      `${description} must be a string`,
    );
  }

  return value;
}

function requireNumber(
  value: unknown,
  description: string,
): number {
  let converted = value;

  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    converted = value.toNumber();
  }

  if (
    typeof converted !== "number" ||
    !Number.isSafeInteger(converted) ||
    converted < 0
  ) {
    throw new TypeError(
      `${description} must be a nonnegative safe integer`,
    );
  }

  return converted;
}

function requireRows(
  parameters: Readonly<UnknownRecord>,
): UnknownRecord[] {
  const rows = parameters.rows;

  assert.ok(
    Array.isArray(rows),
    "rows parameter must be an array",
  );

  return rows.map((row, index) =>
    requireRecord(row, `rows[${index}]`),
  );
}

function requireMatch(
  query: string,
  pattern: RegExp,
  description: string,
): string {
  const match = query.match(pattern);

  assert.ok(
    match?.[1] !== undefined,
    `Could not parse ${description}`,
  );

  return match[1];
}

function mutationKindForQuery(
  query: string,
): MutationKind | undefined {
  if (!query.startsWith("UNWIND $rows AS row")) {
    return undefined;
  }

  if (query.includes("MERGE (n {id: row.vertex})")) {
    return "node";
  }

  if (query.includes("MERGE (s)-[r:USED_BY ")) {
    return "derived";
  }

  if (query.includes("MERGE (s)-[r:")) {
    return "canonical";
  }

  return undefined;
}

class SuccessfulHydraStore {
  readonly nodes =
    new Map<number, StoredNode>();

  readonly relationships =
    new Map<number, StoredRelationship>();

  sessionsCreated = 0;
  sessionsClosed = 0;

  public readonly sessionFactory = (): Session => {
    this.sessionsCreated += 1;

    return new SuccessfulFakeSession(
      this,
    ) as unknown as Session;
  };

  public noteSessionClosed(): void {
    this.sessionsClosed += 1;
  }

  public async run(
    query: string,
    parameters: Readonly<UnknownRecord> = {},
    transactionConfig?: {
      readonly metadata?: Readonly<
        Record<string, string>
      >;
    },
  ): Promise<FakeResult> {
    const metadata =
      transactionConfig?.metadata ?? {};
    const mutationKind =
      mutationKindForQuery(query);

    if (mutationKind !== undefined) {
      if (mutationKind === "node") {
        this.upsertNodes(parameters);
      } else {
        this.upsertRelationships(
          query,
          parameters,
        );
      }

      return { records: [] };
    }

    const step =
      metadata["hydradb.caller.step"] ?? "";

    if (step.startsWith("preflight.")) {
      return { records: [] };
    }

    if (step.startsWith("verify.node.")) {
      return this.verifyNode(parameters);
    }

    if (step.startsWith("verify.edge.")) {
      return this.verifyRelationship(
        query,
        parameters,
      );
    }

    throw new Error(
      `Fake HydraDB received an unsupported query:\n${query}`,
    );
  }

  private upsertNodes(
    parameters: Readonly<UnknownRecord>,
  ): void {
    for (const row of requireRows(parameters)) {
      const vertex = requireNumber(
        row.vertex,
        "node vertex",
      );

      this.nodes.set(vertex, {
        ...row,
        vertex,
        logical_id: requireString(
          row.logical_id,
          "node logical_id",
        ),
        kind: requireString(
          row.kind,
          "node kind",
        ),
      });
    }
  }

  private upsertRelationships(
    query: string,
    parameters: Readonly<UnknownRecord>,
  ): void {
    const relationshipType = requireMatch(
      query,
      /MERGE \(s\)-\[r:([A-Za-z_][A-Za-z0-9_]*) /,
      "relationship type",
    );

    for (const row of requireRows(parameters)) {
      const relationshipVertex =
        requireNumber(
          row.relationship_vertex,
          "relationship vertex",
        );

      this.relationships.set(
        relationshipVertex,
        {
          ...row,
          relationship_vertex:
            relationshipVertex,
          source_vertex: requireNumber(
            row.source_vertex,
            "relationship source vertex",
          ),
          destination_vertex:
            requireNumber(
              row.destination_vertex,
              "relationship destination vertex",
          ),
          logical_id: requireString(
            row.logical_id,
            "relationship logical_id",
          ),
          kind: requireString(
            row.kind,
            "relationship kind",
          ),
          relationshipType,
        },
      );
    }
  }

  private verifyNode(
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const vertex = requireNumber(
      parameters.id,
      "verification node ID",
    );
    const node = this.nodes.get(vertex);

    if (node === undefined) {
      return { records: [] };
    }

    return {
      records: [
        new FakeRecord({
          logical_id: node.logical_id,
          kind: node.kind,
        }),
      ],
    };
  }

  private verifyRelationship(
    query: string,
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const relationshipType = requireMatch(
      query,
      /\[:([A-Za-z_][A-Za-z0-9_]*) \{/,
      "verification relationship type",
    );
    const sourceVertex = requireNumber(
      parameters.source_vertex,
      "verification source vertex",
    );
    const destinationVertex = requireNumber(
      parameters.destination_vertex,
      "verification destination vertex",
    );
    const relationshipVertex = requireNumber(
      parameters.relationship_vertex,
      "verification relationship vertex",
    );
    const logicalId = requireString(
      parameters.logical_id,
      "verification relationship logical identity",
    );
    const kind = requireString(
      parameters.kind,
      "verification relationship kind",
    );

    const records = [
      ...this.relationships.values(),
    ]
      .filter(
        (relationship) =>
          relationship.relationshipType ===
            relationshipType &&
          relationship.source_vertex ===
            sourceVertex &&
          relationship.destination_vertex ===
            destinationVertex &&
          relationship.relationship_vertex ===
            relationshipVertex &&
          relationship.logical_id ===
            logicalId &&
          relationship.kind === kind,
      )
      .map(
        (relationship) =>
          new FakeRecord({
            source_vertex:
              relationship.source_vertex,
            destination_vertex:
              relationship.destination_vertex,
          }),
      );

    return { records };
  }
}

class SuccessfulFakeSession {
  private closed = false;

  public constructor(
    private readonly store: SuccessfulHydraStore,
  ) {}

  public run(
    query: string,
    parameters?: Readonly<UnknownRecord>,
    transactionConfig?: {
      readonly metadata?: Readonly<
        Record<string, string>
      >;
    },
  ): Promise<FakeResult> {
    assert.equal(
      this.closed,
      false,
      "Cannot run a closed fake session",
    );

    return this.store.run(
      query,
      parameters,
      transactionConfig,
    );
  }

  public async close(): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      this.store.noteSessionClosed();
    }
  }
}

function createEvidence(
  suffix: string,
  detail: string,
): EvidenceNode {
  const identity = createEntityIdentity(
    `evidence:analysis:${suffix}`,
  );

  return {
    ...identity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt: OBSERVED_AT,
    sourceType: "synthetic-fixture",
    sourceUri:
      `fixture://analysis/${suffix}`,
    collectorVersion: "analysis-smoke-v2",
    confidence: 1,
    detail,
  };
}

function createFixture(): AnalysisFixture {
  const resolutionEvidence = createEvidence(
    "resolution",
    "Exact dependency resolution evidence",
  );
  const buildEvidence = createEvidence(
    "build",
    "Build inclusion evidence",
  );
  const deploymentEvidence = createEvidence(
    "deployment",
    "Deployment evidence",
  );
  const reachabilityEvidence = createEvidence(
    "reachability",
    "Runtime reachability evidence",
  );
  const executionEvidence = createEvidence(
    "execution",
    "Observed execution evidence",
  );

  const affectedIdentity = createEntityIdentity(
    "pkgver:npm:fixture-affected@1.0.0",
  );
  const affectedVersion: PackageVersionNode = {
    ...affectedIdentity,
    kind: "PackageVersion",
    evidenceIds: [resolutionEvidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    ecosystem: "npm",
    packageName: "fixture-affected",
    version: "1.0.0",
  };

  const bridgeIdentity = createEntityIdentity(
    "pkgver:npm:fixture-bridge@2.0.0",
  );
  const bridgeVersion: PackageVersionNode = {
    ...bridgeIdentity,
    kind: "PackageVersion",
    evidenceIds: [resolutionEvidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    ecosystem: "npm",
    packageName: "fixture-bridge",
    version: "2.0.0",
  };

  const alphaIdentity = createEntityIdentity(
    "service:fixture:alpha",
  );
  const alphaService: ServiceNode = {
    ...alphaIdentity,
    kind: "Service",
    evidenceIds: [resolutionEvidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    name: "alpha-service",
    criticality: "critical",
    internetExposed: true,
    dataSensitivity: "high",
  };

  const betaIdentity = createEntityIdentity(
    "service:fixture:beta",
  );
  const betaService: ServiceNode = {
    ...betaIdentity,
    kind: "Service",
    evidenceIds: [resolutionEvidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    name: "beta-service",
    criticality: "medium",
  };

  const alphaDirectPair = createDependencyPair({
    source: alphaService,
    target: affectedVersion,
    discriminator: "alpha-direct",
    dependencyType: "production",
    evidenceIds: [resolutionEvidence.id],
    observedAt: OBSERVED_AT,
    generatorVersion: "analysis-smoke-v2",
    declaredRange: "1.0.0",
    lockfilePath:
      "alpha/node_modules/fixture-affected",
  });

  const bridgeToAffectedPair =
    createDependencyPair({
      source: bridgeVersion,
      target: affectedVersion,
      discriminator: "bridge-to-affected",
      dependencyType: "production",
      evidenceIds: [resolutionEvidence.id],
      observedAt: OBSERVED_AT,
      generatorVersion: "analysis-smoke-v2",
      declaredRange: "1.0.0",
      lockfilePath:
        "bridge/node_modules/fixture-affected",
    });

  const betaDirectPair = createDependencyPair({
    source: betaService,
    target: affectedVersion,
    discriminator: "beta-direct",
    dependencyType: "production",
    evidenceIds: [resolutionEvidence.id],
    observedAt: OBSERVED_AT,
    generatorVersion: "analysis-smoke-v2",
    declaredRange: "1.0.0",
    lockfilePath:
      "beta/node_modules/fixture-affected",
  });

  const alphaThroughBridgePair =
    createDependencyPair({
      source: alphaService,
      target: bridgeVersion,
      discriminator: "alpha-through-bridge",
      dependencyType: "production",
      evidenceIds: [resolutionEvidence.id],
      observedAt: OBSERVED_AT,
      generatorVersion: "analysis-smoke-v2",
      declaredRange: "2.0.0",
      lockfilePath:
        "alpha/node_modules/fixture-bridge",
    });

  const cyclePair = createDependencyPair({
    source: affectedVersion,
    target: bridgeVersion,
    discriminator: "cycle-back-to-bridge",
    dependencyType: "production",
    evidenceIds: [resolutionEvidence.id],
    observedAt: OBSERVED_AT,
    generatorVersion: "analysis-smoke-v2",
    declaredRange: "2.0.0",
    lockfilePath:
      "affected/node_modules/fixture-bridge",
  });

  const pairs = [
    alphaDirectPair,
    bridgeToAffectedPair,
    betaDirectPair,
    alphaThroughBridgePair,
    cyclePair,
  ];

  const edges: GraphEdge[] = [];

  for (const pair of pairs) {
    edges.push(
      pair.canonical,
      pair.reverseIndex,
    );
  }

  const batch = mergeGraphFragments([
    {
      source: "analysis-smoke-production-fixture",
      nodes: [
        resolutionEvidence,
        buildEvidence,
        deploymentEvidence,
        reachabilityEvidence,
        executionEvidence,
        affectedVersion,
        bridgeVersion,
        alphaService,
        betaService,
      ],
      edges,
    },
  ]);

  return {
    batch,
    affectedVersion,
    bridgeVersion,
    alphaService,
    betaService,
    resolutionEvidence,
    buildEvidence,
    deploymentEvidence,
    reachabilityEvidence,
    executionEvidence,
    alphaDirectPair,
  };
}



function persistenceOptions(
  store: SuccessfulHydraStore,
): PersistenceServiceOptions {
  return {
    chunkSize: 1,
    maxAttempts: 1,
    retryDelayMs: 0,
    maxPartialReplays: 0,
    partialReplayDelayMs: 0,
    idempotencyKey: "analysis-smoke-v2",
    correlationId:
      "analysis-smoke-v2-correlation",
    sessionFactory: store.sessionFactory,
  };
}

function exposureSignals(
  fixture: AnalysisFixture,
): ExposureEvidenceSignals {
  return {
    semverEligible: true,
    exactResolutionEvidenceIds: [
      fixture.resolutionEvidence.id,
    ],
    buildEvidenceIds: [
      fixture.buildEvidence.id,
    ],
    deploymentEvidenceIds: [
      fixture.deploymentEvidence.id,
    ],
    reachabilityEvidenceIds: [
      fixture.reachabilityEvidence.id,
    ],
    executionEvidenceIds: [
      fixture.executionEvidence.id,
    ],
  };
}

async function verifyProductionPath(
  fixture: AnalysisFixture,
): Promise<void> {
  const store = new SuccessfulHydraStore();
  const service =
    new HydraPersistenceService(
      {} as Driver,
    );

  const report =
    await service.persistThenAnalyze(
      fixture.batch,
      (persisted) =>
        runBlastRadius(
          persisted,
          [fixture.affectedVersion.id],
        ),
      persistenceOptions(store),
    );

  assert.match(report.batchHash, /^[a-f0-9]{64}$/);
  assert.equal(
    report.correlationId,
    "analysis-smoke-v2-correlation",
  );
  assert.equal(report.totalPathCount, 3);
  assert.equal(report.services.length, 2);
  assert.equal(report.truncated, false);

  const alphaCandidate = report.services.find(
    (candidate) =>
      candidate.service.id ===
      fixture.alphaService.id,
  );
  const betaCandidate = report.services.find(
    (candidate) =>
      candidate.service.id ===
      fixture.betaService.id,
  );

  assert.ok(alphaCandidate);
  assert.ok(betaCandidate);
  assert.equal(alphaCandidate.paths.length, 2);
  assert.equal(alphaCandidate.minimumDepth, 1);
  assert.equal(betaCandidate.paths.length, 1);

  assert.ok(
    report.warnings.some(
      (warning) =>
        warning.code === "cycle-skipped",
    ),
  );

  assert.equal(
    store.sessionsClosed,
    store.sessionsCreated,
    "Every persistence session must close",
  );
}

async function verifyDerivedResolution(
  fixture: AnalysisFixture,
  reader: GraphBatchReader,
): Promise<void> {
  const page = await reader.findDependents(
    fixture.affectedVersion.id,
    {
      limit: 100,
    },
  );

  assert.equal(page.truncated, false);

  const hops = page.hops;

  assert.ok(hops.length >= 3);


  for (const hop of hops) {
    assert.equal(
      hop.canonicalEdge.kind,
      "DEPENDS_ON",
    );
    assert.equal(
      hop.canonicalEdge.derived,
      false,
    );
    assert.equal(
      hop.canonicalEdge.targetId,
      fixture.affectedVersion.id,
    );
    assert.notEqual(
      hop.traversalIndexEdgeId,
      undefined,
    );
  }
}

async function verifyEvidenceValidation(
  fixture: AnalysisFixture,
  reader: GraphBatchReader,
): Promise<void> {
  const assessment =
    await classifyExposureWithValidatedEvidence(
      reader,
      exposureSignals(fixture),
    );

  assert.equal(
    assessment.stage,
    "execution-observed",
  );
  assert.equal(
    assessment.conclusion,
    "executed",
  );
  assert.equal(
    assessment.evidenceIds.length,
    5,
  );

  await assert.rejects(
    classifyExposureWithValidatedEvidence(
      reader,
      {
        ...exposureSignals(fixture),
        executionEvidenceIds: [
          Number.MAX_SAFE_INTEGER,
        ],
      },
    ),
    (error: unknown) =>
      error instanceof
        ExposureEvidenceValidationError &&
      error.code === "missing-evidence",
  );

  await assert.rejects(
    classifyExposureWithValidatedEvidence(
      reader,
      {
        ...exposureSignals(fixture),
        executionEvidenceIds: [
          fixture.alphaService.id,
        ],
      },
    ),
    (error: unknown) =>
      error instanceof
        ExposureEvidenceValidationError &&
      error.code === "wrong-evidence-kind",
  );
}

async function verifyTraversalLimits(
  fixture: AnalysisFixture,
  reader: GraphBatchReader,
): Promise<void> {
  const boundedPage =
    await reader.findDependents(
      fixture.affectedVersion.id,
      {
        limit: 1,
      },
    );

  assert.equal(boundedPage.hops.length, 1);
  assert.equal(boundedPage.truncated, true);

  const roots = [fixture.affectedVersion.id];

  const stateLimited = await analyzeBlastRadius(
    reader,
    roots,
    {
      maxTraversalStates: 1,
    },
  );

  assert.equal(stateLimited.truncated, true);
  assert.ok(
    stateLimited.warnings.some(
      (warning) =>
        warning.code ===
        "traversal-state-limit-reached",
    ),
  );

  const fanOutLimited = await analyzeBlastRadius(
    reader,
    roots,
    {
      maxDependentsPerNode: 1,
    },
  );

  assert.equal(fanOutLimited.truncated, true);
  assert.ok(
    fanOutLimited.warnings.some(
      (warning) =>
        warning.code ===
        "dependents-per-node-limit-reached",
    ),
  );

  const depthLimited = await analyzeBlastRadius(
    reader,
    roots,
    {
      maxDepth: 1,
    },
  );

  assert.equal(depthLimited.truncated, true);
  assert.ok(
    depthLimited.warnings.some(
      (warning) =>
        warning.code ===
        "depth-limit-reached",
    ),
  );

  const perServiceLimited =
    await analyzeBlastRadius(
      reader,
      roots,
      {
        maxPathsPerService: 1,
      },
    );

  assert.equal(perServiceLimited.truncated, true);
  assert.ok(
    perServiceLimited.warnings.some(
      (warning) =>
        warning.code ===
        "paths-per-service-limit-reached",
    ),
  );

  const totalPathLimited =
    await analyzeBlastRadius(
      reader,
      roots,
      {
        maxTotalPaths: 1,
      },
    );

  assert.equal(totalPathLimited.truncated, true);
  assert.ok(
    totalPathLimited.warnings.some(
      (warning) =>
        warning.code ===
        "path-limit-reached",
    ),
  );

  const warningLimited =
    await analyzeBlastRadius(
      reader,
      [
        Number.MAX_SAFE_INTEGER - 1,
        Number.MAX_SAFE_INTEGER,
      ],
      {
        maxWarnings: 1,
      },
    );

  assert.equal(warningLimited.truncated, true);
  assert.deepEqual(
    warningLimited.warnings.map(
      (warning) => warning.code,
    ),
    ["warning-limit-reached"],
  );
}

async function verifyMalformedCanonicalHop(
  fixture: AnalysisFixture,
  reader: GraphBatchReader,
): Promise<void> {
  const malformedCanonical = {
    ...fixture.alphaDirectPair.canonical,
    derived: true,
  } as unknown as DependencyEdge;

  const malformedReader: ReadonlyGraphReader = {
    getNode: (nodeId) =>
      reader.getNode(nodeId),

    findDependents: async (
      nodeId,
      options,
    ) => {
      const hops: DependencyHop[] =
        nodeId === fixture.affectedVersion.id
          ? [
              {
                dependentNode:
                  fixture.alphaService,
                canonicalEdge:
                  malformedCanonical,
              },
            ]
          : [];

      return {
        hops: hops.slice(0, options.limit),
        truncated: hops.length > options.limit,
      };
    },


    getEvidence: (evidenceIds) =>
      reader.getEvidence(evidenceIds),
  };

  const result = await analyzeBlastRadius(
    malformedReader,
    [fixture.affectedVersion.id],
  );

  assert.equal(result.services.length, 0);
  assert.ok(
    result.warnings.some(
      (warning) =>
        warning.code ===
        "invalid-canonical-hop",
    ),
  );
}

async function main(): Promise<void> {
  const fixture = createFixture();

  assert.equal(
    fixture.batch.validation.valid,
    true,
  );
  assert.equal(
    Object.isFrozen(fixture.batch),
    true,
  );
  assert.equal(
    Object.isFrozen(fixture.batch.nodes),
    true,
  );
  assert.equal(
    Object.isFrozen(fixture.batch.edges),
    true,
  );

  const sourceSnapshot =
    JSON.stringify(fixture.batch);

  const reader =
    new GraphBatchReader(fixture.batch);

  await verifyDerivedResolution(
    fixture,
    reader,
  );
  await verifyProductionPath(
    fixture,
  );
  await verifyEvidenceValidation(
    fixture,
    reader,
  );
  await verifyTraversalLimits(
    fixture,
    reader,
  );
  await verifyMalformedCanonicalHop(
    fixture,
    reader,
  );

  assert.equal(
    JSON.stringify(fixture.batch),
    sourceSnapshot,
    "Analysis must not mutate the immutable source graph",
  );

  console.log(
    "HydraSCOPE analysis smoke passed",
  );
  console.log(
    "- deterministic identities and GraphBatch validation passed",
  );
  console.log(
    "- DEPENDS_ON and USED_BY parity passed",
  );
  console.log(
    "- verified persistence gated production analysis",
  );
  console.log(
    "- evidence existence and node-kind validation passed",
  );
  console.log(
    "- traversal, fan-out, depth, path, and warning limits passed",
  );
  console.log(
    "- malformed canonical hops fail closed",
  );
  console.log(
    "- immutable source graph remained unchanged",
  );
}

await main();
