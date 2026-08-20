import assert from "node:assert/strict";

import type {
  Driver,
  Session,
} from "neo4j-driver";

import {
  createDependencyPair,
} from "../../domain/factories.js";

import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../../domain/identity.js";

import type {
  CanonicalEdge,
  EvidenceNode,
  GraphEdge,
  GraphNode,
  IncidentNode,
  PackageVersionNode,
  ServiceNode,
} from "../../domain/schema.js";

import {
  serializeHydraEdge,
  serializeHydraNode,
} from "../../db/hydra-serializer.js";

import type {
  HydraEdgeRow,
  HydraNodeRow,
} from "../../db/hydra-serializer.js";

import {
  runLiveBlastRadius,
} from "../live-analysis.js";

import {
  HydraGraphReaderError,
} from "../readers/hydra-graph-reader.js";

type UnknownRecord =
  Record<string, unknown>;

interface FakeResult {
  readonly records:
    readonly FakeRecord[];
}

interface QueryObservation {
  readonly step: string;
  readonly query: string;
}

interface Fixture {
  readonly incident:
    IncidentNode;

  readonly affectedVersion:
    PackageVersionNode;

  readonly service:
    ServiceNode;

  readonly evidence:
    EvidenceNode;

  readonly nodes:
    readonly GraphNode[];

  readonly edges:
    readonly GraphEdge[];

  readonly dependencyEdgeId:
    number;
}

interface StoreOptions {
  readonly missingEvidenceIds?:
    ReadonlySet<number>;

  readonly tamperedNodeIds?:
    ReadonlySet<number>;

  readonly missingCanonicalEdgeIds?:
    ReadonlySet<number>;

  readonly evidenceSourceTypeOverride?:
    EvidenceNode["sourceType"];

  readonly evidenceConfidenceOverride?:
    number;

  readonly additionalEvidenceNodes?:
    readonly EvidenceNode[];

  readonly additionalDependencyEvidenceIds?:
    readonly number[];
}

const OBSERVED_AT =
  1_700_000_000_000;

const COMPLETED_AT =
  OBSERVED_AT + 37;

class FakeRecord {
  constructor(
    private readonly values:
      Readonly<UnknownRecord>,
  ) {}

  public get(
    key: string,
  ): unknown {
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
  field: string,
): UnknownRecord {
  assert.ok(
    isRecord(value),
    `${field} must be a record`,
  );

  return value;
}

function requireSafeInteger(
  value: unknown,
  description: string,
): number {
  let converted = value;

  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof (value as any).toNumber === "function"
  ) {
    converted = (value as any).toNumber();
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

  return converted as number;
}

function limitFromQuery(
  query: string,
): number {
  const match =
    query.match(
      /LIMIT\s+(\d+)\s*$/,
    );

  assert.ok(
    match?.[1] !== undefined,
    "Every smoke read must have a literal LIMIT",
  );

  const limit =
    Number(match[1]);

  assert.ok(
    Number.isSafeInteger(limit) &&
      limit > 0,
    "Query LIMIT must be a positive safe integer",
  );

  return limit;
}

function projectNode(
  prefix: string,
  row: HydraNodeRow,
  tampered = false,
): UnknownRecord {
  const output: UnknownRecord = {
    [`${prefix}_vertex`]:
      row.vertex,
  };

  for (
    const [key, value]
    of Object.entries(row)
  ) {
    if (key === "vertex") {
      continue;
    }

    output[
      `${prefix}_${key}`
    ] = value;
  }

  /*
   * Mutate one projected field without recomputing payload_hash. The strict
   * deserializer must reject this row.
   */
  if (
    tampered &&
    row.kind === "Service"
  ) {
    output[
      `${prefix}_name`
    ] = "tampered-service-name";
  }

  return output;
}

function projectEdge(
  prefix: string,
  row: HydraEdgeRow,
): UnknownRecord {
  const output: UnknownRecord = {
    [`${prefix}_vertex`]:
      row.relationship_vertex,
  };

  for (
    const [key, value]
    of Object.entries(row)
  ) {
    if (
      key ===
        "relationship_vertex" ||
      key === "source_vertex" ||
      key ===
        "destination_vertex"
    ) {
      continue;
    }

    output[
      `${prefix}_${key}`
    ] = value;
  }

  return output;
}

function createAffectsEdge(
  incident: IncidentNode,
  version: PackageVersionNode,
  evidenceId: number,
  discriminator: string,
): CanonicalEdge {
  const identity =
    createEdgeIdentity({
      kind: "AFFECTS",
      sourceLogicalId:
        incident.logicalId,
      targetLogicalId:
        version.logicalId,
      discriminator,
    });

  return {
    ...identity,
    kind: "AFFECTS",
    sourceId: incident.id,
    targetId: version.id,
    observedAt: OBSERVED_AT,
    derived: false,
    identityDiscriminator:
      discriminator,
    evidenceIds: [
      evidenceId,
    ],
  };
}

function createFixture(
  includeSecondAffectedVersion = false,
): Fixture {
  const incidentIdentity =
    createEntityIdentity(
      "incident:live-analysis-smoke",
    );

  const evidenceIdentity =
    createEntityIdentity(
      "evidence:live-analysis-smoke:advisory",
    );

  const evidence: EvidenceNode = {
    ...evidenceIdentity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt: OBSERVED_AT,
    sourceType:
      "synthetic-fixture",
    sourceUri:
      "fixture://live-analysis/advisory",
    collectorVersion:
      "live-analysis-smoke-v1",
    confidence: 0.96,
    detail:
      "Synthetic advisory and lockfile evidence for live HydraDB analysis",
    incidentId:
      incidentIdentity.id,
  };

  const incident: IncidentNode = {
    ...incidentIdentity,
    kind: "Incident",
    evidenceIds: [
      evidence.id,
    ],
    synthetic: true,
    observedAt: OBSERVED_AT,
    title:
      "Synthetic poisoned package incident",
    status: "active",
    intervalStart:
      OBSERVED_AT - 60_000,
    intervalEnd: null,
  };

  const affectedIdentity =
    createEntityIdentity(
      "pkgver:npm:poisoned-demo-lib@1.2.4",
    );

  const affectedVersion:
    PackageVersionNode = {
      ...affectedIdentity,
      kind: "PackageVersion",
      evidenceIds: [
        evidence.id,
      ],
      synthetic: true,
      observedAt: OBSERVED_AT,
      ecosystem: "npm",
      packageName:
        "poisoned-demo-lib",
      version: "1.2.4",
      publishedAt:
        OBSERVED_AT - 3_600_000,
    };

  const serviceIdentity =
    createEntityIdentity(
      "service:demo-org:payments-api",
    );

  const service: ServiceNode = {
    ...serviceIdentity,
    kind: "Service",
    evidenceIds: [
      evidence.id,
    ],
    synthetic: true,
    observedAt: OBSERVED_AT,
    name: "payments-api",
    criticality: "critical",
    internetExposed: true,
    dataSensitivity: "high",
  };

  const dependencyPair =
    createDependencyPair({
      source: service,
      target: affectedVersion,
      discriminator:
        "package-lock:payments-api>poisoned-demo-lib",
      dependencyType:
        "production",
      evidenceIds: [
        evidence.id,
      ],
      observedAt: OBSERVED_AT,
      generatorVersion:
        "live-analysis-smoke-v1",
      declaredRange: "^1.2.0",
      lockfilePath:
        "node_modules/poisoned-demo-lib",
    });

  const nodes: GraphNode[] = [
    incident,
    evidence,
    affectedVersion,
    service,
  ];

  const edges: GraphEdge[] = [
    createAffectsEdge(
      incident,
      affectedVersion,
      evidence.id,
      "synthetic-advisory-primary",
    ),
    dependencyPair.canonical,
    dependencyPair.reverseIndex,
  ];

  if (
    includeSecondAffectedVersion
  ) {
    const secondIdentity =
      createEntityIdentity(
        "pkgver:npm:poisoned-demo-lib@1.2.5",
      );

    const secondVersion:
      PackageVersionNode = {
        ...secondIdentity,
        kind: "PackageVersion",
        evidenceIds: [
          evidence.id,
        ],
        synthetic: true,
        observedAt: OBSERVED_AT,
        ecosystem: "npm",
        packageName:
          "poisoned-demo-lib",
        version: "1.2.5",
      };

    nodes.push(secondVersion);

    const secondDependencyPair =
      createDependencyPair({
        source: service,
        target: secondVersion,
        discriminator:
          "package-lock:payments-api>poisoned-demo-lib-secondary",
        dependencyType:
          "production",
        evidenceIds: [
          evidence.id,
        ],
        observedAt: OBSERVED_AT,
        generatorVersion:
          "live-analysis-smoke-v1",
        declaredRange: "^1.2.0",
        lockfilePath:
          "node_modules/poisoned-demo-lib",
      });

    edges.push(
      createAffectsEdge(
        incident,
        secondVersion,
        evidence.id,
        "synthetic-advisory-secondary",
      ),
      secondDependencyPair.canonical,
      secondDependencyPair.reverseIndex,
    );
  }

  return {
    incident,
    affectedVersion,
    service,
    evidence,
    nodes,
    edges,
    dependencyEdgeId:
      dependencyPair.canonical.id,
  };
}

class FakeHydraReadStore {
  private readonly nodeRows =
    new Map<number, HydraNodeRow>();

  private readonly edgeRows =
    new Map<number, HydraEdgeRow>();

  public sessionsCreated = 0;
  public sessionsClosed = 0;

  public readonly observations:
    QueryObservation[] = [];

  constructor(
    fixture: Fixture,
    private readonly options:
      StoreOptions = {},
  ) {
    for (const node of fixture.nodes) {
      const sourceNode =
        node.kind === "Evidence" &&
        (this.options
          .evidenceSourceTypeOverride !==
          undefined ||
          this.options
            .evidenceConfidenceOverride !==
            undefined)
          ? {
              ...node,
              ...(this.options
                .evidenceSourceTypeOverride ===
                undefined
                ? {}
                : {
                    sourceType:
                      this.options
                        .evidenceSourceTypeOverride,
                  }),
              ...(this.options
                .evidenceConfidenceOverride ===
                undefined
                ? {}
                : {
                    confidence:
                      this.options
                        .evidenceConfidenceOverride,
                  }),
            }
          : node;

      const row =
        serializeHydraNode(sourceNode);

      this.nodeRows.set(
        row.vertex,
        row,
      );
    }

    for (
      const evidence of
      this.options.additionalEvidenceNodes ??
        []
    ) {
      const row =
        serializeHydraNode(evidence);

      this.nodeRows.set(
        row.vertex,
        row,
      );
    }

    for (const edge of fixture.edges) {
      const additionalEvidenceIds =
        edge.kind === "DEPENDS_ON" &&
        edge.derived === false
          ? this.options
              .additionalDependencyEvidenceIds ??
            []
          : [];

      const sourceEdge: GraphEdge =
        edge.kind === "DEPENDS_ON" &&
        edge.derived === false &&
        additionalEvidenceIds.length > 0
          ? {
              ...edge,
              evidenceIds: [
                ...(edge.evidenceIds ?? []),
                ...additionalEvidenceIds,
              ],
            }
          : edge;

      const row =
        serializeHydraEdge(sourceEdge);

      this.edgeRows.set(
        row.relationship_vertex,
        row,
      );
    }
  }

  public readonly sessionFactory =
    (): Session => {
      this.sessionsCreated += 1;

      return new FakeHydraSession(
        this,
      ) as unknown as Session;
    };

  public noteClosed(): void {
    this.sessionsClosed += 1;
  }

  public async run(
    query: string,
    parameters:
      Readonly<UnknownRecord> = {},
    transactionConfig?: {
      readonly metadata?:
        Readonly<
          Record<string, string>
        >;
    },
  ): Promise<FakeResult> {
    const step =
      transactionConfig
        ?.metadata
        ?.[
          "hydradb.caller.step"
        ] ?? "";

    this.observations.push({
      step,
      query,
    });

    assert.match(
      query,
      /ORDER BY/,
      `${step} must use deterministic ORDER BY`,
    );

    limitFromQuery(query);

    switch (step) {
      case "get-node":
        return this.getNode(
          parameters,
        );

      case "find-affected-versions":
        return this.findAffectedVersions(
          query,
          parameters,
        );

      case "find-dependents":
        return this.findDependents(
          query,
          parameters,
        );

      case "get-evidence":
        return this.getEvidence(
          query,
          parameters,
        );

      default:
        throw new Error(
          `Unsupported fake HydraDB read step: ${step}`,
        );
    }
  }

  private getNode(
    parameters:
      Readonly<UnknownRecord>,
  ): FakeResult {
    const nodeId =
      requireSafeInteger(
        parameters.node_id,
        "node_id",
      );

    const row =
      this.nodeRows.get(nodeId);

    if (row === undefined) {
      return {
        records: [],
      };
    }

    const tampered =
      this.options
        .tamperedNodeIds
        ?.has(nodeId) === true;

    return {
      records: [
        new FakeRecord(
          projectNode(
            "node",
            row,
            tampered,
          ),
        ),
      ],
    };
  }

  private findAffectedVersions(
    query: string,
    parameters:
      Readonly<UnknownRecord>,
  ): FakeResult {
    const incidentId =
      requireSafeInteger(
        parameters.incident_id,
        "incident_id",
      );

    const incidentRow =
      this.nodeRows.get(
        incidentId,
      );

    if (
      incidentRow === undefined
    ) {
      return {
        records: [],
      };
    }

    const rows = [
      ...this.edgeRows.values(),
    ]
      .filter(
        (edge) =>
          edge.kind === "AFFECTS" &&
          edge.source_vertex ===
            incidentId,
      )
      .sort(
        (left, right) =>
          left.destination_vertex -
            right.destination_vertex ||
          left.relationship_vertex -
            right.relationship_vertex,
      )
      .slice(
        0,
        limitFromQuery(query),
      );

    const records =
      rows.map((edge) => {
        const version =
          this.nodeRows.get(
            edge.destination_vertex,
          );

        assert.ok(
          version,
          "AFFECTS target must exist",
        );

        return new FakeRecord({
          incident_vertex:
            incidentRow.vertex,

          incident_logical_id:
            incidentRow.logical_id,

          ...projectNode(
            "version",
            version,
          ),

          ...projectEdge(
            "affects",
            edge,
          ),
        });
      });

    return {
      records,
    };
  }

  private findDependents(
    query: string,
    parameters:
      Readonly<UnknownRecord>,
  ): FakeResult {
    const rootId =
      requireSafeInteger(
        parameters.node_id,
        "node_id",
      );

    const root =
      this.nodeRows.get(rootId);

    if (root === undefined) {
      return {
        records: [],
      };
    }

    const reverseEdges = [
      ...this.edgeRows.values(),
    ]
      .filter(
        (edge) =>
          edge.kind === "USED_BY" &&
          edge.source_vertex ===
            rootId,
      )
      .sort(
        (left, right) => {
          const leftDerived =
            requireSafeInteger(
              left.derived_from,
              "left.derived_from",
            );

          const rightDerived =
            requireSafeInteger(
              right.derived_from,
              "right.derived_from",
            );

          return (
            leftDerived -
              rightDerived ||
            left.destination_vertex -
              right.destination_vertex ||
            left.relationship_vertex -
              right.relationship_vertex
          );
        },
      )
      .slice(
        0,
        limitFromQuery(query),
      );

    const records =
      reverseEdges.map(
        (reverse) => {
          const dependent =
            this.nodeRows.get(
              reverse.destination_vertex,
            );

          assert.ok(
            dependent,
            "USED_BY dependent must exist",
          );

          const canonicalId =
            requireSafeInteger(
              reverse.derived_from,
              "derived_from",
            );

          const canonical =
            this.options
              .missingCanonicalEdgeIds
              ?.has(canonicalId) ===
            true
              ? undefined
              : this.edgeRows.get(
                  canonicalId,
                );

          return new FakeRecord({
            root_vertex:
              root.vertex,

            root_logical_id:
              root.logical_id,

            ...projectNode(
              "dependent",
              dependent,
              this.options
                .tamperedNodeIds
                ?.has(
                  dependent.vertex,
                ) === true,
            ),

            ...projectEdge(
              "reverse",
              reverse,
            ),

            canonical_vertex:
              canonical
                ?.relationship_vertex ??
              null,

            ...(canonical ===
            undefined
              ? {}
              : projectEdge(
                  "canonical",
                  canonical,
                )),
          });
        },
      );

    return {
      records,
    };
  }

  private getEvidence(
    query: string,
    parameters:
      Readonly<UnknownRecord>,
  ): FakeResult {
    /*
     * Evidence is read one node per statement, because HydraDB restricts
     * UNWIND batches to one-hop relationship patterns and accepts composite
     * parameters only as UNWIND input.
     */
    const requestedIds = [
      requireSafeInteger(
        parameters.node_id,
        "node_id",
      ),
    ];

    const records =
      requestedIds
        .filter(
          (evidenceId) =>
            this.options
              .missingEvidenceIds
              ?.has(evidenceId) !==
            true,
        )
        .map((evidenceId) =>
          this.nodeRows.get(
            evidenceId,
          ),
        )
        .filter(
          (
            row,
          ): row is HydraNodeRow =>
            row !== undefined &&
            row.kind === "Evidence",
        )
        .slice(
          0,
          limitFromQuery(query),
        )
        .map(
          (row) =>
            new FakeRecord(
              projectNode(
                "evidence",
                row,
              ),
            ),
        );

    return {
      records,
    };
  }
}

class FakeHydraSession {
  private closed = false;

  constructor(
    private readonly store:
      FakeHydraReadStore,
  ) {}

  public run(
    query: string,
    parameters?:
      Readonly<UnknownRecord>,
    transactionConfig?: {
      readonly metadata?:
        Readonly<
          Record<string, string>
        >;
    },
  ): Promise<FakeResult> {
    assert.equal(
      this.closed,
      false,
      "A closed fake session cannot be reused",
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
      this.store.noteClosed();
    }
  }
}

function deterministicClock(
  start: number,
  completed: number,
): () => number {
  let callCount = 0;

  return () => {
    callCount += 1;

    if (callCount === 1) {
      return start;
    }

    return completed;
  };
}

function assertSessionsClosed(
  store: FakeHydraReadStore,
): void {
  assert.equal(
    store.sessionsClosed,
    store.sessionsCreated,
    "Every HydraDB read session must close",
  );
}

async function verifySuccessfulLiveAnalysis(
  fixture: Fixture,
): Promise<void> {
  const store =
    new FakeHydraReadStore(
      fixture,
    );

  const result =
    await runLiveBlastRadius(
      {} as Driver,
      fixture.incident.id,
      {
        maxAffectedVersions: 10,

        blastRadius: {
          maxDepth: 8,
          maxServices: 10,
          maxPathsPerService: 10,
          maxTotalPaths: 100,
          maxTraversalStates: 100,
          maxDependentsPerNode: 10,
          maxWarnings: 20,
        },

        evidenceFunnel: {
          highConfidenceThreshold:
            0.8,
          maxEvidenceIds: 100,
          evidenceReadChunkSize: 10,
        },

        reader: {
          statementTimeoutMs:
            5_000,
          maxPageSize: 100,
          maxEvidenceIdsPerRead: 100,
          sessionFactory:
            store.sessionFactory,
        },

        clock:
          deterministicClock(
            OBSERVED_AT,
            COMPLETED_AT,
          ),
      },
    );

  assert.equal(
    result.incidentId,
    fixture.incident.id,
  );

  assert.deepEqual(
    result.affectedVersionIds,
    [
      fixture.affectedVersion.id,
    ],
  );

  assert.equal(
    result.services.length,
    1,
  );

  assert.equal(
    result.totalPathCount,
    1,
  );

  assert.equal(
    result.truncated,
    false,
  );
  assert.deepEqual(
    result.incident,
    {
        id:
        fixture.incident.id,
        title:
        fixture.incident.title,
        status:
        fixture.incident.status,
        intervalStart:
        fixture.incident
            .intervalStart,
        intervalEnd:
        fixture.incident
            .intervalEnd,
        synthetic:
        fixture.incident.synthetic,
    },
    );

    assert.deepEqual(
    result.affectedVersions,
    [
        {
        id:
            fixture.affectedVersion.id,

        packageName:
            fixture.affectedVersion
            .packageName,

        version:
            fixture.affectedVersion
            .version,

        publishedAt:
            fixture.affectedVersion
            .publishedAt,

        synthetic:
            fixture.affectedVersion
            .synthetic,
        },
    ],
    );

    assert.deepEqual(
    result.evidenceCatalog,
    [
        {
        id:
            fixture.evidence.id,

        sourceType:
            fixture.evidence
            .sourceType,

        confidence:
            fixture.evidence
            .confidence,

        observedAt:
            fixture.evidence
            .observedAt,

        synthetic:
            fixture.evidence
            .synthetic,

        incidentLinked: true,
        },
    ],
    );
  const publicEvidence =
    result.evidenceCatalog[0];

    assert.ok(publicEvidence);

    assert.equal(
    "sourceUri" in publicEvidence,
    false,
    );

    assert.equal(
    "detail" in publicEvidence,
    false,
    );

    assert.equal(
    "collectorVersion" in
        publicEvidence,
    false,
    );

  const candidate =
    result.services[0];

  assert.ok(candidate);

  assert.equal(
    candidate.service.id,
    fixture.service.id,
  );

  assert.equal(
    candidate.minimumDepth,
    1,
  );

  assert.equal(
    candidate.paths.length,
    1,
  );

  const impact =
    result.serviceImpacts[0];

  assert.ok(impact);
  assert.equal(
    impact.serviceId,
    fixture.service.id,
  );
  assert.equal(
    impact.stage,
    "resolved",
  );
  assert.equal(
    impact.conclusion,
    "affected",
  );
  assert.equal(
    impact.confidence.level,
    "strong",
  );
  assert.equal(
    impact.confidence.policyVersion,
    "service-impact-v1",
  );
  assert.equal(
    impact.confidence.complete,
    true,
  );
  assert.equal(
    impact.confidence.synthetic,
    true,
  );
  assert.equal(
    impact.selection.state,
    "exactly-resolved",
  );
  assert.deepEqual(
    impact.selection.dependencyTypes,
    ["production"],
  );
  assert.deepEqual(
    impact.selection.declaredRanges,
    ["^1.2.0"],
  );
  assert.deepEqual(
    impact.selection.lockfilePaths,
    ["node_modules/poisoned-demo-lib"],
  );
  assert.deepEqual(
    impact.selection.resolvedVersions,
    [
      {
        id: fixture.affectedVersion.id,
        packageName:
          fixture.affectedVersion.packageName,
        version:
          fixture.affectedVersion.version,
      },
    ],
  );
  assert.equal(
    impact.temporal.status,
    "unknown",
  );
  assert.equal(
    impact.temporal.asOf,
    OBSERVED_AT,
  );
  assert.equal(
    impact.build.status,
    "not-proven",
  );
  assert.equal(
    impact.deployment.status,
    "not-proven",
  );
  assert.equal(
    impact.runtime.status,
    "not-proven",
  );
  assert.equal(
    impact.authority.status,
    "not-proven",
  );
  assert.equal(
    impact.paths.length,
    1,
  );
  assert.equal(
    impact.paths[0]?.stage,
    "resolved",
  );
  assert.equal(
    impact.complete,
    true,
  );

  const path =
    candidate.paths[0];

  assert.ok(path);

  assert.equal(
    path.canonicalEdges.length,
    1,
  );

  assert.equal(
    path.canonicalEdges[0]?.kind,
    "DEPENDS_ON",
  );

  assert.equal(
    path.canonicalEdges[0]?.derived,
    false,
  );

  assert.equal(
    path.canonicalEdges[0]?.id,
    fixture.dependencyEdgeId,
  );

  /*
   * USED_BY is a traversal index only and must never be returned as the
   * evidence path.
   */
  assert.equal(
    path.canonicalEdges.some(
      (edge) =>
        edge.kind ===
          ("USED_BY" as string),
    ),
    false,
  );

  const funnel =
    result.evidenceFunnel.stages;

  assert.deepEqual(
    funnel.map(
      (stage) =>
        stage.pathCount,
    ),
    [1, 1, 1],
  );

  assert.deepEqual(
    funnel.map(
      (stage) =>
        stage.serviceCount,
    ),
    [1, 1, 1],
  );

  assert.equal(
    result.evidenceFunnel
      .evidenceLookup
      .complete,
    true,
  );

  assert.equal(
    result.evidenceFunnel
      .completeForIncident,
    true,
  );

  assert.deepEqual(
    result.evidenceFunnel
      .sources,
    [
      {
        sourceType:
          "synthetic-fixture",
        evidenceCount: 1,
        averageConfidence: 0.96,
      },
    ],
  );

  assert.equal(
    result.hydraRead.engine,
    "HydraDB",
  );

  assert.equal(
    result.hydraRead
      .consistencyModel,
    "bounded-multi-statement-read",
  );

  assert.equal(
    result.hydraRead.readEpochMs,
    OBSERVED_AT,
  );

  assert.equal(
    result.hydraRead.latencyMs,
    37,
  );

  assert.equal(
  result.hydraRead.queryCount,
  6,
);

assert.equal(
  result.hydraRead.rowsRead,
  6,
);


  assert.equal(
    store.observations.some(
      (observation) =>
        observation.step ===
          "find-dependents" &&
        observation.query.includes(
          "OPTIONAL MATCH",
        ) &&
        observation.query.includes(
          "LIMIT 11",
        ),
    ),
    true,
  );

  assertSessionsClosed(store);
}

async function verifyMissingEvidenceDoesNotCreateFalseClaims(
  fixture: Fixture,
): Promise<void> {
  const store =
    new FakeHydraReadStore(
      fixture,
      {
        missingEvidenceIds:
          new Set([
            fixture.evidence.id,
          ]),
      },
    );

  const result =
    await runLiveBlastRadius(
      {} as Driver,
      fixture.incident.id,
      {
        reader: {
          sessionFactory:
            store.sessionFactory,
        },

        clock:
          deterministicClock(
            OBSERVED_AT,
            COMPLETED_AT,
          ),
      },
    );

  assert.deepEqual(
    result.evidenceFunnel
      .stages
      .map(
        (stage) =>
          stage.pathCount,
      ),
    [1, 0, 0],
  );

  assert.equal(
    result.evidenceFunnel
      .evidenceLookup
      .missingEvidenceCount,
    1,
  );

  assert.deepEqual(
    result.evidenceFunnel
      .evidenceLookup
      .missingEvidenceIds,
    [
      fixture.evidence.id,
    ],
  );

  assert.equal(
    result.evidenceFunnel
      .completeForReturnedCandidates,
    false,
  );

  assert.equal(
    result.evidenceFunnel
      .completeForIncident,
    false,
  );

  const impact =
    result.serviceImpacts[0];

  assert.ok(impact);
  assert.equal(
    impact.stage,
    "candidate",
  );
  assert.equal(
    impact.conclusion,
    "candidate",
  );
  assert.equal(
    impact.confidence.level,
    "unknown",
  );
  assert.equal(
    impact.confidence.complete,
    false,
  );
  assert.equal(
    impact.selection.state,
    "unknown",
  );
  assert.equal(
    impact.complete,
    false,
  );
  assert.deepEqual(
    impact.paths[0]
      ?.missingEvidenceIds,
    [fixture.evidence.id],
  );

  const serialized =
    JSON.stringify(result);

  assert.equal(
    serialized.includes(
      '"conclusion":"executed"',
    ),
    false,
  );

  assert.equal(
    serialized.includes(
      '"conclusion":"compromised"',
    ),
    false,
  );

  assertSessionsClosed(store);
}

async function verifyContextualEvidenceRemainsCandidate(
  fixture: Fixture,
): Promise<void> {
  const store =
    new FakeHydraReadStore(
      fixture,
      {
        evidenceSourceTypeOverride:
          "npm-registry",
      },
    );

  const result =
    await runLiveBlastRadius(
      {} as Driver,
      fixture.incident.id,
      {
        reader: {
          sessionFactory:
            store.sessionFactory,
        },

        clock:
          deterministicClock(
            OBSERVED_AT,
            COMPLETED_AT,
          ),
      },
    );

  const impact =
    result.serviceImpacts[0];

  assert.ok(impact);
  assert.equal(
    impact.stage,
    "candidate",
  );
  assert.equal(
    impact.conclusion,
    "candidate",
  );
  assert.equal(
    impact.confidence.level,
    "contextual",
  );
  assert.equal(
    impact.confidence.complete,
    true,
  );
  assert.equal(
    impact.selection.state,
    "unknown",
  );
  assert.equal(
    impact.complete,
    true,
  );
  assert.match(
    impact.summary,
    /structurally connected/,
  );

  assertSessionsClosed(store);
}

async function verifyContextualEvidenceCannotInflateExactConfidence(
  fixture: Fixture,
): Promise<void> {
  const contextualIdentity =
    createEntityIdentity(
      "evidence:live-analysis-smoke:high-confidence-context",
    );

  const contextualEvidence: EvidenceNode = {
    ...contextualIdentity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt: OBSERVED_AT,
    sourceType: "npm-registry",
    sourceUri:
      "fixture://live-analysis/contextual-registry",
    collectorVersion:
      "live-analysis-smoke-v1",
    confidence: 0.99,
    detail:
      "High-confidence contextual metadata that must not inflate exact-resolution confidence",
    incidentId:
      fixture.incident.id,
  };

  const store =
    new FakeHydraReadStore(
      fixture,
      {
        evidenceConfidenceOverride:
          0.2,
        additionalEvidenceNodes: [
          contextualEvidence,
        ],
        additionalDependencyEvidenceIds: [
          contextualEvidence.id,
        ],
      },
    );

  const result =
    await runLiveBlastRadius(
      {} as Driver,
      fixture.incident.id,
      {
        reader: {
          sessionFactory:
            store.sessionFactory,
        },

        clock:
          deterministicClock(
            OBSERVED_AT,
            COMPLETED_AT,
          ),
      },
    );

  const impact =
    result.serviceImpacts[0];

  assert.ok(impact);
  assert.equal(
    impact.stage,
    "resolved",
  );
  assert.equal(
    impact.conclusion,
    "affected",
  );
  assert.equal(
    impact.confidence.level,
    "probable",
  );
  assert.deepEqual(
    impact.confidence
      .supportingEvidenceIds,
    [fixture.evidence.id],
  );
  assert.deepEqual(
    impact.evidenceIds,
    [
      fixture.evidence.id,
      contextualEvidence.id,
    ].sort((left, right) => left - right),
  );

  assertSessionsClosed(store);
}

async function verifyPartialMissingEvidenceFailsClosed(
  fixture: Fixture,
): Promise<void> {
  const missingEvidenceId =
    createEntityIdentity(
      "evidence:live-analysis-smoke:missing-lock-proof",
    ).id;

  const store =
    new FakeHydraReadStore(
      fixture,
      {
        additionalDependencyEvidenceIds:
          [missingEvidenceId],
      },
    );

  const result =
    await runLiveBlastRadius(
      {} as Driver,
      fixture.incident.id,
      {
        reader: {
          sessionFactory:
            store.sessionFactory,
        },

        clock:
          deterministicClock(
            OBSERVED_AT,
            COMPLETED_AT,
          ),
      },
    );

  assert.equal(
    result.evidenceFunnel
      .evidenceLookup
      .complete,
    false,
  );
  assert.deepEqual(
    result.evidenceFunnel
      .evidenceLookup
      .missingEvidenceIds,
    [missingEvidenceId],
  );

  const impact =
    result.serviceImpacts[0];

  assert.ok(impact);
  assert.equal(
    impact.stage,
    "candidate",
  );
  assert.equal(
    impact.conclusion,
    "candidate",
  );
  assert.equal(
    impact.confidence.level,
    "unknown",
  );
  assert.equal(
    impact.confidence.complete,
    false,
  );
  assert.equal(
    impact.selection.state,
    "unknown",
  );
  assert.equal(
    impact.complete,
    false,
  );
  assert.deepEqual(
    impact.paths[0]
      ?.missingEvidenceIds,
    [missingEvidenceId],
  );
  assert.equal(
    impact.paths[0]
      ?.evidenceIds.includes(
        fixture.evidence.id,
      ),
    true,
  );

  assertSessionsClosed(store);
}

async function verifyPayloadTamperingFailsClosed(
  fixture: Fixture,
): Promise<void> {
  const store =
    new FakeHydraReadStore(
      fixture,
      {
        tamperedNodeIds:
          new Set([
            fixture.service.id,
          ]),
      },
    );

  await assert.rejects(
    runLiveBlastRadius(
      {} as Driver,
      fixture.incident.id,
      {
        reader: {
          sessionFactory:
            store.sessionFactory,
        },

        clock:
          deterministicClock(
            OBSERVED_AT,
            COMPLETED_AT,
          ),
      },
    ),
    (
      error: unknown,
    ) =>
      error instanceof
        HydraGraphReaderError &&
      error.code ===
        "GRAPH_CORRUPTION",
  );

  assertSessionsClosed(store);
}

async function verifyMissingCanonicalDependencyFailsClosed(
  fixture: Fixture,
): Promise<void> {
  const store =
    new FakeHydraReadStore(
      fixture,
      {
        missingCanonicalEdgeIds:
          new Set([
            fixture.dependencyEdgeId,
          ]),
      },
    );

  await assert.rejects(
    runLiveBlastRadius(
      {} as Driver,
      fixture.incident.id,
      {
        reader: {
          sessionFactory:
            store.sessionFactory,
        },

        clock:
          deterministicClock(
            OBSERVED_AT,
            COMPLETED_AT,
          ),
      },
    ),
    (
      error: unknown,
    ) =>
      error instanceof
        HydraGraphReaderError &&
      error.code ===
        "GRAPH_CORRUPTION",
  );

  assertSessionsClosed(store);
}

async function verifyAffectedVersionLimitPlusOne(
): Promise<void> {
  const fixture =
    createFixture(true);

  const store =
    new FakeHydraReadStore(
      fixture,
    );

  const result =
    await runLiveBlastRadius(
      {} as Driver,
      fixture.incident.id,
      {
        maxAffectedVersions: 1,

        reader: {
          sessionFactory:
            store.sessionFactory,
        },

        clock:
          deterministicClock(
            OBSERVED_AT,
            COMPLETED_AT,
          ),
      },
    );

  assert.equal(
    result.affectedVersionLookup.limit,
    1,
  );

  assert.equal(
    result.affectedVersionLookup
      .returnedCount,
    1,
  );

  assert.equal(
    result.affectedVersionLookup
      .truncated,
    true,
  );

  assert.equal(
    result.truncated,
    true,
  );

  assert.equal(
    result.evidenceFunnel
      .completeForIncident,
    false,
  );

  const impact =
    result.serviceImpacts[0];

  assert.ok(impact);
  assert.equal(
    impact.stage,
    "candidate",
  );
  assert.equal(
    impact.conclusion,
    "candidate",
  );
  assert.equal(
    impact.confidence.level,
    "unknown",
  );
  assert.equal(
    impact.confidence.complete,
    false,
  );
  assert.equal(
    impact.selection.state,
    "unknown",
  );
  assert.equal(
    impact.complete,
    false,
  );
  assert.equal(
    impact.warnings.some(
      (warning) =>
        warning.includes("truncated"),
    ),
    true,
  );

  const affectedLookup =
    store.observations.find(
      (observation) =>
        observation.step ===
        "find-affected-versions",
    );

  assert.ok(affectedLookup);

  /*
   * A requested limit of one must fetch at most two rows in HydraDB. This
   * proves truncation without reading every AFFECTS relationship.
   */
  assert.match(
    affectedLookup.query,
    /LIMIT 2\s*$/,
  );

  assertSessionsClosed(store);
}

async function main(): Promise<void> {
  const fixture =
    createFixture();

  await verifySuccessfulLiveAnalysis(
    fixture,
  );

  await verifyMissingEvidenceDoesNotCreateFalseClaims(
    fixture,
  );

  await verifyContextualEvidenceRemainsCandidate(
    fixture,
  );

  await verifyContextualEvidenceCannotInflateExactConfidence(
    fixture,
  );

  await verifyPartialMissingEvidenceFailsClosed(
    fixture,
  );

  await verifyPayloadTamperingFailsClosed(
    fixture,
  );

  await verifyMissingCanonicalDependencyFailsClosed(
    fixture,
  );

  await verifyAffectedVersionLimitPlusOne();

  console.log(
    "HydraGuard live HydraDB analysis smoke passed",
  );

  console.log(
    "- incident AFFECTS targets were resolved from HydraDB",
  );

  console.log(
    "- USED_BY traversal returned canonical DEPENDS_ON proof paths",
  );

  console.log(
    "- evidence funnel counts remained monotonic",
  );

  console.log(
    "- missing, partial, contextual-only, mixed-source, and truncated evidence obeyed fail-closed confidence policy",
  );

  console.log(
    "- payload tampering and missing canonical edges failed closed",
  );

  console.log(
    "- ORDER BY and LIMIT limit + 1 bounded database reads",
  );

  console.log(
    "- read epoch, query count, row count, and latency were reported",
  );

  console.log(
    "- every fake Bolt session was closed",
  );
  console.log(
    "- incident and affected-version summaries were returned",
    );

    console.log(
    "- evidence catalog excluded source URI and unrestricted detail",
    );

}

await main();
