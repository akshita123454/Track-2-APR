import assert from "node:assert/strict";

import type {
  PersistedGraphBatch,
} from "../../db/persistence-service.js";
import {
  createDependencyPair,
} from "../../domain/factories.js";
import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../../domain/identity.js";
import type {
  ControlNode,
  CredentialNode,
  DerivedEdge,
  EvidenceNode,
  GraphEdge,
  GraphNode,
  MaintainerNode,
  NodeId,
  PackageNode,
  PackageVersionNode,
  ServiceNode,
  StandardCanonicalEdge,
} from "../../domain/schema.js";
import {
  mergeGraphFragments,
} from "../../ingest/graph-batch.js";
import type {
  GraphBatch,
} from "../../ingest/graph-batch.js";
import type {
  AuthorityCanonicalEdge,
  AuthorityHop,
  AuthorityRelationKind,
} from "../authority/wave2-propagation.js";
import type {
  DependencyHop,
} from "../core/analysis-types.js";
import {
  ContainmentPlanError,
  simulateContainment,
} from "../containment/containment-simulator.js";
import type {
  ContainmentPlan,
  ContainmentSimulationInput,
} from "../containment/containment-simulator.js";
import type {
  PersistedContainmentAuthorityReader,
  PersistedContainmentGraphReader,
} from "../containment/persisted-containment.js";
import {
  ContainmentEvidenceValidationError,
  ContainmentSnapshotValidationError,
  runContainmentSimulation,
} from "../containment/persisted-containment.js";

const OBSERVED_AT = 1_700_000_000_000;

const AUTHORITY_KINDS:
  ReadonlySet<string> = new Set([
    "MAINTAINS",
    "MEMBER_OF",
    "OWNS",
    "TRIGGERS",
    "CONTROLS",
    "CAN_ACCESS",
    "CAN_PUBLISH",
  ]);

interface ContainmentFixture {
  readonly batch: GraphBatch;
  readonly evidence: EvidenceNode;
  readonly unrelatedEvidence: EvidenceNode;
  readonly affectedVersion: PackageVersionNode;
  readonly alphaService: ServiceNode;
  readonly betaService: ServiceNode;
  readonly maintainer: MaintainerNode;
  readonly credential: CredentialNode;
  readonly packageNode: PackageNode;
  readonly canPublishEdge: AuthorityCanonicalEdge;
  readonly isolateServiceControl: ControlNode;
  readonly removePublishingControl: ControlNode;
  readonly unsupportedPublishingControl: ControlNode;
}

function createEvidence(): EvidenceNode {
  const identity = createEntityIdentity(
    "evidence:containment-smoke:observed-graph",
  );

  return {
    ...identity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt: OBSERVED_AT,
    sourceType: "synthetic-fixture",
    sourceUri:
      "fixture://containment-smoke/observed-graph",
    collectorVersion: "containment-smoke-v1",
    confidence: 1,
    detail:
      "Synthetic evidence supporting containment simulation inputs.",
  };
}

function createUnrelatedEvidence(): EvidenceNode {
  const identity = createEntityIdentity(
    "evidence:containment-smoke:unrelated-control",
  );

  return {
    ...identity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt: OBSERVED_AT,
    sourceType: "synthetic-fixture",
    sourceUri:
      "fixture://containment-smoke/unrelated-control",
    collectorVersion: "containment-smoke-v1",
    confidence: 1,
    detail:
      "Synthetic evidence intentionally unrelated to the target edge.",
  };
}

function createAuthorityEdge(
  kind: AuthorityRelationKind,
  source: GraphNode,
  target: GraphNode,
  evidenceId: NodeId,
  discriminator: string,
): AuthorityCanonicalEdge {
  const identity = createEdgeIdentity({
    kind,
    sourceLogicalId: source.logicalId,
    targetLogicalId: target.logicalId,
    discriminator,
  });

  const edge: StandardCanonicalEdge = {
    ...identity,
    sourceId: source.id,
    targetId: target.id,
    kind,
    observedAt: OBSERVED_AT,
    derived: false,
    identityDiscriminator: discriminator,
    evidenceIds: [evidenceId],
  };

  return edge as AuthorityCanonicalEdge;
}

function createControl(
  logicalId: string,
  action: ControlNode["action"],
  evidenceId: NodeId,
): ControlNode {
  const identity = createEntityIdentity(
    logicalId,
  );

  return {
    ...identity,
    kind: "Control",
    evidenceIds: [evidenceId],
    synthetic: true,
    observedAt: OBSERVED_AT,
    action,
    status: "proposed",
    reversible: true,
    estimatedMinutes: 15,
  };
}

function createFixture(): ContainmentFixture {
  const evidence = createEvidence();
  const unrelatedEvidence =
    createUnrelatedEvidence();

  const affectedVersion: PackageVersionNode = {
    ...createEntityIdentity(
      "pkgver:npm:containment-target@1.0.0",
    ),
    kind: "PackageVersion",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    ecosystem: "npm",
    packageName: "containment-target",
    version: "1.0.0",
  };

  const alphaService: ServiceNode = {
    ...createEntityIdentity(
      "service:containment:alpha",
    ),
    kind: "Service",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    name: "containment-alpha",
    criticality: "critical",
  };

  const betaService: ServiceNode = {
    ...createEntityIdentity(
      "service:containment:beta",
    ),
    kind: "Service",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    name: "containment-beta",
    criticality: "medium",
  };

  const maintainer: MaintainerNode = {
    ...createEntityIdentity(
      "maintainer:containment:alice",
    ),
    kind: "Maintainer",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    handle: "containment-alice",
  };

  const credential: CredentialNode = {
    ...createEntityIdentity(
      "credential:containment:publisher",
    ),
    kind: "Credential",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    credentialType: "npm-token",
    scopes: ["publish"],
    status: "active",
  };

  const packageNode: PackageNode = {
    ...createEntityIdentity(
      "pkg:npm:containment-publish-target",
    ),
    kind: "Package",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    ecosystem: "npm",
    name: "containment-publish-target",
  };

  const alphaDependency = createDependencyPair({
    source: alphaService,
    target: affectedVersion,
    discriminator: "alpha-direct",
    dependencyType: "production",
    evidenceIds: [evidence.id],
    observedAt: OBSERVED_AT,
    generatorVersion: "containment-smoke-v1",
    declaredRange: "1.0.0",
  });

  const betaDependency = createDependencyPair({
    source: betaService,
    target: affectedVersion,
    discriminator: "beta-direct",
    dependencyType: "production",
    evidenceIds: [evidence.id],
    observedAt: OBSERVED_AT,
    generatorVersion: "containment-smoke-v1",
    declaredRange: "1.0.0",
  });

  const controlsEdge = createAuthorityEdge(
    "CONTROLS",
    maintainer,
    credential,
    evidence.id,
    "maintainer-controls-publisher",
  );
  const canPublishEdge = createAuthorityEdge(
    "CAN_PUBLISH",
    credential,
    packageNode,
    evidence.id,
    "publisher-can-publish-target",
  );

  const isolateServiceControl = createControl(
    "control:containment:isolate-alpha",
    "isolate-service",
    evidence.id,
  );
  const removePublishingControl = createControl(
    "control:containment:remove-publishing",
    "remove-publishing-access",
    evidence.id,
  );
  const unsupportedPublishingControl = createControl(
    "control:containment:unsupported-publishing",
    "remove-publishing-access",
    unrelatedEvidence.id,
  );

  const edges: GraphEdge[] = [
    alphaDependency.canonical,
    alphaDependency.reverseIndex,
    betaDependency.canonical,
    betaDependency.reverseIndex,
    controlsEdge,
    canPublishEdge,
  ];

  const batch = mergeGraphFragments([
    {
      source:
        "containment-smoke-production-fixture",
      nodes: [
        evidence,
        unrelatedEvidence,
        affectedVersion,
        alphaService,
        betaService,
        maintainer,
        credential,
        packageNode,
        isolateServiceControl,
        removePublishingControl,
        unsupportedPublishingControl,
      ],
      edges,
    },
  ]);

  return {
    batch,
    evidence,
    unrelatedEvidence,
    affectedVersion,
    alphaService,
    betaService,
    maintainer,
    credential,
    packageNode,
    canPublishEdge,
    isolateServiceControl,
    removePublishingControl,
    unsupportedPublishingControl,
  };
}

class BatchContainmentReader
  implements
    PersistedContainmentGraphReader,
    PersistedContainmentAuthorityReader {
  private readonly nodesById =
    new Map<NodeId, GraphNode>();

  private readonly edgesById =
    new Map<number, GraphEdge>();

  private readonly batch: GraphBatch;

  public constructor(
    readonly persisted: PersistedGraphBatch,
  ) {
    this.batch = persisted.batch;

    for (const node of this.batch.nodes) {
      this.nodesById.set(node.id, node);
    }

    for (const edge of this.batch.edges) {
      this.edgesById.set(edge.id, edge);
    }
  }

  public async getNode(
    nodeId: NodeId,
  ): Promise<GraphNode | null> {
    return this.nodesById.get(nodeId) ?? null;
  }

  public findDependents(
    nodeId: NodeId,
  ): Promise<readonly DependencyHop[]>;
  public findDependents(
    nodeId: NodeId,
    options: { readonly limit: number },
  ): Promise<{
    readonly hops: readonly DependencyHop[];
    readonly truncated: boolean;
  }>;
  public async findDependents(
    nodeId: NodeId,
    options?: { readonly limit: number },
  ): Promise<
    | readonly DependencyHop[]
    | {
        readonly hops: readonly DependencyHop[];
        readonly truncated: boolean;
      }
  > {
    const allReverseIndexes = this.batch.edges
      .filter(
        (edge): edge is DerivedEdge =>
          edge.kind === "USED_BY" &&
          edge.sourceId === nodeId,
      )
      .sort((left, right) => left.id - right.id);

    const reverseIndexes =
      options === undefined
        ? allReverseIndexes
        : allReverseIndexes.slice(
            0,
            options.limit,
          );
    const hops: DependencyHop[] = [];

    for (const reverseIndex of reverseIndexes) {
      const canonical = this.edgesById.get(
        reverseIndex.derivedFrom,
      );

      if (
        canonical === undefined ||
        canonical.kind !== "DEPENDS_ON" ||
        canonical.derived !== false ||
        canonical.sourceId !==
          reverseIndex.targetId ||
        canonical.targetId !==
          reverseIndex.sourceId
      ) {
        throw new Error(
          `Invalid fixture USED_BY edge ${String(reverseIndex.id)}`,
        );
      }

      const dependentNode = this.nodesById.get(
        reverseIndex.targetId,
      );

      if (dependentNode === undefined) {
        throw new Error(
          `Fixture edge ${String(reverseIndex.id)} references a missing node`,
        );
      }

      hops.push({
        dependentNode,
        canonicalEdge: canonical,
        traversalIndexEdgeId:
          reverseIndex.id,
      });
    }

    if (options === undefined) {
      return hops;
    }

    return {
      hops,
      truncated:
        allReverseIndexes.length > options.limit,
    };
  }

  public async findOutgoingAuthorityHops(
    nodeId: NodeId,
  ): Promise<readonly AuthorityHop[]> {
    const hops: AuthorityHop[] = [];

    for (const edge of this.batch.edges) {
      if (
        edge.kind === "USED_BY" ||
        edge.sourceId !== nodeId ||
        !AUTHORITY_KINDS.has(edge.kind)
      ) {
        continue;
      }

      const targetNode = this.nodesById.get(
        edge.targetId,
      );

      if (targetNode === undefined) {
        throw new Error(
          `Fixture edge ${String(edge.id)} targets a missing node`,
        );
      }

      hops.push({
        targetNode,
        canonicalEdge:
          edge as AuthorityCanonicalEdge,
      });
    }

    return hops;
  }

  public async getEvidence(
    evidenceIds: readonly NodeId[],
  ): Promise<readonly EvidenceNode[]> {
    const evidence: EvidenceNode[] = [];

    for (const evidenceId of evidenceIds) {
      const node = this.nodesById.get(evidenceId);

      if (node?.kind === "Evidence") {
        evidence.push(node);
      }
    }

    return evidence;
  }
}

/*
 * The branded capability is constructed only by HydraPersistenceService in
 * production. This network-free fixture uses a local cast to exercise the
 * containment wrapper; validate:persistence-service covers real capability
 * construction and persistence-before-analysis ordering.
 */
function fixturePersistedBatch(
  batch: GraphBatch,
): PersistedGraphBatch {
  return {
    batch,
    batchHash: "c".repeat(64),
    idempotencyKey: "containment-smoke",
    correlationId:
      "containment-smoke-correlation",
    persistenceAttempts: 1,
    result: {} as PersistedGraphBatch["result"],
  } as unknown as PersistedGraphBatch;
}

function planFor(
  fixture: ContainmentFixture,
): ContainmentPlan {
  return {
    directives: [
      {
        control:
          fixture.removePublishingControl,
        rationale:
          "Remove the modeled publishing authority path.",
        blockedNodeIds: [],
        blockedEdgeIds: [
          fixture.canPublishEdge.id,
        ],
      },
      {
        control:
          fixture.isolateServiceControl,
        rationale:
          "Isolate the modeled affected service.",
        blockedNodeIds: [
          fixture.alphaService.id,
        ],
        blockedEdgeIds: [],
      },
    ],
  };
}

function inputFor(
  fixture: ContainmentFixture,
  plan: ContainmentPlan = planFor(fixture),
): ContainmentSimulationInput {
  return {
    plan,
    affectedVersionIds: [
      fixture.affectedVersion.id,
    ],
    authoritySeeds: [
      {
        nodeId: fixture.maintainer.id,
        evidenceIds: [fixture.evidence.id],
      },
    ],
  };
}

async function verifyProductionSimulation(
  fixture: ContainmentFixture,
  reader: BatchContainmentReader,
): Promise<void> {
  const result =
    await runContainmentSimulation(
      reader.persisted,
      reader,
      reader,
      inputFor(fixture),
    );

  assert.equal(result.batchHash, "c".repeat(64));
  assert.equal(
    result.correlationId,
    "containment-smoke-correlation",
  );
  assert.equal(result.simulationOnly, true);
  assert.equal(
    result.conclusion,
    "simulated-reduction",
  );

  assert.deepEqual(
    result.overlay.controlIds,
    [
      fixture.isolateServiceControl.id,
      fixture.removePublishingControl.id,
    ].sort((left, right) => left - right),
  );
  assert.deepEqual(
    result.overlay.blockedNodeIds,
    [fixture.alphaService.id],
  );
  assert.deepEqual(
    result.overlay.blockedEdgeIds,
    [fixture.canPublishEdge.id],
  );

  assert.equal(
    result.impact.serviceCandidatesBefore,
    2,
  );
  assert.equal(
    result.impact.serviceCandidatesAfter,
    1,
  );
  assert.equal(
    result.impact.serviceCandidatesRemoved,
    1,
  );
  assert.deepEqual(
    result.impact.removedServiceIds,
    [fixture.alphaService.id],
  );

  assert.equal(
    result.impact.authorityTargetsBefore,
    2,
  );
  assert.equal(
    result.impact.authorityTargetsAfter,
    1,
  );
  assert.equal(
    result.impact.authorityTargetsRemoved,
    1,
  );
  assert.deepEqual(
    result.impact.removedAuthorityTargetIds,
    [fixture.packageNode.id],
  );

  assert.ok(
    result.after.authority.targets.every(
      (target) =>
        target.conclusion ===
        "authority-reachability-candidate",
    ),
  );
  assert.ok(
    result.uncertainties.some(
      (uncertainty) =>
        uncertainty.includes(
          "does not prove",
        ),
    ),
  );

  assert.deepEqual(
    result.directives.map(
      (directive) => directive.control.id,
    ),
    result.overlay.controlIds,
  );
}

async function verifyNoEffectResult(
  fixture: ContainmentFixture,
  reader: BatchContainmentReader,
): Promise<void> {
  const edgeOnlyPlan: ContainmentPlan = {
    directives: [planFor(fixture).directives[0]!],
  };

  const result = await simulateContainment(
    reader,
    reader,
    {
      plan: edgeOnlyPlan,
      affectedVersionIds: [
        fixture.affectedVersion.id,
      ],
      authoritySeeds: [],
    },
  );

  assert.equal(result.impact.effective, false);
  assert.equal(
    result.conclusion,
    "no-simulated-reduction",
  );
  assert.equal(
    result.impact.serviceCandidatesBefore,
    result.impact.serviceCandidatesAfter,
  );
}

async function verifyTruncatedComparison(
  fixture: ContainmentFixture,
  reader: BatchContainmentReader,
): Promise<void> {
  const result = await simulateContainment(
    reader,
    reader,
    {
      ...inputFor(fixture, {
        directives: [planFor(fixture).directives[1]!],
      }),
      authoritySeeds: [],
      blastRadiusOptions: {
        maxServices: 1,
      },
    },
  );

  assert.equal(result.impact.conclusive, false);
  assert.equal(result.impact.effective, false);
  assert.equal(result.conclusion, "inconclusive");
  assert.equal(
    result.impact.serviceCandidatesRemoved,
    0,
  );
  assert.equal(result.impact.blastPathsRemoved, 0);
  assert.equal(
    result.impact.authorityTargetsRemoved,
    0,
  );
  assert.equal(
    result.impact.authorityPathsRemoved,
    0,
  );
  assert.deepEqual(
    result.impact.removedServiceIds,
    [],
  );
  assert.deepEqual(
    result.impact.removedAuthorityTargetIds,
    [],
  );
}

async function verifyValidation(
  fixture: ContainmentFixture,
  reader: BatchContainmentReader,
): Promise<void> {
  const missingEvidenceControl: ControlNode = {
    ...fixture.isolateServiceControl,
    evidenceIds: [],
  };

  await assert.rejects(
    runContainmentSimulation(
      reader.persisted,
      reader,
      reader,
      inputFor(fixture, {
        directives: [
          {
            control: missingEvidenceControl,
            rationale: "Invalid missing Evidence control.",
            blockedNodeIds: [
              fixture.alphaService.id,
            ],
            blockedEdgeIds: [],
          },
        ],
      }),
    ),
    (error: unknown) =>
      error instanceof
        ContainmentEvidenceValidationError &&
      error.code ===
        "missing-required-evidence",
  );

  const substitutedEvidenceControl: ControlNode = {
    ...fixture.isolateServiceControl,
    evidenceIds: [fixture.unrelatedEvidence.id],
  };

  await assert.rejects(
    runContainmentSimulation(
      reader.persisted,
      reader,
      reader,
      inputFor(fixture, {
        directives: [
          {
            control: substitutedEvidenceControl,
            rationale:
              "Caller-substituted control Evidence.",
            blockedNodeIds: [
              fixture.alphaService.id,
            ],
            blockedEdgeIds: [],
          },
        ],
      }),
    ),
    (error: unknown) =>
      error instanceof
        ContainmentSnapshotValidationError &&
      error.code === "node-identity-mismatch",
  );

  await assert.rejects(
    runContainmentSimulation(
      reader.persisted,
      reader,
      reader,
      {
        ...inputFor(fixture),
        authoritySeeds: [
          {
            nodeId: fixture.maintainer.id,
            evidenceIds: [
              fixture.alphaService.id,
            ],
          },
        ],
      },
    ),
    (error: unknown) =>
      error instanceof
        ContainmentEvidenceValidationError &&
      error.code === "wrong-evidence-kind",
  );

  await assert.rejects(
    simulateContainment(
      reader,
      reader,
      inputFor(fixture, {
        directives: [
          {
            control:
              fixture.isolateServiceControl,
            rationale:
              "Invalid PackageVersion target for isolate-service.",
            blockedNodeIds: [
              fixture.affectedVersion.id,
            ],
            blockedEdgeIds: [],
          },
        ],
      }),
    ),
    (error: unknown) =>
      error instanceof ContainmentPlanError &&
      error.code === "wrong-target-kind",
  );

  const dependencyEdge = fixture.batch.edges.find(
    (edge) => edge.kind === "DEPENDS_ON",
  );
  assert.ok(dependencyEdge);

  await assert.rejects(
    runContainmentSimulation(
      reader.persisted,
      reader,
      reader,
      inputFor(fixture, {
        directives: [
          {
            control:
              fixture.removePublishingControl,
            rationale:
              "Invalid publishing control over dependency edge.",
            blockedNodeIds: [],
            blockedEdgeIds: [dependencyEdge.id],
          },
        ],
      }),
    ),
    (error: unknown) =>
      error instanceof ContainmentPlanError &&
      error.code === "wrong-target-edge-kind",
  );

  await assert.rejects(
    runContainmentSimulation(
      reader.persisted,
      reader,
      reader,
      inputFor(fixture, {
        directives: [
          {
            control:
              fixture.unsupportedPublishingControl,
            rationale:
              "Control Evidence does not support the target edge.",
            blockedNodeIds: [],
            blockedEdgeIds: [
              fixture.canPublishEdge.id,
            ],
          },
        ],
      }),
    ),
    (error: unknown) =>
      error instanceof ContainmentPlanError &&
      error.code === "target-evidence-mismatch",
  );

  await assert.rejects(
    runContainmentSimulation(
      reader.persisted,
      reader,
      reader,
      inputFor(fixture, {
        directives: [
          {
            control:
              fixture.removePublishingControl,
            rationale:
              "Invalid missing canonical edge.",
            blockedNodeIds: [],
            blockedEdgeIds: [
              Number.MAX_SAFE_INTEGER,
            ],
          },
        ],
      }),
    ),
    (error: unknown) =>
      error instanceof ContainmentPlanError &&
      error.code === "missing-target-edge",
  );

  const mismatchedAuthorityReader:
    PersistedContainmentAuthorityReader = {
      persisted: reader.persisted,
      getNode: async (nodeId) => {
        const node = await reader.getNode(nodeId);

        return nodeId === fixture.maintainer.id &&
          node !== null
          ? {
              ...node,
              logicalId:
                `${node.logicalId}:stale-reader`,
            }
          : node;
      },
      findOutgoingAuthorityHops: (nodeId) =>
        reader.findOutgoingAuthorityHops(nodeId),
      getEvidence: (evidenceIds) =>
        reader.getEvidence(evidenceIds),
    };

  await assert.rejects(
    runContainmentSimulation(
      reader.persisted,
      reader,
      mismatchedAuthorityReader,
      inputFor(fixture),
    ),
    (error: unknown) =>
      error instanceof
        ContainmentSnapshotValidationError &&
      error.code === "node-identity-mismatch",
  );

  const wrongCapabilityAuthorityReader:
    PersistedContainmentAuthorityReader = {
      persisted: fixturePersistedBatch(
        fixture.batch,
      ),
      getNode: (nodeId) => reader.getNode(nodeId),
      findOutgoingAuthorityHops: (nodeId) =>
        reader.findOutgoingAuthorityHops(nodeId),
      getEvidence: (evidenceIds) =>
        reader.getEvidence(evidenceIds),
    };

  await assert.rejects(
    runContainmentSimulation(
      reader.persisted,
      reader,
      wrongCapabilityAuthorityReader,
      inputFor(fixture),
    ),
    (error: unknown) =>
      error instanceof
        ContainmentSnapshotValidationError &&
      error.code ===
        "reader-capability-mismatch",
  );
}

async function main(): Promise<void> {
  const fixture = createFixture();

  assert.equal(
    fixture.batch.validation.valid,
    true,
  );
  assert.equal(Object.isFrozen(fixture.batch), true);
  assert.equal(
    Object.isFrozen(fixture.batch.nodes),
    true,
  );
  assert.equal(
    Object.isFrozen(fixture.batch.edges),
    true,
  );

  const sourceSnapshot = JSON.stringify(
    fixture.batch,
  );
  const reader = new BatchContainmentReader(
    fixturePersistedBatch(fixture.batch),
  );

  await verifyProductionSimulation(
    fixture,
    reader,
  );
  await verifyNoEffectResult(fixture, reader);
  await verifyTruncatedComparison(
    fixture,
    reader,
  );
  await verifyValidation(fixture, reader);

  assert.equal(
    JSON.stringify(fixture.batch),
    sourceSnapshot,
    "Containment simulation must not mutate the source graph",
  );

  console.log("Containment simulation smoke passed");
  console.log(
    "- deterministic identities and GraphBatch validation passed",
  );
  console.log(
    "- persisted snapshot identity and Evidence validation passed",
  );
  console.log(
    "- node and canonical edge overlays reduced modeled paths",
  );
  console.log(
    "- reports remain simulation-only and candidate-only",
  );
  console.log(
    "- invalid node and edge targets fail closed",
  );
  console.log(
    "- truncated comparisons remain explicitly inconclusive",
  );
  console.log(
    "- immutable source graph remained unchanged",
  );
}

await main();
