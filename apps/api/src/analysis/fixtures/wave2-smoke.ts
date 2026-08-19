import assert from "node:assert/strict";

import type {
  PersistedGraphBatch,
} from "../../db/persistence-service.js";
import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../../domain/identity.js";
import type {
  CIWorkflowNode,
  CredentialNode,
  EvidenceNode,
  GraphEdge,
  GraphNode,
  MaintainerNode,
  NodeId,
  OrganizationNode,
  PackageNode,
  RepositoryNode,
  StandardCanonicalEdge,
} from "../../domain/schema.js";
import {
  mergeGraphFragments,
} from "../../ingest/graph-batch.js";
import type {
  GraphBatch,
} from "../../ingest/graph-batch.js";
import {
  analyzeWave2Authority,
} from "../authority/wave2-propagation.js";
import type {
  AuthorityCanonicalEdge,
  AuthorityHop,
  AuthorityRelationKind,
  ReadonlyAuthorityGraphReader,
  Wave2AuthoritySeed,
} from "../authority/wave2-propagation.js";
import {
  runWave2Authority,
  Wave2EvidenceValidationError,
} from "../authority/persisted-wave2.js";

const OBSERVED_AT = 1_700_000_000_000;

interface Wave2Fixture {
  readonly batch: GraphBatch;
  readonly maintainer: MaintainerNode;
  readonly packageNode: PackageNode;
  readonly evidence: EvidenceNode;
  readonly directMaintainsEdge: AuthorityCanonicalEdge;
}

function createEvidence(): EvidenceNode {
  const identity = createEntityIdentity(
    "evidence:wave2-smoke:authority-seed",
  );

  return {
    ...identity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt: OBSERVED_AT,
    sourceType: "synthetic-fixture",
    sourceUri: "fixture://wave2-smoke/authority-seed",
    collectorVersion: "wave2-smoke-v1",
    confidence: 1,
    detail: "Synthetic authority propagation evidence.",
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

function createFixture(): Wave2Fixture {
  const evidence = createEvidence();

  const maintainerIdentity = createEntityIdentity(
    "maintainer:wave2-smoke:alice",
  );
  const maintainer: MaintainerNode = {
    ...maintainerIdentity,
    kind: "Maintainer",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    handle: "alice",
  };

  const organizationIdentity = createEntityIdentity(
    "org:wave2-smoke:hydra",
  );
  const organization: OrganizationNode = {
    ...organizationIdentity,
    kind: "Organization",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    name: "Hydra Smoke Organization",
    provider: "github",
  };

  const repositoryIdentity = createEntityIdentity(
    "repo:wave2-smoke:release",
  );
  const repository: RepositoryNode = {
    ...repositoryIdentity,
    kind: "Repository",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    provider: "github",
    url: "https://example.invalid/wave2/release",
    defaultBranch: "main",
  };

  const workflowIdentity = createEntityIdentity(
    "workflow:wave2-smoke:release",
  );
  const workflow: CIWorkflowNode = {
    ...workflowIdentity,
    kind: "CIWorkflow",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    provider: "github-actions",
    path: ".github/workflows/release.yml",
  };

  const credentialIdentity = createEntityIdentity(
    "credential:wave2-smoke:publisher",
  );
  const credential: CredentialNode = {
    ...credentialIdentity,
    kind: "Credential",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    credentialType: "npm-token",
    scopes: ["publish"],
    status: "active",
  };

  const packageIdentity = createEntityIdentity(
    "pkg:npm:wave2-target",
  );
  const packageNode: PackageNode = {
    ...packageIdentity,
    kind: "Package",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt: OBSERVED_AT,
    ecosystem: "npm",
    name: "wave2-target",
  };

  const directMaintainsEdge = createAuthorityEdge(
    "MAINTAINS",
    maintainer,
    packageNode,
    evidence.id,
    "alice-maintains-target",
  );

  const edges: GraphEdge[] = [
    directMaintainsEdge,
    createAuthorityEdge(
      "MEMBER_OF",
      maintainer,
      organization,
      evidence.id,
      "alice-member-of-hydra",
    ),
    createAuthorityEdge(
      "CONTROLS",
      maintainer,
      credential,
      evidence.id,
      "alice-controls-publisher",
    ),
    createAuthorityEdge(
      "OWNS",
      organization,
      repository,
      evidence.id,
      "hydra-owns-release-repository",
    ),
    createAuthorityEdge(
      "TRIGGERS",
      repository,
      workflow,
      evidence.id,
      "release-triggers-workflow",
    ),
    createAuthorityEdge(
      "CAN_ACCESS",
      workflow,
      credential,
      evidence.id,
      "workflow-accesses-publisher",
    ),
    createAuthorityEdge(
      "CAN_PUBLISH",
      credential,
      packageNode,
      evidence.id,
      "publisher-publishes-target",
    ),
  ];

  const batch = mergeGraphFragments([
    {
      source: "wave2-smoke-production-fixture",
      nodes: [
        evidence,
        maintainer,
        organization,
        repository,
        workflow,
        credential,
        packageNode,
      ],
      edges,
    },
  ]);

  return {
    batch,
    maintainer,
    packageNode,
    evidence,
    directMaintainsEdge,
  };
}

class BatchAuthorityReader
  implements ReadonlyAuthorityGraphReader {
  private readonly nodesById =
    new Map<NodeId, GraphNode>();

  public constructor(
    private readonly batch: GraphBatch,
  ) {
    for (const node of batch.nodes) {
      this.nodesById.set(node.id, node);
    }
  }

  public async getNode(
    nodeId: NodeId,
  ): Promise<GraphNode | null> {
    return this.nodesById.get(nodeId) ?? null;
  }

  public async findOutgoingAuthorityHops(
    nodeId: NodeId,
  ): Promise<readonly AuthorityHop[]> {
    const hops: AuthorityHop[] = [];

    for (const edge of this.batch.edges) {
      if (
        edge.kind === "USED_BY" ||
        edge.sourceId !== nodeId
      ) {
        continue;
      }

      const targetNode = this.nodesById.get(
        edge.targetId,
      );

      if (targetNode === undefined) {
        throw new Error(
          `Fixture edge ${String(edge.id)} targets ` +
          "a missing node",
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
 * The production type prevents ordinary callers from constructing this
 * capability. This fixture uses a local cast only to exercise the Wave 2
 * wrapper; validate:persistence-service covers real persistThenAnalyze()
 * capability construction and gating.
 */
function fixturePersistedBatch(
  batch: GraphBatch,
): PersistedGraphBatch {
  return {
    batch,
    batchHash: "a".repeat(64),
    idempotencyKey: "wave2-smoke",
    correlationId: "wave2-smoke-correlation",
    persistenceAttempts: 1,
    result: {} as PersistedGraphBatch["result"],
  } as unknown as PersistedGraphBatch;
}

function seedFor(
  fixture: Wave2Fixture,
): readonly Wave2AuthoritySeed[] {
  return [
    {
      nodeId: fixture.maintainer.id,
      evidenceIds: [fixture.evidence.id],
    },
  ];
}

async function verifyProductionWrapper(
  fixture: Wave2Fixture,
  reader: BatchAuthorityReader,
): Promise<void> {
  const result = await runWave2Authority(
    fixturePersistedBatch(fixture.batch),
    reader,
    seedFor(fixture),
  );

  assert.equal(
    result.batchHash,
    "a".repeat(64),
  );
  assert.equal(
    result.correlationId,
    "wave2-smoke-correlation",
  );
  assert.equal(result.truncated, false);

  const packageTarget = result.targets.find(
    (target) =>
      target.targetNode.id === fixture.packageNode.id,
  );

  assert.ok(packageTarget);
  assert.equal(
    packageTarget.conclusion,
    "authority-reachability-candidate",
  );
  assert.equal(packageTarget.paths.length, 3);
  assert.ok(
    packageTarget.uncertainties.some(
      (uncertainty) =>
        uncertainty.includes(
          "does not prove",
        ),
    ),
  );

  for (const path of packageTarget.paths) {
    assert.deepEqual(
      path.evidenceIds,
      [fixture.evidence.id],
    );
    assert.ok(
      path.canonicalEdges.every(
        (edge) => edge.derived === false,
      ),
    );
  }

  await assert.rejects(
    runWave2Authority(
      fixturePersistedBatch(fixture.batch),
      reader,
      [
        {
          nodeId: fixture.maintainer.id,
          evidenceIds: [],
        },
      ],
    ),
    (error: unknown) =>
      error instanceof Wave2EvidenceValidationError &&
      error.code === "missing-required-evidence",
  );

  await assert.rejects(
    runWave2Authority(
      fixturePersistedBatch(fixture.batch),
      reader,
      [
        {
          nodeId: fixture.maintainer.id,
          evidenceIds: [fixture.maintainer.id],
        },
      ],
    ),
    (error: unknown) =>
      error instanceof Wave2EvidenceValidationError &&
      error.code === "wrong-evidence-kind",
  );
}

async function verifySafetyLimits(
  fixture: Wave2Fixture,
  reader: BatchAuthorityReader,
): Promise<void> {
  const seeds = seedFor(fixture);

  const stateLimited =
    await analyzeWave2Authority(
      reader,
      seeds,
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

  const fanOutLimited =
    await analyzeWave2Authority(
      reader,
      seeds,
      {
        maxOutgoingEdgesPerNode: 1,
      },
    );

  assert.equal(fanOutLimited.truncated, true);
  assert.ok(
    fanOutLimited.warnings.some(
      (warning) =>
        warning.code ===
        "outgoing-edge-limit-reached",
    ),
  );

  const depthLimited =
    await analyzeWave2Authority(
      reader,
      seeds,
      {
        maxDepth: 1,
      },
    );

  assert.equal(depthLimited.truncated, true);
  assert.ok(
    depthLimited.warnings.some(
      (warning) =>
        warning.code === "depth-limit-reached",
    ),
  );

  const targetLimited =
    await analyzeWave2Authority(
      reader,
      seeds,
      {
        maxTargets: 1,
      },
    );

  assert.equal(targetLimited.truncated, true);
  assert.ok(
    targetLimited.warnings.some(
      (warning) =>
        warning.code === "target-limit-reached",
    ),
  );

  const pathLimited =
    await analyzeWave2Authority(
      reader,
      seeds,
      {
        maxPathsPerTarget: 1,
      },
    );

  assert.equal(pathLimited.truncated, true);
  assert.ok(
    pathLimited.warnings.some(
      (warning) =>
        warning.code ===
        "paths-per-target-limit-reached",
    ),
  );

  const warningLimited =
    await analyzeWave2Authority(
      reader,
      [
        {
          nodeId: Number.MAX_SAFE_INTEGER - 1,
          evidenceIds: [fixture.evidence.id],
        },
        {
          nodeId: Number.MAX_SAFE_INTEGER,
          evidenceIds: [fixture.evidence.id],
        },
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

async function verifyMalformedHop(
  fixture: Wave2Fixture,
  reader: BatchAuthorityReader,
): Promise<void> {
  const malformedEdge = {
    ...fixture.directMaintainsEdge,
    derived: true,
  } as unknown as AuthorityCanonicalEdge;

  const malformedReader:
    ReadonlyAuthorityGraphReader = {
      getNode: (nodeId) =>
        reader.getNode(nodeId),

      findOutgoingAuthorityHops: async (
        nodeId,
      ) =>
        nodeId === fixture.maintainer.id
          ? [
              {
                targetNode: fixture.packageNode,
                canonicalEdge: malformedEdge,
              },
            ]
          : [],

      getEvidence: (evidenceIds) =>
        reader.getEvidence(evidenceIds),
    };

  const result = await analyzeWave2Authority(
    malformedReader,
    seedFor(fixture),
  );

  assert.equal(result.targets.length, 0);
  assert.ok(
    result.warnings.some(
      (warning) =>
        warning.code === "invalid-authority-hop",
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
  const reader = new BatchAuthorityReader(
    fixture.batch,
  );

  await verifyProductionWrapper(
    fixture,
    reader,
  );
  await verifySafetyLimits(
    fixture,
    reader,
  );
  await verifyMalformedHop(
    fixture,
    reader,
  );

  assert.equal(
    JSON.stringify(fixture.batch),
    sourceSnapshot,
    "Wave 2 analysis must not mutate the source graph",
  );

  console.log("Wave 2 authority smoke passed");
  console.log(
    "- deterministic identities and GraphBatch validation passed",
  );
  console.log(
    "- persisted authority wrapper and evidence validation passed",
  );
  console.log(
    "- distinct authority paths remain candidate-only",
  );
  console.log(
    "- traversal, fan-out, target, path, and warning limits passed",
  );
  console.log(
    "- malformed authority hops fail closed",
  );
  console.log(
    "- immutable source graph remained unchanged",
  );
}

await main();
