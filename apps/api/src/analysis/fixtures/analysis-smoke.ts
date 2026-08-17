import {
  deepEqual,
  equal,
  ok,
} from "node:assert/strict";
import type {
  DependencyEdge,
  EvidenceNode,
  GraphNode,
  NodeId,
  PackageVersionNode,
  ServiceNode,
} from "../../domain/schema.js";
import { analyzeBlastRadius } from "../core/blast-radius.js";
import { classifyExposure } from "../core/exposure-ladder.js";
import type {
  DependencyHop,
  ExposureEvidenceSignals,
  ExposureStage,
  ReadonlyGraphReader,
  SecurityConclusion,
} from "../core/analysis-types.js";

const OBSERVED_AT = 1_700_000_000_000;

const AFFECTED_VERSION_ID: NodeId = 100;
const BRIDGE_VERSION_ID: NodeId = 200;
const BETA_SERVICE_ID: NodeId = 300;
const ALPHA_SERVICE_ID: NodeId = 400;

const RESOLUTION_EVIDENCE_ID: NodeId = 901;
const BUILD_EVIDENCE_ID: NodeId = 902;
const DEPLOYMENT_EVIDENCE_ID: NodeId = 903;
const REACHABILITY_EVIDENCE_ID: NodeId = 904;
const EXECUTION_EVIDENCE_ID: NodeId = 905;

function createEvidenceNode(
  id: NodeId,
  detail: string,
): EvidenceNode {
  return {
    id,
    logicalId: `evidence:analysis-smoke:${String(id)}`,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt: OBSERVED_AT,
    sourceType: "synthetic-fixture",
    sourceUri: `fixture://analysis-smoke/${String(id)}`,
    collectorVersion: "analysis-smoke-v1",
    confidence: 1,
    detail,
  };
}

function createDependencyEdge(
  id: number,
  sourceId: NodeId,
  targetId: NodeId,
  identityDiscriminator: string,
): DependencyEdge {
  return {
    id,
    logicalId:
      `dependency:${String(sourceId)}:` +
      `${String(targetId)}:${identityDiscriminator}`,
    sourceId,
    targetId,
    kind: "DEPENDS_ON",
    observedAt: OBSERVED_AT,
    derived: false,
    identityDiscriminator,
    evidenceIds: [RESOLUTION_EVIDENCE_ID],
    dependencyType: "production",
    declaredRange: "^1.0.0",
    lockfilePath: "package-lock.json",
  };
}

const affectedVersion: PackageVersionNode = {
  id: AFFECTED_VERSION_ID,
  logicalId: "npm:@fixture/affected@1.0.0",
  kind: "PackageVersion",
  evidenceIds: [RESOLUTION_EVIDENCE_ID],
  synthetic: true,
  observedAt: OBSERVED_AT,
  ecosystem: "npm",
  packageName: "@fixture/affected",
  version: "1.0.0",
  publishedAt: OBSERVED_AT - 10_000,
};

const bridgeVersion: PackageVersionNode = {
  id: BRIDGE_VERSION_ID,
  logicalId: "npm:@fixture/bridge@2.0.0",
  kind: "PackageVersion",
  evidenceIds: [RESOLUTION_EVIDENCE_ID],
  synthetic: true,
  observedAt: OBSERVED_AT,
  ecosystem: "npm",
  packageName: "@fixture/bridge",
  version: "2.0.0",
  publishedAt: OBSERVED_AT - 5_000,
};

const betaService: ServiceNode = {
  id: BETA_SERVICE_ID,
  logicalId: "service:beta",
  kind: "Service",
  evidenceIds: [],
  synthetic: true,
  observedAt: OBSERVED_AT,
  name: "beta-service",
  criticality: "medium",
};

const alphaService: ServiceNode = {
  id: ALPHA_SERVICE_ID,
  logicalId: "service:alpha",
  kind: "Service",
  evidenceIds: [],
  synthetic: true,
  observedAt: OBSERVED_AT,
  name: "alpha-service",
  criticality: "critical",
  internetExposed: true,
  dataSensitivity: "high",
};

const evidenceNodes: readonly EvidenceNode[] = [
  createEvidenceNode(
    RESOLUTION_EVIDENCE_ID,
    "Exact dependency resolution was observed.",
  ),
  createEvidenceNode(
    BUILD_EVIDENCE_ID,
    "The affected dependency was included in a build.",
  ),
  createEvidenceNode(
    DEPLOYMENT_EVIDENCE_ID,
    "The affected build artifact was deployed.",
  ),
  createEvidenceNode(
    REACHABILITY_EVIDENCE_ID,
    "Runtime reachability was observed.",
  ),
  createEvidenceNode(
    EXECUTION_EVIDENCE_ID,
    "Execution was directly observed.",
  ),
];

const graphNodes: readonly GraphNode[] = [
  affectedVersion,
  bridgeVersion,
  betaService,
  alphaService,
  ...evidenceNodes,
];

const dependencyEdges: readonly DependencyEdge[] = [
  createDependencyEdge(
    1_101,
    ALPHA_SERVICE_ID,
    AFFECTED_VERSION_ID,
    "alpha-direct",
  ),
  createDependencyEdge(
    1_102,
    BRIDGE_VERSION_ID,
    AFFECTED_VERSION_ID,
    "bridge-to-affected",
  ),
  createDependencyEdge(
    1_103,
    BETA_SERVICE_ID,
    AFFECTED_VERSION_ID,
    "beta-direct",
  ),
  createDependencyEdge(
    1_104,
    AFFECTED_VERSION_ID,
    BRIDGE_VERSION_ID,
    "cycle-back-to-bridge",
  ),
  createDependencyEdge(
    1_105,
    ALPHA_SERVICE_ID,
    BRIDGE_VERSION_ID,
    "alpha-through-bridge",
  ),
];

class FixtureGraphReader implements ReadonlyGraphReader {
  private readonly nodesById: ReadonlyMap<NodeId, GraphNode>;

  public constructor(
    nodes: readonly GraphNode[],
    private readonly edges: readonly DependencyEdge[],
  ) {
    this.nodesById = new Map(
      nodes.map((node) => [node.id, node] as const),
    );
  }

  public async getNode(
    nodeId: NodeId,
  ): Promise<GraphNode | null> {
    return this.nodesById.get(nodeId) ?? null;
  }

  public async findDependents(
    nodeId: NodeId,
  ): Promise<readonly DependencyHop[]> {
    const hops: DependencyHop[] = [];

    for (const edge of this.edges) {
      if (edge.targetId !== nodeId) {
        continue;
      }

      const dependentNode = this.nodesById.get(edge.sourceId);

      if (dependentNode === undefined) {
        throw new Error(
          `Fixture edge ${String(edge.id)} references missing node ` +
          String(edge.sourceId),
        );
      }

      hops.push({
        dependentNode,
        canonicalEdge: edge,
      });
    }

    return hops;
  }

  public async getEvidence(
    evidenceIds: readonly NodeId[],
  ): Promise<readonly EvidenceNode[]> {
    const evidenceNodesForIds: EvidenceNode[] = [];

    for (const evidenceId of evidenceIds) {
      const node = this.nodesById.get(evidenceId);

      if (node?.kind === "Evidence") {
        evidenceNodesForIds.push(node);
      }
    }

    return evidenceNodesForIds;
  }
}

function createExposureSignals(
  stage: ExposureStage,
): ExposureEvidenceSignals {
  const semverEligible = stage !== "candidate";

  const exactResolutionEvidenceIds =
    stage === "candidate" || stage === "semver-eligible"
      ? []
      : [RESOLUTION_EVIDENCE_ID];

  const buildEvidenceIds =
    stage === "built" ||
    stage === "deployed" ||
    stage === "runtime-reachable" ||
    stage === "execution-observed"
      ? [BUILD_EVIDENCE_ID]
      : [];

  const deploymentEvidenceIds =
    stage === "deployed" ||
    stage === "runtime-reachable" ||
    stage === "execution-observed"
      ? [DEPLOYMENT_EVIDENCE_ID]
      : [];

  const reachabilityEvidenceIds =
    stage === "runtime-reachable" ||
    stage === "execution-observed"
      ? [REACHABILITY_EVIDENCE_ID]
      : [];

  const executionEvidenceIds =
    stage === "execution-observed"
      ? [EXECUTION_EVIDENCE_ID]
      : [];

  return {
    semverEligible,
    exactResolutionEvidenceIds,
    buildEvidenceIds,
    deploymentEvidenceIds,
    reachabilityEvidenceIds,
    executionEvidenceIds,
  };
}

async function runSmoke(): Promise<void> {
  const graphSnapshot = JSON.stringify({
    graphNodes,
    dependencyEdges,
  });

  const reader = new FixtureGraphReader(
    graphNodes,
    dependencyEdges,
  );

  const result = await analyzeBlastRadius(
    reader,
    [AFFECTED_VERSION_ID, AFFECTED_VERSION_ID],
  );

  deepEqual(
    result.affectedVersionIds,
    [AFFECTED_VERSION_ID],
  );
  deepEqual(
    result.services.map((candidate) => candidate.service.id),
    [BETA_SERVICE_ID, ALPHA_SERVICE_ID],
  );
  equal(result.totalPathCount, 3);
  equal(result.truncated, false);

  const alphaCandidate = result.services.find(
    (candidate) =>
      candidate.service.id === ALPHA_SERVICE_ID,
  );
  const betaCandidate = result.services.find(
    (candidate) =>
      candidate.service.id === BETA_SERVICE_ID,
  );

  ok(alphaCandidate);
  ok(betaCandidate);

  equal(alphaCandidate.minimumDepth, 1);
  equal(alphaCandidate.paths.length, 2);
  equal(betaCandidate.minimumDepth, 1);
  equal(betaCandidate.paths.length, 1);

  ok(
    alphaCandidate.paths.every((path) =>
      path.canonicalEdges.every(
        (edge) =>
          edge.kind === "DEPENDS_ON" &&
          edge.derived === false,
      ),
    ),
  );

  ok(
    result.warnings.some(
      (warning) => warning.code === "cycle-skipped",
    ),
  );

  equal(
    JSON.stringify({
      graphNodes,
      dependencyEdges,
    }),
    graphSnapshot,
    "Blast-radius analysis must not mutate the source graph",
  );

  const expectedStages: readonly ExposureStage[] = [
    "candidate",
    "semver-eligible",
    "resolved",
    "built",
    "deployed",
    "runtime-reachable",
    "execution-observed",
  ];

  const expectedConclusions: readonly SecurityConclusion[] = [
    "candidate",
    "candidate",
    "affected",
    "affected",
    "exposed",
    "reachable",
    "executed",
  ];

  const assessments = expectedStages.map((stage) =>
    classifyExposure(createExposureSignals(stage)),
  );

  deepEqual(
    assessments.map((assessment) => assessment.stage),
    expectedStages,
  );
  deepEqual(
    assessments.map((assessment) => assessment.conclusion),
    expectedConclusions,
  );

  const executedAssessment = assessments.find(
    (assessment) =>
      assessment.stage === "execution-observed",
  );

  ok(executedAssessment);
  deepEqual(executedAssessment.evidenceIds, [
    RESOLUTION_EVIDENCE_ID,
    BUILD_EVIDENCE_ID,
    DEPLOYMENT_EVIDENCE_ID,
    REACHABILITY_EVIDENCE_ID,
    EXECUTION_EVIDENCE_ID,
  ]);
  deepEqual(executedAssessment.uncertainties, []);

  const outOfOrderAssessment = classifyExposure({
    semverEligible: true,
    exactResolutionEvidenceIds: [],
    buildEvidenceIds: [],
    deploymentEvidenceIds: [DEPLOYMENT_EVIDENCE_ID],
    reachabilityEvidenceIds: [],
    executionEvidenceIds: [],
  });

  equal(outOfOrderAssessment.stage, "semver-eligible");
  equal(outOfOrderAssessment.conclusion, "candidate");
  deepEqual(outOfOrderAssessment.evidenceIds, []);

  const resolvedEvidence = await reader.getEvidence([
    RESOLUTION_EVIDENCE_ID,
  ]);

  equal(resolvedEvidence.length, 1);
  equal(resolvedEvidence[0]?.kind, "Evidence");

  console.log(
    "analysis smoke passed: " +
    `${String(result.services.length)} services, ` +
    `${String(result.totalPathCount)} paths, ` +
    `${String(assessments.length)} exposure stages`,
  );
}

void runSmoke().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
