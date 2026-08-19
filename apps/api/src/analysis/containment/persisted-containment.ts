import type {
  PersistedGraphBatch,
} from "../../db/persistence-service.js";
import type {
  EvidenceNode,
  NodeId,
} from "../../domain/schema.js";
import type {
  ReadonlyAuthorityGraphReader,
} from "../authority/wave2-propagation.js";
import type {
  ReadonlyGraphReader,
} from "../core/analysis-types.js";

import {
  ContainmentPlanError,
  simulateContainment,
} from "./containment-simulator.js";
import type {
  ContainmentSimulationInput,
  ContainmentSimulationResult,
} from "./containment-simulator.js";

export type ContainmentEvidenceValidationCode =
  | "missing-required-evidence"
  | "missing-evidence"
  | "wrong-evidence-kind"
  | "evidence-reader-mismatch";

export type ContainmentSnapshotValidationCode =
  | "reader-capability-mismatch"
  | "missing-persisted-node"
  | "missing-reader-node"
  | "node-identity-mismatch"
  | "missing-persisted-edge"
  | "edge-identity-mismatch";

export class ContainmentSnapshotValidationError
  extends Error {
  public constructor(
    readonly code: ContainmentSnapshotValidationCode,
    readonly graphId: number,
    message: string,
  ) {
    super(message);
    this.name = "ContainmentSnapshotValidationError";
  }
}

export class ContainmentEvidenceValidationError
  extends Error {
  public constructor(
    readonly code: ContainmentEvidenceValidationCode,
    readonly nodeId: NodeId,
    message: string,
  ) {
    super(message);
    this.name = "ContainmentEvidenceValidationError";
  }
}

export interface PersistedContainmentSimulationResult
  extends ContainmentSimulationResult {
  readonly batchHash: string;
  readonly correlationId: string;
}

export interface PersistedContainmentGraphReader
  extends ReadonlyGraphReader {
  readonly persisted: PersistedGraphBatch;
}

export interface PersistedContainmentAuthorityReader
  extends ReadonlyAuthorityGraphReader {
  readonly persisted: PersistedGraphBatch;
}

type ContainmentEvidenceReader = Pick<
  ReadonlyGraphReader,
  "getNode" | "getEvidence"
>;

type PersistedNode =
  PersistedGraphBatch["batch"]["nodes"][number];
type PersistedEdge =
  PersistedGraphBatch["batch"]["edges"][number];

function compareNodeIds(
  left: NodeId,
  right: NodeId,
): number {
  return left - right;
}

function uniqueSortedNodeIds(
  nodeIds: readonly NodeId[],
): readonly NodeId[] {
  return [...new Set(nodeIds)].sort(
    compareNodeIds,
  );
}

async function validateEvidenceIds(
  reader: ContainmentEvidenceReader,
  evidenceIds: readonly NodeId[],
): Promise<void> {
  const requestedIds =
    uniqueSortedNodeIds(evidenceIds);

  if (requestedIds.length === 0) {
    return;
  }

  const expectedEvidenceById =
    new Map<NodeId, EvidenceNode>();

  for (const evidenceId of requestedIds) {
    const node = await reader.getNode(
      evidenceId,
    );

    if (node === null) {
      throw new ContainmentEvidenceValidationError(
        "missing-evidence",
        evidenceId,
        `Evidence node ${String(evidenceId)} was not found`,
      );
    }

    if (node.kind !== "Evidence") {
      throw new ContainmentEvidenceValidationError(
        "wrong-evidence-kind",
        evidenceId,
        `Node ${String(evidenceId)} is ${node.kind}, not Evidence`,
      );
    }

    expectedEvidenceById.set(
      evidenceId,
      node,
    );
  }

  const returnedEvidence =
    await reader.getEvidence(requestedIds);
  const returnedEvidenceById =
    new Map<NodeId, EvidenceNode>();

  for (const evidence of returnedEvidence) {
    if (evidence.kind !== "Evidence") {
      throw new ContainmentEvidenceValidationError(
        "wrong-evidence-kind",
        evidence.id,
        `Reader returned non-Evidence node ${String(evidence.id)}`,
      );
    }

    const expected =
      expectedEvidenceById.get(evidence.id);

    if (expected === undefined) {
      throw new ContainmentEvidenceValidationError(
        "evidence-reader-mismatch",
        evidence.id,
        `Reader returned unexpected Evidence node ${String(evidence.id)}`,
      );
    }

    if (returnedEvidenceById.has(evidence.id)) {
      throw new ContainmentEvidenceValidationError(
        "evidence-reader-mismatch",
        evidence.id,
        `Reader returned duplicate Evidence node ${String(evidence.id)}`,
      );
    }

    if (evidence.logicalId !== expected.logicalId) {
      throw new ContainmentEvidenceValidationError(
        "evidence-reader-mismatch",
        evidence.id,
        `Evidence node ${String(evidence.id)} has inconsistent identity`,
      );
    }

    returnedEvidenceById.set(
      evidence.id,
      evidence,
    );
  }

  for (const evidenceId of requestedIds) {
    if (!returnedEvidenceById.has(evidenceId)) {
      throw new ContainmentEvidenceValidationError(
        "evidence-reader-mismatch",
        evidenceId,
        `Evidence reader did not return node ${String(evidenceId)}`,
      );
    }
  }
}

function requiredEvidenceIds(
  input: ContainmentSimulationInput,
): readonly NodeId[] {
  return uniqueSortedNodeIds([
    ...input.plan.directives.flatMap(
      (directive) =>
        directive.control.evidenceIds,
    ),
    ...input.authoritySeeds.flatMap(
      (seed) => seed.evidenceIds,
    ),
  ]);
}

function blastResultEvidenceIds(
  result: ContainmentSimulationResult,
): readonly NodeId[] {
  return uniqueSortedNodeIds([
    ...result.before.blastRadius.services.flatMap(
      (candidate) =>
        candidate.paths.flatMap(
          (path) =>
            path.canonicalEdges.flatMap(
              (edge) => edge.evidenceIds,
            ),
        ),
    ),
    ...result.after.blastRadius.services.flatMap(
      (candidate) =>
        candidate.paths.flatMap(
          (path) =>
            path.canonicalEdges.flatMap(
              (edge) => edge.evidenceIds,
            ),
        ),
    ),
  ]);
}

function authorityResultEvidenceIds(
  result: ContainmentSimulationResult,
): readonly NodeId[] {
  return uniqueSortedNodeIds([
    ...result.before.authority.targets.flatMap(
      (target) =>
        target.paths.flatMap(
          (path) => path.evidenceIds,
        ),
    ),
    ...result.after.authority.targets.flatMap(
      (target) =>
        target.paths.flatMap(
          (path) => path.evidenceIds,
        ),
    ),
  ]);
}

function validateRequiredEvidence(
  input: ContainmentSimulationInput,
): void {
  for (const directive of input.plan.directives) {
    if (directive.control.evidenceIds.length === 0) {
      throw new ContainmentEvidenceValidationError(
        "missing-required-evidence",
        directive.control.id,
        `Containment control ${String(directive.control.id)} requires Evidence`,
      );
    }
  }

  for (const seed of input.authoritySeeds) {
    if (seed.evidenceIds.length === 0) {
      throw new ContainmentEvidenceValidationError(
        "missing-required-evidence",
        seed.nodeId,
        `Containment authority seed ${String(seed.nodeId)} requires Evidence`,
      );
    }
  }
}

function persistedNodesById(
  persisted: PersistedGraphBatch,
): ReadonlyMap<NodeId, PersistedNode> {
  return new Map(
    persisted.batch.nodes.map(
      (node) => [node.id, node] as const,
    ),
  );
}

function inputNodeIds(
  input: ContainmentSimulationInput,
): readonly NodeId[] {
  return uniqueSortedNodeIds([
    ...input.affectedVersionIds,
    ...input.authoritySeeds.map(
      (seed) => seed.nodeId,
    ),
    ...input.plan.directives.map(
      (directive) => directive.control.id,
    ),
    ...input.plan.directives.flatMap(
      (directive) => directive.blockedNodeIds,
    ),
  ]);
}

async function validateReaderSnapshotNodes(
  reader: ContainmentEvidenceReader,
  nodeIds: readonly NodeId[],
  nodesById: ReadonlyMap<NodeId, PersistedNode>,
): Promise<void> {
  for (const nodeId of nodeIds) {
    const persistedNode = nodesById.get(nodeId);

    if (persistedNode === undefined) {
      throw new ContainmentSnapshotValidationError(
        "missing-persisted-node",
        nodeId,
        `Node ${String(nodeId)} is not part of the persisted batch`,
      );
    }

    const readerNode = await reader.getNode(nodeId);

    if (readerNode === null) {
      throw new ContainmentSnapshotValidationError(
        "missing-reader-node",
        nodeId,
        `Reader did not return persisted node ${String(nodeId)}`,
      );
    }

    if (
      readerNode.logicalId !== persistedNode.logicalId ||
      readerNode.kind !== persistedNode.kind
    ) {
      throw new ContainmentSnapshotValidationError(
        "node-identity-mismatch",
        nodeId,
        `Reader node ${String(nodeId)} does not match the persisted identity`,
      );
    }
  }
}

function validateResultSnapshot(
  persisted: PersistedGraphBatch,
  result: ContainmentSimulationResult,
): void {
  const nodesById = persistedNodesById(persisted);
  const edgesById = new Map<number, PersistedEdge>(
    persisted.batch.edges.map(
      (edge) => [edge.id, edge] as const,
    ),
  );
  const blastPaths = [
    ...result.before.blastRadius.services,
    ...result.after.blastRadius.services,
  ].flatMap((candidate) => candidate.paths);
  const authorityPaths = [
    ...result.before.authority.targets,
    ...result.after.authority.targets,
  ].flatMap((target) => target.paths);
  const resultNodes = [
    ...blastPaths.flatMap((path) => path.nodes),
    ...authorityPaths.flatMap((path) => path.nodes),
  ];
  const resultEdges = [
    ...blastPaths.flatMap(
      (path) => path.canonicalEdges,
    ),
    ...authorityPaths.flatMap(
      (path) => path.canonicalEdges,
    ),
  ];

  for (const node of resultNodes) {
    const persistedNode = nodesById.get(node.id);

    if (persistedNode === undefined) {
      throw new ContainmentSnapshotValidationError(
        "missing-persisted-node",
        node.id,
        `Result node ${String(node.id)} is not part of the persisted batch`,
      );
    }

    if (
      node.logicalId !== persistedNode.logicalId ||
      node.kind !== persistedNode.kind
    ) {
      throw new ContainmentSnapshotValidationError(
        "node-identity-mismatch",
        node.id,
        `Result node ${String(node.id)} does not match the persisted identity`,
      );
    }
  }

  for (const edge of resultEdges) {
    const persistedEdge = edgesById.get(edge.id);

    if (
      persistedEdge === undefined ||
      persistedEdge.kind === "USED_BY"
    ) {
      throw new ContainmentSnapshotValidationError(
        "missing-persisted-edge",
        edge.id,
        `Result edge ${String(edge.id)} is not a persisted canonical edge`,
      );
    }

    if (
      edge.logicalId !== persistedEdge.logicalId ||
      edge.kind !== persistedEdge.kind ||
      edge.sourceId !== persistedEdge.sourceId ||
      edge.targetId !== persistedEdge.targetId
    ) {
      throw new ContainmentSnapshotValidationError(
        "edge-identity-mismatch",
        edge.id,
        `Result edge ${String(edge.id)} does not match the persisted identity`,
      );
    }
  }
}

function expectedEdgeKind(
  action:
    ContainmentSimulationInput["plan"]["directives"][number]["control"]["action"],
): "DEPENDS_ON" | "CAN_PUBLISH" | undefined {
  switch (action) {
    case "pin-dependency":
    case "apply-override":
      return "DEPENDS_ON";

    case "remove-publishing-access":
      return "CAN_PUBLISH";

    case "block-package-version":
    case "revoke-credential":
    case "disable-workflow":
    case "rotate-secret":
    case "rollback-artifact":
    case "isolate-service":
    case "restrict-network":
      return undefined;
  }
}

function validatePersistedEdgeTargets(
  persisted: PersistedGraphBatch,
  input: ContainmentSimulationInput,
): void {
  const nodesById = persistedNodesById(
    persisted,
  );
  const edgesById = new Map(
    persisted.batch.edges.map(
      (edge) => [edge.id, edge] as const,
    ),
  );

  for (const directive of input.plan.directives) {
    const persistedControl = nodesById.get(
      directive.control.id,
    );

    if (
      persistedControl === undefined ||
      persistedControl.kind !== "Control"
    ) {
      throw new ContainmentSnapshotValidationError(
        "missing-persisted-node",
        directive.control.id,
        `Control ${String(directive.control.id)} is not part of the persisted batch`,
      );
    }

    const persistedEvidenceIds =
      uniqueSortedNodeIds(
        persistedControl.evidenceIds,
      );
    const requestedEvidenceIds =
      uniqueSortedNodeIds(
        directive.control.evidenceIds,
      );

    if (
      persistedControl.logicalId !==
        directive.control.logicalId ||
      persistedControl.action !==
        directive.control.action ||
      persistedControl.status !==
        directive.control.status ||
      persistedEvidenceIds.length !==
        requestedEvidenceIds.length ||
      persistedEvidenceIds.some(
        (evidenceId, index) =>
          evidenceId !==
          requestedEvidenceIds[index],
      )
    ) {
      throw new ContainmentSnapshotValidationError(
        "node-identity-mismatch",
        directive.control.id,
        `Control ${String(directive.control.id)} does not match the persisted definition`,
      );
    }

    const expectedKind = expectedEdgeKind(
      directive.control.action,
    );

    for (const edgeId of directive.blockedEdgeIds) {
      const edge = edgesById.get(edgeId);

      if (edge === undefined || edge.kind === "USED_BY") {
        throw new ContainmentPlanError(
          "missing-target-edge",
          `Control ${String(directive.control.id)} targets missing canonical edge ${String(edgeId)}`,
          directive.control.id,
          edgeId,
        );
      }

      if (
        expectedKind === undefined ||
        edge.kind !== expectedKind
      ) {
        throw new ContainmentPlanError(
          "wrong-target-edge-kind",
          `Control ${String(directive.control.id)} action ` +
            `${directive.control.action} cannot target ${edge.kind}`,
          directive.control.id,
          edgeId,
        );
      }

      const controlEvidence = new Set(
        directive.control.evidenceIds,
      );
      const sharesEvidence =
        edge.evidenceIds.some(
          (evidenceId) =>
            controlEvidence.has(evidenceId),
        );

      if (!sharesEvidence) {
        throw new ContainmentPlanError(
          "target-evidence-mismatch",
          `Control ${String(directive.control.id)} has no Evidence supporting edge ${String(edgeId)}`,
          directive.control.id,
          edgeId,
        );
      }
    }
  }
}

/**
 * Production containment simulation entry point.
 *
 * PersistedGraphBatch proves that immutable graph persistence and verification
 * completed before analysis. Both readers must carry that exact branded
 * capability object, and every returned node and edge is checked against its
 * immutable batch. Control, seed, and retained-path Evidence IDs are validated
 * before a report is returned.
 *
 * This function models an immutable overlay only. It never applies a control,
 * mutates graph state, or claims that structural reduction proves containment.
 */
export async function runContainmentSimulation(
  persisted: PersistedGraphBatch,
  blastRadiusReader:
    PersistedContainmentGraphReader,
  authorityReader:
    PersistedContainmentAuthorityReader,
  input: ContainmentSimulationInput,
): Promise<PersistedContainmentSimulationResult> {
  if (
    blastRadiusReader.persisted !== persisted ||
    authorityReader.persisted !== persisted
  ) {
    throw new ContainmentSnapshotValidationError(
      "reader-capability-mismatch",
      0,
      "Containment readers must carry the exact persisted batch capability",
    );
  }

  validateRequiredEvidence(input);
  validatePersistedEdgeTargets(
    persisted,
    input,
  );

  const nodesById = persistedNodesById(
    persisted,
  );
  const requiredNodeIds = inputNodeIds(input);

  await validateReaderSnapshotNodes(
    blastRadiusReader,
    requiredNodeIds,
    nodesById,
  );
  await validateReaderSnapshotNodes(
    authorityReader,
    requiredNodeIds,
    nodesById,
  );

  const evidenceIds = requiredEvidenceIds(input);

  await validateEvidenceIds(
    blastRadiusReader,
    evidenceIds,
  );
  await validateEvidenceIds(
    authorityReader,
    evidenceIds,
  );

  const result = await simulateContainment(
    blastRadiusReader,
    authorityReader,
    input,
  );

  validateResultSnapshot(persisted, result);

  await validateEvidenceIds(
    blastRadiusReader,
    blastResultEvidenceIds(result),
  );
  await validateEvidenceIds(
    authorityReader,
    authorityResultEvidenceIds(result),
  );

  return {
    ...result,
    batchHash: persisted.batchHash,
    correlationId: persisted.correlationId,
  };
}
