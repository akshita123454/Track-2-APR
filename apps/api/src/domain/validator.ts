import {
  createDerivedEdgeIdentity,
  createEdgeIdentity,
  generateDeterministicId,
} from "./identity.js";

import type {
  CanonicalEdge,
  CanonicalRelKind,
  DerivedEdge,
  GraphEdge,
  GraphNode,
  NodeKind,
} from "./schema.js";

export interface ValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
}

function isValidId(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function isValidTimestamp(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

const FINDING_STATUSES = new Set([
  "candidate",
  "suspicious",
  "high-confidence",
  "confirmed",
  "dismissed",
]);

const TRANSFORMATION_KINDS = new Set([
  "adjacent-transposition",
  "insertion",
  "deletion",
  "substitution",
  "separator-variation",
  "repeated-character",
  "scope-impersonation",
  "unicode-confusable",
  "prefix-suffix",
]);

function isNonemptyText(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasValidTransformations(values: readonly string[]): boolean {
  return (
    values.length > 0 &&
    new Set(values).size === values.length &&
    values.every((value) => TRANSFORMATION_KINDS.has(value))
  );
}

function hasAllowedEndpoints(
  relationship: CanonicalRelKind,
  sourceKind: NodeKind,
  targetKind: NodeKind,
): boolean {
  switch (relationship) {
    case "HAS_VERSION":
      return sourceKind === "Package" && targetKind === "PackageVersion";

    case "DECLARES_DEPENDENCY":
      return (
        (
          sourceKind === "Repository" ||
          sourceKind === "Service" ||
          sourceKind === "PackageVersion"
        ) &&
        targetKind === "Package"
      );

    case "DEPENDS_ON":
      return (
        (
          sourceKind === "Service" ||
          sourceKind === "PackageVersion"
        ) &&
        targetKind === "PackageVersion"
      );

    case "CONTAINS":
      return sourceKind === "Repository" && targetKind === "Service";

    case "TRIGGERS":
      return sourceKind === "Repository" && targetKind === "CIWorkflow";

    case "PRODUCES":
      return (
        (sourceKind === "CIWorkflow" && targetKind === "Build") ||
        (sourceKind === "Build" && targetKind === "Artifact")
      );

    case "DEPLOYED_AS":
      return sourceKind === "Artifact" && targetKind === "Deployment";

    case "RUNS":
      return sourceKind === "Deployment" && targetKind === "Service";

    case "MAINTAINS":
      return sourceKind === "Maintainer" && targetKind === "Package";

    case "MEMBER_OF":
      return sourceKind === "Maintainer" && targetKind === "Organization";

    case "OWNS":
      return (
        sourceKind === "Organization" &&
        (
          targetKind === "Package" ||
          targetKind === "Repository" ||
          targetKind === "Service"
        )
      );

    case "CAN_PUBLISH":
      return sourceKind === "Credential" && targetKind === "Package";

    case "CAN_ACCESS":
      return sourceKind === "CIWorkflow" && targetKind === "Credential";

    case "CONTROLS":
      return (
        (
          sourceKind === "Maintainer" ||
          sourceKind === "Organization"
        ) &&
        targetKind === "Credential"
      );

    case "AFFECTS":
      return sourceKind === "Incident" && targetKind === "PackageVersion";

    case "SUPPORTS":
      return sourceKind === "Evidence" && targetKind !== "Evidence";

    case "TARGETS":
      return (
        (sourceKind === "Finding" && targetKind === "Package") ||
        (
          sourceKind === "Control" &&
          targetKind !== "Evidence" &&
          targetKind !== "Control"
        )
      );

    case "LOOKALIKE_OF":
      return sourceKind === "Package" && targetKind === "Package";

    case "IMITATES":
      return sourceKind === "Finding" && targetKind === "Package";

    case "RESOLVED_IN":
      return (
        sourceKind === "LockfileSnapshot" &&
        targetKind === "PackageVersion"
      );
  }
}

function validateEvidenceReferences(
  ownerDescription: string,
  evidenceIds: readonly number[],
  nodesById: ReadonlyMap<number, GraphNode>,
  errors: string[],
): void {
  const uniqueIds = new Set<number>();

  for (const evidenceId of evidenceIds) {
    if (uniqueIds.has(evidenceId)) {
      errors.push(
        `${ownerDescription} contains duplicate evidence ID ${evidenceId}`,
      );
      continue;
    }

    uniqueIds.add(evidenceId);

    const evidence = nodesById.get(evidenceId);

    if (evidence === undefined) {
      errors.push(
        `${ownerDescription} references missing Evidence node ${evidenceId}`,
      );
    } else if (evidence.kind !== "Evidence") {
      errors.push(
        `${ownerDescription} references node ${evidenceId}, but its kind ` +
          `is ${evidence.kind}, not Evidence`,
      );
    }
  }
}

/**
 * Validates exactly one reverse USED_BY edge for every DEPENDS_ON edge.
 */
export function validateParity(
  edges: readonly GraphEdge[],
): ValidationResult {
  const errors: string[] = [];
  const canonicalById = new Map<number, CanonicalEdge>();
  const derivedByCanonicalId = new Map<number, DerivedEdge[]>();
  const seenEdgeIds = new Set<number>();

  for (const edge of edges) {
    if (seenEdgeIds.has(edge.id)) {
      errors.push(`Duplicate edge ID ${edge.id}`);
    } else {
      seenEdgeIds.add(edge.id);
    }

    if (edge.kind === "USED_BY") {
      const directEvidence = (
        edge as unknown as { evidenceIds?: unknown }
      ).evidenceIds;

      if (directEvidence !== undefined) {
        errors.push(
          `Derived USED_BY edge ${edge.id} must not contain evidenceIds`,
        );
      }

      const existing =
        derivedByCanonicalId.get(edge.derivedFrom) ?? [];

      existing.push(edge);
      derivedByCanonicalId.set(edge.derivedFrom, existing);
    } else {
      if (canonicalById.has(edge.id)) {
        errors.push(`Duplicate canonical edge ID ${edge.id}`);
      } else {
        canonicalById.set(edge.id, edge);
      }
    }
  }

  for (const canonical of canonicalById.values()) {
    if (canonical.kind !== "DEPENDS_ON") {
      continue;
    }

    const reverseEdges =
      derivedByCanonicalId.get(canonical.id) ?? [];

    if (reverseEdges.length !== 1) {
      errors.push(
        `DEPENDS_ON edge ${canonical.id} must have exactly one derived ` +
          `USED_BY edge; found ${reverseEdges.length}`,
      );
    }
  }

  for (const [canonicalId, derivedEdges] of derivedByCanonicalId) {
    const canonical = canonicalById.get(canonicalId);

    if (canonical === undefined) {
      for (const derived of derivedEdges) {
        errors.push(
          `Orphan USED_BY edge ${derived.id} references missing ` +
            `canonical edge ${canonicalId}`,
        );
      }

      continue;
    }

    if (canonical.kind !== "DEPENDS_ON") {
      for (const derived of derivedEdges) {
        errors.push(
          `USED_BY edge ${derived.id} derives from ${canonical.kind} ` +
            `edge ${canonical.id}, not DEPENDS_ON`,
        );
      }

      continue;
    }

    for (const derived of derivedEdges) {
      if (
        derived.sourceId !== canonical.targetId ||
        derived.targetId !== canonical.sourceId
      ) {
        errors.push(
          `USED_BY edge ${derived.id} does not exactly reverse ` +
            `DEPENDS_ON edge ${canonical.id}`,
        );
      }

      if (derived.derivedFromLogicalId !== canonical.logicalId) {
        errors.push(
          `USED_BY edge ${derived.id} has incorrect ` +
            `derivedFromLogicalId`,
        );
      }

      const expectedIdentity =
        createDerivedEdgeIdentity(canonical.logicalId);

      if (
        derived.id !== expectedIdentity.id ||
        derived.logicalId !== expectedIdentity.logicalId
      ) {
        errors.push(
          `USED_BY edge ${derived.id} does not have the deterministic ` +
            `identity derived from DEPENDS_ON edge ${canonical.id}`,
        );
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validates the complete in-memory graph before HydraDB ingestion.
 */
export function validateGraph(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
): ValidationResult {
  const errors: string[] = [];
  const nodesById = new Map<number, GraphNode>();
  const nodeIdByLogicalId = new Map<string, number>();

  for (const node of nodes) {
    if (!isValidId(node.id)) {
      errors.push(`Node ${node.logicalId} has unsafe ID ${node.id}`);
    }

    if (!isValidTimestamp(node.observedAt)) {
      errors.push(
        `Node ${node.logicalId} has invalid observedAt ${node.observedAt}`,
      );
    }

    const expectedId = generateDeterministicId(node.logicalId);

    if (node.id !== expectedId) {
      errors.push(
        `Node ${node.logicalId} has ID ${node.id}; expected ${expectedId}`,
      );
    }

    const existingNode = nodesById.get(node.id);

    if (existingNode !== undefined) {
      errors.push(
        `Duplicate node ID ${node.id}: "${existingNode.logicalId}" and ` +
          `"${node.logicalId}"`,
      );
    } else {
      nodesById.set(node.id, node);
    }

    const existingId = nodeIdByLogicalId.get(node.logicalId);

    if (existingId !== undefined) {
      errors.push(
        `Duplicate node logicalId "${node.logicalId}" uses IDs ` +
          `${existingId} and ${node.id}`,
      );
    } else {
      nodeIdByLogicalId.set(node.logicalId, node.id);
    }

    if (node.kind === "LockfileSnapshot") {
      if (!isValidId(node.serviceId)) {
        errors.push(
          `LockfileSnapshot node ${node.id} has an invalid serviceId`,
        );
      }

      if (!/^[0-9a-f]{64}$/.test(node.contentSha256)) {
        errors.push(
          `LockfileSnapshot node ${node.id} contentSha256 must be ` +
            `lowercase hex sha256`,
        );
      }

      if (
        node.lockfileVersion !== 1 &&
        node.lockfileVersion !== 2 &&
        node.lockfileVersion !== 3
      ) {
        errors.push(
          `LockfileSnapshot node ${node.id} has unsupported lockfileVersion`,
        );
      }

      if (!isValidTimestamp(node.validFrom)) {
        errors.push(
          `LockfileSnapshot node ${node.id} has invalid validFrom`,
        );
      }

      if (node.validUntil !== null) {
        if (!isValidTimestamp(node.validUntil)) {
          errors.push(
            `LockfileSnapshot node ${node.id} has invalid validUntil`,
          );
        } else if (node.validUntil < node.validFrom) {
          errors.push(
            `LockfileSnapshot node ${node.id} validUntil precedes validFrom`,
          );
        }
      }

      if (
        node.commitSha !== undefined &&
        !isNonemptyText(node.commitSha)
      ) {
        errors.push(
          `LockfileSnapshot node ${node.id} has an empty commitSha`,
        );
      }
    }

    if (node.kind === "Finding") {
      const requiredText = [
        node.detectorVersion,
        node.policyVersion,
        node.corpusId,
        node.comparisonVersion,
        node.indexVersion,
        node.candidatePackageName,
        node.targetPackageName,
        node.summary,
      ];

      if (node.findingType !== "typosquatting") {
        errors.push(`Finding node ${node.id} has unsupported findingType`);
      }

      if (!FINDING_STATUSES.has(node.status)) {
        errors.push(`Finding node ${node.id} has unsupported status`);
      }

      if (!Number.isFinite(node.score) || node.score < 0 || node.score > 100) {
        errors.push(`Finding node ${node.id} score must be between 0 and 100`);
      }

      if (requiredText.some((value) => !isNonemptyText(value))) {
        errors.push(`Finding node ${node.id} has an empty required property`);
      }

      if (!hasValidTransformations(node.transformations)) {
        errors.push(`Finding node ${node.id} has invalid transformations`);
      }

      if (
        node.reasonCodes.length === 0 ||
        new Set(node.reasonCodes).size !== node.reasonCodes.length ||
        node.reasonCodes.some((value) => !isNonemptyText(value))
      ) {
        errors.push(`Finding node ${node.id} has invalid reasonCodes`);
      }

      if (!isValidTimestamp(node.detectedAt)) {
        errors.push(`Finding node ${node.id} has invalid detectedAt`);
      }

      const terminal = node.status === "confirmed" || node.status === "dismissed";
      const hasDecision = node.decidedAt !== undefined && node.decisionReason !== undefined;

      if (terminal && !hasDecision) {
        errors.push(`Finding node ${node.id} terminal status requires decision fields`);
      } else if (!terminal && (node.decidedAt !== undefined || node.decisionReason !== undefined)) {
        errors.push(`Finding node ${node.id} nonterminal status cannot carry decision fields`);
      }

      if (node.decidedAt !== undefined && !isValidTimestamp(node.decidedAt)) {
        errors.push(`Finding node ${node.id} has invalid decidedAt`);
      }

      if (node.decisionReason !== undefined && !isNonemptyText(node.decisionReason)) {
        errors.push(`Finding node ${node.id} has invalid decisionReason`);
      }
    }

    if (node.kind === "Evidence") {
      if (node.evidenceIds.length !== 0) {
        errors.push(
          `Evidence node ${node.id} must not recursively reference evidence`,
        );
      }

      if (
        !Number.isFinite(node.confidence) ||
        node.confidence < 0 ||
        node.confidence > 1
      ) {
        errors.push(
          `Evidence node ${node.id} confidence must be between 0 and 1`,
        );
      }
    } else if (node.evidenceIds.length === 0) {
      errors.push(
        `${node.kind} node ${node.id} has no supporting Evidence node`,
      );
    }

    if (
      node.kind === "Incident" &&
      node.intervalEnd !== null &&
      node.intervalEnd < node.intervalStart
    ) {
      errors.push(
        `Incident ${node.id} ends before its start timestamp`,
      );
    }
  }

  for (const node of nodes) {
    validateEvidenceReferences(
      `${node.kind} node ${node.id}`,
      node.evidenceIds,
      nodesById,
      errors,
    );

    if (node.synthetic && node.kind !== "Evidence") {
      const hasSyntheticEvidence = node.evidenceIds.some(
        (evidenceId) => nodesById.get(evidenceId)?.synthetic === true,
      );

      if (!hasSyntheticEvidence) {
        errors.push(
          `Synthetic ${node.kind} node ${node.id} must reference at least ` +
            `one synthetic Evidence node`,
        );
      }
    }
  }

  const edgeById = new Map<number, GraphEdge>();
  const edgeIdByLogicalId = new Map<string, number>();

  for (const edge of edges) {
    if (!isValidId(edge.id)) {
      errors.push(`Edge ${edge.logicalId} has unsafe ID ${edge.id}`);
    }

    if (!isValidTimestamp(edge.observedAt)) {
      errors.push(
        `Edge ${edge.logicalId} has invalid observedAt ${edge.observedAt}`,
      );
    }

    const existingEdge = edgeById.get(edge.id);

    if (existingEdge !== undefined) {
      errors.push(
        `Duplicate edge ID ${edge.id}: "${existingEdge.logicalId}" and ` +
          `"${edge.logicalId}"`,
      );
    } else {
      edgeById.set(edge.id, edge);
    }

    const existingLogicalEdgeId =
      edgeIdByLogicalId.get(edge.logicalId);

    if (existingLogicalEdgeId !== undefined) {
      errors.push(
        `Duplicate edge logicalId "${edge.logicalId}" uses IDs ` +
          `${existingLogicalEdgeId} and ${edge.id}`,
      );
    } else {
      edgeIdByLogicalId.set(edge.logicalId, edge.id);
    }

    const source = nodesById.get(edge.sourceId);
    const target = nodesById.get(edge.targetId);

    if (source === undefined) {
      errors.push(
        `Edge ${edge.id} references missing source node ${edge.sourceId}`,
      );
    }

    if (target === undefined) {
      errors.push(
        `Edge ${edge.id} references missing target node ${edge.targetId}`,
      );
    }

    if (edge.kind === "USED_BY") {
      continue;
    }

    if (edge.evidenceIds.length === 0) {
      errors.push(
        `Canonical ${edge.kind} edge ${edge.id} has no supporting evidence`,
      );
    }

    validateEvidenceReferences(
      `${edge.kind} edge ${edge.id}`,
      edge.evidenceIds,
      nodesById,
      errors,
    );

    if (
      edge.kind === "LOOKALIKE_OF" &&
      source !== undefined &&
      target !== undefined
    ) {
      if (edge.sourceId === edge.targetId) {
        errors.push(`LOOKALIKE_OF edge ${edge.id} must connect distinct packages`);
      }

      if (!isNonemptyText(edge.algorithm) || !isNonemptyText(edge.comparisonVersion)) {
        errors.push(`LOOKALIKE_OF edge ${edge.id} has an empty required property`);
      }

      if (
        !Number.isFinite(edge.normalizedDistance) ||
        edge.normalizedDistance < 0 ||
        edge.normalizedDistance > 1
      ) {
        errors.push(`LOOKALIKE_OF edge ${edge.id} normalizedDistance must be between 0 and 1`);
      }

      if (!hasValidTransformations(edge.transformations)) {
        errors.push(`LOOKALIKE_OF edge ${edge.id} has invalid transformations`);
      }
    }

    if (edge.kind === "DEPENDS_ON") {
      if (
        edge.validFrom !== undefined &&
        !isValidTimestamp(edge.validFrom)
      ) {
        errors.push(
          `DEPENDS_ON edge ${edge.id} has invalid validFrom`,
        );
      }

      if (edge.validUntil !== undefined) {
        if (!isValidTimestamp(edge.validUntil)) {
          errors.push(
            `DEPENDS_ON edge ${edge.id} has invalid validUntil`,
          );
        } else if (
          edge.validFrom !== undefined &&
          edge.validUntil < edge.validFrom
        ) {
          errors.push(
            `DEPENDS_ON edge ${edge.id} validUntil precedes validFrom`,
          );
        }
      }

      /*
       * A closing timestamp without an opening one cannot be placed on the
       * time axis, so it would silently read as "unknown" while looking
       * temporally precise.
       */
      if (
        edge.validUntil !== undefined &&
        edge.validFrom === undefined
      ) {
        errors.push(
          `DEPENDS_ON edge ${edge.id} declares validUntil without validFrom`,
        );
      }

      if (edge.snapshotId !== undefined) {
        if (!isValidId(edge.snapshotId)) {
          errors.push(
            `DEPENDS_ON edge ${edge.id} has an invalid snapshotId`,
          );
        } else {
          const snapshot = nodesById.get(edge.snapshotId);

          if (snapshot === undefined) {
            errors.push(
              `DEPENDS_ON edge ${edge.id} references missing ` +
                `LockfileSnapshot ${edge.snapshotId}`,
            );
          } else if (snapshot.kind !== "LockfileSnapshot") {
            errors.push(
              `DEPENDS_ON edge ${edge.id} snapshotId ${edge.snapshotId} is ` +
                `${snapshot.kind}, not LockfileSnapshot`,
            );
          }
        }
      }
    }

    if (
      source !== undefined &&
      target !== undefined &&
      !hasAllowedEndpoints(edge.kind, source.kind, target.kind)
    ) {
      errors.push(
        `${edge.kind} edge ${edge.id} cannot connect ` +
          `${source.kind} to ${target.kind}`,
      );
    }

    if (source !== undefined && target !== undefined) {
      const expectedIdentity = createEdgeIdentity({
        kind: edge.kind,
        sourceLogicalId: source.logicalId,
        targetLogicalId: target.logicalId,
        discriminator: edge.identityDiscriminator,
      });

      if (
        edge.id !== expectedIdentity.id ||
        edge.logicalId !== expectedIdentity.logicalId
      ) {
        errors.push(
          `${edge.kind} edge ${edge.id} does not match its deterministic ` +
            `relationship identity`,
        );
      }
    }
  }

  const parityResult = validateParity(edges);
  errors.push(...parityResult.errors);

  return {
    valid: errors.length === 0,
    errors,
  };
}
