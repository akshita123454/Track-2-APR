import type {
  PersistedGraphBatch,
} from "../../db/persistence-service.js";
import type {
  EvidenceNode,
  NodeId,
} from "../../domain/schema.js";

import {
  analyzeWave2Authority,
} from "./wave2-propagation.js";
import type {
  ReadonlyAuthorityGraphReader,
  Wave2AuthorityOptions,
  Wave2AuthorityResult,
  Wave2AuthoritySeed,
} from "./wave2-propagation.js";

export type Wave2EvidenceValidationCode =
  | "missing-required-evidence"
  | "missing-evidence"
  | "wrong-evidence-kind"
  | "evidence-reader-mismatch";

export class Wave2EvidenceValidationError
  extends Error {
  public constructor(
    readonly code: Wave2EvidenceValidationCode,
    readonly nodeId: NodeId,
    message: string,
  ) {
    super(message);
    this.name = "Wave2EvidenceValidationError";
  }
}

export interface PersistedWave2AuthorityResult
  extends Wave2AuthorityResult {
  readonly batchHash: string;
  readonly correlationId: string;
}

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
  reader: ReadonlyAuthorityGraphReader,
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
      throw new Wave2EvidenceValidationError(
        "missing-evidence",
        evidenceId,
        `Evidence node ${String(evidenceId)} was not found`,
      );
    }

    if (node.kind !== "Evidence") {
      throw new Wave2EvidenceValidationError(
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
      throw new Wave2EvidenceValidationError(
        "wrong-evidence-kind",
        evidence.id,
        `Reader returned non-Evidence node ${String(evidence.id)}`,
      );
    }

    const expected =
      expectedEvidenceById.get(evidence.id);

    if (expected === undefined) {
      throw new Wave2EvidenceValidationError(
        "evidence-reader-mismatch",
        evidence.id,
        `Reader returned unexpected Evidence node ${String(evidence.id)}`,
      );
    }

    if (
      returnedEvidenceById.has(evidence.id)
    ) {
      throw new Wave2EvidenceValidationError(
        "evidence-reader-mismatch",
        evidence.id,
        `Reader returned duplicate Evidence node ${String(evidence.id)}`,
      );
    }

    if (
      evidence.logicalId !==
      expected.logicalId
    ) {
      throw new Wave2EvidenceValidationError(
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
    if (
      !returnedEvidenceById.has(evidenceId)
    ) {
      throw new Wave2EvidenceValidationError(
        "evidence-reader-mismatch",
        evidenceId,
        `Evidence reader did not return node ${String(evidenceId)}`,
      );
    }
  }
}

function seedEvidenceIds(
  seeds: readonly Wave2AuthoritySeed[],
): readonly NodeId[] {
  return uniqueSortedNodeIds(
    seeds.flatMap(
      (seed) => seed.evidenceIds,
    ),
  );
}

function resultEvidenceIds(
  result: Wave2AuthorityResult,
): readonly NodeId[] {
  return uniqueSortedNodeIds(
    result.targets.flatMap(
      (target) =>
        target.paths.flatMap(
          (path) => path.evidenceIds,
        ),
    ),
  );
}

/**
 * Production Wave 2 entry point.
 *
 * PersistedGraphBatch proves that immutable graph persistence and verification
 * completed before analysis. Every seed and retained path Evidence ID is
 * validated before a report is returned.
 *
 * Results remain structural authority-reachability candidates. This function
 * does not claim credential theft, publishing, execution, lateral movement,
 * or compromise.
 */
export async function runWave2Authority(
  persisted: PersistedGraphBatch,
  reader: ReadonlyAuthorityGraphReader,
  seeds: readonly Wave2AuthoritySeed[],
  options: Wave2AuthorityOptions = {},
): Promise<PersistedWave2AuthorityResult> {
  for (const seed of seeds) {
    if (seed.evidenceIds.length === 0) {
      throw new Wave2EvidenceValidationError(
        "missing-required-evidence",
        seed.nodeId,
        `Wave 2 seed ${String(seed.nodeId)} requires Evidence`,
      );
    }
  }

  await validateEvidenceIds(
    reader,
    seedEvidenceIds(seeds),
  );

  const result = await analyzeWave2Authority(
    reader,
    seeds,
    options,
  );

  await validateEvidenceIds(
    reader,
    resultEvidenceIds(result),
  );

  return {
    ...result,
    batchHash: persisted.batchHash,
    correlationId: persisted.correlationId,
  };
}
