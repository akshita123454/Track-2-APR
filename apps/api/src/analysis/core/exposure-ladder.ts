import type {
  EvidenceNode,
  NodeId,
} from "../../domain/schema.js";
import type {
  ExposureAssessment,
  ExposureEvidenceSignals,
  ExposureStage,
  ReadonlyGraphReader,
  SecurityConclusion,
} from "./analysis-types.js";

export type ExposureEvidenceValidationCode =
  | "missing-evidence"
  | "wrong-evidence-kind"
  | "evidence-reader-mismatch";

export class ExposureEvidenceValidationError
  extends Error {
  public constructor(
    readonly code: ExposureEvidenceValidationCode,
    readonly evidenceId: NodeId,
    message: string,
  ) {
    super(message);
    this.name = "ExposureEvidenceValidationError";
  }
}

const CONCLUSION_BY_STAGE: Readonly<
  Record<ExposureStage, SecurityConclusion>
> = {
  candidate: "candidate",
  "semver-eligible": "candidate",
  resolved: "affected",
  built: "affected",
  deployed: "exposed",
  "runtime-reachable": "reachable",
  "execution-observed": "executed",
};

const UNCERTAINTIES_BY_STAGE: Readonly<
  Record<ExposureStage, readonly string[]>
> = {
  candidate: [
    "Semantic-version eligibility has not been established.",
  ],
  "semver-eligible": [
    "Exact dependency resolution has not been proven.",
  ],
  resolved: [
    "Inclusion in a build has not been proven.",
  ],
  built: [
    "Deployment has not been proven.",
  ],
  deployed: [
    "Runtime reachability has not been proven.",
  ],
  "runtime-reachable": [
    "Execution has not been observed.",
  ],
  "execution-observed": [],
};

function uniqueSortedEvidenceIds(
  evidenceGroups: readonly (readonly NodeId[])[],
): readonly NodeId[] {
  const evidenceIds = evidenceGroups.flat();

  return [...new Set(evidenceIds)].sort(
    (left, right) => left - right,
  );
}

function allSignalEvidenceIds(
  signals: ExposureEvidenceSignals,
): readonly NodeId[] {
  return uniqueSortedEvidenceIds([
    signals.exactResolutionEvidenceIds,
    signals.buildEvidenceIds,
    signals.deploymentEvidenceIds,
    signals.reachabilityEvidenceIds,
    signals.executionEvidenceIds,
  ]);
}

function determineExposureStage(
  signals: ExposureEvidenceSignals,
): ExposureStage {
  if (!signals.semverEligible) {
    return "candidate";
  }

  if (signals.exactResolutionEvidenceIds.length === 0) {
    return "semver-eligible";
  }

  if (signals.buildEvidenceIds.length === 0) {
    return "resolved";
  }

  if (signals.deploymentEvidenceIds.length === 0) {
    return "built";
  }

  if (signals.reachabilityEvidenceIds.length === 0) {
    return "deployed";
  }

  if (signals.executionEvidenceIds.length === 0) {
    return "runtime-reachable";
  }

  return "execution-observed";
}

function evidenceForStage(
  stage: ExposureStage,
  signals: ExposureEvidenceSignals,
): readonly NodeId[] {
  switch (stage) {
    case "candidate":
    case "semver-eligible":
      return [];

    case "resolved":
      return uniqueSortedEvidenceIds([
        signals.exactResolutionEvidenceIds,
      ]);

    case "built":
      return uniqueSortedEvidenceIds([
        signals.exactResolutionEvidenceIds,
        signals.buildEvidenceIds,
      ]);

    case "deployed":
      return uniqueSortedEvidenceIds([
        signals.exactResolutionEvidenceIds,
        signals.buildEvidenceIds,
        signals.deploymentEvidenceIds,
      ]);

    case "runtime-reachable":
      return uniqueSortedEvidenceIds([
        signals.exactResolutionEvidenceIds,
        signals.buildEvidenceIds,
        signals.deploymentEvidenceIds,
        signals.reachabilityEvidenceIds,
      ]);

    case "execution-observed":
      return uniqueSortedEvidenceIds([
        signals.exactResolutionEvidenceIds,
        signals.buildEvidenceIds,
        signals.deploymentEvidenceIds,
        signals.reachabilityEvidenceIds,
        signals.executionEvidenceIds,
      ]);
  }
}

/**
 * Pure staged classifier used by internal deterministic tests.
 *
 * This function trusts its inputs and therefore must not be exposed through
 * the production public barrel. Production-facing code must first establish
 * persistence and validate evidence.
 */
export function classifyExposure(
  signals: ExposureEvidenceSignals,
): ExposureAssessment {
  const stage = determineExposureStage(signals);

  return {
    stage,
    conclusion: CONCLUSION_BY_STAGE[stage],
    evidenceIds: evidenceForStage(stage, signals),
    uncertainties: [...UNCERTAINTIES_BY_STAGE[stage]],
  };
}

async function validateEvidence(
  reader: ReadonlyGraphReader,
  signals: ExposureEvidenceSignals,
): Promise<void> {
  const requestedIds = allSignalEvidenceIds(signals);

  if (requestedIds.length === 0) {
    return;
  }

  const expectedEvidenceById =
    new Map<NodeId, EvidenceNode>();

  for (const evidenceId of requestedIds) {
    const node = await reader.getNode(evidenceId);

    if (node === null) {
      throw new ExposureEvidenceValidationError(
        "missing-evidence",
        evidenceId,
        `Evidence node ${String(evidenceId)} was not found`,
      );
    }

    if (node.kind !== "Evidence") {
      throw new ExposureEvidenceValidationError(
        "wrong-evidence-kind",
        evidenceId,
        `Node ${String(evidenceId)} is ${node.kind}, not Evidence`,
      );
    }

    expectedEvidenceById.set(evidenceId, node);
  }

  const readerEvidence = await reader.getEvidence(
    requestedIds,
  );
  const returnedEvidenceById =
    new Map<NodeId, EvidenceNode>();

  for (const evidence of readerEvidence) {
    if (evidence.kind !== "Evidence") {
      throw new ExposureEvidenceValidationError(
        "wrong-evidence-kind",
        evidence.id,
        `Reader returned non-Evidence node ${String(evidence.id)}`,
      );
    }

    const expected =
      expectedEvidenceById.get(evidence.id);

    if (expected === undefined) {
      throw new ExposureEvidenceValidationError(
        "evidence-reader-mismatch",
        evidence.id,
        `Reader returned unexpected Evidence node ${String(evidence.id)}`,
      );
    }

    if (returnedEvidenceById.has(evidence.id)) {
      throw new ExposureEvidenceValidationError(
        "evidence-reader-mismatch",
        evidence.id,
        `Reader returned duplicate Evidence node ${String(evidence.id)}`,
      );
    }

    if (evidence.logicalId !== expected.logicalId) {
      throw new ExposureEvidenceValidationError(
        "evidence-reader-mismatch",
        evidence.id,
        `Evidence node ${String(evidence.id)} has inconsistent identity`,
      );
    }

    returnedEvidenceById.set(evidence.id, evidence);
  }

  for (const evidenceId of requestedIds) {
    if (!returnedEvidenceById.has(evidenceId)) {
      throw new ExposureEvidenceValidationError(
        "evidence-reader-mismatch",
        evidenceId,
        `Evidence reader did not return node ${String(evidenceId)}`,
      );
    }
  }
}

/**
 * Internal evidence-aware classifier.
 *
 * Every supplied evidence ID must resolve through both generic node lookup
 * and the reader's evidence lookup. Missing IDs, wrong node kinds, duplicate
 * records, unexpected records, and inconsistent identities fail closed.
 *
 * This remains an internal helper because semverEligible is still a caller
 * assertion. A future production API must derive semver eligibility from the
 * declared range and affected package version.
 */
export async function classifyExposureWithValidatedEvidence(
  reader: ReadonlyGraphReader,
  signals: ExposureEvidenceSignals,
): Promise<ExposureAssessment> {
  await validateEvidence(reader, signals);
  return classifyExposure(signals);
}
