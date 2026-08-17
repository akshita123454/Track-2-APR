import type { NodeId } from "../../domain/schema.js";
import type {
  ExposureAssessment,
  ExposureEvidenceSignals,
  ExposureStage,
  SecurityConclusion,
} from "./analysis-types.js";

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
 * Classifies one structural blast-radius candidate using only explicitly
 * supplied evidence.
 *
 * Evidence stages form a strict ladder. Evidence for a later stage cannot
 * skip an unproven prerequisite. For example, deployment evidence alone does
 * not prove that the affected package version was exactly resolved and built.
 *
 * This function does not query or mutate the graph. Confidence and severity
 * remain separate concerns and are intentionally not inferred here.
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
