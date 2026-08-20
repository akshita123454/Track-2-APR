import type {
  DependencyType,
  EvidenceSourceType,
  NodeId,
  PackageVersionNode,
} from "../../domain/schema.js";

import type {
  BlastRadiusPath,
  BlastRadiusResult,
  ExposureStage,
  SecurityConclusion,
} from "./analysis-types.js";

export const SERVICE_IMPACT_POLICY_VERSION =
  "service-impact-v1" as const;

export type EvidenceConfidenceLevel =
  | "confirmed"
  | "strong"
  | "probable"
  | "possible"
  | "contextual"
  | "unknown";

export type SelectionState =
  | "exactly-resolved"
  | "unknown";

export type EvidenceFactStatus =
  | "proven"
  | "not-proven"
  | "unknown";

export interface DecisionEvidence {
  readonly id: NodeId;
  readonly sourceType: EvidenceSourceType;
  readonly confidence: number;
  readonly observedAt: number;
  readonly synthetic: boolean;
}

export interface ConfidenceAssessment {
  readonly level: EvidenceConfidenceLevel;
  readonly policyVersion: typeof SERVICE_IMPACT_POLICY_VERSION;
  readonly supportingEvidenceIds: readonly NodeId[];
  readonly reasons: readonly string[];
  readonly complete: boolean;
  readonly synthetic: boolean;
}

export interface EvidenceFactAssessment {
  readonly status: EvidenceFactStatus;
  readonly evidenceIds: readonly NodeId[];
  readonly reason: string;
}

export interface PathImpactAssessment {
  readonly pathKey: string;
  readonly stage: ExposureStage;
  readonly conclusion: SecurityConclusion;
  readonly confidence: ConfidenceAssessment;
  readonly evidenceIds: readonly NodeId[];
  readonly missingEvidenceIds: readonly NodeId[];
  readonly uncertainties: readonly string[];
}

export interface ImpactAffectedVersion {
  readonly id: NodeId;
  readonly packageName: string;
  readonly version: string;
}

export interface ServiceSelectionAssessment {
  readonly state: SelectionState;
  readonly dependencyTypes: readonly DependencyType[];
  readonly declaredRanges: readonly string[];
  readonly lockfilePaths: readonly string[];
  readonly resolvedVersions: readonly ImpactAffectedVersion[];
  readonly reason: string;
}

export interface ServiceTemporalAssessment {
  readonly status: "unknown";
  readonly asOf: number;
  readonly reason: string;
}

export interface ServiceImpactExplanation {
  readonly serviceId: NodeId;
  readonly stage: ExposureStage;
  readonly conclusion: SecurityConclusion;
  readonly confidence: ConfidenceAssessment;
  readonly summary: string;
  readonly selection: ServiceSelectionAssessment;
  readonly temporal: ServiceTemporalAssessment;
  readonly build: EvidenceFactAssessment;
  readonly deployment: EvidenceFactAssessment;
  readonly runtime: EvidenceFactAssessment;
  readonly authority: EvidenceFactAssessment;
  readonly paths: readonly PathImpactAssessment[];
  readonly evidenceIds: readonly NodeId[];
  readonly missingEvidence: readonly string[];
  readonly warnings: readonly string[];
  readonly complete: boolean;
  readonly synthetic: boolean;
}

export interface ServiceImpactOptions {
  readonly asOf: number;
  readonly highConfidenceThreshold: number;
  readonly evidenceComplete: boolean;
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

const STAGE_ORDER: Readonly<
  Record<ExposureStage, number>
> = {
  candidate: 0,
  "semver-eligible": 1,
  resolved: 2,
  built: 3,
  deployed: 4,
  "runtime-reachable": 5,
  "execution-observed": 6,
};

const CONFIDENCE_ORDER: Readonly<
  Record<EvidenceConfidenceLevel, number>
> = {
  unknown: 0,
  contextual: 1,
  possible: 2,
  probable: 3,
  strong: 4,
  confirmed: 5,
};

const EXACT_RESOLUTION_SOURCES:
  ReadonlySet<EvidenceSourceType> =
    new Set([
      "package-lock",
      "cyclonedx",
      "spdx",
      "synthetic-fixture",
    ]);

const CONTEXTUAL_SOURCES:
  ReadonlySet<EvidenceSourceType> =
    new Set([
      "npm-registry",
      "package-manifest",
      "security-advisory",
      "other",
    ]);

function uniqueSortedNumbers(
  values: readonly number[],
): readonly number[] {
  return Object.freeze(
    [...new Set(values)].sort(
      (left, right) => left - right,
    ),
  );
}

function uniqueSortedStrings<T extends string>(
  values: readonly T[],
): readonly T[] {
  return Object.freeze(
    [...new Set(values)].sort(
      (left, right) =>
        left.localeCompare(right),
    ),
  );
}

function factNotProven(
  reason: string,
): EvidenceFactAssessment {
  return Object.freeze({
    status: "not-proven",
    evidenceIds: Object.freeze([]),
    reason,
  });
}

function evidenceForPath(
  path: BlastRadiusPath,
  evidenceById: ReadonlyMap<
    NodeId,
    DecisionEvidence
  >,
): {
  readonly resolved: readonly DecisionEvidence[];
  readonly resolvedIds: readonly NodeId[];
  readonly exactResolutionIds: readonly NodeId[];
  readonly missingIds: readonly NodeId[];
  readonly everyEdgeVerified: boolean;
  readonly everyEdgeHasExactResolutionSource: boolean;
  readonly everySourceContextual: boolean;
  readonly minimumExactResolutionConfidence: number;
} {
  const resolved = new Map<
    NodeId,
    DecisionEvidence
  >();
  const exactResolution = new Map<
    NodeId,
    DecisionEvidence
  >();
  const missingIds: NodeId[] = [];
  let everyEdgeVerified =
    path.canonicalEdges.length > 0;
  let everyEdgeHasExactResolutionSource =
    path.canonicalEdges.length > 0;
  let everySourceContextual = true;
  let minimumExactResolutionConfidence = 1;

  for (const edge of path.canonicalEdges) {
    const edgeEvidence = edge.evidenceIds
      .map((id) => evidenceById.get(id))
      .filter(
        (
          evidence,
        ): evidence is DecisionEvidence =>
          evidence !== undefined,
      );

    for (const evidenceId of edge.evidenceIds) {
      if (!evidenceById.has(evidenceId)) {
        missingIds.push(evidenceId);
      }
    }

    if (edgeEvidence.length === 0) {
      everyEdgeVerified = false;
    }

    const exactEdgeEvidence =
      edgeEvidence.filter((evidence) =>
        EXACT_RESOLUTION_SOURCES.has(
          evidence.sourceType,
        ),
      );

    if (exactEdgeEvidence.length === 0) {
      everyEdgeHasExactResolutionSource = false;
      minimumExactResolutionConfidence = 0;
    } else {
      const maximumExactConfidence =
        Math.max(
          ...exactEdgeEvidence.map(
            (evidence) =>
              evidence.confidence,
          ),
        );

      minimumExactResolutionConfidence =
        Math.min(
          minimumExactResolutionConfidence,
          maximumExactConfidence,
        );

      for (const evidence of exactEdgeEvidence) {
        exactResolution.set(
          evidence.id,
          evidence,
        );
      }
    }

    for (const evidence of edgeEvidence) {
      resolved.set(evidence.id, evidence);

      if (
        !CONTEXTUAL_SOURCES.has(
          evidence.sourceType,
        )
      ) {
        everySourceContextual = false;
      }
    }
  }

  return {
    resolved: Object.freeze(
      [...resolved.values()].sort(
        (left, right) => left.id - right.id,
      ),
    ),
    resolvedIds: uniqueSortedNumbers(
      [...resolved.keys()],
    ),
    exactResolutionIds: uniqueSortedNumbers(
      [...exactResolution.keys()],
    ),
    missingIds: uniqueSortedNumbers(missingIds),
    everyEdgeVerified,
    everyEdgeHasExactResolutionSource,
    everySourceContextual,
    minimumExactResolutionConfidence,
  };
}

function assessPath(
  path: BlastRadiusPath,
  evidenceById: ReadonlyMap<
    NodeId,
    DecisionEvidence
  >,
  options: ServiceImpactOptions,
): PathImpactAssessment {
  const evidence = evidenceForPath(
    path,
    evidenceById,
  );

  const complete =
    options.evidenceComplete &&
    evidence.missingIds.length === 0;

  const exactResolutionProven =
    complete &&
    evidence.everyEdgeVerified &&
    evidence.everyEdgeHasExactResolutionSource;

  const stage: ExposureStage =
    exactResolutionProven
      ? "resolved"
      : "candidate";

  let level: EvidenceConfidenceLevel =
    "unknown";
  let reasons: readonly string[] = [
    "One or more canonical dependency claims lack exact-resolution evidence.",
  ];

  if (!complete) {
    reasons = [
      "The evidence or analysis result is incomplete, so this path cannot support a conclusive exposure decision.",
    ];
  } else if (exactResolutionProven) {
    if (
      evidence.minimumExactResolutionConfidence >=
        options.highConfidenceThreshold
    ) {
      level = "strong";
      reasons = [
        "Every canonical dependency claim has an exact-resolution source meeting the configured confidence threshold.",
      ];
    } else {
      level = "probable";
      reasons = [
        "Every canonical dependency claim has an exact-resolution source, but at least one edge is below the strong-confidence threshold.",
      ];
    }
  } else if (evidence.everyEdgeVerified) {
    if (evidence.everySourceContextual) {
      level = "contextual";
      reasons = [
        "Every canonical dependency claim has contextual evidence, but no complete exact-resolution proof supports the path.",
      ];
    } else {
      level = "possible";
      reasons = [
        "Evidence exists for every canonical dependency claim, but at least one edge lacks an accepted exact-resolution source.",
      ];
    }
  }

  const synthetic =
    path.nodes.some((node) => node.synthetic) ||
    evidence.resolved.some(
      (item) => item.synthetic,
    );

  const confidence: ConfidenceAssessment =
    Object.freeze({
      level,
      policyVersion:
        SERVICE_IMPACT_POLICY_VERSION,
      supportingEvidenceIds:
        exactResolutionProven
          ? evidence.exactResolutionIds
          : evidence.resolvedIds,
      reasons: Object.freeze([...reasons]),
      complete,
      synthetic,
    });

  return Object.freeze({
    pathKey: path.pathKey,
    stage,
    conclusion:
      CONCLUSION_BY_STAGE[stage],
    confidence,
    evidenceIds: evidence.resolvedIds,
    missingEvidenceIds:
      evidence.missingIds,
    uncertainties: Object.freeze(
      stage === "resolved"
        ? [
            "Build inclusion has not been proven.",
            "Deployment has not been proven.",
            "Runtime reachability has not been proven.",
            "Execution has not been observed.",
          ]
        : [
            complete
              ? "Exact dependency resolution has not been proven with an accepted source on every canonical edge."
              : "Incomplete evidence prevents a conclusive dependency-resolution decision.",
          ],
    ),
  });
}

function comparePathAssessments(
  left: PathImpactAssessment,
  right: PathImpactAssessment,
): number {
  return (
    STAGE_ORDER[right.stage] -
      STAGE_ORDER[left.stage] ||
    CONFIDENCE_ORDER[
      right.confidence.level
    ] -
      CONFIDENCE_ORDER[
        left.confidence.level
      ] ||
    left.pathKey.localeCompare(
      right.pathKey,
    )
  );
}

function summarizeSelection(
  paths: readonly BlastRadiusPath[],
  assessments:
    readonly PathImpactAssessment[],
  versionById: ReadonlyMap<
    NodeId,
    PackageVersionNode
  >,
): ServiceSelectionAssessment {
  const resolvedPathKeys = new Set(
    assessments
      .filter(
        (assessment) =>
          assessment.stage === "resolved",
      )
      .map(
        (assessment) => assessment.pathKey,
      ),
  );

  const resolvedPaths = paths.filter(
    (path) =>
      resolvedPathKeys.has(path.pathKey),
  );

  const state: SelectionState =
    resolvedPaths.length > 0
      ? "exactly-resolved"
      : "unknown";

  const affectedVersionIds =
    uniqueSortedNumbers(
      resolvedPaths.map(
        (path) => path.affectedVersionId,
      ),
    );

  const resolvedVersions =
    affectedVersionIds
      .map((id) => versionById.get(id))
      .filter(
        (
          version,
        ): version is PackageVersionNode =>
          version !== undefined,
      )
      .map((version) =>
        Object.freeze({
          id: version.id,
          packageName: version.packageName,
          version: version.version,
        }),
      );

  const edges = resolvedPaths.flatMap(
    (path) => path.canonicalEdges,
  );

  return Object.freeze({
    state,
    dependencyTypes: uniqueSortedStrings(
      edges.map(
        (edge) => edge.dependencyType,
      ),
    ),
    declaredRanges: uniqueSortedStrings(
      edges
        .map((edge) => edge.declaredRange)
        .filter(
          (value): value is string =>
            value !== undefined,
        ),
    ),
    lockfilePaths: uniqueSortedStrings(
      edges
        .map((edge) => edge.lockfilePath)
        .filter(
          (value): value is string =>
            value !== undefined,
        ),
    ),
    resolvedVersions:
      Object.freeze(resolvedVersions),
    reason:
      state === "exactly-resolved"
        ? "At least one complete canonical DEPENDS_ON path is backed by resolved evidence."
        : "No complete canonical dependency path has fully resolved evidence.",
  });
}

export function buildServiceImpactExplanations(
  blastRadius: BlastRadiusResult,
  affectedVersions:
    readonly PackageVersionNode[],
  evidenceCatalog:
    readonly DecisionEvidence[],
  options: ServiceImpactOptions,
): readonly ServiceImpactExplanation[] {
  options = Object.freeze({
    ...options,
    evidenceComplete:
      options.evidenceComplete &&
      !blastRadius.truncated,
  });

  const evidenceById = new Map(
    evidenceCatalog.map(
      (evidence) =>
        [evidence.id, evidence] as const,
    ),
  );

  const versionById = new Map(
    affectedVersions.map(
      (version) =>
        [version.id, version] as const,
    ),
  );

  return Object.freeze(
    blastRadius.services.map((candidate) => {
      const paths = candidate.paths.map(
        (path) =>
          assessPath(
            path,
            evidenceById,
            options,
          ),
      );

      const orderedPaths = [...paths].sort(
        comparePathAssessments,
      );

      const strongest = orderedPaths[0];

      const stage: ExposureStage =
        strongest?.stage ?? "candidate";

      const fallbackConfidence:
        ConfidenceAssessment =
          Object.freeze({
            level: "unknown",
            policyVersion:
              SERVICE_IMPACT_POLICY_VERSION,
            supportingEvidenceIds:
              Object.freeze([]),
            reasons: Object.freeze([
              "No dependency path was retained for this service.",
            ]),
            complete: false,
            synthetic:
              candidate.service.synthetic,
          });

      const confidence =
        strongest?.confidence ??
        fallbackConfidence;

      const selection = summarizeSelection(
        candidate.paths,
        paths,
        versionById,
      );

      const evidenceIds =
        uniqueSortedNumbers(
          paths.flatMap(
            (path) => path.evidenceIds,
          ),
        );

      const missingEvidence = [
        ...(paths.some(
          (path) =>
            path.missingEvidenceIds.length > 0,
        )
          ? [
              "One or more dependency evidence records could not be resolved.",
            ]
          : []),
        "Build inclusion evidence is unavailable.",
        "Deployment evidence is unavailable.",
        "Runtime reachability evidence is unavailable.",
        "Execution evidence is unavailable.",
        "Authority propagation is evaluated separately.",
      ];

      const warnings =
        blastRadius.truncated
          ? [
              "Blast-radius traversal was truncated; additional paths or services may exist.",
            ]
          : [];

      const resolvedLabels =
        selection.resolvedVersions.map(
          (version) =>
            `${version.packageName}@${version.version}`,
        );

      const summary =
        selection.state === "exactly-resolved"
          ? `${candidate.service.name} has an evidence-backed exact dependency path to ${resolvedLabels.join(", ") || "an incident-affected version"}; build, deployment, runtime, and execution remain unproven.`
          : `${candidate.service.name} is structurally connected to an incident-affected version, but exact resolution is not supported by complete resolved evidence.`;

      return Object.freeze({
        serviceId:
          candidate.service.id,
        stage,
        conclusion:
          CONCLUSION_BY_STAGE[stage],
        confidence,
        summary,
        selection,
        temporal: Object.freeze({
          status: "unknown" as const,
          asOf: options.asOf,
          reason:
            "Historical lock, build, artifact, and deployment validity intervals are not yet available.",
        }),
        build: factNotProven(
          "No verified build-inclusion evidence is connected to this service impact.",
        ),
        deployment: factNotProven(
          "No verified deployment evidence is connected to this service impact.",
        ),
        runtime: factNotProven(
          "No verified runtime-reachability or execution evidence is connected to this service impact.",
        ),
        authority: factNotProven(
          "Wave 2 authority reachability is not part of this dependency-only response.",
        ),
        paths: Object.freeze(paths),
        evidenceIds,
        missingEvidence:
          Object.freeze(missingEvidence),
        warnings:
          Object.freeze(warnings),
        complete:
          !blastRadius.truncated &&
          options.evidenceComplete &&
          paths.every(
            (path) =>
              path.confidence.complete,
          ),
        synthetic:
          candidate.service.synthetic ||
          confidence.synthetic,
      });
    }),
  );
}
