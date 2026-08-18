import type {
  EvidenceNode,
  EvidenceSourceType,
  NodeId,
} from "../../domain/schema.js";

import type {
  BlastRadiusPath,
  BlastRadiusResult,
  ReadonlyGraphReader,
} from "./analysis-types.js";

const DEFAULT_HIGH_CONFIDENCE_THRESHOLD = 0.8;
const DEFAULT_MAX_EVIDENCE_IDS = 2_000;
const DEFAULT_EVIDENCE_READ_CHUNK_SIZE = 250;

const MAX_EVIDENCE_IDS = 10_000;
const MAX_EVIDENCE_READ_CHUNK_SIZE = 2_000;

export type EvidenceFunnelStageId =
  | "structural-candidate"
  | "evidence-verified"
  | "high-confidence-evidence";

export interface EvidenceFunnelOptions {
  /**
   * An edge reaches the high-confidence stage only when at least one
   * existing Evidence node attached to it has confidence at or above this
   * threshold.
   *
   * Defaults to 0.8.
   */
  readonly highConfidenceThreshold?: number;

  /**
   * Maximum number of unique Evidence nodes resolved for one analysis.
   *
   * Additional IDs are omitted deterministically and reported as an
   * incomplete lookup rather than silently producing an unbounded query.
   */
  readonly maxEvidenceIds?: number;

  /**
   * Number of IDs passed to getEvidence() per bounded database call.
   *
   * Defaults to 250.
   */
  readonly evidenceReadChunkSize?: number;
}

export interface EvidenceFunnelStage {
  readonly id: EvidenceFunnelStageId;
  readonly label: string;
  readonly description: string;

  /**
   * Number of returned blast-radius paths reaching this stage.
   */
  readonly pathCount: number;

  /**
   * Number of returned Services having at least one path at this stage.
   */
  readonly serviceCount: number;

  /**
   * Percentage relative to all structurally discovered paths.
   */
  readonly pathPercentage: number;

  /**
   * Percentage relative to all structurally discovered Services.
   */
  readonly servicePercentage: number;
}

export interface EvidenceSourceSummary {
  readonly sourceType: EvidenceSourceType;
  readonly evidenceCount: number;
  readonly averageConfidence: number;
}

export interface EvidenceLookupSummary {
  /**
   * All unique Evidence IDs referenced by canonical DEPENDS_ON edges in
   * the returned blast-radius paths.
   */
  readonly referencedEvidenceCount: number;

  /**
   * IDs selected for bounded database verification.
   */
  readonly requestedEvidenceCount: number;

  /**
   * Existing Evidence nodes returned by the reader.
   */
  readonly resolvedEvidenceCount: number;

  /**
   * Selected IDs that did not resolve to Evidence nodes.
   */
  readonly missingEvidenceCount: number;
  readonly missingEvidenceIds: readonly NodeId[];

  /**
   * IDs not queried because maxEvidenceIds was reached.
   */
  readonly omittedEvidenceCount: number;

  /**
   * True only when every referenced Evidence ID was queried and resolved.
   */
  readonly complete: boolean;
}

export interface EvidenceFunnelResult {
  readonly affectedVersionCount: number;
  readonly candidatePathCount: number;
  readonly candidateServiceCount: number;

  readonly highConfidenceThreshold: number;
  readonly stages: readonly EvidenceFunnelStage[];

  readonly evidenceLookup: EvidenceLookupSummary;
  readonly sources: readonly EvidenceSourceSummary[];

  /**
   * Complete for every candidate returned by blast-radius traversal.
   */
  readonly completeForReturnedCandidates: boolean;

  /**
   * Complete for the incident only when traversal was also untruncated.
   */
  readonly completeForIncident: boolean;

  /**
   * Human-readable reasons preventing a complete conclusion.
   */
  readonly limitations: readonly string[];
}

export type EvidenceFunnelErrorCode =
  | "INVALID_OPTIONS"
  | "INVALID_BLAST_RADIUS_RESULT"
  | "INVALID_EVIDENCE_RESULT";

export class EvidenceFunnelError extends Error {
  constructor(
    readonly code: EvidenceFunnelErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(
      message,
      cause === undefined
        ? undefined
        : { cause },
    );

    this.name = "EvidenceFunnelError";
  }
}

interface NormalizedOptions {
  readonly highConfidenceThreshold: number;
  readonly maxEvidenceIds: number;
  readonly evidenceReadChunkSize: number;
}

interface PathAssessment {
  readonly path: BlastRadiusPath;
  readonly evidenceVerified: boolean;
  readonly highConfidenceEvidence: boolean;
}

interface MutableSourceSummary {
  count: number;
  totalConfidence: number;
}

function readPositiveInteger(
  value: number | undefined,
  fallback: number,
  field: string,
  maximum: number,
): number {
  const normalized = value ?? fallback;

  if (
    !Number.isSafeInteger(normalized) ||
    normalized < 1 ||
    normalized > maximum
  ) {
    throw new EvidenceFunnelError(
      "INVALID_OPTIONS",
      `${field} must be a positive safe integer not greater than ${maximum}`,
    );
  }

  return normalized;
}

function normalizeOptions(
  options: EvidenceFunnelOptions,
): NormalizedOptions {
  const highConfidenceThreshold =
    options.highConfidenceThreshold ??
    DEFAULT_HIGH_CONFIDENCE_THRESHOLD;

  if (
    !Number.isFinite(highConfidenceThreshold) ||
    highConfidenceThreshold < 0 ||
    highConfidenceThreshold > 1
  ) {
    throw new EvidenceFunnelError(
      "INVALID_OPTIONS",
      "highConfidenceThreshold must be a finite number between 0 and 1",
    );
  }

  const maxEvidenceIds = readPositiveInteger(
    options.maxEvidenceIds,
    DEFAULT_MAX_EVIDENCE_IDS,
    "maxEvidenceIds",
    MAX_EVIDENCE_IDS,
  );

  const evidenceReadChunkSize = readPositiveInteger(
    options.evidenceReadChunkSize,
    DEFAULT_EVIDENCE_READ_CHUNK_SIZE,
    "evidenceReadChunkSize",
    MAX_EVIDENCE_READ_CHUNK_SIZE,
  );

  return {
    highConfidenceThreshold,
    maxEvidenceIds,
    evidenceReadChunkSize: Math.min(
      evidenceReadChunkSize,
      maxEvidenceIds,
    ),
  };
}

function percentage(
  value: number,
  total: number,
): number {
  if (total === 0) {
    return 0;
  }

  return Math.round(
    (value / total) * 10_000,
  ) / 100;
}

function average(
  total: number,
  count: number,
): number {
  if (count === 0) {
    return 0;
  }

  return Math.round(
    (total / count) * 10_000,
  ) / 10_000;
}

function assertNodeId(
  value: NodeId,
  field: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new EvidenceFunnelError(
      "INVALID_BLAST_RADIUS_RESULT",
      `${field} must be a nonnegative safe integer`,
    );
  }
}

function collectPaths(
  blastRadius: BlastRadiusResult,
): readonly BlastRadiusPath[] {
  const paths: BlastRadiusPath[] = [];
  const pathKeys = new Set<string>();

  for (const candidate of blastRadius.services) {
    for (const path of candidate.paths) {
      if (path.serviceId !== candidate.service.id) {
        throw new EvidenceFunnelError(
          "INVALID_BLAST_RADIUS_RESULT",
          `Path ${path.pathKey} does not target its containing Service`,
        );
      }

      if (
        path.depth !==
          path.canonicalEdges.length ||
        path.nodes.length !==
          path.canonicalEdges.length + 1
      ) {
        throw new EvidenceFunnelError(
          "INVALID_BLAST_RADIUS_RESULT",
          `Path ${path.pathKey} has inconsistent depth or topology`,
        );
      }

      if (pathKeys.has(path.pathKey)) {
        throw new EvidenceFunnelError(
          "INVALID_BLAST_RADIUS_RESULT",
          `Duplicate blast-radius path key ${path.pathKey}`,
        );
      }

      pathKeys.add(path.pathKey);
      paths.push(path);
    }
  }

  if (paths.length !== blastRadius.totalPathCount) {
    throw new EvidenceFunnelError(
      "INVALID_BLAST_RADIUS_RESULT",
      "totalPathCount does not match the retained paths",
    );
  }

  return paths.sort((left, right) =>
    left.pathKey.localeCompare(right.pathKey),
  );
}

function collectReferencedEvidenceIds(
  paths: readonly BlastRadiusPath[],
): readonly NodeId[] {
  const evidenceIds = new Set<NodeId>();

  for (const path of paths) {
    for (const edge of path.canonicalEdges) {
      for (const evidenceId of edge.evidenceIds) {
        assertNodeId(
          evidenceId,
          `Evidence ID on edge ${edge.id}`,
        );

        evidenceIds.add(evidenceId);
      }
    }
  }

  return [...evidenceIds].sort(
    (left, right) => left - right,
  );
}

async function resolveEvidence(
  reader: ReadonlyGraphReader,
  requestedIds: readonly NodeId[],
  chunkSize: number,
): Promise<ReadonlyMap<NodeId, EvidenceNode>> {
  const requestedIdSet =
    new Set(requestedIds);

  const evidenceById =
    new Map<NodeId, EvidenceNode>();

  for (
    let offset = 0;
    offset < requestedIds.length;
    offset += chunkSize
  ) {
    const chunk = requestedIds.slice(
      offset,
      offset + chunkSize,
    );

    let evidenceNodes: readonly EvidenceNode[];

    try {
      evidenceNodes =
        await reader.getEvidence(chunk);
    } catch (error) {
      throw new EvidenceFunnelError(
        "INVALID_EVIDENCE_RESULT",
        "Evidence lookup failed",
        error,
      );
    }

    for (const evidence of evidenceNodes) {
      if (!requestedIdSet.has(evidence.id)) {
        throw new EvidenceFunnelError(
          "INVALID_EVIDENCE_RESULT",
          `Reader returned unrequested Evidence ${evidence.id}`,
        );
      }

      if (evidenceById.has(evidence.id)) {
        throw new EvidenceFunnelError(
          "INVALID_EVIDENCE_RESULT",
          `Reader returned duplicate Evidence ${evidence.id}`,
        );
      }

      if (
        !Number.isFinite(evidence.confidence) ||
        evidence.confidence < 0 ||
        evidence.confidence > 1
      ) {
        throw new EvidenceFunnelError(
          "INVALID_EVIDENCE_RESULT",
          `Evidence ${evidence.id} has invalid confidence`,
        );
      }

      evidenceById.set(
        evidence.id,
        evidence,
      );
    }
  }

  return evidenceById;
}

function assessPath(
  path: BlastRadiusPath,
  evidenceById: ReadonlyMap<
    NodeId,
    EvidenceNode
  >,
  highConfidenceThreshold: number,
): PathAssessment {
  /*
   * A zero-edge path is not considered evidence-backed. It should not be
   * produced for PackageVersion -> Service analysis, but this prevents
   * Array.every() from classifying an invalid empty path as verified.
   */
  if (path.canonicalEdges.length === 0) {
    return {
      path,
      evidenceVerified: false,
      highConfidenceEvidence: false,
    };
  }

  let evidenceVerified = true;
  let highConfidenceEvidence = true;

  for (const edge of path.canonicalEdges) {
    const resolvedEvidence =
      edge.evidenceIds
        .map((evidenceId) =>
          evidenceById.get(evidenceId),
        )
        .filter(
          (
            evidence,
          ): evidence is EvidenceNode =>
            evidence !== undefined,
        );

    if (resolvedEvidence.length === 0) {
      evidenceVerified = false;
      highConfidenceEvidence = false;
      continue;
    }

    const hasHighConfidenceEvidence =
      resolvedEvidence.some(
        (evidence) =>
          evidence.confidence >=
          highConfidenceThreshold,
      );

    if (!hasHighConfidenceEvidence) {
      highConfidenceEvidence = false;
    }
  }

  return {
    path,
    evidenceVerified,
    highConfidenceEvidence:
      evidenceVerified &&
      highConfidenceEvidence,
  };
}

function countServices(
  assessments: readonly PathAssessment[],
  predicate: (
    assessment: PathAssessment,
  ) => boolean,
): number {
  const serviceIds = new Set<NodeId>();

  for (const assessment of assessments) {
    if (predicate(assessment)) {
      serviceIds.add(
        assessment.path.serviceId,
      );
    }
  }

  return serviceIds.size;
}

function createStage(
  id: EvidenceFunnelStageId,
  label: string,
  description: string,
  pathCount: number,
  serviceCount: number,
  candidatePathCount: number,
  candidateServiceCount: number,
): EvidenceFunnelStage {
  return Object.freeze({
    id,
    label,
    description,
    pathCount,
    serviceCount,
    pathPercentage: percentage(
      pathCount,
      candidatePathCount,
    ),
    servicePercentage: percentage(
      serviceCount,
      candidateServiceCount,
    ),
  });
}

function summarizeSources(
  evidenceById: ReadonlyMap<
    NodeId,
    EvidenceNode
  >,
): readonly EvidenceSourceSummary[] {
  const mutable = new Map<
    EvidenceSourceType,
    MutableSourceSummary
  >();

  for (const evidence of evidenceById.values()) {
    const current =
      mutable.get(evidence.sourceType) ?? {
        count: 0,
        totalConfidence: 0,
      };

    current.count += 1;
    current.totalConfidence +=
      evidence.confidence;

    mutable.set(
      evidence.sourceType,
      current,
    );
  }

  return Object.freeze(
    [...mutable.entries()]
      .sort(([left], [right]) =>
        left.localeCompare(right),
      )
      .map(
        ([sourceType, summary]) =>
          Object.freeze({
            sourceType,
            evidenceCount:
              summary.count,
            averageConfidence:
              average(
                summary.totalConfidence,
                summary.count,
              ),
          }),
      ),
  );
}

/**
 * Builds a monotonic evidence funnel for returned blast-radius candidates.
 *
 * The stages intentionally stop at graph-evidence confidence. This function
 * does not infer build, deployment, runtime reachability, or execution.
 * Those claims require their own explicit evidence model.
 */
export async function buildEvidenceFunnel(
  reader: ReadonlyGraphReader,
  blastRadius: BlastRadiusResult,
  options: EvidenceFunnelOptions = {},
): Promise<EvidenceFunnelResult> {
  const normalized =
    normalizeOptions(options);

  const paths =
    collectPaths(blastRadius);

  const referencedIds =
    collectReferencedEvidenceIds(paths);

  const requestedIds =
    referencedIds.slice(
      0,
      normalized.maxEvidenceIds,
    );

  const omittedEvidenceCount =
    referencedIds.length -
    requestedIds.length;

  const evidenceById =
    await resolveEvidence(
      reader,
      requestedIds,
      normalized.evidenceReadChunkSize,
    );

  const missingEvidenceIds =
    requestedIds.filter(
      (evidenceId) =>
        !evidenceById.has(evidenceId),
    );

  const assessments = paths.map(
    (path) =>
      assessPath(
        path,
        evidenceById,
        normalized.highConfidenceThreshold,
      ),
  );

  const candidatePathCount =
    paths.length;

  const candidateServiceCount =
    blastRadius.services.length;

  const evidenceVerifiedPathCount =
    assessments.filter(
      (assessment) =>
        assessment.evidenceVerified,
    ).length;

  const evidenceVerifiedServiceCount =
    countServices(
      assessments,
      (assessment) =>
        assessment.evidenceVerified,
    );

  const highConfidencePathCount =
    assessments.filter(
      (assessment) =>
        assessment.highConfidenceEvidence,
    ).length;

  const highConfidenceServiceCount =
    countServices(
      assessments,
      (assessment) =>
        assessment.highConfidenceEvidence,
    );

  const stages: readonly EvidenceFunnelStage[] =
    Object.freeze([
      createStage(
        "structural-candidate",
        "Structural candidates",
        "Services connected to an affected PackageVersion by canonical dependency paths; compromise is not implied.",
        candidatePathCount,
        candidateServiceCount,
        candidatePathCount,
        candidateServiceCount,
      ),

      createStage(
        "evidence-verified",
        "Evidence-verified dependency paths",
        "Every canonical DEPENDS_ON edge in the path is backed by at least one Evidence node resolved from HydraDB.",
        evidenceVerifiedPathCount,
        evidenceVerifiedServiceCount,
        candidatePathCount,
        candidateServiceCount,
      ),

      createStage(
        "high-confidence-evidence",
        "High-confidence dependency paths",
        "Every canonical DEPENDS_ON edge has resolved Evidence meeting the configured confidence threshold.",
        highConfidencePathCount,
        highConfidenceServiceCount,
        candidatePathCount,
        candidateServiceCount,
      ),
    ]);

  const evidenceLookupComplete =
    omittedEvidenceCount === 0 &&
    missingEvidenceIds.length === 0;

  const limitations: string[] = [];

  if (blastRadius.truncated) {
    limitations.push(
      "Blast-radius traversal was truncated; additional candidate Services or paths may exist.",
    );
  }

  if (omittedEvidenceCount > 0) {
    limitations.push(
      `${omittedEvidenceCount} referenced Evidence IDs were not read because the evidence budget was reached.`,
    );
  }

  if (missingEvidenceIds.length > 0) {
    limitations.push(
      `${missingEvidenceIds.length} referenced Evidence IDs did not resolve to Evidence nodes.`,
    );
  }

  limitations.push(
    "Dependency evidence does not by itself prove build inclusion, deployment, runtime reachability, or execution.",
  );

  const evidenceLookup: EvidenceLookupSummary =
    Object.freeze({
      referencedEvidenceCount:
        referencedIds.length,
      requestedEvidenceCount:
        requestedIds.length,
      resolvedEvidenceCount:
        evidenceById.size,
      missingEvidenceCount:
        missingEvidenceIds.length,
      missingEvidenceIds:
        Object.freeze([
          ...missingEvidenceIds,
        ]),
      omittedEvidenceCount,
      complete: evidenceLookupComplete,
    });

  const completeForReturnedCandidates =
    evidenceLookupComplete;

  return Object.freeze({
    affectedVersionCount:
      blastRadius.affectedVersionIds.length,
    candidatePathCount,
    candidateServiceCount,
    highConfidenceThreshold:
      normalized.highConfidenceThreshold,
    stages,
    evidenceLookup,
    sources:
      summarizeSources(evidenceById),
    completeForReturnedCandidates,
    completeForIncident:
      completeForReturnedCandidates &&
      !blastRadius.truncated,
    limitations:
      Object.freeze(limitations),
  });
}
