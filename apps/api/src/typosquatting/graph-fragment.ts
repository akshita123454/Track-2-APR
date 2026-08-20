import {
  createHash,
} from "node:crypto";

import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../domain/identity.js";

import type {
  EvidenceNode,
  GraphEdge,
  GraphNode,
  LookalikeEdge,
  PackageNode,
  StandardCanonicalEdge,
  TyposquatFindingNode,
} from "../domain/schema.js";

import type {
  GraphFragment,
} from "../ingest/graph-batch.js";

import {
  TRUSTED_CORPUS_EVIDENCE,
  TRUSTED_CORPUS_PACKAGE_BY_ID,
  TYPOSQUATTING_DETECTOR_VERSION,
  TYPOSQUATTING_POLICY_VERSION,
} from "./trusted-corpus.js";

import type {
  DetectionResult,
  TyposquattingFinding,
} from "./types.js";

export interface TyposquattingGraphFragmentInput {
  readonly detection: DetectionResult;
  readonly candidatePackages:
    ReadonlyMap<number, PackageNode>;
  readonly sourceEvidence:
    ReadonlyMap<number, EvidenceNode>;
  readonly sourceFingerprint: string;
  readonly observationEvidenceId: number;
  readonly observedAt: number;
}

export interface TyposquattingGraphFragmentResult {
  readonly fragment: GraphFragment;
  readonly findingIds: readonly number[];
}

function sha256(value: string): string {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

function uniqueNumbers(
  values: readonly number[],
): readonly number[] {
  return [...new Set(values)]
    .sort((left, right) => left - right);
}

function uniqueStrings(
  values: readonly string[],
): readonly string[] {
  return [...new Set(values)]
    .sort((left, right) =>
      left.localeCompare(right),
    );
}

function requireFingerprint(value: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(
      "sourceFingerprint must be a lowercase SHA-256 digest",
    );
  }
}

function standardEdge(
  kind: "TARGETS" | "IMITATES" | "SUPPORTS",
  source: GraphNode,
  target: GraphNode,
  evidenceIds: readonly number[],
  observedAt: number,
  discriminator: string,
): StandardCanonicalEdge {
  const identity = createEdgeIdentity({
    kind,
    sourceLogicalId: source.logicalId,
    targetLogicalId: target.logicalId,
    discriminator,
  });

  return {
    ...identity,
    kind,
    sourceId: source.id,
    targetId: target.id,
    observedAt,
    derived: false,
    identityDiscriminator:
      discriminator,
    evidenceIds:
      uniqueNumbers(evidenceIds),
  };
}

function findingToken(
  finding: TyposquattingFinding,
  input: TyposquattingGraphFragmentInput,
): string {
  return sha256(
    JSON.stringify([
      "typosquatting-finding-v1",
      input.sourceFingerprint,
      input.observationEvidenceId,
      input.detection.corpus.corpusId,
      input.detection.corpus.comparisonVersion,
      input.detection.corpus.indexVersion,
      TYPOSQUATTING_DETECTOR_VERSION,
      TYPOSQUATTING_POLICY_VERSION,
      finding.observedPackageId,
      finding.targetPackageId,
    ]),
  );
}

function detectorEvidence(
  finding: TyposquattingFinding,
  token: string,
  synthetic: boolean,
  observedAt: number,
): EvidenceNode {
  const identity = createEntityIdentity(
    `evidence:typosquatting-detector:${token}`,
  );

  return {
    ...identity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic,
    observedAt,
    sourceType:
      "typosquat-detector",
    sourceUri:
      `detector://typosquatting/${token}`,
    collectorVersion:
      TYPOSQUATTING_DETECTOR_VERSION,

    /*
     * This confidence describes deterministic execution provenance, not the
     * probability that the candidate is malicious. Classification and score
     * remain explicit heuristic fields on Finding.
     */
    confidence: 1,
    detail: JSON.stringify({
      statement:
        "Heuristic package-name similarity finding; not a maliciousness determination.",
      classification:
        finding.classification,
      score: finding.score,
      scoreMeaning:
        "ranking-only-not-probability",
      strongLexicalMatch:
        finding.strongLexicalMatch,
      candidateSource:
        finding.candidateSource,
      candidateVersion:
        finding.candidateVersion ?? null,
      nonLexicalEvidenceCategories:
        finding.nonLexicalEvidenceCategories,
      targetSelectionReasons:
        finding.targetSelectionReasons,
      reasons: finding.reasons.map(
        (reason) => ({
          code: reason.code,
          group: reason.group,
          points: reason.points,
          detail: reason.detail,
          evidenceIds:
            reason.evidenceIds,
        }),
      ),
      distance: {
        cost: finding.distance.cost,
        normalizedCost:
          finding.distance.normalizedCost,
        operations:
          finding.distance.operations,
      },
    }),
  };
}

export function buildTyposquattingGraphFragment(
  input: TyposquattingGraphFragmentInput,
): TyposquattingGraphFragmentResult {
  requireFingerprint(
    input.sourceFingerprint,
  );

  if (
    !Number.isSafeInteger(
      input.observationEvidenceId,
    ) ||
    input.observationEvidenceId < 0
  ) {
    throw new Error(
      "observationEvidenceId must be a nonnegative safe integer",
    );
  }

  if (
    !Number.isSafeInteger(input.observedAt) ||
    input.observedAt < 0
  ) {
    throw new Error(
      "observedAt must be a nonnegative epoch-millisecond value",
    );
  }

  const nodes = new Map<number, GraphNode>();
  const edges = new Map<number, GraphEdge>();
  const findingIds: number[] = [];

  const addNode = (node: GraphNode): void => {
    const existing = nodes.get(node.id);

    if (
      existing !== undefined &&
      existing.logicalId !== node.logicalId
    ) {
      throw new Error(
        `Typosquatting graph node ID collision: ${node.id}`,
      );
    }

    nodes.set(node.id, node);
  };

  const addEdge = (edge: GraphEdge): void => {
    const existing = edges.get(edge.id);

    if (
      existing !== undefined &&
      existing.logicalId !== edge.logicalId
    ) {
      throw new Error(
        `Typosquatting graph edge ID collision: ${edge.id}`,
      );
    }

    edges.set(edge.id, edge);
  };

  for (const detected of input.detection.findings) {
    const candidate =
      input.candidatePackages.get(
        detected.observedPackageId,
      );

    if (candidate === undefined) {
      throw new Error(
        `Missing observed candidate Package ${detected.observedPackageId}`,
      );
    }

    if (
      candidate.name !==
      detected.candidateName
    ) {
      throw new Error(
        "Detector candidate identity does not match the collected Package",
      );
    }

    const target =
      TRUSTED_CORPUS_PACKAGE_BY_ID.get(
        detected.targetPackageId,
      );

    if (target === undefined) {
      throw new Error(
        `Trusted corpus has no Package node ${detected.targetPackageId}`,
      );
    }

    const token = findingToken(
      detected,
      input,
    );

    const detector = detectorEvidence(
      detected,
      token,
      candidate.synthetic,
      input.observedAt,
    );

    const sourceEvidenceIds =
      uniqueNumbers([
        ...detected.sourceEvidenceIds,
        detector.id,
      ]);

    for (const evidenceId of detected.sourceEvidenceIds) {
      const evidence =
        evidenceId ===
        TRUSTED_CORPUS_EVIDENCE.id
          ? TRUSTED_CORPUS_EVIDENCE
          : input.sourceEvidence.get(
              evidenceId,
            );

      if (evidence === undefined) {
        throw new Error(
          `Missing source Evidence ${evidenceId} for typosquatting finding`,
        );
      }

      addNode(evidence);
    }

    addNode(detector);
    addNode(candidate);
    addNode(target);

    const findingIdentity =
      createEntityIdentity(
        `finding:typosquatting:${token}`,
      );

    const finding:
      TyposquatFindingNode = {
        ...findingIdentity,
        kind: "Finding",
        evidenceIds:
          sourceEvidenceIds,
        synthetic:
          candidate.synthetic,
        observedAt:
          input.observedAt,
        findingType:
          "typosquatting",
        status:
          detected.classification,
        score: detected.score,
        detectorVersion:
          TYPOSQUATTING_DETECTOR_VERSION,
        policyVersion:
          TYPOSQUATTING_POLICY_VERSION,
        corpusId:
          input.detection.corpus.corpusId,
        comparisonVersion:
          input.detection.corpus.comparisonVersion,
        indexVersion:
          input.detection.corpus.indexVersion,
        candidatePackageName:
          detected.candidateName,
        targetPackageName:
          detected.targetName,
        summary:
          `${detected.candidateName} is a heuristic name-similarity candidate for ${detected.targetName}; an exact lockfile observation is present, but maliciousness is not asserted.`,
        transformations:
          uniqueStrings(
            detected.transformations,
          ) as typeof detected.transformations,
        reasonCodes:
          uniqueStrings(
            detected.reasons.map(
              (reason) => reason.code,
            ),
          ),
        detectedAt:
          input.observedAt,
      };

    addNode(finding);
    findingIds.push(finding.id);

    const relationshipDiscriminator =
      `typosquatting:${token}`;

    const lookalikeIdentity =
      createEdgeIdentity({
        kind: "LOOKALIKE_OF",
        sourceLogicalId:
          candidate.logicalId,
        targetLogicalId:
          target.logicalId,
        discriminator:
          relationshipDiscriminator,
      });

    const lookalike:
      LookalikeEdge = {
        ...lookalikeIdentity,
        kind: "LOOKALIKE_OF",
        sourceId: candidate.id,
        targetId: target.id,
        observedAt:
          input.observedAt,
        derived: false,
        identityDiscriminator:
          relationshipDiscriminator,
        evidenceIds: [detector.id],
        algorithm:
          "weighted-damerau-levenshtein",
        comparisonVersion:
          input.detection.corpus.comparisonVersion,
        normalizedDistance:
          detected.distance.normalizedCost,
        transformations:
          finding.transformations,
      };

    addEdge(lookalike);
    addEdge(
      standardEdge(
        "TARGETS",
        finding,
        candidate,
        [detector.id],
        input.observedAt,
        relationshipDiscriminator,
      ),
    );
    addEdge(
      standardEdge(
        "IMITATES",
        finding,
        target,
        [detector.id],
        input.observedAt,
        relationshipDiscriminator,
      ),
    );

    for (const evidenceId of sourceEvidenceIds) {
      const evidence = nodes.get(evidenceId);

      if (
        evidence === undefined ||
        evidence.kind !== "Evidence"
      ) {
        throw new Error(
          `Finding support Evidence ${evidenceId} is unavailable`,
        );
      }

      addEdge(
        standardEdge(
          "SUPPORTS",
          evidence,
          finding,
          [evidence.id],
          input.observedAt,
          relationshipDiscriminator,
        ),
      );
    }
  }

  return Object.freeze({
    fragment: Object.freeze({
      source:
        `typosquatting:${input.sourceFingerprint}:${input.detection.corpus.corpusId}`,
      nodes: Object.freeze(
        [...nodes.values()].sort(
          (left, right) =>
            left.id - right.id,
        ),
      ),
      edges: Object.freeze(
        [...edges.values()].sort(
          (left, right) =>
            left.id - right.id,
        ),
      ),
    }),
    findingIds: Object.freeze(
      [...findingIds].sort(
        (left, right) =>
          left - right,
      ),
    ),
  });
}
