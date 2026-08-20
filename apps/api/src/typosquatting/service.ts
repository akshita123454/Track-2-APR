import {
  createHash,
} from "node:crypto";

import type {
  Driver,
} from "neo4j-driver";

import {
  HydraGraphReader,
} from "../analysis/readers/hydra-graph-reader.js";

import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../domain/identity.js";

import type {
  EvidenceNode,
  GraphEdge,
  GraphNode,
  IncidentNode,
  PackageNode,
  PackageVersionNode,
  StandardCanonicalEdge,
  TyposquatFindingNode,
  TyposquatFindingStatus,
} from "../domain/schema.js";

import {
  NODE_PROPERTY_KEYS,
  serializeHydraNode,
} from "../db/hydra-serializer.js";

import {
  toHydraParameters,
} from "../db/hydra-parameters.js";

import {
  PersistenceServiceError,
} from "../db/persistence-service.js";

import type {
  HydraPersistenceService,
  PersistenceServiceOptions,
} from "../db/persistence-service.js";

import {
  mergeGraphFragments,
} from "../ingest/graph-batch.js";

import type {
  LockfileCollectorResult,
} from "../ingest/lockfile/collector.js";

import {
  detectTyposquatting,
} from "./detector.js";

import {
  buildTyposquattingGraphFragment,
} from "./graph-fragment.js";

import {
  FindingReaderError,
  TyposquattingFindingReader,
} from "./finding-reader.js";

import type {
  ExactCandidateVersionsPage,
  ExposureTrace,
  ExposureTraceOptions,
  FindingCursor,
  FindingListPage,
} from "./finding-reader.js";

import {
  TRUSTED_TYPOSQUATTING_CORPUS,
} from "./trusted-corpus.js";

import type {
  DetectionDiagnostics,
  DetectorOptions,
  ObservedPackage,
} from "./types.js";

export type TyposquattingServiceErrorCode =
  | "FINDING_NOT_FOUND"
  | "FINDING_CONFLICT"
  | "FINDING_ALREADY_DECIDED"
  | "PROMOTION_REQUIRES_TRUSTED_EVIDENCE"
  | "PROMOTION_REQUIRES_EXACT_EXPOSURE"
  | "INVALID_REVIEW"
  | "DATABASE_UNAVAILABLE"
  | "PERSISTENCE_FAILED";

export class TyposquattingServiceError
  extends Error {
  constructor(
    readonly code:
      TyposquattingServiceErrorCode,
    readonly httpStatusCode: number,
    message: string,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name =
      "TyposquattingServiceError";
  }
}

export interface LockfileTyposquattingScanInput {
  readonly collected:
    LockfileCollectorResult;
  readonly observedAt: number;
  readonly persistenceIdempotencyKey:
    string;
  readonly correlationId: string;
}

export interface TyposquattingScanResult {
  readonly sourceFingerprint: string;
  readonly corpusId: string;
  readonly packageCount: number;
  readonly findingCount: number;
  readonly findingIds: readonly number[];
  readonly diagnostics:
    DetectionDiagnostics;
}

export interface FindingDetail {
  readonly finding:
    TyposquatFindingNode;
  readonly candidate: PackageNode;
  readonly target: PackageNode;
  readonly evidence:
    readonly EvidenceNode[];
  readonly exactVersions:
    ExactCandidateVersionsPage;
  readonly exposure:
    ExposureTrace;
  readonly incidentIds:
    readonly number[];
}

export interface FindingListRequest {
  readonly limit: number;
  readonly cursor?: FindingCursor;
}

export interface FindingReviewCommand {
  readonly findingId: number;
  readonly action:
    | "dismiss"
    | "promote";
  readonly reason: string;
  readonly reviewer: string;
  readonly decidedAt: number;
  readonly idempotencyKey: string;
  readonly requestFingerprint: string;
}

export interface FindingReviewResult {
  readonly finding:
    TyposquatFindingNode;
  readonly incidentId?: number;
  readonly replayed: boolean;
}

export interface TyposquattingServiceOptions {
  readonly detector?:
    Partial<DetectorOptions>;
  readonly statementTimeoutMs?: number;
  readonly maxCandidateVersions?: number;
  readonly exposure?: Partial<{
    readonly maxDepth: number;
    readonly maxServices: number;
    readonly maxTraversalStates: number;
    readonly maxDependentsPerNode: number;
  }>;
  readonly persistenceOptions?: Omit<
    PersistenceServiceOptions,
    "idempotencyKey" | "correlationId"
  >;
}

const DEFAULT_DETECTOR_OPTIONS:
  DetectorOptions = {
    maxPackages: 10_000,
    maxCandidatesPerPackage: 32,
    maxComparisons: 200_000,
    maxNormalizedDistance: 0.25,
  };

const DEFAULT_EXPOSURE_OPTIONS = {
  maxDepth: 12,
  maxServices: 100,
  maxTraversalStates: 2_000,
  maxDependentsPerNode: 250,
} as const;

const DEFAULT_STATEMENT_TIMEOUT_MS =
  20_000;
const DEFAULT_MAX_CANDIDATE_VERSIONS =
  200;

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

function requireTimestamp(
  value: number,
  field: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new TyposquattingServiceError(
      "INVALID_REVIEW",
      400,
      `${field} must be a nonnegative epoch-millisecond value`,
    );
  }
}

function requireReviewText(
  value: string,
  field: string,
  maximum: number,
): void {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > maximum
  ) {
    throw new TyposquattingServiceError(
      "INVALID_REVIEW",
      400,
      `${field} is invalid`,
    );
  }
}

function requireReviewCommand(
  command: FindingReviewCommand,
): void {
  if (
    !Number.isSafeInteger(
      command.findingId,
    ) ||
    command.findingId < 0
  ) {
    throw new TyposquattingServiceError(
      "INVALID_REVIEW",
      400,
      "findingId must be a nonnegative safe integer",
    );
  }

  if (
    command.action !== "dismiss" &&
    command.action !== "promote"
  ) {
    throw new TyposquattingServiceError(
      "INVALID_REVIEW",
      400,
      "Unsupported review action",
    );
  }

  requireReviewText(
    command.reason,
    "reason",
    2_000,
  );
  requireReviewText(
    command.reviewer,
    "reviewer",
    200,
  );
  requireTimestamp(
    command.decidedAt,
    "decidedAt",
  );

  if (
    !/^[A-Za-z0-9._-]{8,80}$/.test(
      command.idempotencyKey,
    )
  ) {
    throw new TyposquattingServiceError(
      "INVALID_REVIEW",
      400,
      "idempotencyKey is invalid",
    );
  }

  if (
    !/^[a-f0-9]{64}$/.test(
      command.requestFingerprint,
    )
  ) {
    throw new TyposquattingServiceError(
      "INVALID_REVIEW",
      400,
      "requestFingerprint is invalid",
    );
  }
}

function createStandardEdge(
  kind: "SUPPORTS" | "AFFECTS",
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
    sourceId: source.id,
    targetId: target.id,
    kind,
    observedAt,
    derived: false,
    identityDiscriminator:
      discriminator,
    evidenceIds:
      uniqueNumbers(evidenceIds),
  };
}

interface ParsedReviewDetail {
  readonly requestFingerprint: string;
  readonly findingId: number;
  readonly action: string;
  readonly reviewer: string;
  readonly reason: string;
}

function parseReviewDetail(
  value: string,
): ParsedReviewDetail {
  try {
    const parsed =
      JSON.parse(value) as unknown;

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !("requestFingerprint" in parsed) ||
      typeof parsed.requestFingerprint !==
        "string" ||
      !("findingId" in parsed) ||
      typeof parsed.findingId !== "number" ||
      !("action" in parsed) ||
      typeof parsed.action !== "string" ||
      !("reviewer" in parsed) ||
      typeof parsed.reviewer !== "string" ||
      !("reason" in parsed) ||
      typeof parsed.reason !== "string"
    ) {
      throw new Error();
    }

    return {
      requestFingerprint:
        parsed.requestFingerprint,
      findingId: parsed.findingId,
      action: parsed.action,
      reviewer: parsed.reviewer,
      reason: parsed.reason,
    };
  } catch {
    throw new TyposquattingServiceError(
      "FINDING_CONFLICT",
      409,
      "Existing review evidence has an invalid identity payload",
    );
  }
}

function trustedLockfileEvidenceIds(
  evidence: readonly EvidenceNode[],
): readonly number[] {
  return evidence
    .filter((entry) =>
      entry.synthetic === false &&
      entry.sourceType === "package-lock" &&
      entry.confidence >= 0.8,
    )
    .map((entry) => entry.id)
    .sort((left, right) => left - right);
}

function reviewStatus(
  action: FindingReviewCommand["action"],
): Extract<
  TyposquatFindingStatus,
  "dismissed" | "confirmed"
> {
  return action === "dismiss"
    ? "dismissed"
    : "confirmed";
}

export class TyposquattingService {
  private readonly reader:
    TyposquattingFindingReader;
  private readonly detectorOptions:
    DetectorOptions;
  private readonly statementTimeoutMs:
    number;
  private readonly maxCandidateVersions:
    number;
  private readonly exposureOptions:
    ExposureTraceOptions;
  private readonly persistenceOptions:
    Omit<
      PersistenceServiceOptions,
      "idempotencyKey" |
        "correlationId"
    >;

  private operationTail:
    Promise<void> =
      Promise.resolve();

  constructor(
    private readonly driver: Driver,
    private readonly persistence:
      Pick<
        HydraPersistenceService,
        "persist"
      >,
    options:
      TyposquattingServiceOptions = {},
  ) {
    this.statementTimeoutMs =
      options.statementTimeoutMs ??
      DEFAULT_STATEMENT_TIMEOUT_MS;
    this.maxCandidateVersions =
      options.maxCandidateVersions ??
      DEFAULT_MAX_CANDIDATE_VERSIONS;

    this.detectorOptions = {
      ...DEFAULT_DETECTOR_OPTIONS,
      ...options.detector,
    };
    this.exposureOptions = {
      ...DEFAULT_EXPOSURE_OPTIONS,
      ...options.exposure,
    };
    this.persistenceOptions =
      options.persistenceOptions ?? {};
    this.reader =
      new TyposquattingFindingReader(
        driver,
        {
          statementTimeoutMs:
            this.statementTimeoutMs,
        },
      );
  }

  async scanLockfile(
    input: LockfileTyposquattingScanInput,
  ): Promise<TyposquattingScanResult> {
    requireTimestamp(
      input.observedAt,
      "observedAt",
    );

    const candidatePackages =
      new Map<number, PackageNode>();
    const sourceEvidence =
      new Map<number, EvidenceNode>();
    const versionsByPackage =
      new Map<string, string[]>();

    for (const node of input.collected.nodes) {
      if (node.kind === "Package") {
        candidatePackages.set(
          node.id,
          node,
        );
      } else if (
        node.kind === "Evidence"
      ) {
        sourceEvidence.set(
          node.id,
          node,
        );
      } else if (
        node.kind ===
        "PackageVersion"
      ) {
        const versions =
          versionsByPackage.get(
            node.packageName,
          ) ?? [];
        versions.push(node.version);
        versionsByPackage.set(
          node.packageName,
          versions,
        );
      }
    }

    const lockEvidence =
      sourceEvidence.get(
        input.collected.evidenceId,
      );

    if (
      lockEvidence === undefined ||
      lockEvidence.sourceType !==
        "package-lock"
    ) {
      throw new TyposquattingServiceError(
        "PERSISTENCE_FAILED",
        500,
        "Collected lockfile evidence is unavailable",
      );
    }

    const observedPackages:
      ObservedPackage[] =
        [...candidatePackages.values()]
          .sort(
            (left, right) =>
              left.name.localeCompare(
                right.name,
              ) || left.id - right.id,
          )
          .map((packageNode) => {
            const versions = [
              ...new Set(
                versionsByPackage.get(
                  packageNode.name,
                ) ?? [],
              ),
            ].sort((left, right) =>
              left.localeCompare(right),
            );

            return {
              packageId:
                packageNode.id,
              name: packageNode.name,
              ...(versions.length === 1
                ? {
                    version:
                      versions[0],
                  }
                : {}),
              source: "lockfile",
              sourceEvidenceIds: [
                input.collected
                  .evidenceId,
              ],
              contextualEvidence: [
                {
                  category:
                    "dependency-graph",
                  evidenceIds: [
                    input.collected
                      .evidenceId,
                  ],
                  detail:
                    "Exact package resolution is present in a persisted package-lock dependency graph.",
                },
              ],
            };
          });

    const boundedOptions:
      DetectorOptions = {
        ...this.detectorOptions,
        maxPackages: Math.min(
          this.detectorOptions
            .maxPackages,
          observedPackages.length,
        ),
      };

    const detection =
      detectTyposquatting(
        observedPackages,
        TRUSTED_TYPOSQUATTING_CORPUS,
        boundedOptions,
      );

    if (detection.findings.length === 0) {
      return Object.freeze({
        sourceFingerprint:
          input.collected
            .contentSha256,
        corpusId:
          detection.corpus.corpusId,
        packageCount:
          observedPackages.length,
        findingCount: 0,
        findingIds:
          Object.freeze([]),
        diagnostics:
          detection.diagnostics,
      });
    }

    const converted =
      buildTyposquattingGraphFragment({
        detection,
        candidatePackages,
        sourceEvidence,
        sourceFingerprint:
          input.collected
            .contentSha256,
        observationEvidenceId:
          input.collected.evidenceId,
        observedAt:
          input.observedAt,
      });

    const batch = mergeGraphFragments([
      converted.fragment,
    ]);

    try {
      await this.persistence.persist(
        batch,
        {
          ...this.persistenceOptions,
          idempotencyKey:
            `${input.persistenceIdempotencyKey}.typo`,
          correlationId:
            input.correlationId,
        },
      );
    } catch (error: unknown) {
      throw new TyposquattingServiceError(
        "PERSISTENCE_FAILED",
        503,
        "Typosquatting findings could not be persisted and verified",
        error,
      );
    }

    return Object.freeze({
      sourceFingerprint:
        input.collected
          .contentSha256,
      corpusId:
        detection.corpus.corpusId,
      packageCount:
        observedPackages.length,
      findingCount:
        converted.findingIds.length,
      findingIds:
        converted.findingIds,
      diagnostics:
        detection.diagnostics,
    });
  }

  listFindings(
    request: FindingListRequest,
  ): Promise<FindingListPage> {
    return this.reader.listFindings(
      request,
    );
  }

  async getFindingDetail(
    findingId: number,
  ): Promise<FindingDetail> {
    try {
      const finding =
        await this.reader.requireFinding(
          findingId,
        );
      const packages =
        await this.reader
          .getFindingPackages(finding);
      const evidence =
        await this.reader.getEvidence(
          finding.evidenceIds,
        );
      const acceptedLockfileEvidenceIds =
        trustedLockfileEvidenceIds(
          evidence,
        );
      const exactVersions =
        await this.reader
          .getExactCandidateVersions(
            packages.candidate,
            acceptedLockfileEvidenceIds,
            this.maxCandidateVersions,
          );
      const exposure =
        await this.reader.traceExposure(
          exactVersions.versions,
          acceptedLockfileEvidenceIds,
          this.exposureOptions,
        );
      const incidentIds =
        uniqueNumbers(
          evidence.flatMap(
            (entry) =>
              entry.incidentId ===
              undefined
                ? []
                : [entry.incidentId],
          ),
        );

      return Object.freeze({
        finding,
        candidate:
          packages.candidate,
        target: packages.target,
        evidence,
        exactVersions,
        exposure,
        incidentIds:
          Object.freeze(incidentIds),
      });
    } catch (error: unknown) {
      throw this.mapReadError(error);
    }
  }

  reviewFinding(
    command: FindingReviewCommand,
  ): Promise<FindingReviewResult> {
    const operation =
      this.operationTail.then(
        () =>
          this.reviewFindingExclusive(
            command,
          ),
        () =>
          this.reviewFindingExclusive(
            command,
          ),
      );

    this.operationTail =
      operation.then(
        () => undefined,
        () => undefined,
      );

    return operation;
  }

  private async reviewFindingExclusive(
    command: FindingReviewCommand,
  ): Promise<FindingReviewResult> {
    requireReviewCommand(command);

    let current:
      TyposquatFindingNode;

    try {
      current =
        await this.reader.requireFinding(
          command.findingId,
        );
    } catch (error: unknown) {
      throw this.mapReadError(error);
    }

    if (
      command.decidedAt <
      current.detectedAt
    ) {
      throw new TyposquattingServiceError(
        "INVALID_REVIEW",
        400,
        "decidedAt cannot precede detection",
      );
    }

    const desiredStatus =
      reviewStatus(command.action);
    const reviewToken = sha256(
      `typosquatting-review:${command.idempotencyKey}`,
    );
    const reviewIdentity =
      createEntityIdentity(
        `evidence:analyst-review:${reviewToken}`,
      );
    const incidentIdentity =
      command.action === "promote"
        ? createEntityIdentity(
            `incident:typosquatting:${current.id}`,
          )
        : undefined;

    const reviewDetail = JSON.stringify({
      requestFingerprint:
        command.requestFingerprint,
      findingId: command.findingId,
      action: command.action,
      reviewer: command.reviewer,
      reason: command.reason,
    });

    let reviewEvidence:
      EvidenceNode = {
        ...reviewIdentity,
        kind: "Evidence",
        evidenceIds: [],
        synthetic: false,
        observedAt:
          command.decidedAt,
        sourceType: "analyst-review",
        sourceUri:
          `analyst://hydraguard/${encodeURIComponent(command.reviewer)}`,
        collectorVersion:
          "analyst-review-v1",
        confidence: 1,
        detail: reviewDetail,
        ...(incidentIdentity ===
        undefined
          ? {}
          : {
              incidentId:
                incidentIdentity.id,
            }),
      };

    const existingReview =
      await this.readNode(
        reviewEvidence.id,
      );

    let replayed = false;

    if (existingReview !== null) {
      if (
        existingReview.kind !==
          "Evidence" ||
        existingReview.logicalId !==
          reviewEvidence.logicalId
      ) {
        throw new TyposquattingServiceError(
          "FINDING_CONFLICT",
          409,
          "Review evidence identity is already in use",
        );
      }

      const persistedDetail =
        parseReviewDetail(
          existingReview.detail,
        );

      if (
        persistedDetail
          .requestFingerprint !==
          command.requestFingerprint ||
        persistedDetail.findingId !==
          command.findingId ||
        persistedDetail.action !==
          command.action
      ) {
        throw new TyposquattingServiceError(
          "FINDING_CONFLICT",
          409,
          "The Idempotency-Key is associated with a different review",
        );
      }

      reviewEvidence =
        existingReview;
      replayed = true;
    }

    const effectiveCommand:
      FindingReviewCommand =
        reviewEvidence.observedAt ===
        command.decidedAt
          ? command
          : {
              ...command,
              decidedAt:
                reviewEvidence.observedAt,
            };

    if (
      (current.status === "confirmed" ||
        current.status === "dismissed") &&
      (current.status === "dismissed" ||
        command.action === "dismiss")
    ) {
      const isMatchingReplay =
        replayed &&
        current.status ===
          desiredStatus &&
        current.evidenceIds.includes(
          reviewEvidence.id,
        );

      if (!isMatchingReplay) {
        throw new TyposquattingServiceError(
          "FINDING_ALREADY_DECIDED",
          409,
          `Finding is already ${current.status}`,
        );
      }

      await this.persistLifecycleGraph(
        current,
        reviewEvidence,
        effectiveCommand,
        incidentIdentity,
      );

      return Object.freeze({
        finding: current,
        replayed: true,
      });
    }

    if (
      current.status === "confirmed" &&
      command.action === "promote"
    ) {
      /*
       * The Finding CAS and graph persistence cannot be atomic across the
       * direct HydraDB update and verified GraphBatch writer. A new,
       * authorized promotion therefore acts as a repair trigger if the CAS
       * committed but Incident/AFFECTS persistence failed. The repaired graph
       * is reconstructed from the original confirmation evidence so a repair
       * cannot replace decision provenance or its timestamp.
       */
      if (existingReview === null) {
        await this.persistReviewEvidence(
          reviewEvidence,
          reviewToken,
        );
      }

      const confirmation =
        await this.getConfirmationReview(
          current,
          incidentIdentity!,
        );
      const repairCommand:
        FindingReviewCommand = {
          ...command,
          reason:
            confirmation.detail.reason,
          reviewer:
            confirmation.detail.reviewer,
          decidedAt:
            confirmation.evidence.observedAt,
        };

      await this.assertPromotable(
        current,
      );
      await this.persistLifecycleGraph(
        current,
        confirmation.evidence,
        repairCommand,
        incidentIdentity,
      );

      return Object.freeze({
        finding: current,
        incidentId:
          incidentIdentity!.id,
        replayed: true,
      });
    }

    if (command.action === "promote") {
      await this.assertPromotable(
        current,
      );
    }

    if (existingReview === null) {
      await this.persistReviewEvidence(
        reviewEvidence,
        reviewToken,
      );
    }

    const updated:
      TyposquatFindingNode = {
        ...current,
        evidenceIds:
          uniqueNumbers([
            ...current.evidenceIds,
            reviewEvidence.id,
          ]),
        status: desiredStatus,
        observedAt: Math.max(
          current.observedAt,
          effectiveCommand.decidedAt,
        ),
        decidedAt:
          effectiveCommand.decidedAt,
        decisionReason:
          effectiveCommand.reason,
      };

    const transitioned =
      await this.compareAndSetFinding(
        current,
        updated,
        reviewToken,
      );

    if (!transitioned) {
      const latest =
        await this.reader.requireFinding(
          command.findingId,
        );

      if (
        latest.status !==
          desiredStatus ||
        !latest.evidenceIds.includes(
          reviewEvidence.id,
        )
      ) {
        throw new TyposquattingServiceError(
          "FINDING_CONFLICT",
          409,
          "Finding changed during analyst review",
        );
      }

      current = latest;
      replayed = true;
    } else {
      current = updated;
    }

    await this.persistLifecycleGraph(
      current,
      reviewEvidence,
      command,
      incidentIdentity,
    );

    return Object.freeze({
      finding: current,
      ...(incidentIdentity ===
      undefined
        ? {}
        : {
            incidentId:
              incidentIdentity.id,
          }),
      replayed,
    });
  }

  private async getConfirmationReview(
    finding: TyposquatFindingNode,
    incidentIdentity: {
      readonly id: number;
      readonly logicalId: string;
    },
  ): Promise<{
    readonly evidence: EvidenceNode;
    readonly detail: ParsedReviewDetail;
  }> {
    const evidence =
      await this.reader.getEvidence(
        finding.evidenceIds,
      );
    const confirmations: Array<{
      readonly evidence: EvidenceNode;
      readonly detail: ParsedReviewDetail;
    }> = [];

    for (const entry of evidence) {
      if (
        entry.sourceType !==
          "analyst-review" ||
        entry.synthetic ||
        entry.incidentId !==
          incidentIdentity.id
      ) {
        continue;
      }

      const detail =
        parseReviewDetail(entry.detail);

      if (
        detail.findingId === finding.id &&
        detail.action === "promote"
      ) {
        confirmations.push({
          evidence: entry,
          detail,
        });
      }
    }

    if (confirmations.length !== 1) {
      throw new TyposquattingServiceError(
        "FINDING_CONFLICT",
        409,
        "Confirmed finding does not have one authoritative promotion review",
      );
    }

    const confirmation =
      confirmations[0]!;

    if (
      finding.decidedAt !==
        confirmation.evidence.observedAt ||
      finding.decisionReason !==
        confirmation.detail.reason
    ) {
      throw new TyposquattingServiceError(
        "FINDING_CONFLICT",
        409,
        "Confirmed finding decision does not match its promotion evidence",
      );
    }

    return confirmation;
  }

  private async assertPromotable(
    finding: TyposquatFindingNode,
  ): Promise<void> {
    if (finding.synthetic) {
      throw new TyposquattingServiceError(
        "PROMOTION_REQUIRES_TRUSTED_EVIDENCE",
        409,
        "Synthetic findings cannot be promoted to confirmed incidents",
      );
    }

    const evidence =
      await this.reader.getEvidence(
        finding.evidenceIds,
      );
    const acceptedLockfileEvidenceIds =
      trustedLockfileEvidenceIds(
        evidence,
      );

    if (
      acceptedLockfileEvidenceIds.length === 0
    ) {
      throw new TyposquattingServiceError(
        "PROMOTION_REQUIRES_TRUSTED_EVIDENCE",
        409,
        "Promotion requires non-synthetic, high-confidence package-lock evidence",
      );
    }

    const packages =
      await this.reader
        .getFindingPackages(finding);
    const versions =
      await this.reader
        .getExactCandidateVersions(
          packages.candidate,
          acceptedLockfileEvidenceIds,
          this.maxCandidateVersions,
        );

    if (
      versions.truncated ||
      versions.versions.length === 0
    ) {
      throw new TyposquattingServiceError(
        "PROMOTION_REQUIRES_EXACT_EXPOSURE",
        409,
        "Promotion requires a bounded, exact lockfile-resolved PackageVersion",
      );
    }
  }

  private async persistReviewEvidence(
    evidence: EvidenceNode,
    reviewToken: string,
  ): Promise<void> {
    const batch = mergeGraphFragments([
      {
        source:
          `analyst-review:${reviewToken}`,
        nodes: [evidence],
        edges: [],
      },
    ]);

    try {
      await this.persistence.persist(
        batch,
        {
          ...this.persistenceOptions,
          idempotencyKey:
            `hg-typo-review-${reviewToken.slice(0, 32)}.e`,
          correlationId:
            `hg-typo-review-${reviewToken.slice(0, 32)}`,
        },
      );
    } catch (error: unknown) {
      throw new TyposquattingServiceError(
        "PERSISTENCE_FAILED",
        503,
        "Analyst review evidence could not be persisted and verified",
        error,
      );
    }
  }

  private async compareAndSetFinding(
    current: TyposquatFindingNode,
    updated: TyposquatFindingNode,
    reviewToken: string,
  ): Promise<boolean> {
    const currentRow =
      serializeHydraNode(current);
    const updatedRow =
      serializeHydraNode(updated);
    const assignments =
      NODE_PROPERTY_KEYS.Finding
        .map(
          (property) =>
            `f.${property} = $${property}`,
        )
        .join(", ");
    const parameters:
      Record<string, unknown> = {
        finding_id: current.id,
        expected_status:
          current.status,
        expected_payload_hash:
          currentRow.payload_hash,
      };

    for (
      const property
      of NODE_PROPERTY_KEYS.Finding
    ) {
      parameters[property] =
        updatedRow[property];
    }

    const session =
      this.driver.session();

    try {
      const result = await session.run(
        [
          "MATCH (f:Finding {id: $finding_id})",
          "WHERE f.status = $expected_status",
          "  AND f.payload_hash = $expected_payload_hash",
          `SET ${assignments}, f.__hydradb_update_if_newer_by = $observed_at`,
          "RETURN f.id AS finding_id, f.payload_hash AS payload_hash",
          "LIMIT 2",
        ].join("\n"),
        toHydraParameters(parameters),
        {
          timeout:
            this.statementTimeoutMs,
          metadata: {
            "hydradb.correlation_id":
              `hg-typo-review-${reviewToken.slice(0, 32)}`,
            "hydradb.idempotency_key":
              `hg-typo-review-${reviewToken.slice(0, 32)}.cas`,
            "hydradb.caller.step":
              "typosquatting.finding.compare-and-set",
          },
        },
      );

      const records = (
        result as {
          readonly records?: unknown;
        }
      ).records;

      if (!Array.isArray(records)) {
        throw new Error(
          "HydraDB returned no records array",
        );
      }

      if (records.length === 0) {
        return false;
      }

      if (records.length !== 1) {
        throw new Error(
          "HydraDB returned duplicate Finding rows",
        );
      }

      const record = records[0] as {
        get(key: string): unknown;
      };

      if (
        record.get("payload_hash") !==
        updatedRow.payload_hash
      ) {
        throw new Error(
          "HydraDB did not materialize the reviewed Finding payload",
        );
      }

      return true;
    } catch (error: unknown) {
      throw new TyposquattingServiceError(
        "DATABASE_UNAVAILABLE",
        503,
        "HydraDB could not update the Finding safely",
        error,
      );
    } finally {
      await session.close();
    }
  }

  private async persistLifecycleGraph(
    finding: TyposquatFindingNode,
    reviewEvidence: EvidenceNode,
    command: FindingReviewCommand,
    incidentIdentity?: {
      readonly id: number;
      readonly logicalId: string;
    },
  ): Promise<void> {
    const evidence =
      await this.reader.getEvidence(
        finding.evidenceIds,
      );
    const acceptedLockfileEvidenceIds =
      trustedLockfileEvidenceIds(
        evidence,
      );
    const nodes =
      new Map<number, GraphNode>();
    const edges:
      GraphEdge[] = [];

    for (const entry of evidence) {
      nodes.set(entry.id, entry);
    }
    nodes.set(
      reviewEvidence.id,
      reviewEvidence,
    );
    nodes.set(finding.id, finding);

    const discriminator =
      `analyst-review:${reviewEvidence.id}`;

    edges.push(
      createStandardEdge(
        "SUPPORTS",
        reviewEvidence,
        finding,
        [reviewEvidence.id],
        command.decidedAt,
        discriminator,
      ),
    );

    if (incidentIdentity !== undefined) {
      const packages =
        await this.reader
          .getFindingPackages(finding);
      const exactVersions =
        await this.reader
          .getExactCandidateVersions(
            packages.candidate,
            acceptedLockfileEvidenceIds,
            this.maxCandidateVersions,
          );

      if (
        exactVersions.truncated ||
        exactVersions.versions.length ===
          0
      ) {
        throw new TyposquattingServiceError(
          "PROMOTION_REQUIRES_EXACT_EXPOSURE",
          409,
          "Confirmed finding has no bounded exact PackageVersion exposure",
        );
      }

      const incident:
        IncidentNode = {
          ...incidentIdentity,
          kind: "Incident",
          evidenceIds: [
            reviewEvidence.id,
          ],
          synthetic: false,
          observedAt:
            command.decidedAt,
          title:
            `Confirmed typosquatting review: ${finding.candidatePackageName} imitating ${finding.targetPackageName}`,
          status: "active",
          intervalStart:
            finding.detectedAt,
          intervalEnd: null,
        };

      nodes.set(incident.id, incident);
      edges.push(
        createStandardEdge(
          "SUPPORTS",
          reviewEvidence,
          incident,
          [reviewEvidence.id],
          command.decidedAt,
          discriminator,
        ),
      );

      for (
        const version
        of exactVersions.versions
      ) {
        nodes.set(version.id, version);
        const versionEvidence =
          await this.reader.getEvidence(
            version.evidenceIds,
          );

        for (const entry of versionEvidence) {
          nodes.set(entry.id, entry);
        }

        edges.push(
          createStandardEdge(
            "AFFECTS",
            incident,
            version,
            [reviewEvidence.id],
            command.decidedAt,
            discriminator,
          ),
        );
      }
    }

    const batch = mergeGraphFragments([
      {
        source:
          `typosquatting-review:${command.requestFingerprint}`,
        nodes:
          [...nodes.values()],
        edges,
      },
    ]);
    const reviewToken = sha256(
      `typosquatting-review:${command.idempotencyKey}`,
    );

    try {
      await this.persistence.persist(
        batch,
        {
          ...this.persistenceOptions,
          idempotencyKey:
            `hg-typo-review-${reviewToken.slice(0, 32)}.g`,
          correlationId:
            `hg-typo-review-${reviewToken.slice(0, 32)}`,
        },
      );
    } catch (error: unknown) {
      throw new TyposquattingServiceError(
        "PERSISTENCE_FAILED",
        503,
        "Reviewed finding graph could not be persisted and verified",
        error instanceof
          PersistenceServiceError
          ? error
          : error,
      );
    }
  }

  private async readNode(
    nodeId: number,
  ): Promise<GraphNode | null> {
    try {
      const reader =
        new HydraGraphReader(
          this.driver,
          {
            statementTimeoutMs:
              this.statementTimeoutMs,
          },
        );
      return await reader.getNode(
        nodeId,
      );
    } catch (error: unknown) {
      throw new TyposquattingServiceError(
        "DATABASE_UNAVAILABLE",
        503,
        "HydraDB could not verify the review identity",
        error,
      );
    }
  }

  private mapReadError(
    error: unknown,
  ): TyposquattingServiceError {
    if (
      error instanceof
      TyposquattingServiceError
    ) {
      return error;
    }

    if (
      error instanceof
      FindingReaderError
    ) {
      if (
        error.code ===
        "FINDING_NOT_FOUND"
      ) {
        return new TyposquattingServiceError(
          "FINDING_NOT_FOUND",
          404,
          "The requested finding was not found",
          error,
        );
      }

      return new TyposquattingServiceError(
        "DATABASE_UNAVAILABLE",
        503,
        "HydraDB could not read typosquatting findings",
        error,
      );
    }

    return new TyposquattingServiceError(
      "DATABASE_UNAVAILABLE",
      503,
      "HydraDB could not read typosquatting findings",
      error,
    );
  }
}
