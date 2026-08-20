import type {
  FastifyInstance,
} from "fastify";

import type {
  AnalystAuthorizer,
} from "../analyst-authorization.js";

import {
  ApiError,
} from "../errors.js";

import {
  assertValidIdempotencyKey,
  createRequestFingerprint,
} from "../jobs/job-manager.js";

import {
  createLockfileIngestionWorker,
} from "../jobs/workers.js";

import {
  createAndDispatch,
} from "./ingestions.js";

import type {
  IngestionRoutesOptions,
} from "./ingestions.js";

import type {
  TyposquatFindingNode,
} from "../../domain/schema.js";

import type {
  TyposquattingService,
} from "../../typosquatting/service.js";

import {
  CREATE_TYPOSQUATTING_SCAN_ROUTE_SCHEMA,
  GET_TYPOSQUATTING_FINDING_ROUTE_SCHEMA,
  LIST_TYPOSQUATTING_FINDINGS_ROUTE_SCHEMA,
  REVIEW_TYPOSQUATTING_FINDING_ROUTE_SCHEMA,
  TYPOSQUATTING_LIMITS,
} from "../schemas/typosquatting.js";

import type {
  FindingIdParams,
  FindingListQuery,
  FindingReviewBody,
  RequiredAnalystReviewHeaders,
} from "../schemas/typosquatting.js";

import type {
  IdempotencyHeaders,
  LockfileIngestionRequestBody,
} from "../schemas/ingestions.js";

export interface TyposquattingRoutesOptions
  extends IngestionRoutesOptions {
  readonly service:
    TyposquattingService;
  readonly analystAuthorizer:
    AnalystAuthorizer;
  readonly now?: () => number;
}

function parseFindingId(
  value: string,
): number {
  const parsed = Number(value);

  if (
    !Number.isSafeInteger(parsed) ||
    parsed < 0
  ) {
    throw new ApiError(
      "INVALID_FINDING_ID",
      400,
      "findingId must be a nonnegative safe integer.",
    );
  }

  return parsed;
}

function summary(
  finding: TyposquatFindingNode,
) {
  return {
    findingId: finding.id,
    status: finding.status,
    score: finding.score,
    scoreMeaning:
      "heuristic-ranking-not-probability" as const,
    candidateName:
      finding.candidatePackageName,
    targetName:
      finding.targetPackageName,
    summary: finding.summary,
    transformations:
      finding.transformations,
    reasonCodes:
      finding.reasonCodes,
    detectedAt:
      finding.detectedAt,
    ...(finding.decidedAt === undefined
      ? {}
      : {
          decidedAt:
            finding.decidedAt,
        }),
    ...(finding.decisionReason ===
    undefined
      ? {}
      : {
          decisionReason:
            finding.decisionReason,
        }),
    synthetic: finding.synthetic,
  };
}

function validateCursor(
  query: FindingListQuery,
) {
  const hasDetectedAt =
    query.cursorDetectedAt !== undefined;
  const hasFindingId =
    query.cursorFindingId !== undefined;

  if (hasDetectedAt !== hasFindingId) {
    throw new ApiError(
      "INVALID_FINDING_CURSOR",
      400,
      "cursorDetectedAt and cursorFindingId must be supplied together.",
    );
  }

  return hasDetectedAt
    ? {
        detectedAt:
          query.cursorDetectedAt!,
        findingId:
          query.cursorFindingId!,
      }
    : undefined;
}

export async function registerTyposquattingRoutes(
  app: FastifyInstance,
  options: TyposquattingRoutesOptions,
): Promise<void> {
  const now = options.now ?? Date.now;

  app.post<{
    Headers: IdempotencyHeaders;
    Body: LockfileIngestionRequestBody;
  }>(
    "/typosquatting/scans",
    {
      schema:
        CREATE_TYPOSQUATTING_SCAN_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const accepted = createAndDispatch(
        options,
        {
          kind: "lockfile",
          requestBody: request.body,
          idempotencyKey:
            request.headers[
              "idempotency-key"
            ],
          createWorker: () =>
            createLockfileIngestionWorker(
              request.body,
              options.workerDependencies,
            ),
        },
      );

      return reply.code(202).send(
        accepted,
      );
    },
  );

  app.get<{
    Querystring: FindingListQuery;
  }>(
    "/typosquatting/findings",
    {
      schema:
        LIST_TYPOSQUATTING_FINDINGS_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const page =
        await options.service.listFindings({
          limit:
            request.query.limit ??
            TYPOSQUATTING_LIMITS
              .defaultFindings,
          ...(validateCursor(
            request.query,
          ) === undefined
            ? {}
            : {
                cursor:
                  validateCursor(
                    request.query,
                  ),
              }),
        });

      return reply.code(200).send({
        findings:
          page.findings.map(summary),
        truncated: page.truncated,
        ...(page.nextCursor === undefined
          ? {}
          : {
              nextCursor:
                page.nextCursor,
            }),
      });
    },
  );

  app.get<{
    Params: FindingIdParams;
  }>(
    "/typosquatting/findings/:findingId",
    {
      schema:
        GET_TYPOSQUATTING_FINDING_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const detail =
        await options.service
          .getFindingDetail(
            parseFindingId(
              request.params.findingId,
            ),
          );

      return reply.code(200).send({
        finding:
          summary(detail.finding),
        candidatePackageId:
          detail.candidate.id,
        targetPackageId:
          detail.target.id,
        evidence:
          detail.evidence.map(
            (entry) => ({
              id: entry.id,
              sourceType:
                entry.sourceType,
              confidence:
                entry.confidence,
              observedAt:
                entry.observedAt,
              synthetic:
                entry.synthetic,
            }),
          ),
        exactVersions:
          detail.exactVersions
            .versions.map(
              (version) => ({
                id: version.id,
                version:
                  version.version,
                synthetic:
                  version.synthetic,
              }),
            ),
        versionLookup: {
          scannedCount:
            detail.exactVersions
              .scannedCount,
          truncated:
            detail.exactVersions
              .truncated,
        },
        exposure: detail.exposure,
        incidentIds:
          detail.incidentIds,
      });
    },
  );

  const registerReview = (
    action: "dismiss" | "promote",
  ): void => {
    app.post<{
      Headers:
        RequiredAnalystReviewHeaders;
      Params: FindingIdParams;
      Body: FindingReviewBody;
    }>(
      `/typosquatting/findings/:findingId/${action}`,
      {
        schema:
          REVIEW_TYPOSQUATTING_FINDING_ROUTE_SCHEMA,
      },
      async (request, reply) => {
        let principal: {
          readonly reviewer: string;
        };

        try {
          principal =
            await options
              .analystAuthorizer
              .authorize(
                request.headers
                  .authorization,
              );
        } catch (error: unknown) {
          if (
            error instanceof ApiError &&
            error.httpStatusCode === 401
          ) {
            reply.header(
              "WWW-Authenticate",
              'Bearer realm="hydraguard-analyst"',
            );
          }
          throw error;
        }

        const idempotencyKey =
          request.headers[
            "idempotency-key"
          ];
        assertValidIdempotencyKey(
          idempotencyKey,
        );
        const findingId =
          parseFindingId(
            request.params.findingId,
          );
        const requestFingerprint =
          createRequestFingerprint({
            operation:
              `typosquatting-${action}`,
            findingId,
            body: request.body,
            reviewer:
              principal.reviewer,
          });
        const result =
          await options.service
            .reviewFinding({
              findingId,
              action,
              reason:
                request.body.reason,
              reviewer:
                principal.reviewer,
              decidedAt: now(),
              idempotencyKey,
              requestFingerprint,
            });

        return reply.code(200).send({
          finding:
            summary(result.finding),
          ...(result.incidentId ===
          undefined
            ? {}
            : {
                incidentId:
                  result.incidentId,
              }),
          replayed:
            result.replayed,
        });
      },
    );
  };

  registerReview("dismiss");
  registerReview("promote");
}
