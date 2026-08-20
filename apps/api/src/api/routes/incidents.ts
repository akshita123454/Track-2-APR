import type {
  FastifyInstance,
} from "fastify";

import {
  assertValidIdempotencyKey,
  createRequestFingerprint,
} from "../jobs/job-manager.js";

import {
  CREATE_INCIDENT_ROUTE_SCHEMA,
  INCIDENT_LIMITS,
  INCIDENT_LIST_LIMITS,
  LIST_INCIDENTS_ROUTE_SCHEMA,
} from "../schemas/incidents.js";

import type {
  AffectedReleaseInput,
  IncidentCreateRequestBody,
  IncidentCreatedResponse,
  IncidentIdempotencyHeaders,
  IncidentListItemResponse,
  IncidentListQuerystring,
  IncidentListResponse,
} from "../schemas/incidents.js";

import {
  IncidentListStoreError,
} from "../../incidents/incident-list-store.js";

import type {
  IncidentListEntry,
  IncidentListReader,
} from "../../incidents/incident-list-store.js";

import {
  ApiError,
} from "../errors.js";

/**
 * Fully validated command passed to the incident persistence boundary.
 *
 * The creator must handle durable idempotency and must not construct
 * PackageVersion nodes for versions that have not been resolved from trusted
 * graph or registry evidence.
 */
export interface IncidentCreateCommand {
  readonly request:
    IncidentCreateRequestBody;

  readonly requestFingerprint:
    string;

  readonly intervalStart:
    number;

  readonly intervalEnd:
    number | null;

  readonly provenanceObservedAt:
    number;

  readonly totalExactVersions:
    number;

  readonly idempotencyKey?:
    string;
}

/**
 * Dedicated incident persistence boundary.
 *
 * This is intentionally separate from JobManager because POST /incidents is
 * synchronous and returns 201 in the existing OpenAPI contract.
 */
export interface IncidentCreator {
  createIncident(
    command: IncidentCreateCommand,
  ): Promise<IncidentCreatedResponse>;
}

export interface IncidentRoutesOptions {
  readonly incidentCreator:
    IncidentCreator;

  /**
   * Bounded incident index used by GET /incidents.
   */
  readonly incidentListReader:
    IncidentListReader;
}

/**
 * Converts a stored epoch into the ISO date-time the wire contract declares.
 *
 * Persisted incidents are validated on write, so an unrepresentable epoch
 * here means stored data is corrupt rather than that the request was bad.
 */
function toIsoTimestamp(
  epochMs: number,
  field: string,
): string {
  const date = new Date(epochMs);

  if (Number.isNaN(date.getTime())) {
    /*
     * The offending field name stays out of the public payload; it is only
     * useful to an operator reading private logs.
     */
    void field;

    throw new ApiError(
      "INCIDENT_LIST_UNAVAILABLE",
      503,
      "The incident index is temporarily unavailable.",
    );
  }

  return date.toISOString();
}

function toIncidentListItem(
  entry: IncidentListEntry,
): IncidentListItemResponse {
  return Object.freeze({
    incidentId: entry.id,
    logicalId: entry.logicalId,
    title: entry.title,
    status: entry.status,

    intervalStart: toIsoTimestamp(
      entry.intervalStart,
      "incident.interval_start",
    ),

    intervalEnd:
      entry.intervalEnd === null
        ? null
        : toIsoTimestamp(
            entry.intervalEnd,
            "incident.interval_end",
          ),

    affectedVersionCount:
      entry.affectedVersionCount,

    synthetic: entry.synthetic,

    observedAt: toIsoTimestamp(
      entry.observedAt,
      "incident.observed_at",
    ),
  });
}

interface IncidentSemanticValidation {
  readonly ok: boolean;

  readonly intervalStart?: number;
  readonly intervalEnd?: number | null;
  readonly provenanceObservedAt?: number;
  readonly totalExactVersions?: number;

  readonly message?: string;
}

function parseTimestamp(
  value: string,
): number | null {
  const timestamp =
    Date.parse(value);

  return (
    Number.isSafeInteger(timestamp) &&
    timestamp >= 0
  )
    ? timestamp
    : null;
}

function normalizedPackageName(
  release: AffectedReleaseInput,
): string {
  return release.packageName
    .normalize("NFC");
}

function validateIncidentSemantics(
  request:
    IncidentCreateRequestBody,
): IncidentSemanticValidation {
  const intervalStart =
    parseTimestamp(
      request.intervalStart,
    );

  if (intervalStart === null) {
    return {
      ok: false,
      message:
        "intervalStart must be a valid nonnegative date-time.",
    };
  }

  let intervalEnd:
    number | null = null;

  if (
    request.intervalEnd !==
      undefined &&
    request.intervalEnd !== null
  ) {
    intervalEnd =
      parseTimestamp(
        request.intervalEnd,
      );

    if (intervalEnd === null) {
      return {
        ok: false,
        message:
          "intervalEnd must be null or a valid nonnegative date-time.",
      };
    }

    if (
      intervalEnd <
      intervalStart
    ) {
      return {
        ok: false,
        message:
          "intervalEnd must not precede intervalStart.",
      };
    }
  }

  const provenanceObservedAt =
    parseTimestamp(
      request.provenance
        .observedAt,
    );

  if (
    provenanceObservedAt ===
    null
  ) {
    return {
      ok: false,
      message:
        "provenance.observedAt must be a valid nonnegative date-time.",
    };
  }

  /*
   * A synthetic-fixture source must identify itself as synthetic. This avoids
   * presenting demonstration evidence as a real security advisory.
   */
  if (
    request.provenance
      .sourceType ===
      "synthetic-fixture" &&
    request.provenance
      .synthetic !== true
  ) {
    return {
      ok: false,
      message:
        "Synthetic fixture provenance must set synthetic to true.",
    };
  }

  const seenPackageNames =
    new Set<string>();

  let totalExactVersions = 0;

  for (
    const release
    of request.affectedReleases
  ) {
    const packageName =
      normalizedPackageName(
        release,
      );

    if (
      seenPackageNames.has(
        packageName,
      )
    ) {
      return {
        ok: false,
        message:
          `Package ${packageName} appears more than once in affectedReleases.`,
      };
    }

    seenPackageNames.add(
      packageName,
    );

    const hasRange =
      release.affectedRange !==
      undefined;

    const exactVersions =
      release.exactVersions ??
      [];

    if (
      !hasRange &&
      exactVersions.length === 0
    ) {
      return {
        ok: false,
        message:
          `Package ${packageName} must define affectedRange, exactVersions, or both.`,
      };
    }

    const normalizedVersions =
      new Set(
        exactVersions.map(
          (version) =>
            version.normalize("NFC"),
        ),
      );

    if (
      normalizedVersions.size !==
      exactVersions.length
    ) {
      return {
        ok: false,
        message:
          `Package ${packageName} contains duplicate normalized exact versions.`,
      };
    }

    totalExactVersions +=
      exactVersions.length;

    if (
      totalExactVersions >
      INCIDENT_LIMITS
        .maxTotalExactVersions
    ) {
      return {
        ok: false,
        message:
          "The incident contains too many exact affected versions.",
      };
    }
  }

  return {
    ok: true,
    intervalStart,
    intervalEnd,
    provenanceObservedAt,
    totalExactVersions,
  };
}

function assertCreatorResponse(
  response:
    IncidentCreatedResponse,
): void {
  if (
    !Number.isSafeInteger(
      response.incidentId,
    ) ||
    response.incidentId < 0 ||
    !response.logicalId
      .startsWith("incident:") ||
    (
      response.status !==
        "draft" &&
      response.status !==
        "active"
    )
  ) {
    throw new Error(
      "IncidentCreator returned an invalid incident response",
    );
  }
}

/**
 * Registers POST /incidents.
 *
 * The route validates bounded request semantics. Incident identity,
 * affected-range resolution, durable idempotency, graph construction,
 * persistence and verification belong to IncidentCreator.
 */
export async function registerIncidentRoutes(
  app: FastifyInstance,
  options: IncidentRoutesOptions,
): Promise<void> {
  app.get<{
    Querystring:
      IncidentListQuerystring;
  }>(
    "/incidents",
    {
      schema:
        LIST_INCIDENTS_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const {
        limit,
        cursorObservedAt,
        cursorId,
      } = request.query;

      /*
       * Both cursor halves define one position. Accepting a partial cursor
       * would silently return the first page again and look like data loss.
       */
      if (
        (cursorObservedAt ===
          undefined) !==
        (cursorId === undefined)
      ) {
        throw new ApiError(
          "INVALID_INCIDENT_CURSOR",
          400,
          "cursorObservedAt and cursorId must be supplied together.",
        );
      }

      let page;

      try {
        page =
          await options
            .incidentListReader
            .listIncidents({
              limit:
                limit ??
                INCIDENT_LIST_LIMITS
                  .defaultLimit,

              ...(cursorObservedAt ===
                undefined ||
              cursorId === undefined
                ? {}
                : {
                    cursor: {
                      observedAt:
                        cursorObservedAt,
                      id: cursorId,
                    },
                  }),
            });
      } catch (error: unknown) {
        if (
          error instanceof
          IncidentListStoreError
        ) {
          request.log.error(
            {
              err: error,
            },
            "Incident index read failed",
          );

          throw new ApiError(
            "INCIDENT_LIST_UNAVAILABLE",
            503,
            "The incident index is temporarily unavailable.",
          );
        }

        throw error;
      }

      const body: IncidentListResponse =
        Object.freeze({
          incidents: Object.freeze(
            page.incidents.map(
              toIncidentListItem,
            ),
          ),

          truncated: page.truncated,

          nextCursor:
            page.nextCursor === null
              ? null
              : Object.freeze({
                  cursorObservedAt:
                    page.nextCursor
                      .observedAt,
                  cursorId:
                    page.nextCursor.id,
                }),
        });

      return reply
        .code(200)
        .send(body);
    },
  );

  app.post<{
    Headers:
      IncidentIdempotencyHeaders;

    Body:
      IncidentCreateRequestBody;
  }>(
    "/incidents",
    {
      schema:
        CREATE_INCIDENT_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const idempotencyKey =
        request.headers[
          "idempotency-key"
        ];

      /*
       * Fastify already validates this through JSON Schema. Calling the shared
       * runtime validator also protects direct route tests and prevents the
       * schema and identity implementation from drifting apart.
       */
      if (
        idempotencyKey !==
        undefined
      ) {
        assertValidIdempotencyKey(
          idempotencyKey,
        );
      }

      const semantic =
        validateIncidentSemantics(
          request.body,
        );

      if (
        !semantic.ok ||
        semantic.intervalStart ===
          undefined ||
        semantic.intervalEnd ===
          undefined ||
        semantic
          .provenanceObservedAt ===
          undefined ||
        semantic
          .totalExactVersions ===
          undefined
      ) {
        return reply
          .code(400)
          .send({
            code:
              "INVALID_INCIDENT_REQUEST",

            message:
              semantic.message ??
              "The incident request is invalid.",
          });
      }

      const requestFingerprint =
        createRequestFingerprint({
          operation:
            "create-incident",

          body:
            request.body,
        });

      const command:
        IncidentCreateCommand =
          Object.freeze({
            request:
              request.body,

            requestFingerprint,

            intervalStart:
              semantic.intervalStart,

            intervalEnd:
              semantic.intervalEnd,

            provenanceObservedAt:
              semantic
                .provenanceObservedAt,

            totalExactVersions:
              semantic
                .totalExactVersions,

            ...(idempotencyKey ===
            undefined
              ? {}
              : {
                  idempotencyKey,
                }),
          });

      const created =
        await options
          .incidentCreator
          .createIncident(command);

      assertCreatorResponse(
        created,
      );

      return reply
        .code(201)
        .send(created);
    },
  );
}
