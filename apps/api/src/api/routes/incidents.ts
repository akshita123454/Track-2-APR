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
} from "../schemas/incidents.js";

import type {
  AffectedReleaseInput,
  IncidentCreateRequestBody,
  IncidentCreatedResponse,
  IncidentIdempotencyHeaders,
} from "../schemas/incidents.js";

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
