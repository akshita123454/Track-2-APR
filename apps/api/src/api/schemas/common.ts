import type {
  FastifyInstance,
} from "fastify";

import type {
  IngestionJobStatus,
} from "../jobs/job-manager.js";

/**
 * Shared security and wire-contract limits.
 *
 * Keep these synchronized with:
 * - job-manager.ts
 * - contracts/openapi.yaml
 * - the dashboard API client
 */
export const IDEMPOTENCY_KEY_MIN_LENGTH = 8;
export const IDEMPOTENCY_KEY_MAX_LENGTH = 80;
export const INGESTION_ID_MIN_LENGTH = 8;
export const INGESTION_ID_MAX_LENGTH = 128;

export const IDEMPOTENCY_KEY_PATTERN =
  "^[A-Za-z0-9._-]{8,80}$";

export const INGESTION_ID_PATTERN =
  "^[A-Za-z0-9._-]{8,128}$";

export const MAX_SAFE_INTEGER =
  9_007_199_254_740_991;

/**
 * Exact values from contracts/openapi.yaml and job-manager.ts.
 *
 * `satisfies` ensures no unsupported value can be added accidentally.
 */
export const INGESTION_JOB_STATUSES = [
  "queued",
  "running",
  "completed",
  "partially-completed",
  "failed",
] as const satisfies readonly IngestionJobStatus[];

export const COMMON_SCHEMA_IDS = {
  errorResponse:
    "HydraGuardErrorResponse",

  ingestionAccepted:
    "HydraGuardIngestionAccepted",

  ingestionJob:
    "HydraGuardIngestionJob",
} as const;

export const ERROR_RESPONSE_SCHEMA = {
  $id: COMMON_SCHEMA_IDS.errorResponse,

  type: "object",

  /*
   * Prevent internal stack traces, query details, credentials or arbitrary
   * error fields from accidentally entering the HTTP response.
   */
  additionalProperties: false,

  required: [
    "code",
    "message",
  ],

  properties: {
    code: {
      type: "string",
      minLength: 2,
      maxLength: 64,

      /*
       * Public error codes use stable machine-readable uppercase tokens.
       */
      pattern:
        "^[A-Z][A-Z0-9_]{1,63}$",
    },

    message: {
      type: "string",
      minLength: 1,
      maxLength: 1_024,
    },

    details: {
      type: "array",
      minItems: 1,
      maxItems: 50,
      uniqueItems: true,

      items: {
        type: "string",
        minLength: 1,
        maxLength: 512,
      },
    },
  },
} as const;

export const INGESTION_ACCEPTED_SCHEMA = {
  $id:
    COMMON_SCHEMA_IDS.ingestionAccepted,

  type: "object",
  additionalProperties: false,

  required: [
    "ingestionId",
    "status",
    "submittedAt",
  ],

  properties: {
    ingestionId: {
      type: "string",
      minLength:
        INGESTION_ID_MIN_LENGTH,
      maxLength:
        INGESTION_ID_MAX_LENGTH,
      pattern: INGESTION_ID_PATTERN,
    },

    /*
     * This is intentionally fixed to queued because the 202 response
     * represents the original job acceptance. Current status is obtained
     * from GET /ingestions/:ingestionId.
     */
    status: {
      type: "string",
      enum: ["queued"],
    },

    submittedAt: {
      type: "string",
      format: "date-time",
    },
  },
} as const;

export const INGESTION_JOB_SCHEMA = {
  $id: COMMON_SCHEMA_IDS.ingestionJob,

  type: "object",
  additionalProperties: false,

  required: [
    "ingestionId",
    "status",
    "submittedAt",
  ],

  properties: {
    ingestionId: {
      type: "string",
      minLength:
        INGESTION_ID_MIN_LENGTH,
      maxLength:
        INGESTION_ID_MAX_LENGTH,
      pattern: INGESTION_ID_PATTERN,
    },

    status: {
      type: "string",
      enum: INGESTION_JOB_STATUSES,
    },

    submittedAt: {
      type: "string",
      format: "date-time",
    },

    /*
     * OpenAPI currently permits nullable completedAt. JobManager normally
     * omits it until terminal and emits a string afterward, but preserving
     * null compatibility avoids breaking existing clients.
     */
    completedAt: {
      anyOf: [
        {
          type: "string",
          format: "date-time",
        },
        {
          type: "null",
        },
      ],
    },

    nodeCount: {
      type: "integer",
      minimum: 0,
      maximum: MAX_SAFE_INTEGER,
    },

    edgeCount: {
      type: "integer",
      minimum: 0,
      maximum: MAX_SAFE_INTEGER,
    },

    errors: {
      type: "array",
      minItems: 1,
      maxItems: 50,
      uniqueItems: true,

      items: {
        type: "string",
        minLength: 1,
        maxLength: 512,
      },
    },
  },
} as const;

/**
 * Fastify normalizes incoming header names to lowercase.
 *
 * additionalProperties must remain true because normal requests also contain
 * host, content-type, content-length, user-agent and other HTTP headers.
 * Setting it to false would reject legitimate requests.
 */
export const IDEMPOTENCY_HEADERS_SCHEMA = {
  type: "object",
  additionalProperties: true,

  properties: {
    "idempotency-key": {
      type: "string",
      minLength:
        IDEMPOTENCY_KEY_MIN_LENGTH,
      maxLength:
        IDEMPOTENCY_KEY_MAX_LENGTH,
      pattern:
        IDEMPOTENCY_KEY_PATTERN,
    },
  },
} as const;

export const INGESTION_ID_PARAMS_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "ingestionId",
  ],

  properties: {
    ingestionId: {
      type: "string",
      minLength:
        INGESTION_ID_MIN_LENGTH,
      maxLength:
        INGESTION_ID_MAX_LENGTH,
      pattern: INGESTION_ID_PATTERN,
    },
  },
} as const;

/**
 * Reusable references for route response schemas.
 *
 * Fastify resolves these after registerCommonSchemas() has registered the
 * corresponding shared definitions.
 */
export const ERROR_RESPONSE_REF = {
  $ref:
    `${COMMON_SCHEMA_IDS.errorResponse}#`,
} as const;

export const INGESTION_ACCEPTED_REF = {
  $ref:
    `${COMMON_SCHEMA_IDS.ingestionAccepted}#`,
} as const;

export const INGESTION_JOB_REF = {
  $ref:
    `${COMMON_SCHEMA_IDS.ingestionJob}#`,
} as const;

export const COMMON_SCHEMAS = [
  ERROR_RESPONSE_SCHEMA,
  INGESTION_ACCEPTED_SCHEMA,
  INGESTION_JOB_SCHEMA,
] as const;

/**
 * Registers common response schemas once per Fastify instance.
 *
 * The existence check makes registration safe when buildServer() composes
 * multiple route plugins that share this registration helper.
 */
export function registerCommonSchemas(
  app: FastifyInstance,
): void {
  for (const schema of COMMON_SCHEMAS) {
    if (
      app.getSchema(schema.$id) !==
      undefined
    ) {
      continue;
    }

    app.addSchema(schema);
  }
}
