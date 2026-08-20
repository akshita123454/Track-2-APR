import type {
  ProvenanceInput,
} from "./ingestions.js";

import {
  NPM_INGESTION_LIMITS,
  NPM_PACKAGE_NAME_PATTERN,
  PROVENANCE_INPUT_SCHEMA,
} from "./ingestions.js";

import {
  ERROR_RESPONSE_REF,
  IDEMPOTENCY_HEADERS_SCHEMA,
  MAX_SAFE_INTEGER,
} from "./common.js";

/**
 * Incident API limits are deliberately bounded because one incident may
 * produce:
 *
 * - one Incident node;
 * - one Evidence node;
 * - multiple AFFECTS relationships;
 * - a blast-radius traversal for every resolved affected version.
 *
 * These limits protect both HydraDB persistence and later graph analysis.
 */
export const INCIDENT_LIMITS = {
  maxTitleLength: 300,

  maxAffectedReleases: 500,

  maxExactVersionsPerRelease: 100,

  /**
   * Cross-release total. JSON Schema cannot conveniently enforce this sum,
   * so the incident service must enforce it before persistence.
   */
  maxTotalExactVersions: 5_000,

  maxAffectedRangeLength: 512,

  maxVersionLength:
    NPM_INGESTION_LIMITS
      .maxVersionLength,
} as const;

export const INCIDENT_STATUSES = [
  "draft",
  "active",
] as const;

export type IncidentCreatedStatus =
  (typeof INCIDENT_STATUSES)[number];

/**
 * One package release declaration supplied by incident evidence.
 *
 * At least one of affectedRange or exactVersions is required. Supplying both
 * is valid: an advisory may declare a broad range while also identifying
 * specific versions confirmed by direct evidence.
 */
export interface AffectedReleaseInput {
  readonly packageName: string;

  readonly affectedRange?: string;

  readonly exactVersions?:
    readonly string[];
}

/**
 * POST /incidents request body.
 *
 * Creating an incident records affected package versions. It must not
 * automatically claim that dependent services were compromised, exposed or
 * executed. Those conclusions belong to the evidence-aware analysis layer.
 */
export interface IncidentCreateRequestBody {
  readonly title: string;

  /**
   * RFC 3339 / ISO date-time value describing when the suspected compromise
   * interval began.
   */
  readonly intervalStart: string;

  /**
   * Null or omitted means the compromise interval remains open.
   */
  readonly intervalEnd?:
    | string
    | null;

  readonly affectedReleases:
    readonly AffectedReleaseInput[];

  readonly provenance:
    ProvenanceInput;
}

export interface IncidentIdempotencyHeaders {
  readonly "idempotency-key"?: string;
}

/**
 * Exact successful response currently declared by contracts/openapi.yaml.
 *
 * Detailed blast-radius analysis should be retrieved through a separate
 * analysis endpoint rather than being hidden inside incident creation.
 */
export interface IncidentCreatedResponse {
  readonly incidentId: number;
  readonly logicalId: string;
  readonly status:
    IncidentCreatedStatus;
}

/**
 * Semantically valid npm package name.
 *
 * This intentionally uses the same pattern and length as npm ingestion so
 * the two API surfaces cannot disagree about package identity.
 */
export const AFFECTED_PACKAGE_NAME_SCHEMA = {
  type: "string",
  minLength: 1,
  maxLength:
    NPM_INGESTION_LIMITS
      .maxPackageNameLength,
  pattern:
    NPM_PACKAGE_NAME_PATTERN,
} as const;

/**
 * This is structural range validation only.
 *
 * Complete npm-semver interpretation belongs in the incident service. The
 * service must never construct a Cypher query by interpolating this value.
 */
export const AFFECTED_RANGE_SCHEMA = {
  type: "string",
  minLength: 1,
  maxLength:
    INCIDENT_LIMITS
      .maxAffectedRangeLength,

  /*
   * Reject surrounding whitespace, newlines and control-character payloads.
   * Internal spaces remain valid for ranges such as ">=1.2.4 <1.2.5".
   */
  pattern:
    "^\\S(?:[^\\r\\n]*\\S)?$",
} as const;

export const AFFECTED_EXACT_VERSION_SCHEMA = {
  type: "string",
  minLength: 1,
  maxLength:
    INCIDENT_LIMITS
      .maxVersionLength,

  /*
   * Full semantic-version validation happens in the incident service.
   * At the API boundary, versions must be nonempty single tokens.
   */
  pattern: "^\\S+$",
} as const;

export const AFFECTED_RELEASE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "packageName",
  ],

  properties: {
    packageName:
      AFFECTED_PACKAGE_NAME_SCHEMA,

    affectedRange:
      AFFECTED_RANGE_SCHEMA,

    exactVersions: {
      type: "array",
      minItems: 1,
      maxItems:
        INCIDENT_LIMITS
          .maxExactVersionsPerRelease,
      uniqueItems: true,

      items:
        AFFECTED_EXACT_VERSION_SCHEMA,
    },
  },

  /*
   * At least one version-selection mechanism is required.
   *
   * anyOf is intentional rather than oneOf because supplying both a range
   * and exact confirmed versions is valid evidence.
   */
  anyOf: [
    {
      required: [
        "affectedRange",
      ],
    },
    {
      required: [
        "exactVersions",
      ],
    },
  ],
} as const;

/**
 * Reuse the exact provenance contract accepted by ingestion.
 *
 * Do not narrow this only to "security-advisory": future incidents may be
 * supported by Sigstore, SLSA, runtime telemetry, git evidence or a clearly
 * labelled synthetic fixture. The Evidence node retains the exact sourceType.
 */
export const INCIDENT_PROVENANCE_INPUT_SCHEMA = {
  ...PROVENANCE_INPUT_SCHEMA,

  properties: {
    ...PROVENANCE_INPUT_SCHEMA
      .properties,
  },
} as const;

export const INCIDENT_CREATE_REQUEST_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "title",
    "intervalStart",
    "affectedReleases",
    "provenance",
  ],

  properties: {
    title: {
      type: "string",
      minLength: 1,
      maxLength:
        INCIDENT_LIMITS
          .maxTitleLength,

      /*
       * Reject leading and trailing whitespace while allowing internal spaces.
       */
      pattern:
        "^\\S(?:[\\s\\S]*\\S)?$",
    },

    intervalStart: {
      type: "string",
      minLength: 20,
      maxLength: 64,
      format: "date-time",
    },

    intervalEnd: {
      anyOf: [
        {
          type: "string",
          minLength: 20,
          maxLength: 64,
          format: "date-time",
        },
        {
          type: "null",
        },
      ],
    },

    affectedReleases: {
      type: "array",
      minItems: 1,
      maxItems:
        INCIDENT_LIMITS
          .maxAffectedReleases,

      /*
       * This rejects byte-for-byte duplicate declarations. The incident
       * service must additionally reject or merge multiple declarations for
       * the same normalized package name.
       */
      uniqueItems: true,

      items:
        AFFECTED_RELEASE_SCHEMA,
    },

    provenance:
      INCIDENT_PROVENANCE_INPUT_SCHEMA,
  },
} as const;

export const INCIDENT_CREATED_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "incidentId",
    "logicalId",
    "status",
  ],

  properties: {
    incidentId: {
      type: "integer",
      minimum: 0,
      maximum:
        MAX_SAFE_INTEGER,
    },

    logicalId: {
      type: "string",
      minLength:
        "incident:x".length,
      maxLength: 1_024,
      pattern:
        "^incident:[^\\s]+$",
    },

    status: {
      type: "string",
      enum:
        INCIDENT_STATUSES,
    },
  },
} as const;

/**
 * POST /incidents
 *
 * Incident creation remains synchronous because the existing OpenAPI contract
 * returns 201 and because JobManager currently represents only npm and
 * lockfile ingestion jobs.
 */
export const CREATE_INCIDENT_ROUTE_SCHEMA = {
  headers:
    IDEMPOTENCY_HEADERS_SCHEMA,

  body:
    INCIDENT_CREATE_REQUEST_SCHEMA,

  response: {
    201:
      INCIDENT_CREATED_RESPONSE_SCHEMA,

    /*
     * Includes JSON-Schema validation, invalid temporal intervals, malformed
     * semver ranges and unsupported affected-version declarations.
     */
    400:
      ERROR_RESPONSE_REF,

    /*
     * Used for idempotency conflicts, deterministic identity conflicts, or an
     * incident identity that already belongs to different evidence.
     */
    409:
      ERROR_RESPONSE_REF,

    /*
     * Fastify's configured request-body limit.
     */
    413:
      ERROR_RESPONSE_REF,

    /*
     * HydraDB or the incident persistence boundary is temporarily
     * unavailable.
     */
    503:
      ERROR_RESPONSE_REF,

    /*
     * Unknown internal failures remain redacted by the centralized API error
     * handler.
     */
    500:
      ERROR_RESPONSE_REF,
  },
} as const;

/**
 * Incident index limits.
 *
 * The list endpoint exists so an analyst never has to guess a numeric
 * incident ID. It stays bounded because the underlying read counts canonical
 * AFFECTS targets per returned incident.
 */
export const INCIDENT_LIST_LIMITS = {
  defaultLimit: 50,
  maxLimit: 200,
} as const;

export const INCIDENT_LIST_STATUSES = [
  "draft",
  "active",
  "contained",
  "closed",
] as const;

export interface IncidentListQuerystring {
  readonly limit?: number;

  /**
   * Both cursor components are required together. They are validated as a
   * pair by the route because JSON Schema cannot express the dependency
   * cleanly across query parameters.
   */
  readonly cursorObservedAt?: number;
  readonly cursorId?: number;
}

export interface IncidentListItemResponse {
  readonly incidentId: number;
  readonly logicalId: string;
  readonly title: string;
  readonly status:
    (typeof INCIDENT_LIST_STATUSES)[number];
  readonly intervalStart: string;
  readonly intervalEnd: string | null;
  readonly affectedVersionCount: number;
  readonly synthetic: boolean;
  readonly observedAt: string;
}

export interface IncidentListResponse {
  readonly incidents:
    readonly IncidentListItemResponse[];
  readonly truncated: boolean;

  readonly nextCursor:
    | {
        readonly cursorObservedAt: number;
        readonly cursorId: number;
      }
    | null;
}

const INCIDENT_LIST_ITEM_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "incidentId",
    "logicalId",
    "title",
    "status",
    "intervalStart",
    "intervalEnd",
    "affectedVersionCount",
    "synthetic",
    "observedAt",
  ],

  properties: {
    incidentId: {
      type: "integer",
      minimum: 0,
      maximum: MAX_SAFE_INTEGER,
    },

    logicalId: {
      type: "string",
      minLength: "incident:x".length,
      maxLength: 1_024,
      pattern: "^incident:[^\\s]+$",
    },

    title: {
      type: "string",
      minLength: 1,
      maxLength:
        INCIDENT_LIMITS.maxTitleLength,
    },

    status: {
      type: "string",
      enum: INCIDENT_LIST_STATUSES,
    },

    intervalStart: {
      type: "string",
      format: "date-time",
    },

    intervalEnd: {
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

    affectedVersionCount: {
      type: "integer",
      minimum: 0,
      maximum: MAX_SAFE_INTEGER,
    },

    synthetic: {
      type: "boolean",
    },

    observedAt: {
      type: "string",
      format: "date-time",
    },
  },
} as const;

export const INCIDENT_LIST_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "incidents",
    "truncated",
    "nextCursor",
  ],

  properties: {
    incidents: {
      type: "array",
      maxItems:
        INCIDENT_LIST_LIMITS.maxLimit,
      items: INCIDENT_LIST_ITEM_SCHEMA,
    },

    truncated: {
      type: "boolean",
    },

    nextCursor: {
      anyOf: [
        {
          type: "object",
          additionalProperties: false,

          required: [
            "cursorObservedAt",
            "cursorId",
          ],

          properties: {
            cursorObservedAt: {
              type: "integer",
              minimum: 0,
              maximum: MAX_SAFE_INTEGER,
            },

            cursorId: {
              type: "integer",
              minimum: 0,
              maximum: MAX_SAFE_INTEGER,
            },
          },
        },
        {
          type: "null",
        },
      ],
    },
  },
} as const;

export const INCIDENT_LIST_QUERYSTRING_SCHEMA = {
  type: "object",
  additionalProperties: false,

  properties: {
    limit: {
      type: "integer",
      minimum: 1,
      maximum:
        INCIDENT_LIST_LIMITS.maxLimit,
      default:
        INCIDENT_LIST_LIMITS.defaultLimit,
    },

    cursorObservedAt: {
      type: "integer",
      minimum: 0,
      maximum: MAX_SAFE_INTEGER,
    },

    cursorId: {
      type: "integer",
      minimum: 0,
      maximum: MAX_SAFE_INTEGER,
    },
  },
} as const;

/**
 * GET /incidents
 *
 * Returns a bounded, newest-first incident index. This is a read-only
 * projection: it never asserts exposure, and affectedVersionCount counts
 * canonical AFFECTS targets only.
 */
export const LIST_INCIDENTS_ROUTE_SCHEMA = {
  querystring:
    INCIDENT_LIST_QUERYSTRING_SCHEMA,

  response: {
    200:
      INCIDENT_LIST_RESPONSE_SCHEMA,

    400: ERROR_RESPONSE_REF,
    503: ERROR_RESPONSE_REF,
    500: ERROR_RESPONSE_REF,
  },
} as const;
