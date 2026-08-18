import type {
  EvidenceSourceType,
  ServiceCriticality,
} from "../../domain/schema.js";

import type {
  NpmRootRequest,
} from "../../ingest/npm/orchestrator.js";

import {
  ERROR_RESPONSE_REF,
  IDEMPOTENCY_HEADERS_SCHEMA,
  INGESTION_ACCEPTED_REF,
  INGESTION_ID_PARAMS_SCHEMA,
  INGESTION_JOB_REF,
} from "./common.js";

/**
 * This API deliberately does not accept:
 *
 * - registryUrl
 * - registry credentials
 * - registry request concurrency
 * - persistence safety overrides
 *
 * Those values are controlled by trusted server configuration.
 */

export const NPM_INGESTION_LIMITS = {
  maxRoots: 50,
  maxPackages: 1_000,
  maxDepth: 10,
  maxVersionsPerRoot: 100,
  maxPackageNameLength: 214,
  maxVersionLength: 256,
} as const;

export const NPM_INGESTION_DEFAULTS = {
  maxPackages: 100,
  maxDepth: 3,
  includeDevDependencies: false,
} as const;

export const LOCKFILE_INGESTION_LIMITS = {
  maxPackages: 10_000,
  maxServiceLogicalIdLength: 512,
  maxRepositoryLogicalIdLength: 512,
  maxServiceNameLength: 200,
  maxSourceUriLength: 2_048,
  maxCollectorVersionLength: 128,
} as const;

/**
 * This pattern intentionally mirrors the current registry-client validation:
 *
 * - no whitespace;
 * - no backslashes;
 * - no query or fragment characters;
 * - at most one slash;
 * - a slash is allowed only for a scoped package beginning with @.
 */
export const NPM_PACKAGE_NAME_PATTERN =
  "^(?:[^/\\s\\\\?#]+|@[^/\\s\\\\?#]+/[^/\\s\\\\?#]+)$";

export const SERVICE_LOGICAL_ID_PATTERN =
  "^service:[A-Za-z0-9][A-Za-z0-9._:/-]*$";

export const REPOSITORY_LOGICAL_ID_PATTERN =
  "^repo:[A-Za-z0-9][A-Za-z0-9._:/-]*$";

export const SERVICE_CRITICALITIES = [
  "low",
  "medium",
  "high",
  "critical",
] as const satisfies readonly ServiceCriticality[];

export const EVIDENCE_SOURCE_TYPES = [
  "npm-registry",
  "package-manifest",
  "package-lock",
  "git-commit",
  "cyclonedx",
  "spdx",
  "slsa",
  "sigstore",
  "runtime-telemetry",
  "security-advisory",
  "synthetic-fixture",
  "other",
] as const satisfies readonly EvidenceSourceType[];

export const PACKAGE_LOCK_FORMATS = [
  "npm-package-lock-v2",
  "npm-package-lock-v3",
] as const;

export type PackageLockFormat =
  (typeof PACKAGE_LOCK_FORMATS)[number];

export const LOCKFILE_VERSION_BY_FORMAT = {
  "npm-package-lock-v2": 2,
  "npm-package-lock-v3": 3,
} as const satisfies Readonly<
  Record<PackageLockFormat, 2 | 3>
>;

export interface IdempotencyHeaders {
  readonly "idempotency-key"?: string;
}

export interface IngestionIdParams {
  readonly ingestionId: string;
}

export interface NpmIngestionRequestBody {
  readonly roots:
    readonly NpmRootRequest[];

  readonly maxPackages: number;
  readonly maxDepth: number;

  /**
   * Optional on the wire. Fastify applies the false default during schema
   * validation, but workers should still use `?? false` defensively.
   */
  readonly includeDevDependencies?: boolean;
}

export interface ProvenanceInput {
  readonly sourceType:
    EvidenceSourceType;

  readonly sourceUri: string;

  /**
   * RFC 3339 / ISO date-time string.
   *
   * workers.ts must parse this once and reject an invalid millisecond value
   * before calling the collector.
   */
  readonly observedAt: string;

  readonly collectorVersion: string;
  readonly confidence: number;
  readonly synthetic: boolean;
}

/**
 * Lockfile ingestion always produces package-lock evidence.
 *
 * `synthetic: true` may describe a fabricated demonstration lockfile, but the
 * evidence artifact is still structurally a package-lock.
 */
export interface LockfileProvenanceInput
  extends Omit<
    ProvenanceInput,
    "sourceType"
  > {
  readonly sourceType: "package-lock";
}

export interface LockfileIngestionRequestBody {
  readonly serviceLogicalId: string;
  readonly repositoryLogicalId?: string;

  readonly serviceName: string;

  readonly serviceCriticality:
    ServiceCriticality;

  readonly format: PackageLockFormat;

  readonly lockfile:
    Readonly<Record<string, unknown>>;

  readonly provenance:
    LockfileProvenanceInput;
}

/**
 * Individual npm root.
 */
export const NPM_PACKAGE_ROOT_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "name",
  ],

  properties: {
    name: {
      type: "string",
      minLength: 1,
      maxLength:
        NPM_INGESTION_LIMITS
          .maxPackageNameLength,
      pattern: NPM_PACKAGE_NAME_PATTERN,
    },

    versions: {
      type: "array",
      minItems: 1,
      maxItems:
        NPM_INGESTION_LIMITS
          .maxVersionsPerRoot,
      uniqueItems: true,

      items: {
        type: "string",
        minLength: 1,
        maxLength:
          NPM_INGESTION_LIMITS
            .maxVersionLength,

        /*
         * npm versions cannot contain whitespace. Complete semantic-version
         * interpretation remains the collector's responsibility.
         */
        pattern: "^\\S+$",
      },
    },
  },
} as const;

export const NPM_INGESTION_REQUEST_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "roots",
    "maxPackages",
    "maxDepth",
  ],

  properties: {
    roots: {
      type: "array",
      minItems: 1,
      maxItems:
        NPM_INGESTION_LIMITS.maxRoots,
      items: NPM_PACKAGE_ROOT_SCHEMA,
    },

    maxPackages: {
      type: "integer",
      minimum: 1,
      maximum:
        NPM_INGESTION_LIMITS
          .maxPackages,
      default:
        NPM_INGESTION_DEFAULTS
          .maxPackages,
    },

    maxDepth: {
      type: "integer",
      minimum: 0,
      maximum:
        NPM_INGESTION_LIMITS.maxDepth,
      default:
        NPM_INGESTION_DEFAULTS
          .maxDepth,
    },

    includeDevDependencies: {
      type: "boolean",
      default:
        NPM_INGESTION_DEFAULTS
          .includeDevDependencies,
    },
  },
} as const;

export const PROVENANCE_INPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "sourceType",
    "sourceUri",
    "observedAt",
    "collectorVersion",
    "confidence",
    "synthetic",
  ],

  properties: {
    sourceType: {
      type: "string",
      enum: EVIDENCE_SOURCE_TYPES,
    },

    sourceUri: {
      type: "string",
      minLength: 1,
      maxLength:
        LOCKFILE_INGESTION_LIMITS
          .maxSourceUriLength,
      format: "uri",
    },

    observedAt: {
      type: "string",
      minLength: 20,
      maxLength: 64,
      format: "date-time",
    },

    collectorVersion: {
      type: "string",
      minLength: 1,
      maxLength:
        LOCKFILE_INGESTION_LIMITS
          .maxCollectorVersionLength,
      pattern: "^\\S(?:.*\\S)?$",
    },

    confidence: {
      type: "number",
      minimum: 0,
      maximum: 1,
    },

    synthetic: {
      type: "boolean",
    },
  },
} as const;

/**
 * The lockfile endpoint narrows sourceType to package-lock because the current
 * collector always materializes an Evidence node with that source type.
 * Accepting another value and silently rewriting it would violate the
 * evidence-first contract.
 */
export const LOCKFILE_PROVENANCE_SCHEMA = {
  ...PROVENANCE_INPUT_SCHEMA,

  properties: {
    ...PROVENANCE_INPUT_SCHEMA.properties,

    sourceType: {
      type: "string",
      enum: ["package-lock"],
    },
  },
} as const;

/**
 * Structural package-lock validation performed before creating a job.
 *
 * Deep package-lock semantics remain the responsibility of
 * parsePackageLock(). Duplicating the complete parser in JSON Schema would
 * create two inconsistent validation engines.
 */
export const PACKAGE_LOCK_DOCUMENT_SCHEMA = {
  type: "object",
  additionalProperties: true,

  required: [
    "lockfileVersion",
    "packages",
  ],

  properties: {
    name: {
      type: "string",
      minLength: 1,
      maxLength: 214,
    },

    version: {
      type: "string",
      minLength: 1,
      maxLength: 256,
    },

    lockfileVersion: {
      type: "integer",
      enum: [2, 3],
    },

    requires: {
      type: "boolean",
    },

    packages: {
      type: "object",

      /*
       * package-lock v2/v3 must contain the root package entry under "".
       */
      required: [""],

      /*
       * Root entry plus at most 10,000 non-root packages.
       */
      maxProperties:
        LOCKFILE_INGESTION_LIMITS
          .maxPackages + 1,

      additionalProperties: {
        type: "object",
        additionalProperties: true,
      },
    },

    /*
     * npm may retain this compatibility tree alongside packages.
     * The parser uses packages as the authoritative v2/v3 structure.
     */
    dependencies: {
      type: "object",
      additionalProperties: true,
    },
  },
} as const;

export const LOCKFILE_INGESTION_REQUEST_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "serviceLogicalId",
    "serviceName",
    "serviceCriticality",
    "format",
    "lockfile",
    "provenance",
  ],

  properties: {
    serviceLogicalId: {
      type: "string",
      minLength:
        "service:x".length,
      maxLength:
        LOCKFILE_INGESTION_LIMITS
          .maxServiceLogicalIdLength,
      pattern:
        SERVICE_LOGICAL_ID_PATTERN,
    },

    repositoryLogicalId: {
      type: "string",
      minLength:
        "repo:x".length,
      maxLength:
        LOCKFILE_INGESTION_LIMITS
          .maxRepositoryLogicalIdLength,
      pattern:
        REPOSITORY_LOGICAL_ID_PATTERN,
    },

    serviceName: {
      type: "string",
      minLength: 1,
      maxLength:
        LOCKFILE_INGESTION_LIMITS
          .maxServiceNameLength,

      /*
       * Reject leading/trailing whitespace while allowing internal spaces.
       */
      pattern: "^\\S(?:.*\\S)?$",
    },

    serviceCriticality: {
      type: "string",
      enum: SERVICE_CRITICALITIES,
    },

    format: {
      type: "string",
      enum: PACKAGE_LOCK_FORMATS,
    },

    lockfile:
      PACKAGE_LOCK_DOCUMENT_SCHEMA,

    provenance:
      LOCKFILE_PROVENANCE_SCHEMA,
  },

  /*
   * Fail before queueing when the declared API format disagrees with the
   * lockfile's actual lockfileVersion.
   */
    oneOf: [
    {
      properties: {
        format: {
          const:
            "npm-package-lock-v2",
        },

        lockfile: {
          type: "object",

          required: [
            "lockfileVersion",
          ],

          properties: {
            lockfileVersion: {
              const: 2,
            },
          },
        },
      },
    },
    {
      properties: {
        format: {
          const:
            "npm-package-lock-v3",
        },

        lockfile: {
          type: "object",

          required: [
            "lockfileVersion",
          ],

          properties: {
            lockfileVersion: {
              const: 3,
            },
          },
        },
      },
    },
  ],

} as const;

/**
 * POST /ingestions/npm
 */
export const CREATE_NPM_INGESTION_ROUTE_SCHEMA = {
  headers:
    IDEMPOTENCY_HEADERS_SCHEMA,

  body:
    NPM_INGESTION_REQUEST_SCHEMA,

  response: {
    202: INGESTION_ACCEPTED_REF,

    400: ERROR_RESPONSE_REF,
    409: ERROR_RESPONSE_REF,

    /*
     * Used when Fastify's configured body limit is exceeded.
     */
    413: ERROR_RESPONSE_REF,

    /*
     * Preserved from the OpenAPI contract. Most registry failures occur in
     * the asynchronous worker and therefore appear in job status instead.
     */
    502: ERROR_RESPONSE_REF,

    /*
     * JobManager capacity or server shutdown.
     */
    503: ERROR_RESPONSE_REF,
  },
} as const;

/**
 * POST /ingestions/lockfile
 */
export const CREATE_LOCKFILE_INGESTION_ROUTE_SCHEMA = {
  headers:
    IDEMPOTENCY_HEADERS_SCHEMA,

  body:
    LOCKFILE_INGESTION_REQUEST_SCHEMA,

  response: {
    202: INGESTION_ACCEPTED_REF,
    400: ERROR_RESPONSE_REF,
    409: ERROR_RESPONSE_REF,
    413: ERROR_RESPONSE_REF,
    503: ERROR_RESPONSE_REF,
  },
} as const;

/**
 * GET /ingestions/:ingestionId
 */
export const GET_INGESTION_ROUTE_SCHEMA = {
  params:
    INGESTION_ID_PARAMS_SCHEMA,

  response: {
    200: INGESTION_JOB_REF,
    400: ERROR_RESPONSE_REF,
    404: ERROR_RESPONSE_REF,
    503: ERROR_RESPONSE_REF,
  },
} as const;
