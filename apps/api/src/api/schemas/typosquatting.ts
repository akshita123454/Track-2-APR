import {
  ERROR_RESPONSE_REF,
  IDEMPOTENCY_HEADERS_SCHEMA,
  INGESTION_ACCEPTED_REF,
  MAX_SAFE_INTEGER,
} from "./common.js";

import {
  LOCKFILE_INGESTION_REQUEST_SCHEMA,
} from "./ingestions.js";

export const TYPOSQUATTING_LIMITS = {
  defaultFindings: 50,
  maxFindings: 200,
  maxReasonLength: 2_000,
} as const;

export interface FindingIdParams {
  readonly findingId: string;
}

export interface FindingListQuery {
  readonly limit?: number;
  readonly cursorDetectedAt?: number;
  readonly cursorFindingId?: number;
}

export interface FindingReviewBody {
  readonly reason: string;
}

export interface RequiredAnalystReviewHeaders {
  readonly "idempotency-key": string;
  readonly authorization?: string;
}

const ID_SCHEMA = {
  type: "integer",
  minimum: 0,
  maximum: MAX_SAFE_INTEGER,
} as const;

const FINDING_STATUS_SCHEMA = {
  type: "string",
  enum: [
    "candidate",
    "suspicious",
    "high-confidence",
    "confirmed",
    "dismissed",
  ],
} as const;

const TRANSFORMATION_SCHEMA = {
  type: "string",
  enum: [
    "adjacent-transposition",
    "insertion",
    "deletion",
    "substitution",
    "separator-variation",
    "repeated-character",
    "scope-impersonation",
    "unicode-confusable",
    "prefix-suffix",
  ],
} as const;

export const FINDING_SUMMARY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "findingId",
    "status",
    "score",
    "scoreMeaning",
    "candidateName",
    "targetName",
    "summary",
    "transformations",
    "reasonCodes",
    "detectedAt",
    "synthetic",
  ],
  properties: {
    findingId: ID_SCHEMA,
    status: FINDING_STATUS_SCHEMA,
    score: { type: "number", minimum: 0, maximum: 100 },
    scoreMeaning: { type: "string", enum: ["heuristic-ranking-not-probability"] },
    candidateName: { type: "string", minLength: 1, maxLength: 214 },
    targetName: { type: "string", minLength: 1, maxLength: 214 },
    summary: { type: "string", minLength: 1, maxLength: 2_000 },
    transformations: {
      type: "array",
      minItems: 1,
      uniqueItems: true,
      items: TRANSFORMATION_SCHEMA,
    },
    reasonCodes: {
      type: "array",
      minItems: 1,
      uniqueItems: true,
      items: { type: "string", minLength: 1, maxLength: 128 },
    },
    detectedAt: ID_SCHEMA,
    decidedAt: ID_SCHEMA,
    decisionReason: { type: "string", minLength: 1, maxLength: 2_000 },
    synthetic: { type: "boolean" },
  },
} as const;

export const FINDING_LIST_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings", "truncated"],
  properties: {
    findings: { type: "array", items: FINDING_SUMMARY_SCHEMA },
    truncated: { type: "boolean" },
    nextCursor: {
      type: "object",
      additionalProperties: false,
      required: ["detectedAt", "findingId"],
      properties: {
        detectedAt: ID_SCHEMA,
        findingId: ID_SCHEMA,
      },
    },
  },
} as const;

const EVIDENCE_SUMMARY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["id", "sourceType", "confidence", "observedAt", "synthetic"],
  properties: {
    id: ID_SCHEMA,
    sourceType: { type: "string", minLength: 1, maxLength: 64 },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    observedAt: ID_SCHEMA,
    synthetic: { type: "boolean" },
  },
} as const;

export const FINDING_DETAIL_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "finding",
    "candidatePackageId",
    "targetPackageId",
    "evidence",
    "exactVersions",
    "versionLookup",
    "exposure",
    "incidentIds",
  ],
  properties: {
    finding: FINDING_SUMMARY_SCHEMA,
    candidatePackageId: ID_SCHEMA,
    targetPackageId: ID_SCHEMA,
    evidence: { type: "array", items: EVIDENCE_SUMMARY_SCHEMA },
    exactVersions: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "version", "synthetic"],
        properties: {
          id: ID_SCHEMA,
          version: { type: "string", minLength: 1, maxLength: 256 },
          synthetic: { type: "boolean" },
        },
      },
    },
    versionLookup: {
      type: "object",
      additionalProperties: false,
      required: ["scannedCount", "truncated"],
      properties: {
        scannedCount: { type: "integer", minimum: 0, maximum: 1_000 },
        truncated: { type: "boolean" },
      },
    },
    exposure: {
      type: "object",
      additionalProperties: false,
      required: ["services", "truncated", "traversalStates", "limits"],
      properties: {
        services: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["serviceId", "serviceLogicalId", "serviceName", "serviceCriticality", "packageVersionIds", "evidenceIds"],
            properties: {
              serviceId: ID_SCHEMA,
              serviceLogicalId: { type: "string", minLength: 1, maxLength: 512 },
              serviceName: { type: "string", minLength: 1, maxLength: 200 },
              serviceCriticality: { type: "string", enum: ["low", "medium", "high", "critical"] },
              packageVersionIds: { type: "array", minItems: 1, items: ID_SCHEMA },
              evidenceIds: { type: "array", minItems: 1, items: ID_SCHEMA },
            },
          },
        },
        truncated: { type: "boolean" },
        traversalStates: { type: "integer", minimum: 0, maximum: 10_000 },
        limits: {
          type: "object",
          additionalProperties: false,
          required: ["maxDepth", "maxServices", "maxTraversalStates", "maxDependentsPerNode"],
          properties: {
            maxDepth: { type: "integer", minimum: 1 },
            maxServices: { type: "integer", minimum: 1 },
            maxTraversalStates: { type: "integer", minimum: 1 },
            maxDependentsPerNode: { type: "integer", minimum: 1 },
          },
        },
      },
    },
    incidentIds: { type: "array", uniqueItems: true, items: ID_SCHEMA },
  },
} as const;

export const FINDING_REVIEW_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["finding", "replayed"],
  properties: {
    finding: FINDING_SUMMARY_SCHEMA,
    incidentId: ID_SCHEMA,
    replayed: { type: "boolean" },
  },
} as const;

export const FINDING_ID_PARAMS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findingId"],
  properties: {
    findingId: {
      type: "string",
      pattern: "^(0|[1-9][0-9]{0,15})$",
      maxLength: 16,
    },
  },
} as const;

export const FINDING_LIST_QUERY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    limit: {
      type: "integer",
      minimum: 1,
      maximum: TYPOSQUATTING_LIMITS.maxFindings,
      default: TYPOSQUATTING_LIMITS.defaultFindings,
    },
    cursorDetectedAt: ID_SCHEMA,
    cursorFindingId: ID_SCHEMA,
  },
} as const;

export const FINDING_REVIEW_BODY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["reason"],
  properties: {
    reason: {
      type: "string",
      minLength: 1,
      maxLength: TYPOSQUATTING_LIMITS.maxReasonLength,
      pattern: "^\\S(?:[\\s\\S]*\\S)?$",
    },
  },
} as const;

export const REQUIRED_ANALYST_REVIEW_HEADERS_SCHEMA = {
  ...IDEMPOTENCY_HEADERS_SCHEMA,
  required: ["idempotency-key"],
  properties: {
    ...IDEMPOTENCY_HEADERS_SCHEMA.properties,
    authorization: {
      type: "string",
      maxLength: 1_024,
    },
  },
} as const;

const STANDARD_RESPONSES = {
  400: ERROR_RESPONSE_REF,
  404: ERROR_RESPONSE_REF,
  409: ERROR_RESPONSE_REF,
  503: ERROR_RESPONSE_REF,
  500: ERROR_RESPONSE_REF,
} as const;

export const CREATE_TYPOSQUATTING_SCAN_ROUTE_SCHEMA = {
  headers: IDEMPOTENCY_HEADERS_SCHEMA,
  body: LOCKFILE_INGESTION_REQUEST_SCHEMA,
  response: {
    202: INGESTION_ACCEPTED_REF,
    ...STANDARD_RESPONSES,
  },
} as const;

export const LIST_TYPOSQUATTING_FINDINGS_ROUTE_SCHEMA = {
  querystring: FINDING_LIST_QUERY_SCHEMA,
  response: {
    200: FINDING_LIST_RESPONSE_SCHEMA,
    ...STANDARD_RESPONSES,
  },
} as const;

export const GET_TYPOSQUATTING_FINDING_ROUTE_SCHEMA = {
  params: FINDING_ID_PARAMS_SCHEMA,
  response: {
    200: FINDING_DETAIL_RESPONSE_SCHEMA,
    ...STANDARD_RESPONSES,
  },
} as const;

export const REVIEW_TYPOSQUATTING_FINDING_ROUTE_SCHEMA = {
  headers: REQUIRED_ANALYST_REVIEW_HEADERS_SCHEMA,
  params: FINDING_ID_PARAMS_SCHEMA,
  body: FINDING_REVIEW_BODY_SCHEMA,
  response: {
    200: FINDING_REVIEW_RESPONSE_SCHEMA,
    401: ERROR_RESPONSE_REF,
    ...STANDARD_RESPONSES,
  },
} as const;
