import type {
  FastifyInstance,
} from "fastify";

import type {
  LiveBlastRadiusResult,
} from "../../analysis/live-analysis.js";

import {
  ERROR_RESPONSE_REF,
  MAX_SAFE_INTEGER,
} from "./common.js";

export const ANALYSIS_ROUTE_LIMITS = {
  maxAffectedVersions: 5_000,
  maxDepth: 64,
  maxServices: 1_000,
  maxPathsPerService: 100,
  maxTotalPaths: 10_000,
  maxTraversalStates: 50_000,
  maxDependentsPerNode: 5_000,
  maxWarnings: 1_000,
  maxEvidenceIds: 10_000,
  maxEvidenceReadChunkSize: 2_000,
} as const;

export const ANALYSIS_SCHEMA_IDS = {
  liveBlastRadiusResponse:
    "HydraGuardLiveBlastRadiusResponse",
} as const;

export interface IncidentAnalysisParams {
  readonly incidentId: number;
}

export interface IncidentAnalysisQuerystring {
  readonly maxAffectedVersions?: number;
  readonly maxDepth?: number;
  readonly maxServices?: number;
  readonly maxPathsPerService?: number;
  readonly maxTotalPaths?: number;
  readonly maxTraversalStates?: number;
  readonly maxDependentsPerNode?: number;
  readonly maxWarnings?: number;

  readonly highConfidenceThreshold?: number;
  readonly maxEvidenceIds?: number;
  readonly evidenceReadChunkSize?: number;
}

export type LiveBlastRadiusResponse =
  LiveBlastRadiusResult;

const NODE_ID_SCHEMA = {
  type: "integer",
  minimum: 0,
  maximum: MAX_SAFE_INTEGER,
} as const;

const NONNEGATIVE_COUNT_SCHEMA = {
  type: "integer",
  minimum: 0,
  maximum: MAX_SAFE_INTEGER,
} as const;

const TIMESTAMP_SCHEMA = {
  type: "integer",
  minimum: 0,
  maximum: MAX_SAFE_INTEGER,
} as const;

const EVIDENCE_IDS_SCHEMA = {
  type: "array",
  maxItems:
    ANALYSIS_ROUTE_LIMITS.maxEvidenceIds,
  uniqueItems: true,
  items: NODE_ID_SCHEMA,
} as const;

const PACKAGE_VERSION_NODE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "id",
    "logicalId",
    "kind",
    "evidenceIds",
    "synthetic",
    "observedAt",
    "ecosystem",
    "packageName",
    "version",
  ],

  properties: {
    id: NODE_ID_SCHEMA,

    logicalId: {
      type: "string",
      minLength: 1,
      maxLength: 4_096,
    },

    kind: {
      type: "string",
      const: "PackageVersion",
    },

    evidenceIds:
      EVIDENCE_IDS_SCHEMA,

    synthetic: {
      type: "boolean",
    },

    observedAt:
      TIMESTAMP_SCHEMA,

    ecosystem: {
      type: "string",
      const: "npm",
    },

    packageName: {
      type: "string",
      minLength: 1,
      maxLength: 512,
    },

    version: {
      type: "string",
      minLength: 1,
      maxLength: 256,
    },

    publishedAt:
      TIMESTAMP_SCHEMA,
  },
} as const;

const SERVICE_NODE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "id",
    "logicalId",
    "kind",
    "evidenceIds",
    "synthetic",
    "observedAt",
    "name",
    "criticality",
  ],

  properties: {
    id: NODE_ID_SCHEMA,

    logicalId: {
      type: "string",
      minLength: 1,
      maxLength: 4_096,
    },

    kind: {
      type: "string",
      const: "Service",
    },

    evidenceIds:
      EVIDENCE_IDS_SCHEMA,

    synthetic: {
      type: "boolean",
    },

    observedAt:
      TIMESTAMP_SCHEMA,

    name: {
      type: "string",
      minLength: 1,
      maxLength: 1_024,
    },

    criticality: {
      type: "string",
      enum: [
        "low",
        "medium",
        "high",
        "critical",
      ],
    },

    internetExposed: {
      type: "boolean",
    },

    dataSensitivity: {
      type: "string",
      enum: [
        "low",
        "medium",
        "high",
        "critical",
      ],
    },
  },
} as const;

/**
 * DEPENDS_ON permits only PackageVersion or Service sources and always
 * targets PackageVersion. Keeping this union narrow prevents unrelated
 * graph entities such as Credentials from entering this response.
 */
const BLAST_RADIUS_NODE_SCHEMA = {
  oneOf: [
    PACKAGE_VERSION_NODE_SCHEMA,
    SERVICE_NODE_SCHEMA,
  ],
} as const;

const DEPENDENCY_EDGE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "id",
    "logicalId",
    "sourceId",
    "targetId",
    "kind",
    "observedAt",
    "derived",
    "identityDiscriminator",
    "evidenceIds",
    "dependencyType",
  ],

  properties: {
    id: NODE_ID_SCHEMA,

    logicalId: {
      type: "string",
      minLength: 1,
      maxLength: 16_384,
    },

    sourceId: NODE_ID_SCHEMA,
    targetId: NODE_ID_SCHEMA,

    kind: {
      type: "string",
      const: "DEPENDS_ON",
    },

    observedAt:
      TIMESTAMP_SCHEMA,

    derived: {
      type: "boolean",
      const: false,
    },

    identityDiscriminator: {
      type: "string",
      minLength: 1,
      maxLength: 4_096,
    },

    evidenceIds:
      EVIDENCE_IDS_SCHEMA,

    dependencyType: {
      type: "string",
      enum: [
        "production",
        "development",
        "optional",
        "peer",
      ],
    },

    declaredRange: {
      type: "string",
      maxLength: 1_024,
    },

    lockfilePath: {
      type: "string",
      maxLength: 4_096,
    },

    integrity: {
      type: "string",
      maxLength: 4_096,
    },
  },
} as const;

const BLAST_RADIUS_PATH_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "pathKey",
    "affectedVersionId",
    "serviceId",
    "nodes",
    "canonicalEdges",
    "depth",
  ],

  properties: {
    pathKey: {
      type: "string",
      minLength: 1,
      maxLength: 32_768,
    },

    affectedVersionId:
      NODE_ID_SCHEMA,

    serviceId:
      NODE_ID_SCHEMA,

    nodes: {
      type: "array",
      minItems: 2,
      maxItems:
        ANALYSIS_ROUTE_LIMITS.maxDepth + 1,
      items:
        BLAST_RADIUS_NODE_SCHEMA,
    },

    canonicalEdges: {
      type: "array",
      minItems: 1,
      maxItems:
        ANALYSIS_ROUTE_LIMITS.maxDepth,
      items:
        DEPENDENCY_EDGE_SCHEMA,
    },

    depth: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxDepth,
    },
  },
} as const;

const SERVICE_CANDIDATE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "service",
    "minimumDepth",
    "paths",
  ],

  properties: {
    service:
      SERVICE_NODE_SCHEMA,

    minimumDepth: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxDepth,
    },

    paths: {
      type: "array",
      minItems: 1,
      maxItems:
        ANALYSIS_ROUTE_LIMITS
          .maxPathsPerService,
      items:
        BLAST_RADIUS_PATH_SCHEMA,
    },
  },
} as const;

const ANALYSIS_LIMITS_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "maxDepth",
    "maxServices",
    "maxPathsPerService",
    "maxTotalPaths",
    "maxTraversalStates",
    "maxDependentsPerNode",
    "maxWarnings",
  ],

  properties: {
    maxDepth: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxDepth,
    },

    maxServices: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxServices,
    },

    maxPathsPerService: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS
          .maxPathsPerService,
    },

    maxTotalPaths: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxTotalPaths,
    },

    maxTraversalStates: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS
          .maxTraversalStates,
    },

    maxDependentsPerNode: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS
          .maxDependentsPerNode,
    },

    maxWarnings: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxWarnings,
    },
  },
} as const;

const ANALYSIS_WARNING_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "code",
    "message",
  ],

  properties: {
    code: {
      type: "string",
      enum: [
        "cycle-skipped",
        "depth-limit-reached",
        "service-limit-reached",
        "path-limit-reached",
        "paths-per-service-limit-reached",
        "traversal-state-limit-reached",
        "dependents-per-node-limit-reached",
        "warning-limit-reached",
        "missing-node",
        "invalid-canonical-hop",
        "unsupported-root-node",
      ],
    },

    message: {
      type: "string",
      minLength: 1,
      maxLength: 2_048,
    },

    nodeId:
      NODE_ID_SCHEMA,

    pathNodeIds: {
      type: "array",
      maxItems:
        ANALYSIS_ROUTE_LIMITS.maxDepth + 1,
      items:
        NODE_ID_SCHEMA,
    },
  },
} as const;

const EVIDENCE_FUNNEL_STAGE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "id",
    "label",
    "description",
    "pathCount",
    "serviceCount",
    "pathPercentage",
    "servicePercentage",
  ],

  properties: {
    id: {
      type: "string",
      enum: [
        "structural-candidate",
        "evidence-verified",
        "high-confidence-evidence",
      ],
    },

    label: {
      type: "string",
      minLength: 1,
      maxLength: 256,
    },

    description: {
      type: "string",
      minLength: 1,
      maxLength: 2_048,
    },

    pathCount:
      NONNEGATIVE_COUNT_SCHEMA,

    serviceCount:
      NONNEGATIVE_COUNT_SCHEMA,

    pathPercentage: {
      type: "number",
      minimum: 0,
      maximum: 100,
    },

    servicePercentage: {
      type: "number",
      minimum: 0,
      maximum: 100,
    },
  },
} as const;

const EVIDENCE_SOURCE_TYPES = [
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
] as const;
const LIVE_EVIDENCE_CATALOG_ENTRY_SCHEMA = {
  type: "object",

  /*
   * This is the critical redaction boundary. sourceUri, detail,
   * collectorVersion and any future internal fields are excluded.
   */
  additionalProperties: false,

  required: [
    "id",
    "sourceType",
    "confidence",
    "observedAt",
    "synthetic",
    "incidentLinked",
  ],

  properties: {
    id:
      NODE_ID_SCHEMA,

    sourceType: {
      type: "string",
      enum:
        EVIDENCE_SOURCE_TYPES,
    },

    confidence: {
      type: "number",
      minimum: 0,
      maximum: 1,
    },

    observedAt:
      TIMESTAMP_SCHEMA,

    synthetic: {
      type: "boolean",
    },

    incidentLinked: {
      type: "boolean",
    },
  },
} as const;

const EVIDENCE_SOURCE_SUMMARY_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "sourceType",
    "evidenceCount",
    "averageConfidence",
  ],

  properties: {
    sourceType: {
      type: "string",
      enum:
        EVIDENCE_SOURCE_TYPES,
    },

    evidenceCount:
      NONNEGATIVE_COUNT_SCHEMA,

    averageConfidence: {
      type: "number",
      minimum: 0,
      maximum: 1,
    },
  },
} as const;

const EVIDENCE_LOOKUP_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "referencedEvidenceCount",
    "requestedEvidenceCount",
    "resolvedEvidenceCount",
    "missingEvidenceCount",
    "missingEvidenceIds",
    "omittedEvidenceCount",
    "complete",
  ],

  properties: {
    referencedEvidenceCount:
      NONNEGATIVE_COUNT_SCHEMA,

    requestedEvidenceCount:
      NONNEGATIVE_COUNT_SCHEMA,

    resolvedEvidenceCount:
      NONNEGATIVE_COUNT_SCHEMA,

    missingEvidenceCount:
      NONNEGATIVE_COUNT_SCHEMA,

    missingEvidenceIds: {
      type: "array",
      maxItems:
        ANALYSIS_ROUTE_LIMITS.maxEvidenceIds,
      uniqueItems: true,
      items:
        NODE_ID_SCHEMA,
    },

    omittedEvidenceCount:
      NONNEGATIVE_COUNT_SCHEMA,

    complete: {
      type: "boolean",
    },
  },
} as const;

const EVIDENCE_FUNNEL_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "affectedVersionCount",
    "candidatePathCount",
    "candidateServiceCount",
    "highConfidenceThreshold",
    "stages",
    "evidenceLookup",
    "sources",
    "completeForReturnedCandidates",
    "completeForIncident",
    "limitations",
  ],

  properties: {
    affectedVersionCount:
      NONNEGATIVE_COUNT_SCHEMA,

    candidatePathCount:
      NONNEGATIVE_COUNT_SCHEMA,

    candidateServiceCount:
      NONNEGATIVE_COUNT_SCHEMA,

    highConfidenceThreshold: {
      type: "number",
      minimum: 0,
      maximum: 1,
    },

    stages: {
      type: "array",
      minItems: 3,
      maxItems: 3,
      items:
        EVIDENCE_FUNNEL_STAGE_SCHEMA,
    },

    evidenceLookup:
      EVIDENCE_LOOKUP_SCHEMA,

    sources: {
      type: "array",
      maxItems:
        EVIDENCE_SOURCE_TYPES.length,
      items:
        EVIDENCE_SOURCE_SUMMARY_SCHEMA,
    },

    completeForReturnedCandidates: {
      type: "boolean",
    },

    completeForIncident: {
      type: "boolean",
    },

    limitations: {
      type: "array",
      minItems: 1,
      maxItems: 100,
      uniqueItems: true,

      items: {
        type: "string",
        minLength: 1,
        maxLength: 2_048,
      },
    },
  },
} as const;

const HYDRA_READ_TELEMETRY_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "readEpoch",
    "readEpochMs",
    "queryCount",
    "rowsRead",
    "startedAt",
    "completedAt",
    "latencyMs",
    "consistencyModel",
    "engine",
  ],

  properties: {
    readEpoch: {
      type: "string",
      format: "date-time",
    },

    readEpochMs:
      TIMESTAMP_SCHEMA,

    queryCount:
      NONNEGATIVE_COUNT_SCHEMA,

    rowsRead:
      NONNEGATIVE_COUNT_SCHEMA,

    startedAt: {
      type: "string",
      format: "date-time",
    },

    completedAt: {
      type: "string",
      format: "date-time",
    },

    latencyMs:
      NONNEGATIVE_COUNT_SCHEMA,

    consistencyModel: {
      type: "string",
      const:
        "bounded-multi-statement-read",
    },

    engine: {
      type: "string",
      const: "HydraDB",
    },
  },
} as const;
const LIVE_INCIDENT_SUMMARY_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "id",
    "title",
    "status",
    "intervalStart",
    "intervalEnd",
    "synthetic",
  ],

  properties: {
    id:
      NODE_ID_SCHEMA,

    title: {
      type: "string",
      minLength: 1,
      maxLength: 1_024,
    },

    status: {
      type: "string",
      enum: [
        "draft",
        "active",
        "contained",
        "closed",
      ],
    },

    intervalStart:
      TIMESTAMP_SCHEMA,

    intervalEnd: {
      anyOf: [
        TIMESTAMP_SCHEMA,
        {
          type: "null",
        },
      ],
    },

    synthetic: {
      type: "boolean",
    },
  },
} as const;
const LIVE_AFFECTED_VERSION_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "id",
    "packageName",
    "version",
    "synthetic",
  ],

  properties: {
    id:
      NODE_ID_SCHEMA,

    packageName: {
      type: "string",
      minLength: 1,
      maxLength: 512,
    },

    version: {
      type: "string",
      minLength: 1,
      maxLength: 256,
    },

    publishedAt:
      TIMESTAMP_SCHEMA,

    synthetic: {
      type: "boolean",
    },
  },
} as const;

export const LIVE_BLAST_RADIUS_RESPONSE_SCHEMA = {
  $id:
    ANALYSIS_SCHEMA_IDS
      .liveBlastRadiusResponse,

  type: "object",
  additionalProperties: false,

  required: [
    "incidentId",
    "affectedVersionLookup",
    "affectedVersionIds",
    "services",
    "totalPathCount",
    "truncated",
    "limits",
    "warnings",
    "evidenceFunnel",
    "hydraRead",
    "incident",
    "affectedVersions",
    "evidenceCatalog",
  ],

  properties: {
    incidentId:
      NODE_ID_SCHEMA,
    incident:
        LIVE_INCIDENT_SUMMARY_SCHEMA,

        affectedVersions: {
        type: "array",
        maxItems:
            ANALYSIS_ROUTE_LIMITS
            .maxAffectedVersions,
        items:
            LIVE_AFFECTED_VERSION_SCHEMA,
        },

        evidenceCatalog: {
        type: "array",
        maxItems:
            ANALYSIS_ROUTE_LIMITS
            .maxEvidenceIds,
        items:
            LIVE_EVIDENCE_CATALOG_ENTRY_SCHEMA,
        },

    affectedVersionLookup: {
      type: "object",
      additionalProperties: false,

      required: [
        "limit",
        "returnedCount",
        "truncated",
      ],

      properties: {
        limit: {
          type: "integer",
          minimum: 1,
          maximum:
            ANALYSIS_ROUTE_LIMITS
              .maxAffectedVersions,
        },

        returnedCount:
          NONNEGATIVE_COUNT_SCHEMA,

        truncated: {
          type: "boolean",
        },
      },
    },

    affectedVersionIds: {
      type: "array",
      maxItems:
        ANALYSIS_ROUTE_LIMITS
          .maxAffectedVersions,
      uniqueItems: true,
      items:
        NODE_ID_SCHEMA,
    },

    services: {
      type: "array",
      maxItems:
        ANALYSIS_ROUTE_LIMITS.maxServices,
      items:
        SERVICE_CANDIDATE_SCHEMA,
    },

    totalPathCount:
      NONNEGATIVE_COUNT_SCHEMA,

    truncated: {
      type: "boolean",
    },

    limits:
      ANALYSIS_LIMITS_SCHEMA,

    warnings: {
      type: "array",
      maxItems:
        ANALYSIS_ROUTE_LIMITS.maxWarnings,
      items:
        ANALYSIS_WARNING_SCHEMA,
    },

    evidenceFunnel:
      EVIDENCE_FUNNEL_SCHEMA,

    hydraRead:
      HYDRA_READ_TELEMETRY_SCHEMA,
  },
} as const;

export const LIVE_BLAST_RADIUS_RESPONSE_REF = {
  $ref:
    `${ANALYSIS_SCHEMA_IDS.liveBlastRadiusResponse}#`,
} as const;

export const INCIDENT_ANALYSIS_PARAMS_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "incidentId",
  ],

  properties: {
    incidentId:
      NODE_ID_SCHEMA,
  },
} as const;

export const INCIDENT_ANALYSIS_QUERY_SCHEMA = {
  type: "object",
  additionalProperties: false,

  properties: {
    maxAffectedVersions: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS
          .maxAffectedVersions,
    },

    maxDepth: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxDepth,
    },

    maxServices: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxServices,
    },

    maxPathsPerService: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS
          .maxPathsPerService,
    },

    maxTotalPaths: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxTotalPaths,
    },

    maxTraversalStates: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS
          .maxTraversalStates,
    },

    maxDependentsPerNode: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS
          .maxDependentsPerNode,
    },

    maxWarnings: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxWarnings,
    },

    highConfidenceThreshold: {
      type: "number",
      minimum: 0,
      maximum: 1,
    },

    maxEvidenceIds: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS.maxEvidenceIds,
    },

    evidenceReadChunkSize: {
      type: "integer",
      minimum: 1,
      maximum:
        ANALYSIS_ROUTE_LIMITS
          .maxEvidenceReadChunkSize,
    },
  },
} as const;

export const GET_LIVE_BLAST_RADIUS_ROUTE_SCHEMA = {
  params:
    INCIDENT_ANALYSIS_PARAMS_SCHEMA,

  querystring:
    INCIDENT_ANALYSIS_QUERY_SCHEMA,

  response: {
    200:
      LIVE_BLAST_RADIUS_RESPONSE_REF,

    400:
      ERROR_RESPONSE_REF,

    404:
      ERROR_RESPONSE_REF,

    503:
      ERROR_RESPONSE_REF,

    500:
      ERROR_RESPONSE_REF,
  },
} as const;

export function registerAnalysisSchemas(
  app: FastifyInstance,
): void {
  if (
    app.getSchema(
      LIVE_BLAST_RADIUS_RESPONSE_SCHEMA.$id,
    ) === undefined
  ) {
    app.addSchema(
      LIVE_BLAST_RADIUS_RESPONSE_SCHEMA,
    );
  }
}
