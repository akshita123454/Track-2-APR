import {
  ERROR_RESPONSE_REF,
  MAX_SAFE_INTEGER,
} from "./common.js";

export const PACKAGE_OVERVIEW_LIMITS = {
  maxResults: 50,
  defaultResults: 12,
} as const;

export interface PackageOverviewParams {
  readonly packageName: string;
}

export interface PackageOverviewQuerystring {
  readonly limit?: number;
}

const PACKAGE_NAME_SCHEMA = {
  type: "string",
  minLength: 1,
  maxLength: 214,
  pattern: "^(?:[^/\\s\\\\?#]+|@[^/\\s\\\\?#]+/[^/\\s\\\\?#]+)$",
} as const;

const NODE_ID_SCHEMA = {
  type: "integer",
  minimum: 0,
  maximum: MAX_SAFE_INTEGER,
} as const;

const PACKAGE_OVERVIEW_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "packageName",
    "found",
    "versions",
    "declarations",
    "dependents",
    "maintainers",
    "authorityPackages",
    "incidents",
    "truncated",
    "hydraRead",
  ],
  properties: {
    packageName: PACKAGE_NAME_SCHEMA,
    found: { type: "boolean" },
    versions: {
      type: "array",
      maxItems: PACKAGE_OVERVIEW_LIMITS.maxResults,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "version", "publishedAt", "observedAt"],
        properties: {
          id: NODE_ID_SCHEMA,
          version: { type: "string", minLength: 1, maxLength: 256 },
          publishedAt: { anyOf: [NODE_ID_SCHEMA, { type: "null" }] },
          observedAt: NODE_ID_SCHEMA,
        },
      },
    },
    declarations: {
      type: "array",
      maxItems: PACKAGE_OVERVIEW_LIMITS.maxResults,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["sourceVersionId", "sourceVersion", "packageName", "declaredRange", "dependencyType"],
        properties: {
          sourceVersionId: NODE_ID_SCHEMA,
          sourceVersion: { type: "string", minLength: 1 },
          packageName: PACKAGE_NAME_SCHEMA,
          declaredRange: { type: "string", minLength: 1, maxLength: 1024 },
          dependencyType: { type: "string", enum: ["production", "development", "optional", "peer"] },
        },
      },
    },
    dependents: {
      type: "array",
      maxItems: PACKAGE_OVERVIEW_LIMITS.maxResults,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["rootVersionId", "nodeId", "nodeKind", "logicalId", "displayName", "criticality", "lockfilePath", "validFrom", "validUntil"],
        properties: {
          rootVersionId: NODE_ID_SCHEMA,
          nodeId: NODE_ID_SCHEMA,
          nodeKind: { type: "string", minLength: 1, maxLength: 64 },
          logicalId: { type: "string", minLength: 1, maxLength: 4096 },
          displayName: { type: "string", minLength: 1, maxLength: 1024 },
          criticality: { anyOf: [{ type: "string", enum: ["low", "medium", "high", "critical"] }, { type: "null" }] },
          lockfilePath: { anyOf: [{ type: "string", maxLength: 4096 }, { type: "null" }] },
          validFrom: { anyOf: [NODE_ID_SCHEMA, { type: "null" }] },
          validUntil: { anyOf: [NODE_ID_SCHEMA, { type: "null" }] },
        },
      },
    },
    maintainers: {
      type: "array",
      maxItems: PACKAGE_OVERVIEW_LIMITS.maxResults,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["handle", "email"],
        properties: {
          handle: { type: "string", minLength: 1, maxLength: 512 },
          email: { anyOf: [{ type: "string", maxLength: 512 }, { type: "null" }] },
        },
      },
    },
    authorityPackages: {
      type: "array",
      maxItems: PACKAGE_OVERVIEW_LIMITS.maxResults,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["maintainerHandle", "packageName"],
        properties: {
          maintainerHandle: { type: "string", minLength: 1, maxLength: 512 },
          packageName: PACKAGE_NAME_SCHEMA,
        },
      },
    },
    incidents: {
      type: "array",
      maxItems: PACKAGE_OVERVIEW_LIMITS.maxResults,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "title", "status", "intervalStart", "intervalEnd"],
        properties: {
          id: NODE_ID_SCHEMA,
          title: { type: "string", minLength: 1, maxLength: 1024 },
          status: { type: "string", enum: ["draft", "active", "contained", "closed"] },
          intervalStart: NODE_ID_SCHEMA,
          intervalEnd: { anyOf: [NODE_ID_SCHEMA, { type: "null" }] },
        },
      },
    },
    truncated: { type: "boolean" },
    hydraRead: {
      type: "object",
      additionalProperties: false,
      required: ["engine", "readEpoch", "queryCount", "rowsRead", "latencyMs", "consistencyModel"],
      properties: {
        engine: { type: "string", const: "HydraDB" },
        readEpoch: { type: "string", format: "date-time" },
        queryCount: { type: "integer", minimum: 0, maximum: MAX_SAFE_INTEGER },
        rowsRead: { type: "integer", minimum: 0, maximum: MAX_SAFE_INTEGER },
        latencyMs: { type: "integer", minimum: 0, maximum: MAX_SAFE_INTEGER },
        consistencyModel: { type: "string", const: "bounded-multi-statement-read" },
      },
    },
  },
} as const;

export const GET_PACKAGE_OVERVIEW_ROUTE_SCHEMA = {
  params: {
    type: "object",
    additionalProperties: false,
    required: ["packageName"],
    properties: { packageName: PACKAGE_NAME_SCHEMA },
  },
  querystring: {
    type: "object",
    additionalProperties: false,
    properties: {
      limit: {
        type: "integer",
        minimum: 1,
        maximum: PACKAGE_OVERVIEW_LIMITS.maxResults,
        default: PACKAGE_OVERVIEW_LIMITS.defaultResults,
      },
    },
  },
  response: {
    200: PACKAGE_OVERVIEW_RESPONSE_SCHEMA,
    400: ERROR_RESPONSE_REF,
    503: ERROR_RESPONSE_REF,
  },
} as const;
