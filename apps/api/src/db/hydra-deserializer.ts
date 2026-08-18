import {
  createDerivedEdgeIdentity,
  createEdgeIdentity,
  generateDeterministicId,
  normalizeLogicalId,
} from "../domain/identity.js";

import type {
  GraphEdge,
  GraphNode,
  GraphRelKind,
  NodeKind,
} from "../domain/schema.js";

import {
  EDGE_PROPERTY_KEYS,
  HYDRA_SCHEMA_VERSION,
  NODE_PROPERTY_KEYS,
  hashHydraScalarRecord,
} from "./hydra-serializer.js";

import type {
  HydraScalar,
} from "./hydra-serializer.js";

export type HydraDeserializationErrorCode =
  | "INVALID_INPUT"
  | "RECORD_SHAPE_MISMATCH"
  | "PROPERTY_TYPE_INVALID"
  | "PROPERTY_VALUE_INVALID"
  | "SCHEMA_VERSION_UNSUPPORTED"
  | "PAYLOAD_HASH_MISMATCH"
  | "KIND_MISMATCH"
  | "IDENTITY_MISMATCH"
  | "ENDPOINT_MISMATCH";

export type HydraEntityType = "node" | "edge";

export class HydraDeserializationError extends Error {
  constructor(
    readonly code: HydraDeserializationErrorCode,
    readonly entityType: HydraEntityType,
    readonly field: string,
    message: string,
  ) {
    super(
      `HydraDB ${entityType} deserialization failed ` +
        `[${code}] at "${field}": ${message}`,
    );

    this.name = "HydraDeserializationError";
  }
}

/**
 * Node properties must contain only the keys listed in
 * NODE_PROPERTY_KEYS[kind].
 *
 * The database-specific `id` property must be supplied separately as
 * `vertex`. Internal HydraDB guard properties must not be included.
 */
export interface HydraNodeReadInput {
  readonly vertex: unknown;
  readonly properties: unknown;

  /**
   * Optional expected kind obtained from the query or caller context.
   * Supplying it prevents a row from changing its discriminated type.
   */
  readonly expectedKind?: NodeKind;
}

/**
 * Edge properties must contain only the keys listed in
 * EDGE_PROPERTY_KEYS[kind].
 *
 * Endpoint logical IDs are required because canonical edge identity is
 * derived from endpoint logical identities, not only numeric IDs.
 */
export interface HydraEdgeReadInput {
  readonly relationshipVertex: unknown;
  readonly sourceVertex: unknown;
  readonly destinationVertex: unknown;
  readonly sourceLogicalId: unknown;
  readonly destinationLogicalId: unknown;
  readonly properties: unknown;

  /**
   * Optional relationship kind obtained from query or caller context.
   */
  readonly expectedKind?: GraphRelKind;
}

const NODE_KINDS = [
  "Package",
  "PackageVersion",
  "Repository",
  "Service",
  "Build",
  "Artifact",
  "Deployment",
  "Maintainer",
  "Credential",
  "CIWorkflow",
  "Organization",
  "Incident",
  "Evidence",
  "Control",
] as const satisfies readonly NodeKind[];

const EDGE_KINDS = [
  "HAS_VERSION",
  "DECLARES_DEPENDENCY",
  "DEPENDS_ON",
  "CONTAINS",
  "TRIGGERS",
  "PRODUCES",
  "DEPLOYED_AS",
  "RUNS",
  "MAINTAINS",
  "MEMBER_OF",
  "OWNS",
  "CAN_PUBLISH",
  "CAN_ACCESS",
  "CONTROLS",
  "AFFECTS",
  "SUPPORTS",
  "TARGETS",
  "USED_BY",
] as const satisfies readonly GraphRelKind[];

const NPM_ECOSYSTEM = ["npm"] as const;

const REPOSITORY_PROVIDERS = [
  "github",
  "gitlab",
  "other",
] as const;

const SERVICE_CRITICALITIES = [
  "low",
  "medium",
  "high",
  "critical",
] as const;

const CREDENTIAL_TYPES = [
  "npm-token",
  "github-token",
  "oidc",
  "signing-key",
  "other",
] as const;

const CREDENTIAL_STATUSES = [
  "active",
  "expired",
  "revoked",
  "unknown",
] as const;

const CI_WORKFLOW_PROVIDERS = [
  "github-actions",
  "gitlab-ci",
  "other",
] as const;

const INCIDENT_STATUSES = [
  "draft",
  "active",
  "contained",
  "closed",
] as const;

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

const CONTROL_ACTIONS = [
  "block-package-version",
  "pin-dependency",
  "apply-override",
  "revoke-credential",
  "remove-publishing-access",
  "disable-workflow",
  "rotate-secret",
  "rollback-artifact",
  "isolate-service",
  "restrict-network",
] as const;

const CONTROL_STATUSES = [
  "proposed",
  "simulated",
  "approved",
  "applied",
] as const;

const DEPENDENCY_TYPES = [
  "production",
  "development",
  "optional",
  "peer",
] as const;

type MutableScalarRecord = Record<string, HydraScalar>;

function fail(
  code: HydraDeserializationErrorCode,
  entityType: HydraEntityType,
  field: string,
  message: string,
): never {
  throw new HydraDeserializationError(
    code,
    entityType,
    field,
    message,
  );
}

function assertNever(value: never): never {
  throw new Error(
    `Unsupported HydraDB discriminated union member: ${String(value)}`,
  );
}

function asRecord(
  value: unknown,
  entityType: HydraEntityType,
): Readonly<Record<string, unknown>> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    return fail(
      "INVALID_INPUT",
      entityType,
      "properties",
      "expected a property record",
    );
  }

  return value as Readonly<Record<string, unknown>>;
}

/**
 * Converts normal JavaScript scalar values and neo4j-driver Integer
 * objects into the scalar form used by the serializer.
 *
 * Integer-like objects are rejected before conversion when the driver
 * reports that they are outside JavaScript's safe integer range.
 */
function asHydraScalar(
  value: unknown,
  entityType: HydraEntityType,
  field: string,
): HydraScalar {
  if (
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        field,
        "number must be finite",
      );
    }

    return value;
  }

  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value
  ) {
    const integerLike = value as {
      readonly inSafeRange?: () => boolean;
      readonly toNumber?: () => unknown;
    };

    if (typeof integerLike.toNumber !== "function") {
      return fail(
        "PROPERTY_TYPE_INVALID",
        entityType,
        field,
        "integer-like value has no callable toNumber method",
      );
    }

    try {
      if (
        typeof integerLike.inSafeRange === "function" &&
        !integerLike.inSafeRange()
      ) {
        return fail(
          "PROPERTY_VALUE_INVALID",
          entityType,
          field,
          "integer is outside the JavaScript safe range",
        );
      }

      const converted = integerLike.toNumber();

      if (
        typeof converted !== "number" ||
        !Number.isFinite(converted)
      ) {
        return fail(
          "PROPERTY_VALUE_INVALID",
          entityType,
          field,
          "integer conversion did not produce a finite number",
        );
      }

      return converted;
    } catch (error) {
      if (error instanceof HydraDeserializationError) {
        throw error;
      }

      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        field,
        "integer conversion failed",
      );
    }
  }

  return fail(
    "PROPERTY_TYPE_INVALID",
    entityType,
    field,
    "expected a string, boolean, finite number, or Neo4j integer",
  );
}

function normalizeExactProperties(
  rawProperties: Readonly<Record<string, unknown>>,
  expectedKeys: readonly string[],
  entityType: HydraEntityType,
): Readonly<Record<string, HydraScalar>> {
  const expected = [...expectedKeys].sort((left, right) =>
    left.localeCompare(right),
  );

  const actual = Object.keys(rawProperties).sort((left, right) =>
    left.localeCompare(right),
  );

  if (
    expected.length !== actual.length ||
    expected.some((key, index) => key !== actual[index])
  ) {
    return fail(
      "RECORD_SHAPE_MISMATCH",
      entityType,
      "properties",
      "stored property keys do not match the static schema",
    );
  }

  const normalized: MutableScalarRecord =
    Object.create(null) as MutableScalarRecord;

  for (const key of expectedKeys) {
    normalized[key] = asHydraScalar(
      rawProperties[key],
      entityType,
      key,
    );
  }

  return normalized;
}

function readString(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): string {
  const value = row[key];

  if (typeof value !== "string") {
    return fail(
      "PROPERTY_TYPE_INVALID",
      entityType,
      key,
      "expected a string",
    );
  }

  return value;
}

function readNonemptyText(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): string {
  const value = readString(row, key, entityType);

  if (value.trim().length === 0) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "must be a nonempty string",
    );
  }

  return value;
}

function readBoolean(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): boolean {
  const value = row[key];

  if (typeof value !== "boolean") {
    return fail(
      "PROPERTY_TYPE_INVALID",
      entityType,
      key,
      "expected a boolean",
    );
  }

  return value;
}

function readNumber(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): number {
  const value = row[key];

  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return fail(
      "PROPERTY_TYPE_INVALID",
      entityType,
      key,
      "expected a finite number",
    );
  }

  return value;
}

function readSafeInteger(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): number {
  const value = readNumber(row, key, entityType);

  if (!Number.isSafeInteger(value) || value < 0) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "must be a nonnegative safe integer",
    );
  }

  return value;
}

function readExternalSafeInteger(
  value: unknown,
  field: string,
  entityType: HydraEntityType,
): number {
  const scalar = asHydraScalar(value, entityType, field);

  if (
    typeof scalar !== "number" ||
    !Number.isSafeInteger(scalar) ||
    scalar < 0
  ) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      field,
      "must be a nonnegative safe integer",
    );
  }

  return scalar;
}

function readFiniteNonnegative(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): number {
  const value = readNumber(row, key, entityType);

  if (value < 0) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "must be nonnegative",
    );
  }

  return value;
}

function readEnum<
  const Values extends readonly string[],
>(
  value: unknown,
  allowedValues: Values,
  entityType: HydraEntityType,
  field: string,
): Values[number] {
  if (
    typeof value !== "string" ||
    !(allowedValues as readonly string[]).includes(value)
  ) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      field,
      "contains an unsupported enum value",
    );
  }

  return value as Values[number];
}

function readRowEnum<
  const Values extends readonly string[],
>(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  allowedValues: Values,
  entityType: HydraEntityType,
): Values[number] {
  return readEnum(
    row[key],
    allowedValues,
    entityType,
    key,
  );
}

function readLogicalIdValue(
  value: unknown,
  entityType: HydraEntityType,
  field: string,
): string {
  if (typeof value !== "string") {
    return fail(
      "PROPERTY_TYPE_INVALID",
      entityType,
      field,
      "expected a logical identity string",
    );
  }

  let normalized: string;

  try {
    normalized = normalizeLogicalId(value);
  } catch {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      field,
      "contains an invalid logical identity",
    );
  }

  if (normalized !== value) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      field,
      "logical identity is not in canonical normalized form",
    );
  }

  return normalized;
}

function readLogicalId(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): string {
  return readLogicalIdValue(
    row[key],
    entityType,
    key,
  );
}

function verifySchemaVersion(
  row: Readonly<Record<string, HydraScalar>>,
  entityType: HydraEntityType,
): void {
  const version = readSafeInteger(
    row,
    "schema_version",
    entityType,
  );

  if (version !== HYDRA_SCHEMA_VERSION) {
    fail(
      "SCHEMA_VERSION_UNSUPPORTED",
      entityType,
      "schema_version",
      `expected version ${HYDRA_SCHEMA_VERSION}`,
    );
  }
}

function verifyPayloadHash(
  row: Readonly<Record<string, HydraScalar>>,
  entityType: HydraEntityType,
): void {
  const actualHash = readString(
    row,
    "payload_hash",
    entityType,
  );

  if (!/^[a-f0-9]{64}$/.test(actualHash)) {
    fail(
      "PAYLOAD_HASH_MISMATCH",
      entityType,
      "payload_hash",
      "stored hash is not a canonical SHA-256 digest",
    );
  }

  const expectedHash = hashHydraScalarRecord(
    row,
    ["payload_hash"],
  );

  if (actualHash !== expectedHash) {
    fail(
      "PAYLOAD_HASH_MISMATCH",
      entityType,
      "payload_hash",
      "stored properties do not match their payload hash",
    );
  }
}

function verifyDeterministicIdentity(
  id: number,
  logicalId: string,
  entityType: HydraEntityType,
  field = "logical_id",
): void {
  let expectedId: number;

  try {
    expectedId = generateDeterministicId(logicalId);
  } catch {
    return fail(
      "IDENTITY_MISMATCH",
      entityType,
      field,
      "could not generate the deterministic identity",
    );
  }

  if (id !== expectedId) {
    fail(
      "IDENTITY_MISMATCH",
      entityType,
      field,
      "numeric ID does not match the logical identity",
    );
  }
}

function decodeIdSet(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): readonly number[] {
  const encoded = readString(row, key, entityType);

  let parsed: unknown;

  try {
    parsed = JSON.parse(encoded);
  } catch {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "is not valid JSON",
    );
  }

  if (!Array.isArray(parsed)) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "must encode an array",
    );
  }

  const values: number[] = [];

  for (let index = 0; index < parsed.length; index += 1) {
    const value: unknown = parsed[index];

    if (
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < 0
    ) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        key,
        `entry ${index} must be a nonnegative safe integer`,
      );
    }

    if (
      index > 0 &&
      values[index - 1] >= value
    ) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        key,
        "IDs must be unique and strictly sorted",
      );
    }

    values.push(value);
  }

  if (JSON.stringify(values) !== encoded) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "ID array is not canonically JSON encoded",
    );
  }

  return values;
}

function decodeStringSet(
  row: Readonly<Record<string, HydraScalar>>,
  key: string,
  entityType: HydraEntityType,
): readonly string[] {
  const encoded = readString(row, key, entityType);

  let parsed: unknown;

  try {
    parsed = JSON.parse(encoded);
  } catch {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "is not valid JSON",
    );
  }

  if (!Array.isArray(parsed)) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "must encode an array",
    );
  }

  const values: string[] = [];

  for (let index = 0; index < parsed.length; index += 1) {
    const value: unknown = parsed[index];

    if (
      typeof value !== "string" ||
      value.trim().length === 0
    ) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        key,
        `entry ${index} must be a nonempty string`,
      );
    }

    values.push(value);
  }

  const sorted = [...values].sort((left, right) =>
    left.localeCompare(right),
  );

  if (
    sorted.some(
      (value, index) => value !== values[index],
    )
  ) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "values must be sorted",
    );
  }

  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1] === values[index]) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        key,
        "values must be unique",
      );
    }
  }

  if (JSON.stringify(values) !== encoded) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      key,
      "string array is not canonically JSON encoded",
    );
  }

  return values;
}

function readOptionalText(
  row: Readonly<Record<string, HydraScalar>>,
  valueKey: string,
  presenceKey: string,
  entityType: HydraEntityType,
  requireNonempty: boolean,
): string | undefined {
  const present = readBoolean(
    row,
    presenceKey,
    entityType,
  );

  const value = readString(
    row,
    valueKey,
    entityType,
  );

  if (!present) {
    if (value !== "") {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        valueKey,
        `must use the empty-string sentinel when ${presenceKey} is false`,
      );
    }

    return undefined;
  }

  if (requireNonempty && value.trim().length === 0) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      valueKey,
      "must be nonempty when present",
    );
  }

  return value;
}

function readOptionalTimestamp(
  row: Readonly<Record<string, HydraScalar>>,
  valueKey: string,
  presenceKey: string,
  entityType: HydraEntityType,
): number | undefined {
  const present = readBoolean(
    row,
    presenceKey,
    entityType,
  );

  const value = readSafeInteger(
    row,
    valueKey,
    entityType,
  );

  if (!present) {
    if (value !== 0) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        valueKey,
        `must use the zero sentinel when ${presenceKey} is false`,
      );
    }

    return undefined;
  }

  return value;
}

function readOptionalBoolean(
  row: Readonly<Record<string, HydraScalar>>,
  valueKey: string,
  presenceKey: string,
  entityType: HydraEntityType,
): boolean | undefined {
  const present = readBoolean(
    row,
    presenceKey,
    entityType,
  );

  const value = readBoolean(
    row,
    valueKey,
    entityType,
  );

  if (!present) {
    if (value !== false) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        valueKey,
        `must use the false sentinel when ${presenceKey} is false`,
      );
    }

    return undefined;
  }

  return value;
}

function readOptionalFiniteNonnegative(
  row: Readonly<Record<string, HydraScalar>>,
  valueKey: string,
  presenceKey: string,
  entityType: HydraEntityType,
): number | undefined {
  const present = readBoolean(
    row,
    presenceKey,
    entityType,
  );

  const value = readFiniteNonnegative(
    row,
    valueKey,
    entityType,
  );

  if (!present) {
    if (value !== 0) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        valueKey,
        `must use the zero sentinel when ${presenceKey} is false`,
      );
    }

    return undefined;
  }

  return value;
}

function readOptionalEnum<
  const Values extends readonly string[],
>(
  row: Readonly<Record<string, HydraScalar>>,
  valueKey: string,
  presenceKey: string,
  allowedValues: Values,
  entityType: HydraEntityType,
): Values[number] | undefined {
  const present = readBoolean(
    row,
    presenceKey,
    entityType,
  );

  const value = readString(
    row,
    valueKey,
    entityType,
  );

  if (!present) {
    if (value !== "") {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        valueKey,
        `must use the empty-string sentinel when ${presenceKey} is false`,
      );
    }

    return undefined;
  }

  return readEnum(
    value,
    allowedValues,
    entityType,
    valueKey,
  );
}

export function deserializeHydraNode(
  input: HydraNodeReadInput,
): GraphNode {
  const entityType = "node" as const;
  const rawProperties = asRecord(
    input.properties,
    entityType,
  );

  const kind = readEnum(
    rawProperties.kind,
    NODE_KINDS,
    entityType,
    "kind",
  );

  if (
    input.expectedKind !== undefined &&
    kind !== input.expectedKind
  ) {
    return fail(
      "KIND_MISMATCH",
      entityType,
      "kind",
      "stored kind does not match the expected node kind",
    );
  }

  const row = normalizeExactProperties(
    rawProperties,
    NODE_PROPERTY_KEYS[kind],
    entityType,
  );

  verifySchemaVersion(row, entityType);
  verifyPayloadHash(row, entityType);

  const vertex = readExternalSafeInteger(
    input.vertex,
    "vertex",
    entityType,
  );

  const logicalId = readLogicalId(
    row,
    "logical_id",
    entityType,
  );

  verifyDeterministicIdentity(
    vertex,
    logicalId,
    entityType,
  );

  const storedKind = readRowEnum(
    row,
    "kind",
    NODE_KINDS,
    entityType,
  );

  if (storedKind !== kind) {
    return fail(
      "KIND_MISMATCH",
      entityType,
      "kind",
      "kind changed while normalizing the record",
    );
  }

  const evidenceIds = decodeIdSet(
    row,
    "evidence_ids_json",
    entityType,
  );

  const synthetic = readBoolean(
    row,
    "synthetic",
    entityType,
  );

  const observedAt = readSafeInteger(
    row,
    "observed_at",
    entityType,
  );

  const base = {
    id: vertex,
    logicalId,
    evidenceIds,
    synthetic,
    observedAt,
  };

  switch (kind) {
    case "Package":
      return {
        ...base,
        kind,
        ecosystem: readRowEnum(
          row,
          "ecosystem",
          NPM_ECOSYSTEM,
          entityType,
        ),
        name: readNonemptyText(
          row,
          "name",
          entityType,
        ),
      };

    case "PackageVersion":
      return {
        ...base,
        kind,
        ecosystem: readRowEnum(
          row,
          "ecosystem",
          NPM_ECOSYSTEM,
          entityType,
        ),
        packageName: readNonemptyText(
          row,
          "package_name",
          entityType,
        ),
        version: readNonemptyText(
          row,
          "version",
          entityType,
        ),
        publishedAt: readOptionalTimestamp(
          row,
          "published_at",
          "has_published_at",
          entityType,
        ),
      };

    case "Repository":
      return {
        ...base,
        kind,
        provider: readRowEnum(
          row,
          "provider",
          REPOSITORY_PROVIDERS,
          entityType,
        ),
        url: readNonemptyText(
          row,
          "url",
          entityType,
        ),
        defaultBranch: readOptionalText(
          row,
          "default_branch",
          "has_default_branch",
          entityType,
          true,
        ),
      };

    case "Service":
      return {
        ...base,
        kind,
        name: readNonemptyText(
          row,
          "name",
          entityType,
        ),
        criticality: readRowEnum(
          row,
          "criticality",
          SERVICE_CRITICALITIES,
          entityType,
        ),
        internetExposed: readOptionalBoolean(
          row,
          "internet_exposed",
          "has_internet_exposed",
          entityType,
        ),
        dataSensitivity: readOptionalEnum(
          row,
          "data_sensitivity",
          "has_data_sensitivity",
          SERVICE_CRITICALITIES,
          entityType,
        ),
      };

    case "Build":
      return {
        ...base,
        kind,
        provider: readNonemptyText(
          row,
          "provider",
          entityType,
        ),
        buildNumber: readNonemptyText(
          row,
          "build_number",
          entityType,
        ),
        commitSha: readNonemptyText(
          row,
          "commit_sha",
          entityType,
        ),
        startedAt: readSafeInteger(
          row,
          "started_at",
          entityType,
        ),
        completedAt: readOptionalTimestamp(
          row,
          "completed_at",
          "has_completed_at",
          entityType,
        ),
      };

    case "Artifact":
      return {
        ...base,
        kind,
        digest: readNonemptyText(
          row,
          "digest",
          entityType,
        ),
        mediaType: readNonemptyText(
          row,
          "media_type",
          entityType,
        ),
      };

    case "Deployment":
      return {
        ...base,
        kind,
        environment: readNonemptyText(
          row,
          "environment",
          entityType,
        ),
        deployedAt: readSafeInteger(
          row,
          "deployed_at",
          entityType,
        ),
        removedAt: readOptionalTimestamp(
          row,
          "removed_at",
          "has_removed_at",
          entityType,
        ),
      };

    case "Maintainer":
      return {
        ...base,
        kind,
        handle: readNonemptyText(
          row,
          "handle",
          entityType,
        ),
        email: readOptionalText(
          row,
          "email",
          "has_email",
          entityType,
          true,
        ),
      };

    case "Credential":
      return {
        ...base,
        kind,
        credentialType: readRowEnum(
          row,
          "credential_type",
          CREDENTIAL_TYPES,
          entityType,
        ),
        scopes: decodeStringSet(
          row,
          "scopes_json",
          entityType,
        ),
        status: readRowEnum(
          row,
          "status",
          CREDENTIAL_STATUSES,
          entityType,
        ),
        expiresAt: readOptionalTimestamp(
          row,
          "expires_at",
          "has_expires_at",
          entityType,
        ),
      };

    case "CIWorkflow":
      return {
        ...base,
        kind,
        provider: readRowEnum(
          row,
          "provider",
          CI_WORKFLOW_PROVIDERS,
          entityType,
        ),
        path: readNonemptyText(
          row,
          "path",
          entityType,
        ),
      };

    case "Organization":
      return {
        ...base,
        kind,
        name: readNonemptyText(
          row,
          "name",
          entityType,
        ),
        provider: readOptionalText(
          row,
          "provider",
          "has_provider",
          entityType,
          true,
        ),
      };

    case "Incident": {
      const intervalStart = readSafeInteger(
        row,
        "interval_start",
        entityType,
      );

      const optionalIntervalEnd = readOptionalTimestamp(
        row,
        "interval_end",
        "has_interval_end",
        entityType,
      );

      if (
        optionalIntervalEnd !== undefined &&
        optionalIntervalEnd < intervalStart
      ) {
        return fail(
          "PROPERTY_VALUE_INVALID",
          entityType,
          "interval_end",
          "must not precede interval_start",
        );
      }

      return {
        ...base,
        kind,
        title: readNonemptyText(
          row,
          "title",
          entityType,
        ),
        status: readRowEnum(
          row,
          "status",
          INCIDENT_STATUSES,
          entityType,
        ),
        intervalStart,
        intervalEnd: optionalIntervalEnd ?? null,
      };
    }

    case "Evidence": {
      if (evidenceIds.length !== 0) {
        return fail(
          "PROPERTY_VALUE_INVALID",
          entityType,
          "evidence_ids_json",
          "Evidence nodes cannot recursively reference evidence",
        );
      }

      const confidence = readNumber(
        row,
        "confidence",
        entityType,
      );

      if (confidence < 0 || confidence > 1) {
        return fail(
          "PROPERTY_VALUE_INVALID",
          entityType,
          "confidence",
          "must be between 0 and 1",
        );
      }

      return {
        ...base,
        kind,
        evidenceIds: [],
        sourceType: readRowEnum(
          row,
          "source_type",
          EVIDENCE_SOURCE_TYPES,
          entityType,
        ),
        sourceUri: readNonemptyText(
          row,
          "source_uri",
          entityType,
        ),
        collectorVersion: readNonemptyText(
          row,
          "collector_version",
          entityType,
        ),
        confidence,
        detail: readString(
          row,
          "detail",
          entityType,
        ),
        incidentId: readOptionalTimestamp(
          row,
          "incident_id",
          "has_incident_id",
          entityType,
        ),
      };
    }

    case "Control":
      return {
        ...base,
        kind,
        action: readRowEnum(
          row,
          "action",
          CONTROL_ACTIONS,
          entityType,
        ),
        status: readRowEnum(
          row,
          "status",
          CONTROL_STATUSES,
          entityType,
        ),
        estimatedCost: readOptionalFiniteNonnegative(
          row,
          "estimated_cost",
          "has_estimated_cost",
          entityType,
        ),
        estimatedMinutes:
          readOptionalFiniteNonnegative(
            row,
            "estimated_minutes",
            "has_estimated_minutes",
            entityType,
          ),
        reversible: readBoolean(
          row,
          "reversible",
          entityType,
        ),
      };

    default:
      return assertNever(kind);
  }
}

export function deserializeHydraEdge(
  input: HydraEdgeReadInput,
): GraphEdge {
  const entityType = "edge" as const;
  const rawProperties = asRecord(
    input.properties,
    entityType,
  );

  const kind = readEnum(
    rawProperties.kind,
    EDGE_KINDS,
    entityType,
    "kind",
  );

  if (
    input.expectedKind !== undefined &&
    kind !== input.expectedKind
  ) {
    return fail(
      "KIND_MISMATCH",
      entityType,
      "kind",
      "stored relationship kind does not match the expected kind",
    );
  }

  const row = normalizeExactProperties(
    rawProperties,
    EDGE_PROPERTY_KEYS[kind],
    entityType,
  );

  verifySchemaVersion(row, entityType);
  verifyPayloadHash(row, entityType);

  const relationshipVertex = readExternalSafeInteger(
    input.relationshipVertex,
    "relationship_vertex",
    entityType,
  );

  const sourceVertex = readExternalSafeInteger(
    input.sourceVertex,
    "source_vertex",
    entityType,
  );

  const destinationVertex = readExternalSafeInteger(
    input.destinationVertex,
    "destination_vertex",
    entityType,
  );

  const sourceLogicalId = readLogicalIdValue(
    input.sourceLogicalId,
    entityType,
    "source_logical_id",
  );

  const destinationLogicalId = readLogicalIdValue(
    input.destinationLogicalId,
    entityType,
    "destination_logical_id",
  );

  verifyDeterministicIdentity(
    sourceVertex,
    sourceLogicalId,
    entityType,
    "source_logical_id",
  );

  verifyDeterministicIdentity(
    destinationVertex,
    destinationLogicalId,
    entityType,
    "destination_logical_id",
  );

  const logicalId = readLogicalId(
    row,
    "logical_id",
    entityType,
  );

  verifyDeterministicIdentity(
    relationshipVertex,
    logicalId,
    entityType,
  );

  const sourceId = readSafeInteger(
    row,
    "source_id",
    entityType,
  );

  const targetId = readSafeInteger(
    row,
    "target_id",
    entityType,
  );

  if (sourceId !== sourceVertex) {
    return fail(
      "ENDPOINT_MISMATCH",
      entityType,
      "source_id",
      "relationship source does not match its source vertex",
    );
  }

  if (targetId !== destinationVertex) {
    return fail(
      "ENDPOINT_MISMATCH",
      entityType,
      "target_id",
      "relationship target does not match its destination vertex",
    );
  }

  const observedAt = readSafeInteger(
    row,
    "observed_at",
    entityType,
  );

  const derived = readBoolean(
    row,
    "derived",
    entityType,
  );

  if (kind === "USED_BY") {
    if (!derived) {
      return fail(
        "PROPERTY_VALUE_INVALID",
        entityType,
        "derived",
        "USED_BY must be marked as a derived relationship",
      );
    }

    const derivedFrom = readSafeInteger(
      row,
      "derived_from",
      entityType,
    );

    const derivedFromLogicalId = readLogicalId(
      row,
      "derived_from_logical_id",
      entityType,
    );

    verifyDeterministicIdentity(
      derivedFrom,
      derivedFromLogicalId,
      entityType,
      "derived_from_logical_id",
    );

    const expectedIdentity = createDerivedEdgeIdentity(
      derivedFromLogicalId,
    );

    if (
      relationshipVertex !== expectedIdentity.id ||
      logicalId !== expectedIdentity.logicalId
    ) {
      return fail(
        "IDENTITY_MISMATCH",
        entityType,
        "logical_id",
        "USED_BY identity does not match its canonical edge identity",
      );
    }

    return {
      id: relationshipVertex,
      logicalId,
      sourceId,
      targetId,
      kind,
      observedAt,
      derived: true,
      derivedFrom,
      derivedFromLogicalId,
      generatedAt: readSafeInteger(
        row,
        "generated_at",
        entityType,
      ),
      generatorVersion: readNonemptyText(
        row,
        "generator_version",
        entityType,
      ),
    };
  }

  if (derived) {
    return fail(
      "PROPERTY_VALUE_INVALID",
      entityType,
      "derived",
      "canonical relationships cannot be marked as derived",
    );
  }

  const identityDiscriminator = readNonemptyText(
    row,
    "identity_discriminator",
    entityType,
  );

  const evidenceIds = decodeIdSet(
    row,
    "evidence_ids_json",
    entityType,
  );

  const expectedIdentity = createEdgeIdentity({
    kind,
    sourceLogicalId,
    targetLogicalId: destinationLogicalId,
    discriminator: identityDiscriminator,
  });

  if (
    relationshipVertex !== expectedIdentity.id ||
    logicalId !== expectedIdentity.logicalId
  ) {
    return fail(
      "IDENTITY_MISMATCH",
      entityType,
      "logical_id",
      "canonical edge identity does not match its endpoints and discriminator",
    );
  }

  const canonicalBase = {
    id: relationshipVertex,
    logicalId,
    sourceId,
    targetId,
    observedAt,
    derived: false as const,
    identityDiscriminator,
    evidenceIds,
  };

  switch (kind) {
    case "DECLARES_DEPENDENCY":
      return {
        ...canonicalBase,
        kind,
        declaredRange: readNonemptyText(
          row,
          "declared_range",
          entityType,
        ),
        dependencyType: readRowEnum(
          row,
          "dependency_type",
          DEPENDENCY_TYPES,
          entityType,
        ),
        workspacePath: readOptionalText(
          row,
          "workspace_path",
          "has_workspace_path",
          entityType,
          false,
        ),
      };

    case "DEPENDS_ON":
      return {
        ...canonicalBase,
        kind,
        dependencyType: readRowEnum(
          row,
          "dependency_type",
          DEPENDENCY_TYPES,
          entityType,
        ),
        declaredRange: readOptionalText(
          row,
          "declared_range",
          "has_declared_range",
          entityType,
          false,
        ),
        lockfilePath: readOptionalText(
          row,
          "lockfile_path",
          "has_lockfile_path",
          entityType,
          false,
        ),
        integrity: readOptionalText(
          row,
          "integrity",
          "has_integrity",
          entityType,
          false,
        ),
      };

    default:
      return {
        ...canonicalBase,
        kind,
      };
  }
}
