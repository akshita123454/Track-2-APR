import { createHash } from "node:crypto";

import { normalizeLogicalId } from "../domain/identity.js";

import type {
  CanonicalEdge,
  GraphEdge,
  GraphNode,
  GraphRelKind,
  NodeKind,
} from "../domain/schema.js";

import type { GraphBatch } from "../ingest/graph-batch.js";

export type HydraScalar = string | number | boolean;
export type HydraRow = Readonly<Record<string, HydraScalar>>;

export type HydraNodeRow = Readonly<
  {
    readonly vertex: number;
  } & Record<string, HydraScalar>
>;

export type HydraEdgeRow = Readonly<
  {
    readonly relationship_vertex: number;
    readonly source_vertex: number;
    readonly destination_vertex: number;
  } & Record<string, HydraScalar>
>;

export interface HydraNodeGroup {
  readonly shapeId: string;
  readonly label: NodeKind;
  readonly propertyKeys: readonly string[];
  readonly rows: readonly HydraNodeRow[];
}

export interface HydraEdgeGroup {
  readonly shapeId: string;
  readonly sourceLabel: NodeKind;
  readonly destinationLabel: NodeKind;
  readonly relationshipType: GraphRelKind;
  readonly propertyKeys: readonly string[];
  readonly rows: readonly HydraEdgeRow[];
}

export interface SerializedHydraBatch {
  readonly schemaVersion: number;
  readonly batchHash: string;
  readonly nodeGroups: readonly HydraNodeGroup[];
  readonly canonicalEdgeGroups: readonly HydraEdgeGroup[];
  readonly derivedEdgeGroups: readonly HydraEdgeGroup[];
  readonly nodeCount: number;
  readonly canonicalEdgeCount: number;
  readonly derivedEdgeCount: number;
}

export const HYDRA_SCHEMA_VERSION = 1;

export const NODE_LABEL_BY_KIND = {
  Package: "Package",
  PackageVersion: "PackageVersion",
  Repository: "Repository",
  Service: "Service",
  Build: "Build",
  Artifact: "Artifact",
  Deployment: "Deployment",
  Maintainer: "Maintainer",
  Credential: "Credential",
  CIWorkflow: "CIWorkflow",
  Organization: "Organization",
  Incident: "Incident",
  Evidence: "Evidence",
  Control: "Control",
} as const satisfies Record<NodeKind, NodeKind>;

export const EDGE_TYPE_BY_KIND = {
  HAS_VERSION: "HAS_VERSION",
  DECLARES_DEPENDENCY: "DECLARES_DEPENDENCY",
  DEPENDS_ON: "DEPENDS_ON",
  CONTAINS: "CONTAINS",
  TRIGGERS: "TRIGGERS",
  PRODUCES: "PRODUCES",
  DEPLOYED_AS: "DEPLOYED_AS",
  RUNS: "RUNS",
  MAINTAINS: "MAINTAINS",
  MEMBER_OF: "MEMBER_OF",
  OWNS: "OWNS",
  CAN_PUBLISH: "CAN_PUBLISH",
  CAN_ACCESS: "CAN_ACCESS",
  CONTROLS: "CONTROLS",
  AFFECTS: "AFFECTS",
  SUPPORTS: "SUPPORTS",
  TARGETS: "TARGETS",
  USED_BY: "USED_BY",
} as const satisfies Record<GraphRelKind, GraphRelKind>;

const BASE_NODE_PROPERTIES = [
  "logical_id",
  "kind",
  "evidence_ids_json",
  "synthetic",
  "observed_at",
  "schema_version",
  "payload_hash",
] as const;

export const NODE_PROPERTY_KEYS = {
  Package: [
    ...BASE_NODE_PROPERTIES,
    "ecosystem",
    "name",
  ],
  PackageVersion: [
    ...BASE_NODE_PROPERTIES,
    "ecosystem",
    "package_name",
    "version",
    "published_at",
    "has_published_at",
  ],
  Repository: [
    ...BASE_NODE_PROPERTIES,
    "provider",
    "url",
    "default_branch",
    "has_default_branch",
  ],
  Service: [
    ...BASE_NODE_PROPERTIES,
    "name",
    "criticality",
    "internet_exposed",
    "has_internet_exposed",
    "data_sensitivity",
    "has_data_sensitivity",
  ],
  Build: [
    ...BASE_NODE_PROPERTIES,
    "provider",
    "build_number",
    "commit_sha",
    "started_at",
    "completed_at",
    "has_completed_at",
  ],
  Artifact: [
    ...BASE_NODE_PROPERTIES,
    "digest",
    "media_type",
  ],
  Deployment: [
    ...BASE_NODE_PROPERTIES,
    "environment",
    "deployed_at",
    "removed_at",
    "has_removed_at",
  ],
  Maintainer: [
    ...BASE_NODE_PROPERTIES,
    "handle",
    "email",
    "has_email",
  ],
  Credential: [
    ...BASE_NODE_PROPERTIES,
    "credential_type",
    "scopes_json",
    "status",
    "expires_at",
    "has_expires_at",
  ],
  CIWorkflow: [
    ...BASE_NODE_PROPERTIES,
    "provider",
    "path",
  ],
  Organization: [
    ...BASE_NODE_PROPERTIES,
    "name",
    "provider",
    "has_provider",
  ],
  Incident: [
    ...BASE_NODE_PROPERTIES,
    "title",
    "status",
    "interval_start",
    "interval_end",
    "has_interval_end",
  ],
  Evidence: [
    ...BASE_NODE_PROPERTIES,
    "source_type",
    "source_uri",
    "collector_version",
    "confidence",
    "detail",
    "incident_id",
    "has_incident_id",
  ],
  Control: [
    ...BASE_NODE_PROPERTIES,
    "action",
    "status",
    "estimated_cost",
    "has_estimated_cost",
    "estimated_minutes",
    "has_estimated_minutes",
    "reversible",
  ],
} as const satisfies Record<NodeKind, readonly string[]>;

const CANONICAL_EDGE_PROPERTIES = [
  "logical_id",
  "kind",
  "source_id",
  "target_id",
  "observed_at",
  "derived",
  "identity_discriminator",
  "evidence_ids_json",
  "schema_version",
  "payload_hash",
] as const;

const DECLARATION_EDGE_PROPERTIES = [
  ...CANONICAL_EDGE_PROPERTIES,
  "declared_range",
  "dependency_type",
  "workspace_path",
  "has_workspace_path",
] as const;

const DEPENDENCY_EDGE_PROPERTIES = [
  ...CANONICAL_EDGE_PROPERTIES,
  "dependency_type",
  "declared_range",
  "has_declared_range",
  "lockfile_path",
  "has_lockfile_path",
  "integrity",
  "has_integrity",
] as const;

const DERIVED_EDGE_PROPERTIES = [
  "logical_id",
  "kind",
  "source_id",
  "target_id",
  "observed_at",
  "derived",
  "derived_from",
  "derived_from_logical_id",
  "generated_at",
  "generator_version",
  "schema_version",
  "payload_hash",
] as const;

export const EDGE_PROPERTY_KEYS = {
  HAS_VERSION: CANONICAL_EDGE_PROPERTIES,
  DECLARES_DEPENDENCY: DECLARATION_EDGE_PROPERTIES,
  DEPENDS_ON: DEPENDENCY_EDGE_PROPERTIES,
  CONTAINS: CANONICAL_EDGE_PROPERTIES,
  TRIGGERS: CANONICAL_EDGE_PROPERTIES,
  PRODUCES: CANONICAL_EDGE_PROPERTIES,
  DEPLOYED_AS: CANONICAL_EDGE_PROPERTIES,
  RUNS: CANONICAL_EDGE_PROPERTIES,
  MAINTAINS: CANONICAL_EDGE_PROPERTIES,
  MEMBER_OF: CANONICAL_EDGE_PROPERTIES,
  OWNS: CANONICAL_EDGE_PROPERTIES,
  CAN_PUBLISH: CANONICAL_EDGE_PROPERTIES,
  CAN_ACCESS: CANONICAL_EDGE_PROPERTIES,
  CONTROLS: CANONICAL_EDGE_PROPERTIES,
  AFFECTS: CANONICAL_EDGE_PROPERTIES,
  SUPPORTS: CANONICAL_EDGE_PROPERTIES,
  TARGETS: CANONICAL_EDGE_PROPERTIES,
  USED_BY: DERIVED_EDGE_PROPERTIES,
} as const satisfies Record<GraphRelKind, readonly string[]>;

function fail(message: string): never {
  throw new Error(`HydraDB serialization failed: ${message}`);
}

function assertNever(value: never): never {
  return fail(`unsupported discriminated union member: ${String(value)}`);
}

function assertSafeId(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${field} must be a nonnegative safe integer`);
  }
}

function assertTimestamp(value: number, field: string): void {
  assertSafeId(value, field);
}

function assertFiniteNonnegative(value: number, field: string): void {
  if (!Number.isFinite(value) || value < 0) {
    fail(`${field} must be finite and nonnegative`);
  }
}

function assertText(value: string, field: string): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    fail(`${field} must be a nonempty string`);
  }
}

function validateLogicalId(value: string, field: string): string {
  const normalized = normalizeLogicalId(value);

  if (normalized !== value) {
    fail(`${field} must already be normalized`);
  }

  return normalized;
}

function encodeIdSet(
  values: readonly number[],
  field: string,
): string {
  const sorted = [...values].sort((left, right) => left - right);

  for (let index = 0; index < sorted.length; index += 1) {
    assertSafeId(sorted[index], `${field}[${index}]`);

    if (index > 0 && sorted[index - 1] === sorted[index]) {
      fail(`${field} contains duplicate ID ${sorted[index]}`);
    }
  }

  return JSON.stringify(sorted);
}

function encodeStringSet(
  values: readonly string[],
  field: string,
): string {
  const sorted = [...values].sort((left, right) =>
    left.localeCompare(right),
  );

  for (let index = 0; index < sorted.length; index += 1) {
    assertText(sorted[index], `${field}[${index}]`);

    if (index > 0 && sorted[index - 1] === sorted[index]) {
      fail(`${field} contains duplicate value`);
    }
  }

  return JSON.stringify(sorted);
}

/**
 * Hashes a scalar record using sorted keys, making the result independent
 * of JavaScript object insertion order.
 */
export function hashHydraScalarRecord(
  record: Readonly<Record<string, HydraScalar>>,
  omittedKeys: readonly string[] = [],
): string {
  const omitted = new Set(omittedKeys);

  const canonicalEntries = Object.keys(record)
    .filter((key) => !omitted.has(key))
    .sort((left, right) => left.localeCompare(right))
    .map((key) => [key, record[key]] as const);

  return createHash("sha256")
    .update(JSON.stringify(canonicalEntries), "utf8")
    .digest("hex");
}

function finalizeProperties(
  expectedKeys: readonly string[],
  input: Record<string, HydraScalar>,
): HydraRow {
  const expectedWithoutHash = expectedKeys
    .filter((key) => key !== "payload_hash")
    .sort();

  const actualKeys = Object.keys(input).sort();

  if (
    expectedWithoutHash.length !== actualKeys.length ||
    expectedWithoutHash.some(
      (key, index) => key !== actualKeys[index],
    )
  ) {
    fail("serialized property shape does not match its static schema");
  }

  const output: Record<string, HydraScalar> = {
    ...input,
    payload_hash: "",
  };

  output.payload_hash = hashHydraScalarRecord(
    output,
    ["payload_hash"],
  );

  return output;
}

function serializeNodeProperties(node: GraphNode): HydraRow {
  assertSafeId(node.id, "node.id");
  assertTimestamp(node.observedAt, "node.observedAt");
  validateLogicalId(node.logicalId, "node.logicalId");

  const base: Record<string, HydraScalar> = {
    logical_id: node.logicalId,
    kind: node.kind,
    evidence_ids_json: encodeIdSet(
      node.evidenceIds,
      "node.evidenceIds",
    ),
    synthetic: node.synthetic,
    observed_at: node.observedAt,
    schema_version: HYDRA_SCHEMA_VERSION,
  };

  let specific: Record<string, HydraScalar>;

  switch (node.kind) {
    case "Package":
      assertText(node.name, "Package.name");
      specific = {
        ecosystem: node.ecosystem,
        name: node.name,
      };
      break;

    case "PackageVersion":
      assertText(node.packageName, "PackageVersion.packageName");
      assertText(node.version, "PackageVersion.version");

      if (node.publishedAt !== undefined) {
        assertTimestamp(
          node.publishedAt,
          "PackageVersion.publishedAt",
        );
      }

      specific = {
        ecosystem: node.ecosystem,
        package_name: node.packageName,
        version: node.version,
        published_at: node.publishedAt ?? 0,
        has_published_at: node.publishedAt !== undefined,
      };
      break;

    case "Repository":
      assertText(node.url, "Repository.url");

      if (node.defaultBranch !== undefined) {
        assertText(node.defaultBranch, "Repository.defaultBranch");
      }

      specific = {
        provider: node.provider,
        url: node.url,
        default_branch: node.defaultBranch ?? "",
        has_default_branch: node.defaultBranch !== undefined,
      };
      break;

    case "Service":
      assertText(node.name, "Service.name");
      specific = {
        name: node.name,
        criticality: node.criticality,
        internet_exposed: node.internetExposed ?? false,
        has_internet_exposed:
          node.internetExposed !== undefined,
        data_sensitivity: node.dataSensitivity ?? "",
        has_data_sensitivity:
          node.dataSensitivity !== undefined,
      };
      break;

    case "Build":
      assertText(node.provider, "Build.provider");
      assertText(node.buildNumber, "Build.buildNumber");
      assertText(node.commitSha, "Build.commitSha");
      assertTimestamp(node.startedAt, "Build.startedAt");

      if (node.completedAt !== undefined) {
        assertTimestamp(node.completedAt, "Build.completedAt");
      }

      specific = {
        provider: node.provider,
        build_number: node.buildNumber,
        commit_sha: node.commitSha,
        started_at: node.startedAt,
        completed_at: node.completedAt ?? 0,
        has_completed_at: node.completedAt !== undefined,
      };
      break;

    case "Artifact":
      assertText(node.digest, "Artifact.digest");
      assertText(node.mediaType, "Artifact.mediaType");
      specific = {
        digest: node.digest,
        media_type: node.mediaType,
      };
      break;

    case "Deployment":
      assertText(node.environment, "Deployment.environment");
      assertTimestamp(node.deployedAt, "Deployment.deployedAt");

      if (node.removedAt !== undefined) {
        assertTimestamp(node.removedAt, "Deployment.removedAt");
      }

      specific = {
        environment: node.environment,
        deployed_at: node.deployedAt,
        removed_at: node.removedAt ?? 0,
        has_removed_at: node.removedAt !== undefined,
      };
      break;

    case "Maintainer":
      assertText(node.handle, "Maintainer.handle");

      if (node.email !== undefined) {
        assertText(node.email, "Maintainer.email");
      }

      specific = {
        handle: node.handle,
        email: node.email ?? "",
        has_email: node.email !== undefined,
      };
      break;

    case "Credential":
      if (node.expiresAt !== undefined) {
        assertTimestamp(node.expiresAt, "Credential.expiresAt");
      }

      specific = {
        credential_type: node.credentialType,
        scopes_json: encodeStringSet(
          node.scopes,
          "Credential.scopes",
        ),
        status: node.status,
        expires_at: node.expiresAt ?? 0,
        has_expires_at: node.expiresAt !== undefined,
      };
      break;

    case "CIWorkflow":
      assertText(node.path, "CIWorkflow.path");
      specific = {
        provider: node.provider,
        path: node.path,
      };
      break;

    case "Organization":
      assertText(node.name, "Organization.name");

      if (node.provider !== undefined) {
        assertText(node.provider, "Organization.provider");
      }

      specific = {
        name: node.name,
        provider: node.provider ?? "",
        has_provider: node.provider !== undefined,
      };
      break;

    case "Incident":
      assertText(node.title, "Incident.title");
      assertTimestamp(
        node.intervalStart,
        "Incident.intervalStart",
      );

      if (node.intervalEnd !== null) {
        assertTimestamp(node.intervalEnd, "Incident.intervalEnd");

        if (node.intervalEnd < node.intervalStart) {
          fail("Incident.intervalEnd precedes intervalStart");
        }
      }

      specific = {
        title: node.title,
        status: node.status,
        interval_start: node.intervalStart,
        interval_end: node.intervalEnd ?? 0,
        has_interval_end: node.intervalEnd !== null,
      };
      break;

    case "Evidence":
      assertText(node.sourceUri, "Evidence.sourceUri");
      assertText(
        node.collectorVersion,
        "Evidence.collectorVersion",
      );

      if (
        !Number.isFinite(node.confidence) ||
        node.confidence < 0 ||
        node.confidence > 1
      ) {
        fail("Evidence.confidence must be between 0 and 1");
      }

      if (node.incidentId !== undefined) {
        assertSafeId(node.incidentId, "Evidence.incidentId");
      }

      specific = {
        source_type: node.sourceType,
        source_uri: node.sourceUri,
        collector_version: node.collectorVersion,
        confidence: node.confidence,
        detail: node.detail,
        incident_id: node.incidentId ?? 0,
        has_incident_id: node.incidentId !== undefined,
      };
      break;

    case "Control":
      if (node.estimatedCost !== undefined) {
        assertFiniteNonnegative(
          node.estimatedCost,
          "Control.estimatedCost",
        );
      }

      if (node.estimatedMinutes !== undefined) {
        assertFiniteNonnegative(
          node.estimatedMinutes,
          "Control.estimatedMinutes",
        );
      }

      specific = {
        action: node.action,
        status: node.status,
        estimated_cost: node.estimatedCost ?? 0,
        has_estimated_cost: node.estimatedCost !== undefined,
        estimated_minutes: node.estimatedMinutes ?? 0,
        has_estimated_minutes:
          node.estimatedMinutes !== undefined,
        reversible: node.reversible,
      };
      break;

    default:
      return assertNever(node);
  }

  return finalizeProperties(
    NODE_PROPERTY_KEYS[node.kind],
    {
      ...base,
      ...specific,
    },
  );
}

function serializeCanonicalEdgeProperties(
  edge: CanonicalEdge,
): HydraRow {
  const base: Record<string, HydraScalar> = {
    logical_id: edge.logicalId,
    kind: edge.kind,
    source_id: edge.sourceId,
    target_id: edge.targetId,
    observed_at: edge.observedAt,
    derived: false,
    identity_discriminator: edge.identityDiscriminator,
    evidence_ids_json: encodeIdSet(
      edge.evidenceIds,
      "edge.evidenceIds",
    ),
    schema_version: HYDRA_SCHEMA_VERSION,
  };

  switch (edge.kind) {
    case "DECLARES_DEPENDENCY":
      assertText(
        edge.declaredRange,
        "DECLARES_DEPENDENCY.declaredRange",
      );

      return finalizeProperties(
        EDGE_PROPERTY_KEYS.DECLARES_DEPENDENCY,
        {
          ...base,
          declared_range: edge.declaredRange,
          dependency_type: edge.dependencyType,
          workspace_path: edge.workspacePath ?? "",
          has_workspace_path:
            edge.workspacePath !== undefined,
        },
      );

    case "DEPENDS_ON":
      return finalizeProperties(
        EDGE_PROPERTY_KEYS.DEPENDS_ON,
        {
          ...base,
          dependency_type: edge.dependencyType,
          declared_range: edge.declaredRange ?? "",
          has_declared_range:
            edge.declaredRange !== undefined,
          lockfile_path: edge.lockfilePath ?? "",
          has_lockfile_path:
            edge.lockfilePath !== undefined,
          integrity: edge.integrity ?? "",
          has_integrity: edge.integrity !== undefined,
        },
      );

    default:
      return finalizeProperties(
        EDGE_PROPERTY_KEYS[edge.kind],
        base,
      );
  }
}

function serializeEdgeProperties(edge: GraphEdge): HydraRow {
  assertSafeId(edge.id, "edge.id");
  assertSafeId(edge.sourceId, "edge.sourceId");
  assertSafeId(edge.targetId, "edge.targetId");
  assertTimestamp(edge.observedAt, "edge.observedAt");
  validateLogicalId(edge.logicalId, "edge.logicalId");

  if (edge.kind !== "USED_BY") {
    assertText(
      edge.identityDiscriminator,
      "edge.identityDiscriminator",
    );

    return serializeCanonicalEdgeProperties(edge);
  }

  assertSafeId(edge.derivedFrom, "USED_BY.derivedFrom");
  assertTimestamp(edge.generatedAt, "USED_BY.generatedAt");
  validateLogicalId(
    edge.derivedFromLogicalId,
    "USED_BY.derivedFromLogicalId",
  );
  assertText(
    edge.generatorVersion,
    "USED_BY.generatorVersion",
  );

  return finalizeProperties(
    EDGE_PROPERTY_KEYS.USED_BY,
    {
      logical_id: edge.logicalId,
      kind: edge.kind,
      source_id: edge.sourceId,
      target_id: edge.targetId,
      observed_at: edge.observedAt,
      derived: true,
      derived_from: edge.derivedFrom,
      derived_from_logical_id:
        edge.derivedFromLogicalId,
      generated_at: edge.generatedAt,
      generator_version: edge.generatorVersion,
      schema_version: HYDRA_SCHEMA_VERSION,
    },
  );
}

export function serializeHydraNode(
  node: GraphNode,
): HydraNodeRow {
  return {
    vertex: node.id,
    ...serializeNodeProperties(node),
  };
}

export function serializeHydraEdge(
  edge: GraphEdge,
): HydraEdgeRow {
  return {
    relationship_vertex: edge.id,
    source_vertex: edge.sourceId,
    destination_vertex: edge.targetId,
    ...serializeEdgeProperties(edge),
  };
}

function compareIds(
  left: { readonly id: number },
  right: { readonly id: number },
): number {
  if (left.id < right.id) {
    return -1;
  }

  if (left.id > right.id) {
    return 1;
  }

  return 0;
}

export function serializeGraphBatch(
  batch: GraphBatch,
): SerializedHydraBatch {
  const nodeKindById = new Map<number, NodeKind>();

  for (const node of batch.nodes) {
    if (nodeKindById.has(node.id)) {
      fail("batch contains duplicate node IDs");
    }

    nodeKindById.set(node.id, node.kind);
  }

  const mutableNodeGroups = new Map<
    string,
    {
      label: NodeKind;
      propertyKeys: readonly string[];
      rows: HydraNodeRow[];
    }
  >();

  for (const node of [...batch.nodes].sort(compareIds)) {
    const label = NODE_LABEL_BY_KIND[node.kind];
    const shapeId = `node.${label}.v${HYDRA_SCHEMA_VERSION}`;
    const row = serializeHydraNode(node);

    const group = mutableNodeGroups.get(shapeId) ?? {
      label,
      propertyKeys: NODE_PROPERTY_KEYS[node.kind],
      rows: [],
    };

    group.rows.push(row);
    mutableNodeGroups.set(shapeId, group);
  }

  const mutableEdgeGroups = new Map<
    string,
    {
      sourceLabel: NodeKind;
      destinationLabel: NodeKind;
      relationshipType: GraphRelKind;
      propertyKeys: readonly string[];
      rows: HydraEdgeRow[];
      derived: boolean;
    }
  >();

  let canonicalEdgeCount = 0;
  let derivedEdgeCount = 0;

  for (const edge of [...batch.edges].sort(compareIds)) {
    const sourceLabel = nodeKindById.get(edge.sourceId);
    const destinationLabel = nodeKindById.get(edge.targetId);

    if (sourceLabel === undefined) {
      fail("edge references a missing source node");
    }

    if (destinationLabel === undefined) {
      fail("edge references a missing destination node");
    }

    const relationshipType = EDGE_TYPE_BY_KIND[edge.kind];
    const propertyKeys = EDGE_PROPERTY_KEYS[edge.kind];

    const shapeId = [
      "edge",
      sourceLabel,
      relationshipType,
      destinationLabel,
      `v${HYDRA_SCHEMA_VERSION}`,
    ].join(".");

    const group = mutableEdgeGroups.get(shapeId) ?? {
      sourceLabel,
      destinationLabel,
      relationshipType,
      propertyKeys,
      rows: [],
      derived: edge.kind === "USED_BY",
    };

    group.rows.push(serializeHydraEdge(edge));
    mutableEdgeGroups.set(shapeId, group);

    if (edge.kind === "USED_BY") {
      derivedEdgeCount += 1;
    } else {
      canonicalEdgeCount += 1;
    }
  }

  const nodeGroups: HydraNodeGroup[] = [
    ...mutableNodeGroups.entries(),
  ]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([shapeId, group]) => ({
      shapeId,
      label: group.label,
      propertyKeys: group.propertyKeys,
      rows: group.rows,
    }));

  const allEdgeGroups = [...mutableEdgeGroups.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([shapeId, group]) => ({
      shapeId,
      sourceLabel: group.sourceLabel,
      destinationLabel: group.destinationLabel,
      relationshipType: group.relationshipType,
      propertyKeys: group.propertyKeys,
      rows: group.rows,
      derived: group.derived,
    }));

  const canonicalEdgeGroups: HydraEdgeGroup[] =
    allEdgeGroups
      .filter((group) => !group.derived)
      .map(({ derived: _derived, ...group }) => group);

  const derivedEdgeGroups: HydraEdgeGroup[] =
    allEdgeGroups
      .filter((group) => group.derived)
      .map(({ derived: _derived, ...group }) => group);

  const batchDigest = createHash("sha256");

  for (const group of nodeGroups) {
    batchDigest.update(group.shapeId, "utf8");

    for (const row of group.rows) {
      batchDigest.update(
        hashHydraScalarRecord(row),
        "utf8",
      );
    }
  }

  for (const group of [
    ...canonicalEdgeGroups,
    ...derivedEdgeGroups,
  ]) {
    batchDigest.update(group.shapeId, "utf8");

    for (const row of group.rows) {
      batchDigest.update(
        hashHydraScalarRecord(row),
        "utf8",
      );
    }
  }

  return {
    schemaVersion: HYDRA_SCHEMA_VERSION,
    batchHash: batchDigest.digest("hex"),
    nodeGroups,
    canonicalEdgeGroups,
    derivedEdgeGroups,
    nodeCount: batch.nodes.length,
    canonicalEdgeCount,
    derivedEdgeCount,
  };
}
