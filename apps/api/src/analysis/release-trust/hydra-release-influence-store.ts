import {
  randomUUID,
} from "node:crypto";

import type {
  Driver,
  Session,
} from "neo4j-driver";

import {
  toHydraParameters,
} from "../../db/hydra-parameters.js";
import {
  evaluateReleaseFirewall,
} from "./release-influence-firewall.js";
import {
  RELEASE_INFLUENCE_EDGE_KINDS,
  RELEASE_INFLUENCE_NODE_KINDS,
  ReleaseFirewallInputError,
} from "./release-influence-types.js";
import type {
  ReleaseFirewallInput,
  ReleaseInfluenceEdge,
  ReleaseInfluenceEdgeKind,
  ReleaseInfluenceNode,
  ReleaseInfluenceNodeKind,
  ReleaseNode,
  ReleasePipelineNode,
  ReleaseTrustBoundary,
  ReleaseTrustLevel,
} from "./release-influence-types.js";

const DEFAULT_STATEMENT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_NODES = 10_000;
const DEFAULT_MAX_EDGES = 25_000;
const MAX_STATEMENT_TIMEOUT_MS = 120_000;
const MAX_CONFIGURED_NODES = 100_000;
const MAX_CONFIGURED_EDGES = 250_000;
const SNAPSHOT_ID_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const CLAIM_SNAPSHOT_QUERY = [
  "MERGE (snapshot:ReleaseInfluenceSnapshot {snapshot_id: $snapshot_id})",
  "ON CREATE SET snapshot.write_token = $write_token,",
  "              snapshot.state = 'writing',",
  "              snapshot.schema_version = 1,",
  "              snapshot.node_count = $node_count,",
  "              snapshot.edge_count = $edge_count,",
  "              snapshot.release_ids_json = $release_ids_json,",
  "              snapshot.persisted_at = $persisted_at",
  "RETURN snapshot.write_token AS write_token, snapshot.state AS state",
].join("\n");

const WRITE_NODES_QUERY = [
  "MATCH (snapshot:ReleaseInfluenceSnapshot {snapshot_id: $snapshot_id, write_token: $write_token, state: 'writing'})",
  "UNWIND $rows AS row",
  "CREATE (entity:ReleaseInfluenceEntity {",
  "  snapshot_id: $snapshot_id,",
  "  entity_id: row.id,",
  "  kind: row.kind,",
  "  label: row.label,",
  "  trust: row.trust,",
  "  evidence_ids_json: row.evidence_ids_json,",
  "  observed_at: row.observed_at,",
  "  metadata_json: row.metadata_json",
  "})",
  "SET entity.subject_ecosystem = row.subject_ecosystem,",
  "    entity.subject_package_name = row.subject_package_name,",
  "    entity.subject_version = row.subject_version,",
  "    entity.subject_artifact_digest = row.subject_artifact_digest",
  "CREATE (snapshot)-[:CONTAINS_RELEASE_INFLUENCE]->(entity)",
  "RETURN count(entity) AS written",
].join("\n");

const WRITE_EDGES_QUERY = [
  "UNWIND $rows AS row",
  "MATCH (source:ReleaseInfluenceEntity {snapshot_id: $snapshot_id, entity_id: row.source_id})",
  "MATCH (target:ReleaseInfluenceEntity {snapshot_id: $snapshot_id, entity_id: row.target_id})",
  "CREATE (source)-[edge:RELEASE_INFLUENCE {",
  "  snapshot_id: $snapshot_id,",
  "  edge_id: row.id,",
  "  kind: row.kind,",
  "  trust: row.trust,",
  "  boundary: row.boundary,",
  "  evidence_ids_json: row.evidence_ids_json,",
  "  observed_at: row.observed_at,",
  "  metadata_json: row.metadata_json",
  "}]->(target)",
  "RETURN count(edge) AS written",
].join("\n");

const FINALIZE_SNAPSHOT_QUERY = [
  "MATCH (snapshot:ReleaseInfluenceSnapshot {snapshot_id: $snapshot_id, write_token: $write_token, state: 'writing'})",
  "SET snapshot.state = 'ready'",
  "RETURN snapshot.state AS state",
].join("\n");

const FAIL_SNAPSHOT_QUERY = [
  "MATCH (snapshot:ReleaseInfluenceSnapshot {snapshot_id: $snapshot_id, write_token: $write_token, state: 'writing'})",
  "SET snapshot.state = 'failed'",
  "RETURN snapshot.state AS state",
].join("\n");

const READ_SNAPSHOT_QUERY = [
  "MATCH (snapshot:ReleaseInfluenceSnapshot {snapshot_id: $snapshot_id})",
  "RETURN snapshot.state AS state,",
  "       snapshot.schema_version AS schema_version,",
  "       snapshot.node_count AS node_count,",
  "       snapshot.edge_count AS edge_count,",
  "       snapshot.release_ids_json AS release_ids_json,",
  "       snapshot.persisted_at AS persisted_at",
  "LIMIT 2",
].join("\n");

function buildReadNodesQuery(fetchLimit: number): string {
  return [
    "MATCH (:ReleaseInfluenceSnapshot {snapshot_id: $snapshot_id, state: 'ready'})",
    "      -[:CONTAINS_RELEASE_INFLUENCE]->",
    "      (entity:ReleaseInfluenceEntity {snapshot_id: $snapshot_id})",
    "RETURN entity.entity_id AS id,",
    "       entity.kind AS kind,",
    "       entity.label AS label,",
    "       entity.trust AS trust,",
    "       entity.evidence_ids_json AS evidence_ids_json,",
    "       entity.observed_at AS observed_at,",
    "       entity.metadata_json AS metadata_json,",
    "       entity.subject_ecosystem AS subject_ecosystem,",
    "       entity.subject_package_name AS subject_package_name,",
    "       entity.subject_version AS subject_version,",
    "       entity.subject_artifact_digest AS subject_artifact_digest",
    "ORDER BY id",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildReadEdgesQuery(fetchLimit: number): string {
  return [
    "MATCH (source:ReleaseInfluenceEntity {snapshot_id: $snapshot_id})",
    "      -[edge:RELEASE_INFLUENCE {snapshot_id: $snapshot_id}]->",
    "      (target:ReleaseInfluenceEntity {snapshot_id: $snapshot_id})",
    "RETURN edge.edge_id AS id,",
    "       edge.kind AS kind,",
    "       source.entity_id AS source_id,",
    "       target.entity_id AS target_id,",
    "       edge.trust AS trust,",
    "       edge.boundary AS boundary,",
    "       edge.evidence_ids_json AS evidence_ids_json,",
    "       edge.observed_at AS observed_at,",
    "       edge.metadata_json AS metadata_json",
    "ORDER BY id",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

interface RecordLike {
  get(key: string): unknown;
}

interface ResultLike {
  readonly records: readonly RecordLike[];
}

export type ReleaseInfluenceStoreErrorCode =
  | "SNAPSHOT_INVALID"
  | "SNAPSHOT_EXISTS"
  | "SNAPSHOT_NOT_FOUND"
  | "SNAPSHOT_NOT_READY"
  | "SNAPSHOT_LIMIT_EXCEEDED"
  | "DATABASE_QUERY_FAILED"
  | "DATABASE_RESULT_INVALID"
  | "SNAPSHOT_CORRUPT";

export class ReleaseInfluenceStoreError extends Error {
  public constructor(
    readonly code: ReleaseInfluenceStoreErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(
      message,
      cause === undefined ? undefined : { cause },
    );
    this.name = "ReleaseInfluenceStoreError";
  }
}

export interface HydraReleaseInfluenceStoreOptions {
  readonly statementTimeoutMs?: number;
  readonly maxNodes?: number;
  readonly maxEdges?: number;
  readonly sessionFactory?: () => Session;
  readonly clock?: () => number;
  readonly writeTokenFactory?: () => string;
}

export interface PersistedReleaseInfluenceSnapshot {
  readonly snapshotId: string;
  readonly persistedAt: number;
  readonly input: ReleaseFirewallInput;
}

export interface PersistReleaseInfluenceResult {
  readonly snapshotId: string;
  readonly persistedAt: number;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly state: "ready";
}

function assertPositiveInteger(
  value: number,
  field: string,
  maximum: number,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximum
  ) {
    throw new RangeError(
      `${field} must be a positive safe integer not greater than ${maximum}`,
    );
  }
}

function assertSnapshotId(snapshotId: string): void {
  if (!SNAPSHOT_ID_PATTERN.test(snapshotId)) {
    throw new ReleaseInfluenceStoreError(
      "SNAPSHOT_INVALID",
      "snapshotId must be 1-128 safe identifier characters",
    );
  }
}

function asResultLike(value: unknown): ResultLike {
  if (
    typeof value !== "object" ||
    value === null ||
    !("records" in value) ||
    !Array.isArray(value.records)
  ) {
    throw new ReleaseInfluenceStoreError(
      "DATABASE_RESULT_INVALID",
      "HydraDB returned a result without a records array",
    );
  }

  for (const record of value.records) {
    if (
      typeof record !== "object" ||
      record === null ||
      !("get" in record) ||
      typeof record.get !== "function"
    ) {
      throw new ReleaseInfluenceStoreError(
        "DATABASE_RESULT_INVALID",
        "HydraDB returned an invalid record",
      );
    }
  }

  return value as ResultLike;
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ReleaseInfluenceStoreError(
      "SNAPSHOT_CORRUPT",
      `Stored ${field} is not a nonempty string`,
    );
  }

  return value;
}

function asNullableString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }

  return asString(value, field);
}

function asSafeInteger(value: unknown, field: string): number {
  let numberValue: number;

  if (typeof value === "number") {
    numberValue = value;
  } else if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    numberValue = value.toNumber();
  } else {
    throw new ReleaseInfluenceStoreError(
      "SNAPSHOT_CORRUPT",
      `Stored ${field} is not an integer`,
    );
  }

  if (!Number.isSafeInteger(numberValue) || numberValue < 0) {
    throw new ReleaseInfluenceStoreError(
      "SNAPSHOT_CORRUPT",
      `Stored ${field} is outside the safe nonnegative range`,
    );
  }

  return numberValue;
}

function parseJson(value: unknown, field: string): unknown {
  const text = asString(value, field);

  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new ReleaseInfluenceStoreError(
      "SNAPSHOT_CORRUPT",
      `Stored ${field} is not valid JSON`,
      error,
    );
  }
}

function parseEvidenceIds(
  value: unknown,
  field: string,
): readonly number[] {
  const parsed = parseJson(value, field);

  if (
    !Array.isArray(parsed) ||
    parsed.some(
      (entry) =>
        !Number.isSafeInteger(entry) ||
        entry < 0,
    )
  ) {
    throw new ReleaseInfluenceStoreError(
      "SNAPSHOT_CORRUPT",
      `Stored ${field} is not an array of safe IDs`,
    );
  }

  return Object.freeze([...parsed] as number[]);
}

function parseMetadata(
  value: unknown,
  field: string,
): Readonly<Record<string, string | number | boolean>> | undefined {
  const parsed = parseJson(value, field);

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed)
  ) {
    throw new ReleaseInfluenceStoreError(
      "SNAPSHOT_CORRUPT",
      `Stored ${field} is not a metadata object`,
    );
  }

  const metadata: Record<string, string | number | boolean> = {};

  for (const [key, entry] of Object.entries(parsed)) {
    if (
      typeof entry !== "string" &&
      typeof entry !== "number" &&
      typeof entry !== "boolean"
    ) {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_CORRUPT",
        `Stored ${field}.${key} has an unsupported value`,
      );
    }

    metadata[key] = entry;
  }

  return Object.keys(metadata).length === 0
    ? undefined
    : Object.freeze(metadata);
}

function asEnum<T extends string>(
  value: unknown,
  allowed: ReadonlySet<string>,
  field: string,
): T {
  const text = asString(value, field);

  if (!allowed.has(text)) {
    throw new ReleaseInfluenceStoreError(
      "SNAPSHOT_CORRUPT",
      `Stored ${field} has unsupported value ${text}`,
    );
  }

  return text as T;
}

const NODE_KIND_SET = new Set<string>(
  RELEASE_INFLUENCE_NODE_KINDS,
);
const EDGE_KIND_SET = new Set<string>(
  RELEASE_INFLUENCE_EDGE_KINDS,
);
const TRUST_SET = new Set<string>([
  "trusted",
  "untrusted",
  "unknown",
]);
const BOUNDARY_SET = new Set<string>([
  "same-trust-zone",
  "cross-trust-boundary",
  "unknown",
]);

function stableMetadataJson(
  metadata: Readonly<Record<string, string | number | boolean>> | undefined,
): string {
  if (metadata === undefined) {
    return "{}";
  }

  return JSON.stringify(
    Object.fromEntries(
      Object.entries(metadata).sort(
        ([left], [right]) => left.localeCompare(right),
      ),
    ),
  );
}

function nodeRow(node: ReleaseInfluenceNode): Readonly<Record<string, unknown>> {
  const release = node.kind === "release" ? node : undefined;

  return {
    id: node.id,
    kind: node.kind,
    label: node.label,
    trust: node.trust,
    evidence_ids_json: JSON.stringify(node.evidenceIds),
    observed_at: node.observedAt,
    metadata_json: stableMetadataJson(node.metadata),
    subject_ecosystem: release?.subject.ecosystem ?? null,
    subject_package_name: release?.subject.packageName ?? null,
    subject_version: release?.subject.version ?? null,
    subject_artifact_digest:
      release?.subject.artifactDigest ?? null,
  };
}

function edgeRow(edge: ReleaseInfluenceEdge): Readonly<Record<string, unknown>> {
  return {
    id: edge.id,
    kind: edge.kind,
    source_id: edge.sourceId,
    target_id: edge.targetId,
    trust: edge.trust,
    boundary: edge.boundary,
    evidence_ids_json: JSON.stringify(edge.evidenceIds),
    observed_at: edge.observedAt,
    metadata_json: stableMetadataJson(edge.metadata),
  };
}

function readNode(record: RecordLike): ReleaseInfluenceNode {
  const kind = asEnum<ReleaseInfluenceNodeKind>(
    record.get("kind"),
    NODE_KIND_SET,
    "node.kind",
  );
  const metadata = parseMetadata(
    record.get("metadata_json"),
    "node.metadata_json",
  );
  const common = {
    id: asSafeInteger(record.get("id"), "node.id"),
    kind,
    label: asString(record.get("label"), "node.label"),
    trust: asEnum<ReleaseTrustLevel>(
      record.get("trust"),
      TRUST_SET,
      "node.trust",
    ),
    evidenceIds: parseEvidenceIds(
      record.get("evidence_ids_json"),
      "node.evidence_ids_json",
    ),
    observedAt: asSafeInteger(
      record.get("observed_at"),
      "node.observed_at",
    ),
    ...(metadata === undefined ? {} : { metadata }),
  };

  if (kind === "release") {
    const artifactDigest = asNullableString(
      record.get("subject_artifact_digest"),
      "node.subject_artifact_digest",
    );
    const node: ReleaseNode = {
      ...common,
      kind: "release",
      subject: Object.freeze({
        ecosystem: asString(
          record.get("subject_ecosystem"),
          "node.subject_ecosystem",
        ),
        packageName: asString(
          record.get("subject_package_name"),
          "node.subject_package_name",
        ),
        version: asString(
          record.get("subject_version"),
          "node.subject_version",
        ),
        ...(artifactDigest === undefined
          ? {}
          : { artifactDigest }),
      }),
    };

    return Object.freeze(node);
  }

  const node: ReleasePipelineNode = {
    ...common,
    kind,
  };

  return Object.freeze(node);
}

function readEdge(record: RecordLike): ReleaseInfluenceEdge {
  const metadata = parseMetadata(
    record.get("metadata_json"),
    "edge.metadata_json",
  );
  const edge: ReleaseInfluenceEdge = {
    id: asSafeInteger(record.get("id"), "edge.id"),
    kind: asEnum<ReleaseInfluenceEdgeKind>(
      record.get("kind"),
      EDGE_KIND_SET,
      "edge.kind",
    ),
    sourceId: asSafeInteger(
      record.get("source_id"),
      "edge.source_id",
    ),
    targetId: asSafeInteger(
      record.get("target_id"),
      "edge.target_id",
    ),
    trust: asEnum<ReleaseTrustLevel>(
      record.get("trust"),
      TRUST_SET,
      "edge.trust",
    ),
    boundary: asEnum<ReleaseTrustBoundary>(
      record.get("boundary"),
      BOUNDARY_SET,
      "edge.boundary",
    ),
    evidenceIds: parseEvidenceIds(
      record.get("evidence_ids_json"),
      "edge.evidence_ids_json",
    ),
    observedAt: asSafeInteger(
      record.get("observed_at"),
      "edge.observed_at",
    ),
    ...(metadata === undefined ? {} : { metadata }),
  };

  return Object.freeze(edge);
}

export class HydraReleaseInfluenceStore {
  private readonly statementTimeoutMs: number;
  private readonly maxNodes: number;
  private readonly maxEdges: number;
  private readonly sessionFactory: () => Session;
  private readonly clock: () => number;
  private readonly writeTokenFactory: () => string;

  public constructor(
    driver: Driver,
    options: HydraReleaseInfluenceStoreOptions = {},
  ) {
    this.statementTimeoutMs =
      options.statementTimeoutMs ?? DEFAULT_STATEMENT_TIMEOUT_MS;
    this.maxNodes = options.maxNodes ?? DEFAULT_MAX_NODES;
    this.maxEdges = options.maxEdges ?? DEFAULT_MAX_EDGES;

    assertPositiveInteger(
      this.statementTimeoutMs,
      "statementTimeoutMs",
      MAX_STATEMENT_TIMEOUT_MS,
    );
    assertPositiveInteger(
      this.maxNodes,
      "maxNodes",
      MAX_CONFIGURED_NODES,
    );
    assertPositiveInteger(
      this.maxEdges,
      "maxEdges",
      MAX_CONFIGURED_EDGES,
    );

    this.sessionFactory =
      options.sessionFactory ?? (() => driver.session());
    this.clock = options.clock ?? Date.now;
    this.writeTokenFactory =
      options.writeTokenFactory ?? randomUUID;
  }

  public async persistSnapshot(
    snapshotId: string,
    input: ReleaseFirewallInput,
  ): Promise<PersistReleaseInfluenceResult> {
    assertSnapshotId(snapshotId);

    // The pure evaluator is the canonical runtime validator.
    evaluateReleaseFirewall(input);

    if (input.graph.nodes.length > this.maxNodes) {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_LIMIT_EXCEEDED",
        `Snapshot contains more than ${String(this.maxNodes)} nodes`,
      );
    }

    if (input.graph.edges.length > this.maxEdges) {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_LIMIT_EXCEEDED",
        `Snapshot contains more than ${String(this.maxEdges)} edges`,
      );
    }

    const persistedAt = this.clock();

    if (!Number.isSafeInteger(persistedAt) || persistedAt < 0) {
      throw new RangeError(
        "clock must return a nonnegative safe Unix epoch",
      );
    }

    const writeToken = this.writeTokenFactory();

    if (typeof writeToken !== "string" || writeToken.length < 1) {
      throw new RangeError("writeTokenFactory must return a nonempty string");
    }

    let claimed = false;

    try {
      const claimRecords = await this.runQuery(
        CLAIM_SNAPSHOT_QUERY,
        {
          snapshot_id: snapshotId,
          write_token: writeToken,
          node_count: input.graph.nodes.length,
          edge_count: input.graph.edges.length,
          release_ids_json: JSON.stringify(input.releaseNodeIds),
          persisted_at: persistedAt,
        },
        "claim-release-influence-snapshot",
      );

      if (claimRecords.length !== 1) {
        throw new ReleaseInfluenceStoreError(
          "DATABASE_RESULT_INVALID",
          "HydraDB did not return exactly one snapshot claim",
        );
      }

      const returnedToken = asString(
        claimRecords[0].get("write_token"),
        "snapshot.write_token",
      );
      const returnedState = asString(
        claimRecords[0].get("state"),
        "snapshot.state",
      );

      if (
        returnedToken !== writeToken ||
        returnedState !== "writing"
      ) {
        throw new ReleaseInfluenceStoreError(
          "SNAPSHOT_EXISTS",
          `Release influence snapshot ${snapshotId} already exists`,
        );
      }

      claimed = true;

      const nodeRecords = await this.runQuery(
        WRITE_NODES_QUERY,
        {
          snapshot_id: snapshotId,
          write_token: writeToken,
          rows: input.graph.nodes.map(nodeRow),
        },
        "write-release-influence-nodes",
      );

      this.assertWrittenCount(
        nodeRecords,
        input.graph.nodes.length,
        "nodes",
      );

      if (input.graph.edges.length > 0) {
        const edgeRecords = await this.runQuery(
          WRITE_EDGES_QUERY,
          {
            snapshot_id: snapshotId,
            rows: input.graph.edges.map(edgeRow),
          },
          "write-release-influence-edges",
        );

        this.assertWrittenCount(
          edgeRecords,
          input.graph.edges.length,
          "edges",
        );
      }

      const finalRecords = await this.runQuery(
        FINALIZE_SNAPSHOT_QUERY,
        {
          snapshot_id: snapshotId,
          write_token: writeToken,
        },
        "finalize-release-influence-snapshot",
      );

      if (
        finalRecords.length !== 1 ||
        finalRecords[0].get("state") !== "ready"
      ) {
        throw new ReleaseInfluenceStoreError(
          "DATABASE_RESULT_INVALID",
          "HydraDB did not finalize the release influence snapshot",
        );
      }

      return Object.freeze({
        snapshotId,
        persistedAt,
        nodeCount: input.graph.nodes.length,
        edgeCount: input.graph.edges.length,
        state: "ready" as const,
      });
    } catch (error) {
      if (claimed) {
        try {
          await this.runQuery(
            FAIL_SNAPSHOT_QUERY,
            {
              snapshot_id: snapshotId,
              write_token: writeToken,
            },
            "fail-release-influence-snapshot",
          );
        } catch {
          // Preserve the primary write failure.
        }
      }

      throw error;
    }
  }

  public async readSnapshot(
    snapshotId: string,
  ): Promise<PersistedReleaseInfluenceSnapshot> {
    assertSnapshotId(snapshotId);

    const metadataRecords = await this.runQuery(
      READ_SNAPSHOT_QUERY,
      { snapshot_id: snapshotId },
      "read-release-influence-snapshot",
    );

    if (metadataRecords.length === 0) {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_NOT_FOUND",
        `Release influence snapshot ${snapshotId} was not found`,
      );
    }

    if (metadataRecords.length !== 1) {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_CORRUPT",
        `Release influence snapshot ${snapshotId} is duplicated`,
      );
    }

    const metadata = metadataRecords[0];
    const state = asString(metadata.get("state"), "snapshot.state");

    if (state !== "ready") {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_NOT_READY",
        `Release influence snapshot ${snapshotId} is ${state}`,
      );
    }

    const schemaVersion = asSafeInteger(
      metadata.get("schema_version"),
      "snapshot.schema_version",
    );

    if (schemaVersion !== 1) {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_CORRUPT",
        `Unsupported release influence schema version ${String(schemaVersion)}`,
      );
    }

    const nodeCount = asSafeInteger(
      metadata.get("node_count"),
      "snapshot.node_count",
    );
    const edgeCount = asSafeInteger(
      metadata.get("edge_count"),
      "snapshot.edge_count",
    );

    if (nodeCount > this.maxNodes || edgeCount > this.maxEdges) {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_LIMIT_EXCEEDED",
        "Stored release influence snapshot exceeds configured read limits",
      );
    }

    const releaseNodeIds = parseEvidenceIds(
      metadata.get("release_ids_json"),
      "snapshot.release_ids_json",
    );
    const persistedAt = asSafeInteger(
      metadata.get("persisted_at"),
      "snapshot.persisted_at",
    );

    const [nodeRecords, edgeRecords] = await Promise.all([
      this.runQuery(
        buildReadNodesQuery(this.maxNodes + 1),
        { snapshot_id: snapshotId },
        "read-release-influence-nodes",
      ),
      this.runQuery(
        buildReadEdgesQuery(this.maxEdges + 1),
        { snapshot_id: snapshotId },
        "read-release-influence-edges",
      ),
    ]);

    if (
      nodeRecords.length !== nodeCount ||
      edgeRecords.length !== edgeCount
    ) {
      throw new ReleaseInfluenceStoreError(
        "SNAPSHOT_CORRUPT",
        "Stored release influence counts do not match snapshot metadata",
      );
    }

    const nodes = Object.freeze(nodeRecords.map(readNode));
    const edges = Object.freeze(edgeRecords.map(readEdge));
    const input: ReleaseFirewallInput = Object.freeze({
      graph: Object.freeze({ nodes, edges }),
      releaseNodeIds,
    });

    // Revalidate endpoint kinds, identities, trust and release roots after read.
    try {
      evaluateReleaseFirewall(input);
    } catch (error) {
      if (error instanceof ReleaseFirewallInputError) {
        throw new ReleaseInfluenceStoreError(
          "SNAPSHOT_CORRUPT",
          "Stored release influence graph failed integrity validation",
          error,
        );
      }

      throw error;
    }

    return Object.freeze({
      snapshotId,
      persistedAt,
      input,
    });
  }

  private assertWrittenCount(
    records: readonly RecordLike[],
    expected: number,
    entity: string,
  ): void {
    if (records.length !== 1) {
      throw new ReleaseInfluenceStoreError(
        "DATABASE_RESULT_INVALID",
        `HydraDB did not return a ${entity} write count`,
      );
    }

    const written = asSafeInteger(
      records[0].get("written"),
      `${entity}.written`,
    );

    if (written !== expected) {
      throw new ReleaseInfluenceStoreError(
        "DATABASE_RESULT_INVALID",
        `HydraDB wrote ${String(written)} of ${String(expected)} ${entity}`,
      );
    }
  }

  private async runQuery(
    query: string,
    parameters: Readonly<Record<string, unknown>>,
    operation: string,
  ): Promise<readonly RecordLike[]> {
    let session: Session;

    try {
      session = this.sessionFactory();
    } catch (error) {
      throw new ReleaseInfluenceStoreError(
        "DATABASE_QUERY_FAILED",
        `Could not open a HydraDB session for ${operation}`,
        error,
      );
    }

    let result: unknown;

    try {
      result = await session.run(
        query,
        toHydraParameters(parameters),
        {
          timeout: this.statementTimeoutMs,
          metadata: {
            "hydradb.caller.step": operation,
          },
        },
      );
    } catch (error) {
      try {
        await session.close();
      } catch {
        // Preserve the query failure.
      }

      throw new ReleaseInfluenceStoreError(
        "DATABASE_QUERY_FAILED",
        `HydraDB operation ${operation} failed`,
        error,
      );
    }

    try {
      await session.close();
    } catch (error) {
      throw new ReleaseInfluenceStoreError(
        "DATABASE_QUERY_FAILED",
        `HydraDB session close failed after ${operation}`,
        error,
      );
    }

    return asResultLike(result).records;
  }
}
