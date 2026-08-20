import type {
  Driver,
  Session,
} from "neo4j-driver";

import {
  toHydraParameters,
} from "../../db/hydra-parameters.js";

import {
  deserializeHydraEdge,
  deserializeHydraNode,
} from "../../db/hydra-deserializer.js";

import {
  EDGE_PROPERTY_KEYS,
  NODE_PROPERTY_KEYS,
  serializeHydraEdge,
  serializeHydraNode,
} from "../../db/hydra-serializer.js";

import type {
  HydraScalar,
} from "../../db/hydra-serializer.js";

import type {
  NodeId,
  UnixEpochMilliseconds,
} from "../../domain/schema.js";

const DEFAULT_STATEMENT_TIMEOUT_MS = 20_000;
const MAX_STATEMENT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_SUPERSEDED_SNAPSHOTS = 100;
const DEFAULT_MAX_CLOSED_EDGES = 25_000;

function projections(
  binding: string,
  propertyKeys: readonly string[],
  aliasPrefix: string,
): string {
  return propertyKeys
    .map(
      (property) =>
        `${binding}.${property} AS ${aliasPrefix}_${property}`,
    )
    .join(",\n       ");
}

/*
 * Only snapshots for this service that are still open and whose content
 * differs from the incoming snapshot may be superseded. Re-ingesting
 * identical content must not close anything, which keeps ingestion idempotent.
 */
function buildFindSupersededSnapshotsQuery(
  fetchLimit: number,
): string {
  return [
    "MATCH (snapshot:LockfileSnapshot {service_id: $service_id})",
    "WHERE snapshot.has_valid_until = false",
    "  AND snapshot.id <> $current_snapshot_id",
    "RETURN snapshot.id AS snapshot_vertex,",
    `       ${projections(
      "snapshot",
      NODE_PROPERTY_KEYS.LockfileSnapshot,
      "snapshot",
    )}`,
    "ORDER BY snapshot_vertex",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildFindOpenResolutionsQuery(
  fetchLimit: number,
): string {
  return [
    "MATCH (source)-[edge:DEPENDS_ON]->(target)",
    "WHERE edge.snapshot_id = $snapshot_id",
    "  AND edge.has_snapshot_id = true",
    "  AND edge.has_valid_from = true",
    "  AND edge.has_valid_until = false",
    "RETURN edge.id AS edge_vertex,",
    "       source.id AS source_vertex,",
    "       target.id AS target_vertex,",
    "       source.logical_id AS source_logical_id,",
    "       target.logical_id AS target_logical_id,",
    `       ${projections(
      "edge",
      EDGE_PROPERTY_KEYS.DEPENDS_ON,
      "edge",
    )}`,
    "ORDER BY edge_vertex",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

/*
 * Closing writes exactly three properties. payload_hash is recomputed by
 * re-serializing the whole entity, because the deserializer verifies it and a
 * blind property write would corrupt the row.
 */
const CLOSE_SNAPSHOT_QUERY = [
  "MATCH (snapshot:LockfileSnapshot {id: $id})",
  "WHERE snapshot.has_valid_until = false",
  "SET snapshot.valid_until = $valid_until,",
  "    snapshot.has_valid_until = true,",
  "    snapshot.payload_hash = $payload_hash",
  "RETURN snapshot.id AS id",
].join("\n");

const CLOSE_RESOLUTION_QUERY = [
  "MATCH ()-[edge:DEPENDS_ON {id: $id}]->()",
  "WHERE edge.has_valid_until = false",
  "SET edge.valid_until = $valid_until,",
  "    edge.has_valid_until = true,",
  "    edge.payload_hash = $payload_hash",
  "RETURN edge.id AS id",
].join("\n");

export type LockfileSnapshotStoreErrorCode =
  | "DATABASE_QUERY_FAILED"
  | "DATABASE_RESULT_INVALID"
  | "SNAPSHOT_HISTORY_CORRUPT"
  | "SNAPSHOT_HISTORY_LIMIT_EXCEEDED"
  | "INVALID_CLOSE_TIME";

export class LockfileSnapshotStoreError extends Error {
  public constructor(
    readonly code: LockfileSnapshotStoreErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(
      message,
      cause === undefined
        ? undefined
        : { cause },
    );

    this.name = "LockfileSnapshotStoreError";
  }
}

export interface CloseSupersededSnapshotsInput {
  readonly serviceId: NodeId;

  /**
   * The snapshot that was just persisted. It is never closed by its own
   * ingestion.
   */
  readonly currentSnapshotId: NodeId;

  /**
   * Instant the superseded state stopped being true. This is normally the new
   * snapshot's validFrom so history has no gap and no overlap.
   */
  readonly closedAt: UnixEpochMilliseconds;
}

export interface CloseSupersededSnapshotsResult {
  readonly closedSnapshotIds: readonly NodeId[];
  readonly closedResolutionCount: number;

  /**
   * True when a safety bound stopped the sweep before it finished, so history
   * is not yet fully closed.
   */
  readonly truncated: boolean;
}

/**
 * Turns a sequence of lockfile ingestions into queryable history.
 *
 * Persisting a snapshot records what a lockfile resolved to. Closing the
 * previous snapshot records when that stopped being true, which is what makes
 * "which services resolved the bad version while it was live" answerable.
 */
export interface LockfileSnapshotCloser {
  closeSupersededSnapshots(
    input: CloseSupersededSnapshotsInput,
  ): Promise<CloseSupersededSnapshotsResult>;
}

interface RecordLike {
  get(key: string): unknown;
}

interface ResultLike {
  readonly records: readonly RecordLike[];
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
      `${field} must be a positive safe integer ` +
        `not greater than ${maximum}`,
    );
  }
}

function asResultLike(
  value: unknown,
): ResultLike {
  if (
    typeof value !== "object" ||
    value === null ||
    !("records" in value) ||
    !Array.isArray(value.records)
  ) {
    throw new LockfileSnapshotStoreError(
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
      throw new LockfileSnapshotStoreError(
        "DATABASE_RESULT_INVALID",
        "HydraDB returned an invalid record",
      );
    }
  }

  return value as ResultLike;
}

function extractProperties(
  record: RecordLike,
  propertyKeys: readonly string[],
  aliasPrefix: string,
): Record<string, HydraScalar> {
  const properties: Record<string, HydraScalar> =
    Object.create(null) as Record<
      string,
      HydraScalar
    >;

  for (const property of propertyKeys) {
    properties[property] = record.get(
      `${aliasPrefix}_${property}`,
    ) as HydraScalar;
  }

  return properties;
}

function asText(
  value: unknown,
  field: string,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0
  ) {
    throw new LockfileSnapshotStoreError(
      "SNAPSHOT_HISTORY_CORRUPT",
      `Stored ${field} is not a nonempty string`,
    );
  }

  return value;
}

export interface HydraLockfileSnapshotStoreOptions {
  readonly statementTimeoutMs?: number;
  readonly maxSupersededSnapshots?: number;
  readonly maxClosedEdges?: number;
  readonly sessionFactory?: () => Session;
}

export class HydraLockfileSnapshotStore
  implements LockfileSnapshotCloser {
  private readonly statementTimeoutMs: number;
  private readonly maxSupersededSnapshots: number;
  private readonly maxClosedEdges: number;
  private readonly sessionFactory: () => Session;

  public constructor(
    driver: Driver,
    options:
      HydraLockfileSnapshotStoreOptions = {},
  ) {
    this.statementTimeoutMs =
      options.statementTimeoutMs ??
      DEFAULT_STATEMENT_TIMEOUT_MS;

    this.maxSupersededSnapshots =
      options.maxSupersededSnapshots ??
      DEFAULT_MAX_SUPERSEDED_SNAPSHOTS;

    this.maxClosedEdges =
      options.maxClosedEdges ??
      DEFAULT_MAX_CLOSED_EDGES;

    assertPositiveInteger(
      this.statementTimeoutMs,
      "statementTimeoutMs",
      MAX_STATEMENT_TIMEOUT_MS,
    );

    assertPositiveInteger(
      this.maxSupersededSnapshots,
      "maxSupersededSnapshots",
      10_000,
    );

    assertPositiveInteger(
      this.maxClosedEdges,
      "maxClosedEdges",
      1_000_000,
    );

    this.sessionFactory =
      options.sessionFactory ??
      (() => driver.session());
  }

  public async closeSupersededSnapshots(
    input: CloseSupersededSnapshotsInput,
  ): Promise<CloseSupersededSnapshotsResult> {
    if (
      !Number.isSafeInteger(input.closedAt) ||
      input.closedAt < 0
    ) {
      throw new LockfileSnapshotStoreError(
        "INVALID_CLOSE_TIME",
        "closedAt must be a nonnegative safe integer epoch",
      );
    }

    const snapshotRecords = await this.runQuery(
      buildFindSupersededSnapshotsQuery(
        this.maxSupersededSnapshots + 1,
      ),
      {
        service_id: input.serviceId,
        current_snapshot_id:
          input.currentSnapshotId,
      },
      "find-superseded-lockfile-snapshots",
    );

    const truncatedSnapshots =
      snapshotRecords.length >
      this.maxSupersededSnapshots;

    const pendingSnapshots = truncatedSnapshots
      ? snapshotRecords.slice(
          0,
          this.maxSupersededSnapshots,
        )
      : snapshotRecords;

    const closedSnapshotIds: NodeId[] = [];
    let closedResolutionCount = 0;
    let truncated = truncatedSnapshots;

    for (const record of pendingSnapshots) {
      const vertex = record.get(
        "snapshot_vertex",
      );

      const snapshot = deserializeHydraNode({
        vertex,
        properties: extractProperties(
          record,
          NODE_PROPERTY_KEYS.LockfileSnapshot,
          "snapshot",
        ),
        expectedKind: "LockfileSnapshot",
      });

      if (
        snapshot.kind !== "LockfileSnapshot"
      ) {
        throw new LockfileSnapshotStoreError(
          "SNAPSHOT_HISTORY_CORRUPT",
          "HydraDB returned a non-snapshot node for a snapshot query",
        );
      }

      /*
       * Closing before the snapshot opened would invert history, so the
       * sweep fails rather than writing an impossible interval.
       */
      if (input.closedAt < snapshot.validFrom) {
        throw new LockfileSnapshotStoreError(
          "INVALID_CLOSE_TIME",
          "closedAt precedes an open snapshot validFrom",
        );
      }

      const closedRow = serializeHydraNode({
        ...snapshot,
        validUntil: input.closedAt,
      });

      await this.runQuery(
        CLOSE_SNAPSHOT_QUERY,
        {
          id: snapshot.id,
          valid_until: input.closedAt,
          payload_hash: asText(
            closedRow.payload_hash,
            "snapshot.payload_hash",
          ),
        },
        "close-lockfile-snapshot",
      );

      const resolutionResult =
        await this.closeResolutions(
          snapshot.id,
          input.closedAt,
        );

      closedResolutionCount +=
        resolutionResult.closed;

      truncated =
        truncated || resolutionResult.truncated;

      closedSnapshotIds.push(snapshot.id);
    }

    return Object.freeze({
      closedSnapshotIds: Object.freeze(
        closedSnapshotIds,
      ),
      closedResolutionCount,
      truncated,
    });
  }

  private async closeResolutions(
    snapshotId: NodeId,
    closedAt: UnixEpochMilliseconds,
  ): Promise<{
    readonly closed: number;
    readonly truncated: boolean;
  }> {
    const records = await this.runQuery(
      buildFindOpenResolutionsQuery(
        this.maxClosedEdges + 1,
      ),
      { snapshot_id: snapshotId },
      "find-open-lockfile-resolutions",
    );

    const truncated =
      records.length > this.maxClosedEdges;

    const pending = truncated
      ? records.slice(0, this.maxClosedEdges)
      : records;

    let closed = 0;

    for (const record of pending) {
      const edge = deserializeHydraEdge({
        relationshipVertex:
          record.get("edge_vertex"),
        sourceVertex:
          record.get("source_vertex"),
        destinationVertex:
          record.get("target_vertex"),
        sourceLogicalId: asText(
          record.get("source_logical_id"),
          "edge.source_logical_id",
        ),
        destinationLogicalId: asText(
          record.get("target_logical_id"),
          "edge.target_logical_id",
        ),
        properties: extractProperties(
          record,
          EDGE_PROPERTY_KEYS.DEPENDS_ON,
          "edge",
        ),
        expectedKind: "DEPENDS_ON",
      });

      if (edge.kind !== "DEPENDS_ON") {
        throw new LockfileSnapshotStoreError(
          "SNAPSHOT_HISTORY_CORRUPT",
          "HydraDB returned a non-dependency edge for a resolution query",
        );
      }

      if (
        edge.validFrom === undefined ||
        closedAt < edge.validFrom
      ) {
        throw new LockfileSnapshotStoreError(
          "INVALID_CLOSE_TIME",
          "closedAt precedes an open resolution validFrom",
        );
      }

      const closedRow = serializeHydraEdge({
        ...edge,
        validUntil: closedAt,
      });

      await this.runQuery(
        CLOSE_RESOLUTION_QUERY,
        {
          id: edge.id,
          valid_until: closedAt,
          payload_hash: asText(
            closedRow.payload_hash,
            "edge.payload_hash",
          ),
        },
        "close-lockfile-resolution",
      );

      closed += 1;
    }

    return { closed, truncated };
  }

  private async runQuery(
    query: string,
    parameters: Readonly<
      Record<string, unknown>
    >,
    operation: string,
  ): Promise<readonly RecordLike[]> {
    let session: Session;

    try {
      session = this.sessionFactory();
    } catch (error) {
      throw new LockfileSnapshotStoreError(
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
        // Preserve the original query failure.
      }

      throw new LockfileSnapshotStoreError(
        "DATABASE_QUERY_FAILED",
        `HydraDB operation ${operation} failed`,
        error,
      );
    }

    try {
      await session.close();
    } catch (error) {
      throw new LockfileSnapshotStoreError(
        "DATABASE_QUERY_FAILED",
        `HydraDB session close failed after ${operation}`,
        error,
      );
    }

    return asResultLike(result).records;
  }
}
