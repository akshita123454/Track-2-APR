import type {
  Driver,
  Session,
} from "neo4j-driver";

import type {
  EvidenceNode,
  GraphEdge,
  GraphNode,
  GraphRelKind,
  IncidentNode,
  PackageVersionNode,
  NodeId,
  NodeKind,
} from "../../domain/schema.js";

import type {
  HydraEdgeRow,
  HydraNodeRow,
} from "../../db/hydra-serializer.js";

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
} from "../../db/hydra-serializer.js";

import type {
  DependencyHop,
  DependencyHopPage,
  FindDependentsOptions,
  ReadonlyGraphReader,
} from "../core/analysis-types.js";

const DEFAULT_STATEMENT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_PAGE_SIZE = 5_000;
const DEFAULT_MAX_EVIDENCE_IDS_PER_READ = 2_000;

const MAX_STATEMENT_TIMEOUT_MS = 120_000;
const MAX_CONFIGURED_PAGE_SIZE = 10_000;
const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;

interface RecordLike {
  get(key: string): unknown;
}

interface ResultLike {
  readonly records: readonly RecordLike[];
}

export type HydraGraphReaderErrorCode =
  | "DATABASE_QUERY_FAILED"
  | "DATABASE_RESULT_INVALID"
  | "GRAPH_CORRUPTION"
  | "INCIDENT_NOT_FOUND"
  | "NODE_KIND_MISMATCH";

export class HydraGraphReaderError extends Error {
  constructor(
    readonly code: HydraGraphReaderErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(
      message,
      cause === undefined
        ? undefined
        : { cause },
    );

    this.name = "HydraGraphReaderError";
  }
}

export interface HydraGraphReaderOptions {
  /**
   * Timeout applied to each individual Bolt read statement.
   */
  readonly statementTimeoutMs?: number;

  /**
   * Maximum limit accepted by findDependents() and
   * findAffectedVersions().
   */
  readonly maxPageSize?: number;

  /**
   * Prevents callers from constructing an unbounded UNWIND evidence read.
   */
  readonly maxEvidenceIdsPerRead?: number;

  /**
   * Intended for deterministic smoke tests.
   *
   * The reader owns and closes every session returned by this function.
   */
  readonly sessionFactory?: () => Session;

  /**
   * Intended for deterministic read-epoch tests.
   */
  readonly clock?: () => number;
}

export interface HydraReadDiagnostics {
  /**
   * Client-side epoch identifying this bounded analysis read.
   *
   * This is not presented as a database snapshot or transaction ID.
   */
  readonly readEpoch: string;
  readonly readEpochMs: number;
  readonly queryCount: number;
  readonly rowsRead: number;
}

export interface FindAffectedVersionsOptions {
  readonly limit: number;
}

export interface AffectedVersionPage {
  /**
   * The verified Incident used as the source of every returned AFFECTS edge.
   */
  readonly incident: IncidentNode;

  /**
   * Bounded PackageVersion targets of canonical AFFECTS edges.
   *
   * Returning complete nodes ensures versions without downstream Services
   * remain visible to the dashboard.
   */
  readonly affectedVersions:
    readonly PackageVersionNode[];

  /**
   * Evidence referenced by the bounded AFFECTS edges.
   *
   * These IDs are used to build the redacted evidence catalog.
   */
  readonly affectsEvidenceIds:
    readonly NodeId[];

  readonly truncated: boolean;
}


const ALL_NODE_PROPERTY_KEYS: readonly string[] =
  Object.freeze(
    Array.from(
      new Set<string>(
        Object.values(NODE_PROPERTY_KEYS)
          .flatMap((keys) => [...keys]),
      ),
    ).sort((left, right) =>
      left.localeCompare(right),
    ),
  );

function propertyProjections(
  binding: string,
  propertyKeys: readonly string[],
  aliasPrefix: string,
): readonly string[] {
  return propertyKeys.map(
    (property) =>
      `${binding}.${property} AS ` +
      `${aliasPrefix}_${property}`,
  );
}

function projectionClause(
  projections: readonly string[],
): string {
  return (
    "RETURN " +
    projections.join(",\n       ")
  );
}

const GET_NODE_QUERY = [
  "MATCH (n {id: $node_id})",
  projectionClause([
    "n.id AS node_vertex",
    ...propertyProjections(
      "n",
      ALL_NODE_PROPERTY_KEYS,
      "node",
    ),
  ]),
  "ORDER BY node_vertex",
  "LIMIT 2",
].join("\n");

const GET_EVIDENCE_PROJECTIONS = [
  "n.id AS evidence_vertex",
  ...propertyProjections(
    "n",
    ALL_NODE_PROPERTY_KEYS,
    "evidence",
  ),
] as const;

const FIND_DEPENDENTS_PROJECTIONS = [
  "root.id AS root_vertex",
  "root.logical_id AS root_logical_id",

  "dependent.id AS dependent_vertex",
  ...propertyProjections(
    "dependent",
    ALL_NODE_PROPERTY_KEYS,
    "dependent",
  ),

  "reverse.id AS reverse_vertex",
  ...propertyProjections(
    "reverse",
    EDGE_PROPERTY_KEYS.USED_BY,
    "reverse",
  ),

  "canonical.id AS canonical_vertex",
  ...propertyProjections(
    "canonical",
    EDGE_PROPERTY_KEYS.DEPENDS_ON,
    "canonical",
  ),
] as const;

const FIND_AFFECTED_VERSION_PROJECTIONS = [
  "incident.id AS incident_vertex",
  "incident.logical_id AS incident_logical_id",

  "version.id AS version_vertex",
  ...propertyProjections(
    "version",
    ALL_NODE_PROPERTY_KEYS,
    "version",
  ),

  "affects.id AS affects_vertex",
  ...propertyProjections(
    "affects",
    EDGE_PROPERTY_KEYS.AFFECTS,
    "affects",
  ),
] as const;


function buildFindDependentsQuery(
  fetchLimit: number,
): string {
  return [
    "MATCH (root {id: $node_id})" +
      "-[reverse:USED_BY]->(dependent)",

    "OPTIONAL MATCH (dependent)" +
      "-[canonical:DEPENDS_ON]->(root)",

    "WHERE canonical.id = reverse.derived_from",

    projectionClause(
      FIND_DEPENDENTS_PROJECTIONS,
    ),

    "ORDER BY canonical_vertex, " +
      "dependent_vertex, reverse_vertex",

    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildGetEvidenceQuery(
  fetchLimit: number,
): string {
  return [
    "UNWIND $rows AS row",
    "MATCH (n:Evidence {id: row.vertex})",
    projectionClause(
      GET_EVIDENCE_PROJECTIONS,
    ),
    "ORDER BY evidence_vertex",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildFindAffectedVersionsQuery(
  fetchLimit: number,
): string {
  return [
    "MATCH (incident:Incident {id: $incident_id})" +
      "-[affects:AFFECTS]->" +
      "(version:PackageVersion)",

    projectionClause(
      FIND_AFFECTED_VERSION_PROJECTIONS,
    ),

    "ORDER BY version_vertex, affects_vertex",

    `LIMIT ${fetchLimit}`,
  ].join("\n");
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

function assertNodeId(
  nodeId: NodeId,
  field: string,
): void {
  if (
    !Number.isSafeInteger(nodeId) ||
    nodeId < 0
  ) {
    throw new RangeError(
      `${field} must be a nonnegative safe integer`,
    );
  }
}

function asNodeKind(
  value: unknown,
  field: string,
): NodeKind {
  if (
    typeof value !== "string" ||
    !Object.prototype.hasOwnProperty.call(
      NODE_PROPERTY_KEYS,
      value,
    )
  ) {
    throw new HydraGraphReaderError(
      "GRAPH_CORRUPTION",
      `HydraDB returned an invalid ${field}`,
    );
  }

  return value as NodeKind;
}

function extractProperties(
  record: RecordLike,
  propertyKeys: readonly string[],
  aliasPrefix: string,
): Readonly<Record<string, unknown>> {
  const properties: Record<string, unknown> =
    Object.create(null) as Record<string, unknown>;

  for (const property of propertyKeys) {
    properties[property] = record.get(
      `${aliasPrefix}_${property}`,
    );
  }

  return properties;
}

function freezeNode(
  node: GraphNode,
): GraphNode {
  Object.freeze(node.evidenceIds);

  if (node.kind === "Credential") {
    Object.freeze(node.scopes);
  }

  return Object.freeze(node);
}

function freezeEdge(
  edge: GraphEdge,
): GraphEdge {
  if (edge.kind !== "USED_BY") {
    Object.freeze(edge.evidenceIds);
  }

  return Object.freeze(edge);
}

function toResultLike(
  value: unknown,
): ResultLike {
  const result = value as {
    readonly records?: unknown;
  };

  if (!Array.isArray(result.records)) {
    throw new HydraGraphReaderError(
      "DATABASE_RESULT_INVALID",
      "HydraDB returned a result without a records array",
    );
  }

  for (const record of result.records) {
    if (
      typeof record !== "object" ||
      record === null ||
      !("get" in record) ||
      typeof (
        record as {
          readonly get?: unknown;
        }
      ).get !== "function"
    ) {
      throw new HydraGraphReaderError(
        "DATABASE_RESULT_INVALID",
        "HydraDB returned an invalid record object",
      );
    }
  }

  return value as ResultLike;
}

function corruptionBoundary<T>(
  operation: string,
  callback: () => T,
): T {
  try {
    return callback();
  } catch (error) {
    if (error instanceof HydraGraphReaderError) {
      throw error;
    }

    throw new HydraGraphReaderError(
      "GRAPH_CORRUPTION",
      `HydraDB returned corrupt graph data during ${operation}`,
      error,
    );
  }
}

function readProjectedNode(
  record: RecordLike,
  aliasPrefix: string,
  expectedKind?: NodeKind,
): GraphNode {
  return corruptionBoundary(
    `reading ${aliasPrefix} node`,
    () => {
      const kind = asNodeKind(
        record.get(`${aliasPrefix}_kind`),
        `${aliasPrefix}.kind`,
      );

      if (
        expectedKind !== undefined &&
        kind !== expectedKind
      ) {
        throw new HydraGraphReaderError(
          "NODE_KIND_MISMATCH",
          `Expected ${expectedKind} but HydraDB returned ${kind}`,
        );
      }

      const node = deserializeHydraNode({
        vertex: record.get(
          `${aliasPrefix}_vertex`,
        ),

        properties: extractProperties(
          record,
          NODE_PROPERTY_KEYS[kind],
          aliasPrefix,
        ),

        expectedKind:
          expectedKind ?? kind,
      });

      return freezeNode(node);
    },
  );
}

interface ProjectedEdgeEndpoints {
  readonly sourceVertex: unknown;
  readonly destinationVertex: unknown;
  readonly sourceLogicalId: unknown;
  readonly destinationLogicalId: unknown;
}

function readProjectedEdge(
  record: RecordLike,
  aliasPrefix: string,
  expectedKind: GraphRelKind,
  endpoints: ProjectedEdgeEndpoints,
): GraphEdge {
  return corruptionBoundary(
    `reading ${aliasPrefix} relationship`,
    () => {
      const edge = deserializeHydraEdge({
        relationshipVertex: record.get(
          `${aliasPrefix}_vertex`,
        ),

        sourceVertex:
          endpoints.sourceVertex,

        destinationVertex:
          endpoints.destinationVertex,

        sourceLogicalId:
          endpoints.sourceLogicalId,

        destinationLogicalId:
          endpoints.destinationLogicalId,

        properties: extractProperties(
          record,
          EDGE_PROPERTY_KEYS[expectedKind],
          aliasPrefix,
        ),

        expectedKind,
      });

      return freezeEdge(edge);
    },
  );
}

function uniqueSortedNodeIds(
  values: readonly NodeId[],
  field: string,
): readonly NodeId[] {
  if (!Array.isArray(values)) {
    throw new TypeError(
      `${field} must be an array`,
    );
  }

  const unique = new Set<NodeId>();

  for (
    let index = 0;
    index < values.length;
    index += 1
  ) {
    const value = values[index];

    assertNodeId(
      value,
      `${field}[${index}]`,
    );

    unique.add(value);
  }

  return [...unique].sort(
    (left, right) => left - right,
  );
}

/**
 * Read-only HydraDB adapter for the pure analysis layer.
 *
 * Every query:
 *
 * - explicitly projects static serializer fields;
 * - is bounded at the database;
 * - closes its own session;
 * - revalidates payload hashes and deterministic identities;
 * - never treats USED_BY as security evidence.
 */
export class HydraGraphReader
  implements ReadonlyGraphReader {
  public readonly readEpoch: string;
  public readonly readEpochMs: number;

  private readonly statementTimeoutMs: number;
  private readonly maxPageSize: number;
  private readonly maxEvidenceIdsPerRead: number;
  private readonly sessionFactory: () => Session;

  private queryCount = 0;
  private rowsRead = 0;

  constructor(
    driver: Driver,
    options: HydraGraphReaderOptions = {},
  ) {
    const statementTimeoutMs =
      options.statementTimeoutMs ??
      DEFAULT_STATEMENT_TIMEOUT_MS;

    const maxPageSize =
      options.maxPageSize ??
      DEFAULT_MAX_PAGE_SIZE;

    const maxEvidenceIdsPerRead =
      options.maxEvidenceIdsPerRead ??
      DEFAULT_MAX_EVIDENCE_IDS_PER_READ;

    assertPositiveInteger(
      statementTimeoutMs,
      "statementTimeoutMs",
      MAX_STATEMENT_TIMEOUT_MS,
    );

    assertPositiveInteger(
      maxPageSize,
      "maxPageSize",
      MAX_CONFIGURED_PAGE_SIZE,
    );

    assertPositiveInteger(
      maxEvidenceIdsPerRead,
      "maxEvidenceIdsPerRead",
      MAX_CONFIGURED_PAGE_SIZE,
    );

    const clock = options.clock ?? Date.now;
    const readEpochMs = clock();

    if (
      !Number.isFinite(readEpochMs) ||
      readEpochMs < 0 ||
      readEpochMs > MAX_DATE_EPOCH_MS
    ) {
      throw new RangeError(
        "clock must return a valid nonnegative Unix epoch in milliseconds",
      );
    }

    this.readEpochMs = readEpochMs;
    this.readEpoch =
      new Date(readEpochMs).toISOString();

    this.statementTimeoutMs =
      statementTimeoutMs;

    this.maxPageSize =
      maxPageSize;

    this.maxEvidenceIdsPerRead =
      maxEvidenceIdsPerRead;

    this.sessionFactory =
      options.sessionFactory ??
      (() => driver.session());
  }

  public getDiagnostics(): HydraReadDiagnostics {
    return Object.freeze({
      readEpoch: this.readEpoch,
      readEpochMs: this.readEpochMs,
      queryCount: this.queryCount,
      rowsRead: this.rowsRead,
    });
  }

  public async getNode(
    nodeId: NodeId,
  ): Promise<GraphNode | null> {
    assertNodeId(nodeId, "nodeId");

    const records = await this.runQuery(
      GET_NODE_QUERY,
      {
        node_id: nodeId,
      },
      "get-node",
    );

    if (records.length === 0) {
      return null;
    }

    if (records.length !== 1) {
      throw new HydraGraphReaderError(
        "GRAPH_CORRUPTION",
        `HydraDB returned multiple nodes for ID ${nodeId}`,
      );
    }

    const node = readProjectedNode(
      records[0],
      "node",
    );

    if (node.id !== nodeId) {
      throw new HydraGraphReaderError(
        "GRAPH_CORRUPTION",
        "HydraDB returned a node with a mismatched ID",
      );
    }

    return node;
  }

  public async findDependents(
    nodeId: NodeId,
    options: FindDependentsOptions,
  ): Promise<DependencyHopPage> {
    assertNodeId(nodeId, "nodeId");

    assertPositiveInteger(
      options.limit,
      "findDependents limit",
      this.maxPageSize,
    );

    const fetchLimit = options.limit + 1;

    const records = await this.runQuery(
      buildFindDependentsQuery(fetchLimit),
      {
        node_id: nodeId,
      },
      "find-dependents",
    );

    const hops: DependencyHop[] = [];

    for (const record of records) {
      const hop = corruptionBoundary(
        "validating reverse dependency traversal",
        () => {
          const dependentNode =
            readProjectedNode(
              record,
              "dependent",
            );

          const rootVertex =
            record.get("root_vertex");

          const rootLogicalId =
            record.get("root_logical_id");

          const reverseEdge =
            readProjectedEdge(
              record,
              "reverse",
              "USED_BY",
              {
                sourceVertex:
                  rootVertex,

                destinationVertex:
                  record.get(
                    "dependent_vertex",
                  ),

                sourceLogicalId:
                  rootLogicalId,

                destinationLogicalId:
                  dependentNode.logicalId,
              },
            );

          if (reverseEdge.kind !== "USED_BY") {
            throw new Error(
              "Reverse traversal edge is not USED_BY",
            );
          }

          const canonicalVertex =
            record.get("canonical_vertex");

          if (
            canonicalVertex === null ||
            canonicalVertex === undefined
          ) {
            throw new Error(
              `USED_BY ${reverseEdge.id} does not resolve ` +
                "to canonical DEPENDS_ON",
            );
          }

          const canonicalEdge =
            readProjectedEdge(
              record,
              "canonical",
              "DEPENDS_ON",
              {
                sourceVertex:
                  record.get(
                    "dependent_vertex",
                  ),

                destinationVertex:
                  rootVertex,

                sourceLogicalId:
                  dependentNode.logicalId,

                destinationLogicalId:
                  rootLogicalId,
              },
            );

          if (
            canonicalEdge.kind !== "DEPENDS_ON" ||
            canonicalEdge.derived !== false
          ) {
            throw new Error(
              "Canonical reverse traversal edge is not DEPENDS_ON",
            );
          }

          if (
            reverseEdge.sourceId !== nodeId ||
            reverseEdge.targetId !==
              dependentNode.id
          ) {
            throw new Error(
              "USED_BY endpoints do not match the traversal nodes",
            );
          }

          if (
            reverseEdge.derivedFrom !==
              canonicalEdge.id ||
            reverseEdge.derivedFromLogicalId !==
              canonicalEdge.logicalId ||
            canonicalEdge.sourceId !==
              reverseEdge.targetId ||
            canonicalEdge.targetId !==
              reverseEdge.sourceId
          ) {
            throw new Error(
              "USED_BY does not mirror its canonical DEPENDS_ON edge",
            );
          }

          return Object.freeze({
            dependentNode,
            canonicalEdge,
            traversalIndexEdgeId:
              reverseEdge.id,
          });
        },
      );

      hops.push(hop);
    }

    const truncated =
      hops.length > options.limit;

    const boundedHops =
      hops.slice(0, options.limit);

    return Object.freeze({
      hops: Object.freeze(boundedHops),
      truncated,
    });
  }

  public async getEvidence(
    evidenceIds: readonly NodeId[],
  ): Promise<readonly EvidenceNode[]> {
    if (
      evidenceIds.length >
      this.maxEvidenceIdsPerRead
    ) {
      throw new RangeError(
        `getEvidence accepts at most ` +
          `${this.maxEvidenceIdsPerRead} IDs`,
      );
    }

    const requestedIds =
      uniqueSortedNodeIds(
        evidenceIds,
        "evidenceIds",
      );

    if (requestedIds.length === 0) {
      return Object.freeze([]);
    }

    const requestedIdSet =
      new Set(requestedIds);

    const rows = requestedIds.map(
      (vertex) => ({ vertex }),
    );

    const records = await this.runQuery(
      buildGetEvidenceQuery(
        requestedIds.length + 1,
      ),
      {
        rows,
      },
      "get-evidence",
    );

    if (records.length > requestedIds.length) {
      throw new HydraGraphReaderError(
        "DATABASE_RESULT_INVALID",
        "HydraDB returned more Evidence rows than requested",
      );
    }

    const evidence: EvidenceNode[] = [];
    const returnedIds = new Set<NodeId>();

    for (const record of records) {
      const node = readProjectedNode(
        record,
        "evidence",
        "Evidence",
      );

      if (node.kind !== "Evidence") {
        throw new HydraGraphReaderError(
          "NODE_KIND_MISMATCH",
          "Evidence query returned a non-Evidence node",
        );
      }

      if (!requestedIdSet.has(node.id)) {
        throw new HydraGraphReaderError(
          "GRAPH_CORRUPTION",
          "Evidence query returned an unrequested node",
        );
      }

      if (returnedIds.has(node.id)) {
        throw new HydraGraphReaderError(
          "GRAPH_CORRUPTION",
          "Evidence query returned a duplicate node",
        );
      }

      returnedIds.add(node.id);
      evidence.push(node);
    }

    evidence.sort(
      (left, right) => left.id - right.id,
    );

    return Object.freeze(evidence);
  }

  /**
   * Resolves PackageVersion roots connected to an Incident by canonical
   * AFFECTS edges.
   *
   * This method verifies each AFFECTS identity. It does not infer affected
   * versions from package names, ranges, or dependency reachability.
   */
  public async findAffectedVersions(
  incidentId: NodeId,
  options: FindAffectedVersionsOptions,
): Promise<AffectedVersionPage> {
  assertNodeId(
    incidentId,
    "incidentId",
  );

  assertPositiveInteger(
    options.limit,
    "findAffectedVersions limit",
    this.maxPageSize,
  );

  const incidentNode =
    await this.getNode(
      incidentId,
    );

  if (incidentNode === null) {
    throw new HydraGraphReaderError(
      "INCIDENT_NOT_FOUND",
      `Incident ${incidentId} was not found`,
    );
  }

  if (incidentNode.kind !== "Incident") {
    throw new HydraGraphReaderError(
      "NODE_KIND_MISMATCH",
      `Node ${incidentId} is not an Incident`,
    );
  }

  const records =
    await this.runQuery(
      buildFindAffectedVersionsQuery(
        options.limit + 1,
      ),
      {
        incident_id: incidentId,
      },
      "find-affected-versions",
    );

  const entries: Array<{
    readonly version:
      PackageVersionNode;

    readonly evidenceIds:
      readonly NodeId[];
  }> = [];

  const seenVersionIds =
    new Set<NodeId>();

  for (const record of records) {
    const entry =
      corruptionBoundary(
        "validating an AFFECTS relationship",
        () => {
          const versionNode =
            readProjectedNode(
              record,
              "version",
              "PackageVersion",
            );

          if (
            versionNode.kind !==
            "PackageVersion"
          ) {
            throw new Error(
              "AFFECTS target is not a PackageVersion",
            );
          }

          const edge =
            readProjectedEdge(
              record,
              "affects",
              "AFFECTS",
              {
                sourceVertex:
                  record.get(
                    "incident_vertex",
                  ),

                destinationVertex:
                  record.get(
                    "version_vertex",
                  ),

                sourceLogicalId:
                  record.get(
                    "incident_logical_id",
                  ),

                destinationLogicalId:
                  versionNode.logicalId,
              },
            );

          if (
            edge.kind !== "AFFECTS" ||
            edge.derived !== false
          ) {
            throw new Error(
              "Incident traversal returned a noncanonical AFFECTS edge",
            );
          }

          if (
            edge.sourceId !==
              incidentNode.id ||
            edge.targetId !==
              versionNode.id
          ) {
            throw new Error(
              "AFFECTS endpoints do not match the Incident and PackageVersion",
            );
          }

          return {
            version: versionNode,
            evidenceIds:
              edge.evidenceIds,
          };
        },
      );

    if (
      seenVersionIds.has(
        entry.version.id,
      )
    ) {
      throw new HydraGraphReaderError(
        "GRAPH_CORRUPTION",
        "Incident has duplicate AFFECTS targets",
      );
    }

    seenVersionIds.add(
      entry.version.id,
    );

    entries.push(entry);
  }

  const truncated =
    entries.length >
    options.limit;

  const boundedEntries =
    entries.slice(
      0,
      options.limit,
    );

  const affectsEvidenceIds =
    [
      ...new Set(
        boundedEntries.flatMap(
          (entry) => [
            ...entry.evidenceIds,
          ],
        ),
      ),
    ].sort(
      (left, right) =>
        left - right,
    );

  return Object.freeze({
    incident:
      incidentNode,

    affectedVersions:
      Object.freeze(
        boundedEntries.map(
          (entry) =>
            entry.version,
        ),
      ),

    affectsEvidenceIds:
      Object.freeze(
        affectsEvidenceIds,
      ),

    truncated,
  });
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
      throw new HydraGraphReaderError(
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
          timeout:
            this.statementTimeoutMs,

          metadata: {
            "hydradb.caller.step":
              operation,

            "hydraguard.read_epoch":
              this.readEpoch,
          },
        },
      );
    } catch (error) {
      try {
        await session.close();
      } catch {
        /*
         * Preserve the primary query failure. The failed session is not
         * reused.
         */
      }

      throw new HydraGraphReaderError(
        "DATABASE_QUERY_FAILED",
        `HydraDB read failed during ${operation}`,
        error,
      );
    }

    try {
      await session.close();
    } catch (error) {
      throw new HydraGraphReaderError(
        "DATABASE_QUERY_FAILED",
        `HydraDB session close failed after ${operation}`,
        error,
      );
    }

    const normalizedResult =
      toResultLike(result);

    this.queryCount += 1;
    this.rowsRead +=
      normalizedResult.records.length;

    return normalizedResult.records;
  }
}
