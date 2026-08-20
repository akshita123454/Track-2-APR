import type {
  Driver,
} from "neo4j-driver";

import {
  HydraGraphReader,
} from "../analysis/readers/hydra-graph-reader.js";

import {
  deserializeHydraNode,
} from "../db/hydra-deserializer.js";

import {
  NODE_PROPERTY_KEYS,
} from "../db/hydra-serializer.js";

import {
  toHydraParameters,
} from "../db/hydra-parameters.js";

import type {
  EvidenceNode,
  PackageNode,
  PackageVersionNode,
  ServiceCriticality,
  TyposquatFindingNode,
} from "../domain/schema.js";

interface RecordLike {
  get(key: string): unknown;
}

export interface FindingCursor {
  readonly detectedAt: number;
  readonly findingId: number;
}

export interface FindingListOptions {
  readonly limit: number;
  readonly cursor?: FindingCursor;
}

export interface FindingListPage {
  readonly findings:
    readonly TyposquatFindingNode[];
  readonly truncated: boolean;
  readonly nextCursor?: FindingCursor;
}

export interface FindingPackages {
  readonly candidate: PackageNode;
  readonly target: PackageNode;
}

export interface ExactCandidateVersionsPage {
  readonly versions:
    readonly PackageVersionNode[];
  readonly scannedCount: number;
  readonly truncated: boolean;
}

export interface ExposurePath {
  readonly serviceId: number;
  readonly serviceLogicalId: string;
  readonly serviceName: string;
  readonly serviceCriticality:
    ServiceCriticality;
  readonly packageVersionIds:
    readonly number[];
  readonly evidenceIds:
    readonly number[];
}

export interface ExposureTrace {
  readonly services:
    readonly ExposurePath[];
  readonly truncated: boolean;
  readonly traversalStates: number;
  readonly limits: {
    readonly maxDepth: number;
    readonly maxServices: number;
    readonly maxTraversalStates: number;
    readonly maxDependentsPerNode: number;
  };
}

export interface ExposureTraceOptions {
  readonly maxDepth: number;
  readonly maxServices: number;
  readonly maxTraversalStates: number;
  readonly maxDependentsPerNode: number;
}

export type FindingReaderErrorCode =
  | "FINDING_NOT_FOUND"
  | "GRAPH_CORRUPTION"
  | "DATABASE_UNAVAILABLE"
  | "INVALID_LIMIT";

export class FindingReaderError
  extends Error {
  constructor(
    readonly code:
      FindingReaderErrorCode,
    message: string,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name = "FindingReaderError";
  }
}

const MAX_LIST_LIMIT = 200;
const MAX_VERSION_SCAN = 1_000;
const MAX_EXPOSURE_BOUND = 10_000;
const DEFAULT_STATEMENT_TIMEOUT_MS = 20_000;

function assertNodeId(
  value: number,
  field: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new RangeError(
      `${field} must be a nonnegative safe integer`,
    );
  }
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
    throw new FindingReaderError(
      "INVALID_LIMIT",
      `${field} must be between 1 and ${maximum}`,
    );
  }
}

function propertyProjections(
  binding: string,
  propertyKeys: readonly string[],
  prefix: string,
): readonly string[] {
  return propertyKeys.map(
    (property) =>
      `${binding}.${property} AS ${prefix}_${property}`,
  );
}

function projectionClause(
  values: readonly string[],
): string {
  return `RETURN ${values.join(",\n       ")}`;
}

function extractProperties(
  record: RecordLike,
  propertyKeys: readonly string[],
  prefix: string,
): Readonly<Record<string, unknown>> {
  const output:
    Record<string, unknown> =
      Object.create(null) as
        Record<string, unknown>;

  for (const property of propertyKeys) {
    output[property] =
      record.get(
        `${prefix}_${property}`,
      );
  }

  return output;
}

function readFindingRecord(
  record: RecordLike,
): TyposquatFindingNode {
  const node = deserializeHydraNode({
    vertex:
      record.get("finding_vertex"),
    properties:
      extractProperties(
        record,
        NODE_PROPERTY_KEYS.Finding,
        "finding",
      ),
    expectedKind: "Finding",
  });

  if (node.kind !== "Finding") {
    throw new Error(
      "Finding query returned a non-Finding node",
    );
  }

  Object.freeze(node.evidenceIds);
  Object.freeze(node.transformations);
  Object.freeze(node.reasonCodes);
  return Object.freeze(node);
}

function asSafeInteger(
  value: unknown,
  field: string,
): number {
  let converted = value;

  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    converted = value.toNumber();
  }

  if (
    typeof converted !== "number" ||
    !Number.isSafeInteger(converted) ||
    converted < 0
  ) {
    throw new Error(
      `HydraDB returned an invalid ${field}`,
    );
  }

  return converted;
}

function toRecords(
  result: unknown,
): readonly RecordLike[] {
  const records = (
    result as {
      readonly records?: unknown;
    }
  ).records;

  if (!Array.isArray(records)) {
    throw new Error(
      "HydraDB returned no records array",
    );
  }

  for (const record of records) {
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
      throw new Error(
        "HydraDB returned an invalid record",
      );
    }
  }

  return records as readonly RecordLike[];
}

function intersects(
  left: readonly number[],
  right: ReadonlySet<number>,
): boolean {
  return left.some((value) =>
    right.has(value),
  );
}

export class TyposquattingFindingReader {
  private readonly statementTimeoutMs:
    number;

  constructor(
    private readonly driver: Driver,
    options: {
      readonly statementTimeoutMs?: number;
    } = {},
  ) {
    this.statementTimeoutMs =
      options.statementTimeoutMs ??
      DEFAULT_STATEMENT_TIMEOUT_MS;

    assertPositiveInteger(
      this.statementTimeoutMs,
      "statementTimeoutMs",
      600_000,
    );
  }

  async listFindings(
    options: FindingListOptions,
  ): Promise<FindingListPage> {
    assertPositiveInteger(
      options.limit,
      "limit",
      MAX_LIST_LIMIT,
    );

    if (options.cursor !== undefined) {
      assertNodeId(
        options.cursor.detectedAt,
        "cursor.detectedAt",
      );
      assertNodeId(
        options.cursor.findingId,
        "cursor.findingId",
      );
    }

    const fetchLimit = options.limit + 1;
    const projections = [
      "f.id AS finding_vertex",
      ...propertyProjections(
        "f",
        NODE_PROPERTY_KEYS.Finding,
        "finding",
      ),
    ];

    const query = [
      "MATCH (f:Finding)",
      "WHERE f.finding_type = 'typosquatting'",
      "  AND ($has_cursor = false",
      "       OR f.detected_at < $cursor_detected_at",
      "       OR (f.detected_at = $cursor_detected_at AND f.id > $cursor_finding_id))",
      projectionClause(projections),
      "ORDER BY f.detected_at DESC, f.id ASC",
      `LIMIT ${fetchLimit}`,
    ].join("\n");

    const records = await this.run(
      query,
      {
        has_cursor:
          options.cursor !== undefined,
        cursor_detected_at:
          options.cursor?.detectedAt ?? 0,
        cursor_finding_id:
          options.cursor?.findingId ?? 0,
      },
    );

    const findings = records.map(
      readFindingRecord,
    );
    const truncated =
      findings.length > options.limit;
    const bounded = findings.slice(
      0,
      options.limit,
    );
    const last =
      bounded[bounded.length - 1];

    return Object.freeze({
      findings:
        Object.freeze(bounded),
      truncated,
      ...(truncated && last !== undefined
        ? {
            nextCursor:
              Object.freeze({
                detectedAt:
                  last.detectedAt,
                findingId: last.id,
              }),
          }
        : {}),
    });
  }

  async getFinding(
    findingId: number,
  ): Promise<TyposquatFindingNode | null> {
    assertNodeId(
      findingId,
      "findingId",
    );

    const query = [
      "MATCH (f:Finding {id: $finding_id})",
      projectionClause([
        "f.id AS finding_vertex",
        ...propertyProjections(
          "f",
          NODE_PROPERTY_KEYS.Finding,
          "finding",
        ),
      ]),
      "ORDER BY finding_vertex",
      "LIMIT 2",
    ].join("\n");

    const records = await this.run(
      query,
      { finding_id: findingId },
    );

    if (records.length === 0) {
      return null;
    }

    if (records.length !== 1) {
      throw new FindingReaderError(
        "GRAPH_CORRUPTION",
        "Multiple Finding nodes use the requested ID",
      );
    }

    return readFindingRecord(
      records[0],
    );
  }

  async requireFinding(
    findingId: number,
  ): Promise<TyposquatFindingNode> {
    const finding =
      await this.getFinding(findingId);

    if (finding === null) {
      throw new FindingReaderError(
        "FINDING_NOT_FOUND",
        `Finding ${findingId} was not found`,
      );
    }

    return finding;
  }

  async getFindingPackages(
    finding:
      TyposquatFindingNode,
  ): Promise<FindingPackages> {
    const records = await this.run(
      [
        "MATCH (f:Finding {id: $finding_id})-[:TARGETS]->(candidate:Package)",
        "MATCH (f)-[:IMITATES]->(target:Package)",
        "RETURN candidate.id AS candidate_id, target.id AS target_id",
        "ORDER BY candidate_id, target_id",
        "LIMIT 2",
      ].join("\n"),
      { finding_id: finding.id },
    );

    if (records.length !== 1) {
      throw new FindingReaderError(
        "GRAPH_CORRUPTION",
        "Finding must have exactly one candidate and one trusted target",
      );
    }

    const candidateId = asSafeInteger(
      records[0].get("candidate_id"),
      "candidate Package ID",
    );
    const targetId = asSafeInteger(
      records[0].get("target_id"),
      "target Package ID",
    );

    const graphReader =
      new HydraGraphReader(
        this.driver,
        {
          statementTimeoutMs:
            this.statementTimeoutMs,
        },
      );

    const [candidateNode, targetNode] =
      await Promise.all([
        graphReader.getNode(candidateId),
        graphReader.getNode(targetId),
      ]);

    if (
      candidateNode?.kind !== "Package" ||
      targetNode?.kind !== "Package" ||
      candidateNode.name !==
        finding.candidatePackageName ||
      targetNode.name !==
        finding.targetPackageName
    ) {
      throw new FindingReaderError(
        "GRAPH_CORRUPTION",
        "Finding package relations do not match the stored finding identity",
      );
    }

    return Object.freeze({
      candidate: candidateNode,
      target: targetNode,
    });
  }

  async getEvidence(
    evidenceIds: readonly number[],
    maximum = 500,
  ): Promise<readonly EvidenceNode[]> {
    assertPositiveInteger(
      maximum,
      "maximum evidence IDs",
      2_000,
    );

    if (evidenceIds.length > maximum) {
      throw new FindingReaderError(
        "GRAPH_CORRUPTION",
        "Finding exceeds the bounded evidence-reference limit",
      );
    }

    const reader = new HydraGraphReader(
      this.driver,
      {
        statementTimeoutMs:
          this.statementTimeoutMs,
        maxEvidenceIdsPerRead:
          maximum,
      },
    );

    const evidence =
      await reader.getEvidence(
        evidenceIds,
      );

    if (
      evidence.length !==
      new Set(evidenceIds).size
    ) {
      throw new FindingReaderError(
        "GRAPH_CORRUPTION",
        "Finding references unavailable Evidence",
      );
    }

    return evidence;
  }

  async getExactCandidateVersions(
    candidate: PackageNode,
    findingEvidenceIds:
      readonly number[],
    limit = 200,
  ): Promise<ExactCandidateVersionsPage> {
    assertPositiveInteger(
      limit,
      "candidate version scan limit",
      MAX_VERSION_SCAN,
    );

    const records = await this.run(
      [
        "MATCH (p:Package {id: $package_id})-[:HAS_VERSION]->(v:PackageVersion)",
        "RETURN v.id AS version_id",
        "ORDER BY version_id",
        `LIMIT ${limit + 1}`,
      ].join("\n"),
      { package_id: candidate.id },
    );

    const truncated =
      records.length > limit;
    const bounded = records.slice(0, limit);
    const findingEvidence =
      new Set(findingEvidenceIds);
    const reader = new HydraGraphReader(
      this.driver,
      {
        statementTimeoutMs:
          this.statementTimeoutMs,
      },
    );
    const versions:
      PackageVersionNode[] = [];

    for (const record of bounded) {
      const versionId = asSafeInteger(
        record.get("version_id"),
        "PackageVersion ID",
      );
      const node =
        await reader.getNode(versionId);

      if (
        node?.kind !==
          "PackageVersion" ||
        node.packageName !==
          candidate.name
      ) {
        throw new FindingReaderError(
          "GRAPH_CORRUPTION",
          "HAS_VERSION returned an invalid PackageVersion",
        );
      }

      if (
        intersects(
          node.evidenceIds,
          findingEvidence,
        )
      ) {
        versions.push(node);
      }
    }

    versions.sort(
      (left, right) =>
        left.version.localeCompare(
          right.version,
        ) || left.id - right.id,
    );

    return Object.freeze({
      versions: Object.freeze(versions),
      scannedCount: bounded.length,
      truncated,
    });
  }

  async traceExposure(
    versions:
      readonly PackageVersionNode[],
    findingEvidenceIds:
      readonly number[],
    options: ExposureTraceOptions,
  ): Promise<ExposureTrace> {
    assertPositiveInteger(
      options.maxDepth,
      "maxDepth",
      32,
    );
    assertPositiveInteger(
      options.maxServices,
      "maxServices",
      1_000,
    );
    assertPositiveInteger(
      options.maxTraversalStates,
      "maxTraversalStates",
      MAX_EXPOSURE_BOUND,
    );
    assertPositiveInteger(
      options.maxDependentsPerNode,
      "maxDependentsPerNode",
      2_000,
    );

    const evidenceSet =
      new Set(findingEvidenceIds);
    const reader = new HydraGraphReader(
      this.driver,
      {
        statementTimeoutMs:
          this.statementTimeoutMs,
        maxPageSize:
          options.maxDependentsPerNode,
      },
    );

    interface State {
      readonly nodeId: number;
      readonly path: readonly number[];
      readonly evidenceIds:
        readonly number[];
      readonly depth: number;
    }

    const queue: State[] =
      versions.map((version) => ({
        nodeId: version.id,
        path: [version.id],
        evidenceIds:
          version.evidenceIds.filter(
            (id) => evidenceSet.has(id),
          ),
        depth: 0,
      }));
    const services =
      new Map<number, ExposurePath>();
    let traversalStates = 0;
    let truncated = false;

    while (queue.length > 0) {
      if (
        traversalStates >=
        options.maxTraversalStates
      ) {
        truncated = true;
        break;
      }

      const state = queue.shift()!;
      traversalStates += 1;

      if (
        state.depth >=
        options.maxDepth
      ) {
        truncated = true;
        continue;
      }

      const page =
        await reader.findDependents(
          state.nodeId,
          {
            limit:
              options.maxDependentsPerNode,
          },
        );

      if (page.truncated) {
        truncated = true;
      }

      for (const hop of page.hops) {
        if (
          !intersects(
            hop.canonicalEdge
              .evidenceIds,
            evidenceSet,
          )
        ) {
          continue;
        }

        if (
          state.path.includes(
            hop.dependentNode.id,
          )
        ) {
          continue;
        }

        const path = [
          ...state.path,
          hop.dependentNode.id,
        ];
        const pathEvidence = [
          ...new Set([
            ...state.evidenceIds,
            ...hop.canonicalEdge
              .evidenceIds.filter(
                (id) =>
                  evidenceSet.has(id),
              ),
          ]),
        ].sort(
          (left, right) =>
            left - right,
        );

        if (
          hop.dependentNode.kind ===
          "Service"
        ) {
          if (
            !services.has(
              hop.dependentNode.id,
            )
          ) {
            if (
              services.size >=
              options.maxServices
            ) {
              truncated = true;
              continue;
            }

            services.set(
              hop.dependentNode.id,
              Object.freeze({
                serviceId:
                  hop.dependentNode.id,
                serviceLogicalId:
                  hop.dependentNode
                    .logicalId,
                serviceName:
                  hop.dependentNode.name,
                serviceCriticality:
                  hop.dependentNode
                    .criticality,
                packageVersionIds:
                  Object.freeze(path),
                evidenceIds:
                  Object.freeze(
                    pathEvidence,
                  ),
              }),
            );
          }

          continue;
        }

        if (
          hop.dependentNode.kind ===
          "PackageVersion"
        ) {
          queue.push({
            nodeId:
              hop.dependentNode.id,
            path,
            evidenceIds:
              pathEvidence,
            depth:
              state.depth + 1,
          });
        }
      }
    }

    return Object.freeze({
      services: Object.freeze(
        [...services.values()].sort(
          (left, right) =>
            left.serviceId -
            right.serviceId,
        ),
      ),
      truncated,
      traversalStates,
      limits: Object.freeze({
        ...options,
      }),
    });
  }

  private async run(
    query: string,
    parameters:
      Record<string, unknown>,
  ): Promise<readonly RecordLike[]> {
    const session =
      this.driver.session();

    try {
      const result =
        await session.run(
          query,
          toHydraParameters(parameters),
          {
            timeout:
              this.statementTimeoutMs,
          },
        );

      return toRecords(result);
    } catch (error: unknown) {
      if (
        error instanceof
          FindingReaderError
      ) {
        throw error;
      }

      throw new FindingReaderError(
        "DATABASE_UNAVAILABLE",
        "HydraDB finding read failed",
        error,
      );
    } finally {
      await session.close();
    }
  }
}
