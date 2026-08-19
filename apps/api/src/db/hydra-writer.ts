import {
  createHash,
  randomUUID,
} from "node:crypto";

import type {
  Driver,
  Session,
} from "neo4j-driver";

import {
  toHydraParameters,
} from "./hydra-parameters.js";

import { validateGraph } from "../domain/validator.js";

import type { GraphBatch } from "../ingest/graph-batch.js";

import {
  HYDRA_SCHEMA_VERSION,
  serializeGraphBatch,
} from "./hydra-serializer.js";

import type {
  HydraEdgeGroup,
  HydraEdgeRow,
  HydraNodeGroup,
  HydraNodeRow,
  HydraScalar,
  SerializedHydraBatch,
} from "./hydra-serializer.js";

import {
  HYDRA_PERSISTENCE_PHASES,
} from "./persistence-result.js";

import type {
  HydraPersistencePhase,
  PersistenceFailure,
  PersistencePhaseResult,
  PersistencePhaseStatus,
  PersistenceResult,
  PersistenceStatus,
} from "./persistence-result.js";

const DEFAULT_CHUNK_SIZE = 250;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_RETRY_DELAY_MS = 100;
const DEFAULT_STATEMENT_TIMEOUT_MS = 20_000;

const COMPONENT_PATTERN = /^[A-Za-z0-9._-]+$/;
const IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

interface RecordLike {
  get(key: string): unknown;
}

interface ResultLike {
  readonly records: readonly RecordLike[];
}

interface StatementOutcome {
  readonly result: ResultLike;
  readonly attempts: number;
}

interface StatementContext {
  readonly phase: HydraPersistencePhase;
  readonly queryShapeId: string;
  readonly step: string;
  readonly mutation: boolean;
  readonly idempotencyKey?: string;
  readonly chunkIndex?: number;
}

interface MutablePhaseResult {
  phase: HydraPersistencePhase;
  status: PersistencePhaseStatus;
  rowsPlanned: number;
  rowsProcessed: number;
  statementsAttempted: number;
  statementsSucceeded: number;
  retries: number;
  durationMs: number;
  queryShapeIds: Set<string>;
  failure?: PersistenceFailure;
  startedAt?: number;
}

export interface HydraWriterOptions {
  readonly chunkSize?: number;
  readonly maxAttempts?: number;
  readonly retryDelayMs?: number;
  readonly statementTimeoutMs?: number;

  /**
   * Stable root key for one logical persistence operation.
   *
   * If omitted, the deterministic serialized batch hash is used.
   */
  readonly idempotencyKey?: string;

  readonly correlationId?: string;

  /**
   * Defaults to true. Uses the merge-policy support present in the
   * pinned HydraDB source to reject stale observed_at updates.
   */
  readonly guardedUpserts?: boolean;

  /**
   * Defaults to true. Verification checks identity and endpoint
   * materialization, not complete property equality.
   */
  readonly verify?: boolean;

  /**
   * Primarily for smoke tests. Every call must return a fresh session.
   * The writer owns and closes every session returned by this factory.
   */
  readonly sessionFactory?: () => Session;
}

class WriterBoundaryError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "WriterBoundaryError";
  }
}

class StatementExecutionError extends Error {
  constructor(
    readonly context: StatementContext,
    readonly attempts: number,
    readonly retryable: boolean,
    readonly causeName?: string,
    readonly causeCode?: string,
  ) {
    super("HydraDB statement execution failed");
    this.name = "StatementExecutionError";
  }
}

function assertIdentifier(
  value: string,
  description: string,
): void {
  if (!IDENTIFIER_PATTERN.test(value)) {
    throw new WriterBoundaryError(
      "UNSAFE_QUERY_IDENTIFIER",
      `Invalid static ${description}`,
    );
  }
}

function assertPositiveInteger(
  value: number,
  description: string,
  maximum: number,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximum
  ) {
    throw new WriterBoundaryError(
      "INVALID_WRITER_OPTION",
      `${description} is outside its allowed range`,
    );
  }
}

function validateComponent(
  value: string,
  description: string,
  maximumLength: number,
): void {
  if (
    value.length === 0 ||
    value.length > maximumLength ||
    !COMPONENT_PATTERN.test(value)
  ) {
    throw new WriterBoundaryError(
      "INVALID_WRITER_OPTION",
      `${description} must contain only ASCII letters, digits, ".", "_", or "-"`,
    );
  }
}

function phaseToken(phase: HydraPersistencePhase): string {
  switch (phase) {
    case "validate-serialize":
      return "validate";
    case "preflight-identities":
      return "preflight";
    case "upsert-nodes":
      return "nodes";
    case "upsert-canonical-edges":
      return "canonical";
    case "upsert-derived-edges":
      return "derived";
    case "verify":
      return "verify";
  }
}

function shortHash(value: string): string {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("hex")
    .slice(0, 12);
}

function createChunkIdempotencyKey(
  baseKey: string,
  phase: HydraPersistencePhase,
  shapeId: string,
  chunkIndex: number,
): string {
  const key = [
    baseKey,
    phaseToken(phase),
    shortHash(shapeId),
    String(chunkIndex),
  ].join(".");

  validateComponent(key, "derived idempotency key", 128);
  return key;
}

function createPhases(): Map<
  HydraPersistencePhase,
  MutablePhaseResult
> {
  return new Map(
    HYDRA_PERSISTENCE_PHASES.map((phase) => [
      phase,
      {
        phase,
        status: "skipped" as const,
        rowsPlanned: 0,
        rowsProcessed: 0,
        statementsAttempted: 0,
        statementsSucceeded: 0,
        retries: 0,
        durationMs: 0,
        queryShapeIds: new Set<string>(),
      },
    ]),
  );
}

function beginPhase(phase: MutablePhaseResult): void {
  phase.status = "succeeded";
  phase.startedAt = Date.now();
}

function finishPhase(
  phase: MutablePhaseResult,
  status: PersistencePhaseStatus,
): void {
  phase.status = status;

  if (phase.startedAt !== undefined) {
    phase.durationMs = Date.now() - phase.startedAt;
  }
}

function immutablePhase(
  phase: MutablePhaseResult,
): PersistencePhaseResult {
  return {
    phase: phase.phase,
    status: phase.status,
    rowsPlanned: phase.rowsPlanned,
    rowsProcessed: phase.rowsProcessed,
    statementsAttempted: phase.statementsAttempted,
    statementsSucceeded: phase.statementsSucceeded,
    retries: phase.retries,
    durationMs: phase.durationMs,
    queryShapeIds: [...phase.queryShapeIds].sort(),
    ...(phase.failure === undefined
      ? {}
      : { failure: phase.failure }),
  };
}

function errorName(error: unknown): string | undefined {
  if (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    typeof error.name === "string"
  ) {
    return error.name;
  }

  return undefined;
}

function errorCode(error: unknown): string | undefined {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string"
  ) {
    return error.code;
  }

  return undefined;
}

function isRetryableError(error: unknown): boolean {
  const name = errorName(error);
  const code = errorCode(error);

  return (
    name === "ServiceUnavailable" ||
    name === "SessionExpired" ||
    code?.startsWith("Neo.TransientError.") === true ||
    code === "ServiceUnavailable" ||
    code === "SessionExpired"
  );
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function asResultLike(value: unknown): ResultLike {
  return value as ResultLike;
}

function asString(
  value: unknown,
  description: string,
): string {
  if (typeof value !== "string") {
    throw new WriterBoundaryError(
      "DATABASE_IDENTITY_INVALID",
      `HydraDB returned a non-string ${description}`,
    );
  }

  return value;
}

function asSafeInteger(
  value: unknown,
  description: string,
): number {
  let converted: unknown = value;

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
    throw new WriterBoundaryError(
      "DATABASE_IDENTITY_INVALID",
      `HydraDB returned an unsafe ${description}`,
    );
  }

  return converted;
}

function buildNodeUpsertQuery(
  group: HydraNodeGroup,
  guarded: boolean,
): string {
  assertIdentifier(group.label, "node label");

  const assignments = group.propertyKeys.map((property) => {
    assertIdentifier(property, "node property");
    return `n.${property} = row.${property}`;
  });

  if (guarded) {
    assignments.push(
      "n.__hydradb_update_if_newer_by = row.observed_at",
    );
  }

  return [
    "UNWIND $rows AS row",
    "MERGE (n {id: row.vertex})",
    `SET n:${group.label}, ${assignments.join(", ")}`,
  ].join("\n");
}

function buildEdgeUpsertQuery(
  group: HydraEdgeGroup,
  guarded: boolean,
): string {
  assertIdentifier(group.sourceLabel, "source label");
  assertIdentifier(
    group.destinationLabel,
    "destination label",
  );
  assertIdentifier(
    group.relationshipType,
    "relationship type",
  );

  const assignments = group.propertyKeys.map((property) => {
    assertIdentifier(property, "relationship property");
    return `r.${property} = row.${property}`;
  });

  if (guarded) {
    assignments.push(
      "r.__hydradb_update_if_newer_by = row.observed_at",
    );
  }

  return [
    "UNWIND $rows AS row",
    `MATCH (s:${group.sourceLabel} {id: row.source_vertex}), ` +
      `(d:${group.destinationLabel} {id: row.destination_vertex})`,
    `MERGE (s)-[r:${group.relationshipType} ` +
      `{id: row.relationship_vertex}]->(d)`,
    `SET ${assignments.join(", ")}`,
  ].join("\n");
}

function buildEdgeIdentityProbeQuery(
  group: HydraEdgeGroup,
  property: "id" | "logical_id",
): string {
  assertIdentifier(
    group.sourceLabel,
    "source label",
  );

  assertIdentifier(
    group.destinationLabel,
    "destination label",
  );

  assertIdentifier(
    group.relationshipType,
    "relationship type",
  );

  const parameter =
    property === "id"
      ? "relationship_vertex"
      : "logical_id";

  return [
    `MATCH (s:${group.sourceLabel})`,
    `-[:${group.relationshipType} {${property}: $${parameter}}]->`,
    `(d:${group.destinationLabel})`,
    "RETURN s.id AS source_vertex,",
    "       d.id AS destination_vertex",
  ].join("\n");
}

function buildEdgeExactIdentityQuery(
  group: HydraEdgeGroup,
): string {
  assertIdentifier(
    group.sourceLabel,
    "source label",
  );

  assertIdentifier(
    group.destinationLabel,
    "destination label",
  );

  assertIdentifier(
    group.relationshipType,
    "relationship type",
  );

  return [
    `MATCH (s:${group.sourceLabel})`,
    `-[:${group.relationshipType} {`,
    "  id: $relationship_vertex,",
    "  logical_id: $logical_id,",
    "  kind: $kind,",
    "  source_id: $source_id,",
    "  target_id: $target_id,",
    "  derived: $derived",
    "}]->",
    `(d:${group.destinationLabel})`,
    "RETURN s.id AS source_vertex,",
    "       d.id AS destination_vertex",
  ].join("\n");
}

function buildEdgeVerificationQuery(
  group: HydraEdgeGroup,
): string {
  assertIdentifier(
    group.sourceLabel,
    "source label",
  );

  assertIdentifier(
    group.destinationLabel,
    "destination label",
  );

  assertIdentifier(
    group.relationshipType,
    "relationship type",
  );

  return [
    `MATCH (s:${group.sourceLabel} {id: $source_vertex})`,
    `-[:${group.relationshipType} {`,
    "  id: $relationship_vertex,",
    "  logical_id: $logical_id,",
    "  kind: $kind",
    "}]->",
    `(d:${group.destinationLabel} {id: $destination_vertex})`,
    "RETURN s.id AS source_vertex,",
    "       d.id AS destination_vertex",
  ].join("\n");
}

function chunks<T>(
  values: readonly T[],
  chunkSize: number,
): readonly T[][] {
  const output: T[][] = [];

  for (
    let offset = 0;
    offset < values.length;
    offset += chunkSize
  ) {
    output.push(values.slice(offset, offset + chunkSize));
  }

  return output;
}

function queryRows(
  rows: readonly (
    | HydraNodeRow
    | HydraEdgeRow
  )[],
): Record<string, HydraScalar>[] {
  return rows.map((row) => ({ ...row }));
}

export async function persistGraphBatch(
  driver: Driver,
  batch: GraphBatch,
  options: HydraWriterOptions = {},
): Promise<PersistenceResult> {
  const startedAtMs = Date.now();
  const startedAt = new Date(startedAtMs).toISOString();
  const phases = createPhases();

  const chunkSize =
    options.chunkSize ?? DEFAULT_CHUNK_SIZE;

  const maxAttempts =
    options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;

  const retryDelayMs =
    options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;

  const statementTimeoutMs =
    options.statementTimeoutMs ??
    DEFAULT_STATEMENT_TIMEOUT_MS;

  const guardedUpserts =
    options.guardedUpserts ?? true;

  const verificationRequested =
    options.verify ?? true;

  const correlationId =
    options.correlationId ?? randomUUID();

  let serialized: SerializedHydraBatch | undefined;
  let idempotencyBaseKey: string | undefined;
  let mutationStatementsSucceeded = 0;
  let rowsSubmitted = 0;

  const sessionFactory =
    options.sessionFactory ??
    (() => driver.session());

  const validationPhase =
    phases.get("validate-serialize")!;

  const makeResult = (
    status: PersistenceStatus,
    failure?: PersistenceFailure,
  ): PersistenceResult => {
    const completedAtMs = Date.now();

    return {
      ok: status === "succeeded",
      status,
      partialWrites:
        status !== "succeeded" &&
        mutationStatementsSucceeded > 0,
      startedAt,
      completedAt:
        new Date(completedAtMs).toISOString(),
      durationMs: completedAtMs - startedAtMs,
      metadata: {
        correlationId,
        ...(idempotencyBaseKey === undefined
          ? {}
          : { idempotencyBaseKey }),
        ...(serialized === undefined
          ? {}
          : {
              batchHash: serialized.batchHash,
              schemaVersion:
                serialized.schemaVersion,
            }),
        atomic: false,
        guardedUpserts,
        verificationRequested,
      },
      totals: {
        nodesPlanned: serialized?.nodeCount ?? 0,
        canonicalEdgesPlanned:
          serialized?.canonicalEdgeCount ?? 0,
        derivedEdgesPlanned:
          serialized?.derivedEdgeCount ?? 0,
        rowsPlanned:
          serialized === undefined
            ? 0
            : serialized.nodeCount +
              serialized.canonicalEdgeCount +
              serialized.derivedEdgeCount,
        rowsSubmitted,
        mutationStatementsSucceeded,
      },
      phases: HYDRA_PERSISTENCE_PHASES.map((phase) =>
        immutablePhase(phases.get(phase)!),
      ),
      ...(failure === undefined ? {} : { failure }),
    };
  };

  const failureFrom = (
    phase: HydraPersistencePhase,
    error: unknown,
  ): PersistenceFailure => {
    if (error instanceof StatementExecutionError) {
      return {
        phase,
        code: "HYDRADB_STATEMENT_FAILED",
        message:
          "A HydraDB statement failed; query parameters and rows are intentionally omitted",
        retryable: error.retryable,
        queryShapeId: error.context.queryShapeId,
        ...(error.context.chunkIndex === undefined
          ? {}
          : { chunkIndex: error.context.chunkIndex }),
        attempts: error.attempts,
        ...(error.causeName === undefined
          ? {}
          : { causeName: error.causeName }),
        ...(error.causeCode === undefined
          ? {}
          : { causeCode: error.causeCode }),
      };
    }

    if (error instanceof WriterBoundaryError) {
      return {
        phase,
        code: error.code,
        message: error.message,
        retryable: false,
        causeName: error.name,
      };
    }

    return {
      phase,
      code: "UNEXPECTED_PERSISTENCE_ERROR",
      message:
        "An unexpected persistence-boundary error occurred; graph rows are intentionally omitted",
      retryable: false,
      ...(errorName(error) === undefined
        ? {}
        : { causeName: errorName(error) }),
      ...(errorCode(error) === undefined
        ? {}
        : { causeCode: errorCode(error) }),
    };
  };

  const failPhase = (
    phase: MutablePhaseResult,
    error: unknown,
  ): PersistenceResult => {
    const failure = failureFrom(phase.phase, error);
    phase.failure = failure;
    finishPhase(phase, "failed");

    const status: PersistenceStatus =
      mutationStatementsSucceeded > 0
        ? "partial"
        : "failed";

    return makeResult(status, failure);
  };

  const executeStatement = async (
    phase: MutablePhaseResult,
    query: string,
    parameters: Record<string, unknown>,
    context: StatementContext,
  ): Promise<ResultLike> => {
    phase.queryShapeIds.add(context.queryShapeId);

    let lastError: unknown;
    let retryable = false;

    for (
      let attempt = 1;
      attempt <= maxAttempts;
      attempt += 1
    ) {
      phase.statementsAttempted += 1;

      let session: Session | undefined;

      try {
        session = sessionFactory();

        const metadata: Record<string, string> = {
          "hydradb.correlation_id": correlationId,
          "hydradb.caller.step": context.step,
        };

        if (context.mutation) {
          if (context.idempotencyKey === undefined) {
            throw new WriterBoundaryError(
              "MISSING_IDEMPOTENCY_KEY",
              "Mutation statement has no idempotency key",
            );
          }

          metadata["hydradb.idempotency_key"] =
            context.idempotencyKey;
        }

        const result = await session.run(
          query,
          toHydraParameters(parameters),
          {
            timeout: statementTimeoutMs,
            metadata,
          },
        );

        await session.close();
        session = undefined;

        phase.statementsSucceeded += 1;
        phase.retries += attempt - 1;

        if (context.mutation) {
          mutationStatementsSucceeded += 1;
        }

        return asResultLike(result);
      } catch (error) {
        lastError = error;
        retryable = isRetryableError(error);

        if (session !== undefined) {
          try {
            await session.close();
          } catch {
            /*
             * Preserve the primary RUN failure. Every failed attempt
             * discards its session, so a close failure cannot leak a
             * reusable session into another statement.
             */
          }
        }

        if (!retryable || attempt === maxAttempts) {
          throw new StatementExecutionError(
            context,
            attempt,
            retryable,
            errorName(error),
            errorCode(error),
          );
        }

        await delay(
          retryDelayMs * 2 ** (attempt - 1),
        );
      }
    }

    throw new StatementExecutionError(
      context,
      maxAttempts,
      retryable,
      errorName(lastError),
      errorCode(lastError),
    );
  };

  try {
    beginPhase(validationPhase);

    assertPositiveInteger(
      chunkSize,
      "chunkSize",
      10_000,
    );
    assertPositiveInteger(
      maxAttempts,
      "maxAttempts",
      10,
    );
    assertPositiveInteger(
      statementTimeoutMs,
      "statementTimeoutMs",
      600_000,
    );

    if (
      !Number.isSafeInteger(retryDelayMs) ||
      retryDelayMs < 0 ||
      retryDelayMs > 60_000
    ) {
      throw new WriterBoundaryError(
        "INVALID_WRITER_OPTION",
        "retryDelayMs is outside its allowed range",
      );
    }

    validateComponent(
      correlationId,
      "correlationId",
      128,
    );

    if (!batch.validation.valid) {
      throw new WriterBoundaryError(
        "INVALID_BATCH",
        "GraphBatch carries an invalid validation result",
      );
    }

    const freshValidation = validateGraph(
      batch.nodes,
      batch.edges,
    );

    if (!freshValidation.valid) {
      throw new WriterBoundaryError(
        "INVALID_BATCH",
        "GraphBatch failed validation at the persistence boundary",
      );
    }

    serialized = serializeGraphBatch(batch);

    idempotencyBaseKey =
      options.idempotencyKey ??
      `hg-${serialized.batchHash.slice(0, 40)}`;

    /*
     * Reserve space beneath HydraDB's 128-character maximum for
     * phase, shape hash, and chunk suffixes.
     */
    validateComponent(
      idempotencyBaseKey,
      "idempotencyKey",
      80,
    );

    validationPhase.rowsPlanned =
      serialized.nodeCount +
      serialized.canonicalEdgeCount +
      serialized.derivedEdgeCount;

    validationPhase.rowsProcessed =
      validationPhase.rowsPlanned;

    finishPhase(validationPhase, "succeeded");
  } catch (error) {
    return failPhase(validationPhase, error);
  }

  const allEdgeGroups = [
    ...serialized.canonicalEdgeGroups,
    ...serialized.derivedEdgeGroups,
  ];

  const preflightPhase =
    phases.get("preflight-identities")!;

  preflightPhase.rowsPlanned =
    serialized.nodeCount +
    serialized.canonicalEdgeCount +
    serialized.derivedEdgeCount;

  try {
    beginPhase(preflightPhase);

    for (const group of serialized.nodeGroups) {
      for (
        let index = 0;
        index < group.rows.length;
        index += 1
      ) {
        const row = group.rows[index];

        const byId = await executeStatement(
          preflightPhase,
          [
            "MATCH (n {id: $id})",
            "RETURN n.logical_id AS logical_id,",
            "       n.kind AS kind",
          ].join("\n"),
          { id: row.vertex },
          {
            phase: "preflight-identities",
            queryShapeId: "preflight.node.by-id",
            step: `preflight.node.id.${index}`,
            mutation: false,
            chunkIndex: index,
          },
        );

        if (byId.records.length > 1) {
          throw new WriterBoundaryError(
            "DATABASE_ID_COLLISION",
            "Multiple HydraDB nodes use the same deterministic ID",
          );
        }

        if (byId.records.length === 1) {
          const record = byId.records[0];

          if (
            asString(
              record.get("logical_id"),
              "node logical_id",
            ) !== row.logical_id ||
            asString(
              record.get("kind"),
              "node kind",
            ) !== row.kind
          ) {
            throw new WriterBoundaryError(
              "DATABASE_ID_COLLISION",
              "Existing node identity conflicts with the incoming deterministic identity",
            );
          }
        }

        const byLogicalId = await executeStatement(
          preflightPhase,
          [
            "MATCH (n {logical_id: $logical_id})",
            "RETURN n.id AS id, n.kind AS kind",
          ].join("\n"),
          { logical_id: row.logical_id },
          {
            phase: "preflight-identities",
            queryShapeId:
              "preflight.node.by-logical-id",
            step: `preflight.node.logical.${index}`,
            mutation: false,
            chunkIndex: index,
          },
        );

        if (byLogicalId.records.length > 1) {
          throw new WriterBoundaryError(
            "DATABASE_LOGICAL_ID_COLLISION",
            "Multiple HydraDB nodes use the same logical identity",
          );
        }

        if (byLogicalId.records.length === 1) {
          const record = byLogicalId.records[0];

          if (
            asSafeInteger(
              record.get("id"),
              "node ID",
            ) !== row.vertex ||
            asString(
              record.get("kind"),
              "node kind",
            ) !== row.kind
          ) {
            throw new WriterBoundaryError(
              "DATABASE_LOGICAL_ID_COLLISION",
              "Existing logical node identity maps to a conflicting node",
            );
          }
        }

        preflightPhase.rowsProcessed += 1;
      }
    }

    for (const group of allEdgeGroups) {
      const byIdQuery =
        buildEdgeIdentityProbeQuery(
          group,
          "id",
        );

      const byLogicalIdQuery =
        buildEdgeIdentityProbeQuery(
          group,
          "logical_id",
        );

      const exactIdentityQuery =
        buildEdgeExactIdentityQuery(
          group,
        );

      for (
        let index = 0;
        index < group.rows.length;
        index += 1
      ) {
        const row = group.rows[index];

        const byId = await executeStatement(
          preflightPhase,
          byIdQuery,
          {
            relationship_vertex:
              row.relationship_vertex,
          },
          {
            phase: "preflight-identities",
            queryShapeId:
              `preflight.${group.shapeId}.by-id`,
            step:
              `preflight.edge.${shortHash(group.shapeId)}.${index}.id`,
            mutation: false,
            chunkIndex: index,
          },
        );

        const byLogicalId =
          await executeStatement(
            preflightPhase,
            byLogicalIdQuery,
            {
              logical_id:
                row.logical_id,
            },
            {
              phase: "preflight-identities",
              queryShapeId:
                `preflight.${group.shapeId}.by-logical-id`,
              step:
                `preflight.edge.${shortHash(group.shapeId)}.${index}.logical`,
              mutation: false,
              chunkIndex: index,
            },
          );

        if (
          byId.records.length > 1 ||
          byLogicalId.records.length > 1
        ) {
          throw new WriterBoundaryError(
            "DATABASE_EDGE_IDENTITY_COLLISION",
            "Multiple HydraDB relationships use the same deterministic identity",
          );
        }

        if (
          byId.records.length === 0 &&
          byLogicalId.records.length === 0
        ) {
          preflightPhase.rowsProcessed += 1;
          continue;
        }

        if (
          byId.records.length !== 1 ||
          byLogicalId.records.length !== 1
        ) {
          throw new WriterBoundaryError(
            "DATABASE_EDGE_IDENTITY_COLLISION",
            "Existing relationship ID and logical identity do not resolve together",
          );
        }

        for (const result of [
          byId,
          byLogicalId,
        ]) {
          const record = result.records[0];

          if (
            asSafeInteger(
              record.get("source_vertex"),
              "relationship source vertex",
            ) !== row.source_vertex ||
            asSafeInteger(
              record.get("destination_vertex"),
              "relationship destination vertex",
            ) !== row.destination_vertex
          ) {
            throw new WriterBoundaryError(
              "DATABASE_EDGE_IDENTITY_COLLISION",
              "Existing relationship identity maps to conflicting endpoints",
            );
          }
        }

        const exact =
          await executeStatement(
            preflightPhase,
            exactIdentityQuery,
            {
              relationship_vertex:
                row.relationship_vertex,
              logical_id:
                row.logical_id,
              kind:
                row.kind,
              source_id:
                row.source_id,
              target_id:
                row.target_id,
              derived:
                row.derived,
            },
            {
              phase: "preflight-identities",
              queryShapeId:
                `preflight.${group.shapeId}.exact`,
              step:
                `preflight.edge.${shortHash(group.shapeId)}.${index}.exact`,
              mutation: false,
              chunkIndex: index,
            },
          );

        if (exact.records.length !== 1) {
          throw new WriterBoundaryError(
            "DATABASE_EDGE_IDENTITY_COLLISION",
            "Existing relationship identity conflicts with the incoming relationship",
          );
        }

        const exactRecord =
          exact.records[0];

        if (
          asSafeInteger(
            exactRecord.get("source_vertex"),
            "relationship source vertex",
          ) !== row.source_vertex ||
          asSafeInteger(
            exactRecord.get("destination_vertex"),
            "relationship destination vertex",
          ) !== row.destination_vertex
        ) {
          throw new WriterBoundaryError(
            "DATABASE_EDGE_IDENTITY_COLLISION",
            "Existing relationship identity maps to conflicting endpoints",
          );
        }

        preflightPhase.rowsProcessed += 1;
      }
    }

    finishPhase(preflightPhase, "succeeded");
  } catch (error) {
    return failPhase(preflightPhase, error);
  }

  const writeGroups = async (
    phaseName:
      | "upsert-nodes"
      | "upsert-canonical-edges"
      | "upsert-derived-edges",
    groups: readonly (
      | HydraNodeGroup
      | HydraEdgeGroup
    )[],
    rowCount: number,
  ): Promise<PersistenceResult | undefined> => {
    const phase = phases.get(phaseName)!;
    phase.rowsPlanned = rowCount;

    try {
      beginPhase(phase);

      for (const group of groups) {
        const query =
          "label" in group
            ? buildNodeUpsertQuery(
                group,
                guardedUpserts,
              )
            : buildEdgeUpsertQuery(
                group,
                guardedUpserts,
              );

        const rowChunks = chunks<
          HydraNodeRow | HydraEdgeRow
        >(
          group.rows,
          chunkSize,
        );

        for (
          let chunkIndex = 0;
          chunkIndex < rowChunks.length;
          chunkIndex += 1
        ) {
          const idempotencyKey =
            createChunkIdempotencyKey(
              idempotencyBaseKey!,
              phaseName,
              group.shapeId,
              chunkIndex,
            );

          const chunk = rowChunks[chunkIndex];

          await executeStatement(
            phase,
            query,
            {
              rows: queryRows(chunk),
            },
            {
              phase: phaseName,
              queryShapeId: group.shapeId,
              step:
                `${phaseToken(phaseName)}.` +
                `${shortHash(group.shapeId)}.${chunkIndex}`,
              mutation: true,
              idempotencyKey,
              chunkIndex,
            },
          );

          phase.rowsProcessed += chunk.length;
          rowsSubmitted += chunk.length;
        }
      }

      finishPhase(phase, "succeeded");
      return undefined;
    } catch (error) {
      return failPhase(phase, error);
    }
  };

  const nodeFailure = await writeGroups(
    "upsert-nodes",
    serialized.nodeGroups,
    serialized.nodeCount,
  );

  if (nodeFailure !== undefined) {
    return nodeFailure;
  }

  const canonicalFailure = await writeGroups(
    "upsert-canonical-edges",
    serialized.canonicalEdgeGroups,
    serialized.canonicalEdgeCount,
  );

  if (canonicalFailure !== undefined) {
    return canonicalFailure;
  }

  const derivedFailure = await writeGroups(
    "upsert-derived-edges",
    serialized.derivedEdgeGroups,
    serialized.derivedEdgeCount,
  );

  if (derivedFailure !== undefined) {
    return derivedFailure;
  }

  const verificationPhase = phases.get("verify")!;
  verificationPhase.rowsPlanned =
    serialized.nodeCount +
    serialized.canonicalEdgeCount +
    serialized.derivedEdgeCount;

  if (!verificationRequested) {
    verificationPhase.status = "skipped";
    return makeResult("succeeded");
  }

  try {
    beginPhase(verificationPhase);

    for (const group of serialized.nodeGroups) {
      for (
        let index = 0;
        index < group.rows.length;
        index += 1
      ) {
        const row = group.rows[index];

        const result = await executeStatement(
          verificationPhase,
          [
            "MATCH (n {id: $id})",
            "RETURN n.logical_id AS logical_id,",
            "       n.kind AS kind",
          ].join("\n"),
          { id: row.vertex },
          {
            phase: "verify",
            queryShapeId: "verify.node.identity",
            step: `verify.node.${index}`,
            mutation: false,
            chunkIndex: index,
          },
        );

        if (result.records.length !== 1) {
          throw new WriterBoundaryError(
            "NODE_VERIFICATION_FAILED",
            "Persisted node identity could not be verified",
          );
        }

        const record = result.records[0];

        if (
          asString(
            record.get("logical_id"),
            "node logical_id",
          ) !== row.logical_id ||
          asString(
            record.get("kind"),
            "node kind",
          ) !== row.kind
        ) {
          throw new WriterBoundaryError(
            "NODE_VERIFICATION_FAILED",
            "Persisted node has an unexpected identity",
          );
        }

        verificationPhase.rowsProcessed += 1;
      }
    }

    for (const group of allEdgeGroups) {
      const query = buildEdgeVerificationQuery(group);

      for (
        let index = 0;
        index < group.rows.length;
        index += 1
      ) {
        const row = group.rows[index];

        const result = await executeStatement(
          verificationPhase,
          query,
          {
            source_vertex:
              row.source_vertex,
            destination_vertex:
              row.destination_vertex,
            relationship_vertex:
              row.relationship_vertex,
            logical_id:
              row.logical_id,
            kind:
              row.kind,
          },
          {
            phase: "verify",
            queryShapeId: `verify.${group.shapeId}`,
            step:
              `verify.edge.${shortHash(group.shapeId)}.${index}`,
            mutation: false,
            chunkIndex: index,
          },
        );

        if (result.records.length !== 1) {
          throw new WriterBoundaryError(
            "EDGE_VERIFICATION_FAILED",
            "Persisted relationship identity could not be uniquely verified",
          );
        }

        verificationPhase.rowsProcessed += 1;
      }
    }

    finishPhase(verificationPhase, "succeeded");
  } catch (error) {
    return failPhase(verificationPhase, error);
  }

  return makeResult("succeeded");
}
