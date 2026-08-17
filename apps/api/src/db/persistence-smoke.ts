import assert from "node:assert/strict";

import type {
  Driver,
  Session,
} from "neo4j-driver";

import { generateFixture } from "../domain/fixture.js";

import {
  mergeGraphFragments,
} from "../ingest/graph-batch.js";

import type {
  GraphBatch,
} from "../ingest/graph-batch.js";

import {
  persistGraphBatch,
} from "./hydra-writer.js";

import type {
  PersistenceResult,
} from "./persistence-result.js";

type UnknownRecord = Record<string, unknown>;
type MutationKind = "node" | "canonical" | "derived";

interface RunCall {
  readonly query: string;
  readonly parameters: Readonly<UnknownRecord>;
  readonly metadata: Readonly<Record<string, string>>;
  readonly mutationKind?: MutationKind;
}

interface FailureRule {
  remaining: number;
  readonly matches: (call: RunCall) => boolean;
  readonly createError: () => Error;
}

interface StoredNode extends UnknownRecord {
  id: number;
  logical_id: string;
  kind: string;
  label: string;
}

interface StoredRelationship extends UnknownRecord {
  relationship_vertex: number;
  source_vertex: number;
  destination_vertex: number;
  logical_id: string;
  kind: string;
  relationship_type: string;
  source_id: number;
  target_id: number;
}

class FakeRecord {
  constructor(
    private readonly values: Readonly<UnknownRecord>,
  ) {}

  get(key: string): unknown {
    return this.values[key];
  }
}

interface FakeResult {
  readonly records: readonly FakeRecord[];
}

class FakeNeo4jError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
    this.name = "FakeNeo4jError";
  }
}

function isRecord(value: unknown): value is UnknownRecord {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function requireRecord(
  value: unknown,
  description: string,
): UnknownRecord {
  assert.ok(isRecord(value), `${description} must be a record`);
  return value;
}

function requireString(
  value: unknown,
  description: string,
): string {
  assert.equal(typeof value, "string", `${description} must be a string`);
  return value;
}

function requireNumber(
  value: unknown,
  description: string,
): number {
  assert.equal(typeof value, "number", `${description} must be a number`);
  assert.ok(
    Number.isSafeInteger(value) && value >= 0,
    `${description} must be a nonnegative safe integer`,
  );
  return value;
}

function requireRows(parameters: Readonly<UnknownRecord>): UnknownRecord[] {
  const value = parameters.rows;
  assert.ok(Array.isArray(value), "rows parameter must be an array");
  return value.map((row, index) =>
    requireRecord(row, `rows[${index}]`),
  );
}

function requireMatch(
  query: string,
  pattern: RegExp,
  description: string,
): string {
  const match = query.match(pattern);
  assert.ok(match?.[1] !== undefined, `Could not parse ${description}`);
  return match[1];
}

function mutationKindForQuery(
  query: string,
): MutationKind | undefined {
  if (!query.startsWith("UNWIND $rows AS row")) {
    return undefined;
  }

  if (query.includes("MERGE (n {id: row.vertex})")) {
    return "node";
  }

  if (query.includes("MERGE (s)-[r:USED_BY ")) {
    return "derived";
  }

  if (query.includes("MERGE (s)-[r:")) {
    return "canonical";
  }

  return undefined;
}

class FakeHydraStore {
  readonly nodes = new Map<number, StoredNode>();
  readonly relationships = new Map<number, StoredRelationship>();
  readonly calls: RunCall[] = [];

  sessionsCreated = 0;
  sessionsClosed = 0;

  private readonly failureRules: FailureRule[] = [];
  private readonly completedMutationKeys = new Set<string>();

  sessionFactory = (): Session => {
    this.sessionsCreated += 1;
    return new FakeSession(this) as unknown as Session;
  };

  addFailure(rule: FailureRule): void {
    this.failureRules.push(rule);
  }

  seedNode(node: StoredNode): void {
    this.nodes.set(node.id, { ...node });
  }

  noteSessionClosed(): void {
    this.sessionsClosed += 1;
  }

  async run(
    query: string,
    parameters: Readonly<UnknownRecord> = {},
    transactionConfig?: {
      readonly metadata?: Readonly<Record<string, string>>;
    },
  ): Promise<FakeResult> {
    const metadata = transactionConfig?.metadata ?? {};
    const mutationKind = mutationKindForQuery(query);

    const call: RunCall = {
      query,
      parameters,
      metadata,
      ...(mutationKind === undefined ? {} : { mutationKind }),
    };

    this.calls.push(call);

    for (const rule of this.failureRules) {
      if (rule.remaining > 0 && rule.matches(call)) {
        rule.remaining -= 1;
        throw rule.createError();
      }
    }

    const idempotencyKey =
      metadata["hydradb.idempotency_key"];

    if (
      mutationKind !== undefined &&
      idempotencyKey !== undefined &&
      this.completedMutationKeys.has(idempotencyKey)
    ) {
      return { records: [] };
    }

    const result = this.execute(query, parameters);

    if (mutationKind !== undefined) {
      assert.ok(
        idempotencyKey !== undefined,
        "Every mutation must carry an idempotency key",
      );
      this.completedMutationKeys.add(idempotencyKey);
    }

    return result;
  }

  private execute(
    query: string,
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    if (
      query.startsWith("UNWIND $rows AS row") &&
      query.includes("MERGE (n {id: row.vertex})")
    ) {
      return this.upsertNodes(query, parameters);
    }

    if (
      query.startsWith("UNWIND $rows AS row") &&
      query.includes("MERGE (s)-[r:")
    ) {
      return this.upsertRelationships(query, parameters);
    }

    if (query.startsWith("MATCH (n {id: $id})")) {
      return this.findNodeById(parameters);
    }

    if (query.startsWith("MATCH (n {logical_id: $logical_id})")) {
      return this.findNodeByLogicalId(parameters);
    }

    if (
      query.includes("]->(d)") &&
      query.includes("destination_vertex") &&
      !query.includes("$destination_vertex")
    ) {
      return this.findOutgoingRelationships(parameters);
    }

    if (
      query.startsWith("MATCH (s:") &&
      query.includes("$destination_vertex")
    ) {
      return this.verifyRelationship(query, parameters);
    }

    assert.fail(`Fake HydraDB received an unsupported query shape:\n${query}`);
  }

  private upsertNodes(
    query: string,
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const label = requireMatch(
      query,
      /SET n:([A-Za-z_][A-Za-z0-9_]*)/,
      "node label",
    );

    for (const row of requireRows(parameters)) {
      const id = requireNumber(row.vertex, "node vertex");
      const logicalId = requireString(row.logical_id, "node logical_id");
      const kind = requireString(row.kind, "node kind");

      this.nodes.set(id, {
        ...row,
        id,
        logical_id: logicalId,
        kind,
        label,
      });
    }

    return { records: [] };
  }

  private upsertRelationships(
    query: string,
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const relationshipType = requireMatch(
      query,
      /MERGE \(s\)-\[r:([A-Za-z_][A-Za-z0-9_]*) /,
      "relationship type",
    );

    for (const row of requireRows(parameters)) {
      const relationshipId = requireNumber(
        row.relationship_vertex,
        "relationship vertex",
      );
      const sourceVertex = requireNumber(
        row.source_vertex,
        "source vertex",
      );
      const destinationVertex = requireNumber(
        row.destination_vertex,
        "destination vertex",
      );

      assert.ok(
        this.nodes.has(sourceVertex),
        "relationship source must already exist",
      );
      assert.ok(
        this.nodes.has(destinationVertex),
        "relationship destination must already exist",
      );

      this.relationships.set(relationshipId, {
        ...row,
        relationship_vertex: relationshipId,
        source_vertex: sourceVertex,
        destination_vertex: destinationVertex,
        logical_id: requireString(
          row.logical_id,
          "relationship logical_id",
        ),
        kind: requireString(row.kind, "relationship kind"),
        relationship_type: relationshipType,
        source_id: requireNumber(row.source_id, "relationship source_id"),
        target_id: requireNumber(row.target_id, "relationship target_id"),
      });
    }

    return { records: [] };
  }

  private findNodeById(
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const id = requireNumber(parameters.id, "node lookup ID");
    const node = this.nodes.get(id);

    return {
      records: node === undefined
        ? []
        : [new FakeRecord({
            logical_id: node.logical_id,
            kind: node.kind,
          })],
    };
  }

  private findNodeByLogicalId(
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const logicalId = requireString(
      parameters.logical_id,
      "node logical ID lookup",
    );

    return {
      records: [...this.nodes.values()]
        .filter((node) => node.logical_id === logicalId)
        .map((node) => new FakeRecord({
          id: node.id,
          kind: node.kind,
        })),
    };
  }

  private findOutgoingRelationships(
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const sourceVertex = requireNumber(
      parameters.source_vertex,
      "relationship source lookup",
    );

    return {
      records: [...this.relationships.values()]
        .filter(
          (relationship) =>
            relationship.source_vertex === sourceVertex,
        )
        .map((relationship) => new FakeRecord({
          relationship_vertex:
            relationship.relationship_vertex,
          logical_id: relationship.logical_id,
          kind: relationship.kind,
          source_id: relationship.source_id,
          target_id: relationship.target_id,
          destination_vertex:
            relationship.destination_vertex,
        })),
    };
  }

  private verifyRelationship(
    query: string,
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const relationshipType = requireMatch(
      query,
      /\[r:([A-Za-z_][A-Za-z0-9_]*)\]->/,
      "verification relationship type",
    );

    const sourceVertex = requireNumber(
      parameters.source_vertex,
      "verification source vertex",
    );
    const destinationVertex = requireNumber(
      parameters.destination_vertex,
      "verification destination vertex",
    );

    return {
      records: [...this.relationships.values()]
        .filter(
          (relationship) =>
            relationship.source_vertex === sourceVertex &&
            relationship.destination_vertex === destinationVertex &&
            relationship.relationship_type === relationshipType,
        )
        .map((relationship) => new FakeRecord({
          relationship_vertex:
            relationship.relationship_vertex,
          logical_id: relationship.logical_id,
          kind: relationship.kind,
        })),
    };
  }
}

class FakeSession {
  private closed = false;

  constructor(private readonly store: FakeHydraStore) {}

  run(
    query: string,
    parameters?: Readonly<UnknownRecord>,
    transactionConfig?: {
      readonly metadata?: Readonly<Record<string, string>>;
    },
  ): Promise<FakeResult> {
    assert.equal(this.closed, false, "Cannot run a closed fake session");
    return this.store.run(query, parameters, transactionConfig);
  }

  async close(): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      this.store.noteSessionClosed();
    }
  }
}

const UNUSED_DRIVER = {} as Driver;

function createBatch(): GraphBatch {
  const fixture = generateFixture();

  assert.equal(fixture.validation.valid, true);

  return mergeGraphFragments([
    {
      source: "persistence-smoke-fixture",
      nodes: fixture.nodes,
      edges: fixture.edges,
    },
  ]);
}

async function persist(
  store: FakeHydraStore,
  batch: GraphBatch,
  options: {
    readonly chunkSize?: number;
    readonly maxAttempts?: number;
    readonly retryDelayMs?: number;
    readonly verify?: boolean;
    readonly idempotencyKey?: string;
  } = {},
): Promise<PersistenceResult> {
  return persistGraphBatch(
    UNUSED_DRIVER,
    batch,
    {
      ...options,
      correlationId: "persistence-smoke",
      sessionFactory: store.sessionFactory,
    },
  );
}

function mutationCalls(store: FakeHydraStore): RunCall[] {
  return store.calls.filter(
    (call): call is RunCall & { mutationKind: MutationKind } =>
      call.mutationKind !== undefined,
  );
}

function mutationKeys(calls: readonly RunCall[]): string[] {
  return calls.map((call) => {
    const key = call.metadata["hydradb.idempotency_key"];
    assert.ok(key !== undefined, "Mutation call has no idempotency key");
    return key;
  });
}

function assertEverySessionClosed(store: FakeHydraStore): void {
  assert.equal(
    store.sessionsClosed,
    store.sessionsCreated,
    "Every writer-owned session must be closed",
  );
}

async function verifiesInvalidBatchFailsBeforeIo(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();

  const invalidBatch: GraphBatch = {
    ...batch,
    validation: {
      valid: false,
      errors: ["deliberately invalid for smoke coverage"],
    },
  };

  const result = await persist(store, invalidBatch);

  assert.equal(result.ok, false);
  assert.equal(result.status, "failed");
  assert.equal(result.partialWrites, false);
  assert.equal(result.failure?.code, "INVALID_BATCH");
  assert.equal(store.sessionsCreated, 0);
  assert.equal(mutationCalls(store).length, 0);
}

async function verifiesCollisionFailsBeforeMutation(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();
  const incoming = batch.nodes[0];

  store.seedNode({
    id: incoming.id,
    logical_id: "service:conflicting-existing-node",
    kind: "Service",
    label: "Service",
  });

  const result = await persist(store, batch);

  assert.equal(result.ok, false);
  assert.equal(result.status, "failed");
  assert.equal(result.partialWrites, false);
  assert.equal(result.failure?.code, "DATABASE_ID_COLLISION");
  assert.equal(mutationCalls(store).length, 0);
  assertEverySessionClosed(store);
}

async function verifiesSuccessOrderingChunkingAndReplay(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();

  assert.equal(Object.isFrozen(batch), true);
  assert.equal(Object.isFrozen(batch.nodes), true);
  assert.equal(Object.isFrozen(batch.edges), true);

  const firstCallStart = store.calls.length;
  const first = await persist(store, batch, {
    chunkSize: 1,
    idempotencyKey: "persistence-smoke-success",
  });

  assert.equal(first.ok, true);
  assert.equal(first.status, "succeeded");
  assert.equal(first.partialWrites, false);
  assert.equal(store.nodes.size, batch.nodes.length);
  assert.equal(store.relationships.size, batch.edges.length);
  assert.equal(
    first.totals.rowsSubmitted,
    batch.nodes.length + batch.edges.length,
  );
  assert.equal(
    first.phases.find((phase) => phase.phase === "verify")?.status,
    "succeeded",
  );

  const firstMutationCalls = store.calls
    .slice(firstCallStart)
    .filter((call) => call.mutationKind !== undefined);

  assert.ok(firstMutationCalls.length > 0);

  for (const call of firstMutationCalls) {
    const rows = requireRows(call.parameters);
    assert.ok(rows.length <= 1, "chunkSize=1 must be honored");
  }

  const mutationOrder = firstMutationCalls.map(
    (call) => call.mutationKind,
  );
  const firstCanonical = mutationOrder.indexOf("canonical");
  const firstDerived = mutationOrder.indexOf("derived");
  const lastNode = mutationOrder.lastIndexOf("node");
  const lastCanonical = mutationOrder.lastIndexOf("canonical");

  assert.ok(lastNode >= 0 && firstCanonical > lastNode);
  assert.ok(lastCanonical >= firstCanonical);
  assert.ok(firstDerived > lastCanonical);

  const firstKeys = mutationKeys(firstMutationCalls);
  const originalNodeCount = store.nodes.size;
  const originalRelationshipCount = store.relationships.size;

  const replayStart = store.calls.length;
  const replay = await persist(store, batch, {
    chunkSize: 1,
    idempotencyKey: "persistence-smoke-success",
  });

  assert.equal(replay.ok, true);
  assert.equal(store.nodes.size, originalNodeCount);
  assert.equal(store.relationships.size, originalRelationshipCount);

  const replayMutationCalls = store.calls
    .slice(replayStart)
    .filter((call) => call.mutationKind !== undefined);

  assert.deepEqual(mutationKeys(replayMutationCalls), firstKeys);
  assertEverySessionClosed(store);
}

async function verifiesRetryUsesTheSameKey(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();

  store.addFailure({
    remaining: 1,
    matches: (call) => call.mutationKind === "node",
    createError: () => new FakeNeo4jError(
      "temporary fake outage",
      "Neo.TransientError.General.DatabaseUnavailable",
    ),
  });

  const result = await persist(store, batch, {
    maxAttempts: 2,
    retryDelayMs: 0,
    verify: false,
    idempotencyKey: "persistence-smoke-retry",
  });

  assert.equal(result.ok, true);

  const calls = mutationCalls(store);
  assert.ok(calls.length >= 2);
  assert.equal(calls[0].mutationKind, "node");
  assert.equal(calls[1].mutationKind, "node");
  assert.equal(
    calls[0].metadata["hydradb.idempotency_key"],
    calls[1].metadata["hydradb.idempotency_key"],
  );
  assert.equal(
    result.phases.find(
      (phase) => phase.phase === "upsert-nodes",
    )?.retries,
    1,
  );
  assertEverySessionClosed(store);
}

async function verifiesPermanentFailureIsNotRetried(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();

  store.addFailure({
    remaining: 1,
    matches: (call) => call.mutationKind === "node",
    createError: () => new FakeNeo4jError(
      "permanent fake failure",
      "Neo.ClientError.Statement.ExecutionFailed",
    ),
  });

  const result = await persist(store, batch, {
    maxAttempts: 3,
    retryDelayMs: 0,
    verify: false,
    idempotencyKey: "persistence-smoke-permanent",
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, "failed");
  assert.equal(result.partialWrites, false);
  assert.equal(result.failure?.retryable, false);
  assert.equal(mutationCalls(store).length, 1);
  assertEverySessionClosed(store);
}

async function verifiesPartialResultIsReplayableAndRedacted(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();
  const secretMarker = "TOP_SECRET_ROW_VALUE";

  store.addFailure({
    remaining: 1,
    matches: (call) => call.mutationKind === "canonical",
    createError: () => new FakeNeo4jError(
      `permanent failure containing ${secretMarker}`,
      "Neo.ClientError.Statement.ExecutionFailed",
    ),
  });

  const first = await persist(store, batch, {
    chunkSize: 1,
    maxAttempts: 2,
    retryDelayMs: 0,
    idempotencyKey: "persistence-smoke-partial",
  });

  assert.equal(first.ok, false);
  assert.equal(first.status, "partial");
  assert.equal(first.partialWrites, true);
  assert.ok(first.totals.mutationStatementsSucceeded > 0);
  assert.equal(
    first.phases.find(
      (phase) => phase.phase === "upsert-derived-edges",
    )?.status,
    "skipped",
  );
  assert.equal(JSON.stringify(first).includes(secretMarker), false);

  const recovered = await persist(store, batch, {
    chunkSize: 1,
    maxAttempts: 2,
    retryDelayMs: 0,
    idempotencyKey: "persistence-smoke-partial",
  });

  assert.equal(recovered.ok, true);
  assert.equal(recovered.status, "succeeded");
  assert.equal(store.nodes.size, batch.nodes.length);
  assert.equal(store.relationships.size, batch.edges.length);
  assertEverySessionClosed(store);
}

async function verifiesVerificationFailureCannotReturnSuccess(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();

  store.addFailure({
    remaining: 1,
    matches: (call) =>
      call.metadata["hydradb.caller.step"]?.startsWith(
        "verify.node.",
      ) === true,
    createError: () => new FakeNeo4jError(
      "verification transport failed",
      "Neo.ClientError.Statement.ExecutionFailed",
    ),
  });

  const result = await persist(store, batch, {
    retryDelayMs: 0,
    idempotencyKey: "persistence-smoke-verification",
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, "partial");
  assert.equal(result.partialWrites, true);
  assert.equal(result.failure?.phase, "verify");
  assertEverySessionClosed(store);
}

async function main(): Promise<void> {
  const batch = createBatch();

  await verifiesInvalidBatchFailsBeforeIo(batch);
  await verifiesCollisionFailsBeforeMutation(batch);
  await verifiesSuccessOrderingChunkingAndReplay(batch);
  await verifiesRetryUsesTheSameKey(batch);
  await verifiesPermanentFailureIsNotRetried(batch);
  await verifiesPartialResultIsReplayableAndRedacted(batch);
  await verifiesVerificationFailureCannotReturnSuccess(batch);

  console.log("HydraDB persistence smoke passed");
  console.log("- invalid batches fail before database I/O");
  console.log("- identity collisions fail before mutation");
  console.log("- nodes precede canonical edges and derived USED_BY edges");
  console.log("- configured chunk sizes are honored");
  console.log("- retries preserve per-chunk idempotency keys");
  console.log("- non-retryable failures execute once");
  console.log("- partial writes are explicit, redacted, and replayable");
  console.log("- verification failures cannot return success");
  console.log("- every writer-owned session is closed");
}

await main();
