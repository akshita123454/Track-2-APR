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
  HydraPersistenceService,
  PersistenceServiceError,
} from "./persistence-service.js";

import type {
  PersistenceServiceOptions,
} from "./persistence-service.js";

type UnknownRecord = Record<string, unknown>;

type MutationKind =
  | "node"
  | "canonical"
  | "derived";

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
  vertex: number;
  logical_id: string;
  kind: string;
}

interface StoredRelationship extends UnknownRecord {
  relationship_vertex: number;
  source_vertex: number;
  destination_vertex: number;
  logical_id: string;
  kind: string;
  relationshipType: string;
}

interface FakeResult {
  readonly records: readonly FakeRecord[];
}

type BeforeRun = (
  call: RunCall,
) => Promise<void> | void;

class FakeRecord {
  constructor(
    private readonly values: Readonly<UnknownRecord>,
  ) {}

  get(key: string): unknown {
    return this.values[key];
  }
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
  assert.ok(
    isRecord(value),
    `${description} must be a record`,
  );

  return value;
}

function requireString(
  value: unknown,
  description: string,
): string {
  if (typeof value !== "string") {
    throw new TypeError(
      `${description} must be a string`,
    );
  }

  return value;
}

function requireNumber(
  value: unknown,
  description: string,
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
    throw new TypeError(
      `${description} must be a nonnegative safe integer`,
    );
  }

  return converted;
}

function requireRows(
  parameters: Readonly<UnknownRecord>,
): UnknownRecord[] {
  const value = parameters.rows;

  assert.ok(
    Array.isArray(value),
    "rows parameter must be an array",
  );

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

  assert.ok(
    match?.[1] !== undefined,
    `Could not parse ${description}`,
  );

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
  readonly nodes =
    new Map<number, StoredNode>();

  readonly relationships =
    new Map<number, StoredRelationship>();

  readonly calls: RunCall[] = [];
  readonly failedCalls: RunCall[] = [];

  sessionsCreated = 0;
  sessionsClosed = 0;

  private readonly failureRules: FailureRule[] = [];

  private readonly completedMutationKeys =
    new Set<string>();

  constructor(
    private readonly beforeRun?: BeforeRun,
  ) {}

  sessionFactory = (): Session => {
    this.sessionsCreated += 1;

    return new FakeSession(this) as unknown as Session;
  };

  addFailure(rule: FailureRule): void {
    this.failureRules.push(rule);
  }

  noteSessionClosed(): void {
    this.sessionsClosed += 1;
  }

  async run(
    query: string,
    parameters: Readonly<UnknownRecord> = {},
    transactionConfig?: {
      readonly metadata?: Readonly<
        Record<string, string>
      >;
    },
  ): Promise<FakeResult> {
    const metadata =
      transactionConfig?.metadata ?? {};

    const mutationKind =
      mutationKindForQuery(query);

    const call: RunCall = {
      query,
      parameters,
      metadata,
      ...(mutationKind === undefined
        ? {}
        : { mutationKind }),
    };

    this.calls.push(call);

    await this.beforeRun?.(call);

    for (const rule of this.failureRules) {
      if (
        rule.remaining > 0 &&
        rule.matches(call)
      ) {
        rule.remaining -= 1;
        this.failedCalls.push(call);
        throw rule.createError();
      }
    }

    if (mutationKind !== undefined) {
      return this.executeMutation(
        call,
        mutationKind,
      );
    }

    const step =
      metadata["hydradb.caller.step"] ?? "";

    /*
     * This service smoke is not intended to repeat the writer's
     * collision-preflight tests. Those are already covered by
     * persistence-smoke.ts.
     */
    if (step.startsWith("preflight.")) {
      return { records: [] };
    }

    if (step.startsWith("verify.node.")) {
      return this.verifyNode(parameters);
    }

    if (step.startsWith("verify.edge.")) {
      return this.verifyRelationship(
        query,
        parameters,
      );
    }

    assert.fail(
      `Fake HydraDB received an unsupported query:\n${query}`,
    );
  }

  private executeMutation(
    call: RunCall,
    mutationKind: MutationKind,
  ): FakeResult {
    const idempotencyKey = requireString(
      call.metadata["hydradb.idempotency_key"],
      "mutation idempotency key",
    );

    /*
     * Simulate HydraDB transaction-metadata idempotency. Replayed
     * statements with a previously completed key do not mutate again.
     */
    if (
      this.completedMutationKeys.has(
        idempotencyKey,
      )
    ) {
      return { records: [] };
    }

    if (mutationKind === "node") {
      this.upsertNodes(call.parameters);
    } else {
      this.upsertRelationships(
        call.query,
        call.parameters,
      );
    }

    this.completedMutationKeys.add(
      idempotencyKey,
    );

    return { records: [] };
  }

  private upsertNodes(
    parameters: Readonly<UnknownRecord>,
  ): void {
    for (const row of requireRows(parameters)) {
      const vertex = requireNumber(
        row.vertex,
        "node vertex",
      );

      this.nodes.set(vertex, {
        ...row,
        vertex,
        logical_id: requireString(
          row.logical_id,
          "node logical_id",
        ),
        kind: requireString(
          row.kind,
          "node kind",
        ),
      });
    }
  }

  private upsertRelationships(
    query: string,
    parameters: Readonly<UnknownRecord>,
  ): void {
    const relationshipType = requireMatch(
      query,
      /MERGE \(s\)-\[r:([A-Za-z_][A-Za-z0-9_]*) /,
      "relationship type",
    );

    for (const row of requireRows(parameters)) {
      const relationshipVertex =
        requireNumber(
          row.relationship_vertex,
          "relationship vertex",
        );

      this.relationships.set(
        relationshipVertex,
        {
          ...row,
          relationship_vertex:
            relationshipVertex,
          source_vertex: requireNumber(
            row.source_vertex,
            "relationship source vertex",
          ),
          destination_vertex:
            requireNumber(
              row.destination_vertex,
              "relationship destination vertex",
            ),
          logical_id: requireString(
            row.logical_id,
            "relationship logical_id",
          ),
          kind: requireString(
            row.kind,
            "relationship kind",
          ),
          relationshipType,
        },
      );
    }
  }

  private verifyNode(
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const vertex = requireNumber(
      parameters.id,
      "verification node ID",
    );

    const node = this.nodes.get(vertex);

    if (node === undefined) {
      return { records: [] };
    }

    return {
      records: [
        new FakeRecord({
          logical_id: node.logical_id,
          kind: node.kind,
        }),
      ],
    };
  }

  private verifyRelationship(
    query: string,
    parameters: Readonly<UnknownRecord>,
  ): FakeResult {
    const relationshipType = requireMatch(
      query,
      /\[:([A-Za-z_][A-Za-z0-9_]*) \{/,
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

    const relationshipVertex = requireNumber(
      parameters.relationship_vertex,
      "verification relationship vertex",
    );

    const logicalId = requireString(
      parameters.logical_id,
      "verification relationship logical identity",
    );

    const kind = requireString(
      parameters.kind,
      "verification relationship kind",
    );

    const records = [
      ...this.relationships.values(),
    ]
      .filter(
        (relationship) =>
          relationship.relationshipType ===
            relationshipType &&
          relationship.source_vertex ===
            sourceVertex &&
          relationship.destination_vertex ===
            destinationVertex &&
          relationship.relationship_vertex ===
            relationshipVertex &&
          relationship.logical_id ===
            logicalId &&
          relationship.kind === kind,
      )
      .map(
        (relationship) =>
          new FakeRecord({
            source_vertex:
              relationship.source_vertex,
            destination_vertex:
              relationship.destination_vertex,
          }),
      );

    return { records };
  }
}

class FakeSession {
  private closed = false;

  constructor(
    private readonly store: FakeHydraStore,
  ) {}

  run(
    query: string,
    parameters?: Readonly<UnknownRecord>,
    transactionConfig?: {
      readonly metadata?: Readonly<
        Record<string, string>
      >;
    },
  ): Promise<FakeResult> {
    assert.equal(
      this.closed,
      false,
      "Cannot run a closed fake session",
    );

    return this.store.run(
      query,
      parameters,
      transactionConfig,
    );
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

  assert.equal(
    fixture.validation.valid,
    true,
  );

  const batch = mergeGraphFragments([
    {
      source:
        "persistence-service-smoke-fixture",
      nodes: fixture.nodes,
      edges: fixture.edges,
    },
  ]);

  assert.equal(Object.isFrozen(batch), true);
  assert.equal(
    Object.isFrozen(batch.nodes),
    true,
  );
  assert.equal(
    Object.isFrozen(batch.edges),
    true,
  );

  return batch;
}

function serviceOptions(
  store: FakeHydraStore,
  idempotencyKey: string,
  correlationId: string,
  overrides: Partial<
    PersistenceServiceOptions
  > = {},
): PersistenceServiceOptions {
  return {
    chunkSize: 1,
    maxAttempts: 1,
    retryDelayMs: 0,
    maxPartialReplays: 0,
    partialReplayDelayMs: 0,
    idempotencyKey,
    correlationId,
    sessionFactory: store.sessionFactory,
    ...overrides,
  };
}

function mutationCalls(
  store: FakeHydraStore,
): RunCall[] {
  return store.calls.filter(
    (
      call,
    ): call is RunCall & {
      mutationKind: MutationKind;
    } => call.mutationKind !== undefined,
  );
}

function mutationKey(
  call: RunCall,
): string {
  return requireString(
    call.metadata["hydradb.idempotency_key"],
    "mutation idempotency key",
  );
}

function assertEverySessionClosed(
  store: FakeHydraStore,
): void {
  assert.equal(
    store.sessionsClosed,
    store.sessionsCreated,
    "Every writer-owned session must be closed",
  );
}

function createGate(): {
  readonly promise: Promise<void>;
  readonly release: () => void;
} {
  let release = (): void => {
    throw new Error(
      "Deferred gate was released before initialization",
    );
  };

  const promise = new Promise<void>(
    (resolve) => {
      release = () => resolve();
    },
  );

  return {
    promise,
    release,
  };
}

async function verifiesMandatorySafetyPolicy(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();

  const service =
    new HydraPersistenceService(
      UNUSED_DRIVER,
    );

  /*
   * The public options type omits verify and guardedUpserts.
   * The cast deliberately simulates untyped JavaScript or an unsafe
   * caller attempting to bypass that TypeScript boundary.
   */
  const attemptedUnsafeOptions = {
    ...serviceOptions(
      store,
      "service-smoke-mandatory-policy",
      "service-smoke-mandatory-correlation",
    ),
    verify: false,
    guardedUpserts: false,
  } as unknown as PersistenceServiceOptions;

  const persisted = await service.persist(
    batch,
    attemptedUnsafeOptions,
  );

  assert.equal(
    Object.isFrozen(persisted),
    true,
  );

  assert.equal(
    persisted.batch,
    batch,
    "The capability must retain the exact immutable batch",
  );

  assert.equal(
    persisted.persistenceAttempts,
    1,
  );

  assert.equal(
    persisted.result.ok,
    true,
  );

  assert.equal(
    persisted.result.metadata
      .verificationRequested,
    true,
    "The service must force verification",
  );

  assert.equal(
    persisted.result.metadata.guardedUpserts,
    true,
    "The service must force guarded upserts",
  );

  assert.equal(
    persisted.result.phases.find(
      (phase) => phase.phase === "verify",
    )?.status,
    "succeeded",
  );

  const mutations = mutationCalls(store);

  assert.ok(
    mutations.length > 0,
    "The smoke must execute mutations",
  );

  for (const call of mutations) {
    assert.equal(
      call.query.includes(
        "__hydradb_update_if_newer_by",
      ),
      true,
      "Every mutation query must contain the update guard",
    );
  }

  const verificationCalls =
    store.calls.filter(
      (call) =>
        call.metadata[
          "hydradb.caller.step"
        ]?.startsWith("verify.") === true,
    );

  assert.ok(
    verificationCalls.length > 0,
    "The verification phase must execute database reads",
  );

  assertEverySessionClosed(store);
}

async function verifiesStablePartialReplay(
  batch: GraphBatch,
): Promise<void> {
  const store = new FakeHydraStore();

  store.addFailure({
    remaining: 1,
    matches: (call) =>
      call.mutationKind === "canonical",
    createError: () =>
      new FakeNeo4jError(
        "Deliberate first canonical-write failure",
        "Neo.ClientError.Statement.ExecutionFailed",
      ),
  });

  const service =
    new HydraPersistenceService(
      UNUSED_DRIVER,
    );

  const idempotencyKey =
    "service-smoke-partial-replay";

  const correlationId =
    "service-smoke-replay-correlation";

  const persisted = await service.persist(
    batch,
    serviceOptions(
      store,
      idempotencyKey,
      correlationId,
      {
        maxPartialReplays: 1,
      },
    ),
  );

  assert.equal(
    persisted.persistenceAttempts,
    2,
    "One initial attempt and one complete-batch replay are expected",
  );

  assert.equal(
    persisted.idempotencyKey,
    idempotencyKey,
  );

  assert.equal(
    persisted.correlationId,
    correlationId,
  );

  assert.equal(persisted.result.ok, true);
  assert.equal(
    persisted.result.status,
    "succeeded",
  );

  assert.equal(
    store.failedCalls.length,
    1,
  );

  /*
   * All statements—not only mutations—must preserve the same
   * correlation identity across the replay.
   */
  for (const call of store.calls) {
    assert.equal(
      call.metadata[
        "hydradb.correlation_id"
      ],
      correlationId,
    );
  }

  const mutations = mutationCalls(store);
  const keys = mutations.map(mutationKey);

  const failedKey = mutationKey(
    store.failedCalls[0],
  );

  assert.equal(
    keys.filter((key) => key === failedKey)
      .length,
    2,
    "The failed chunk must be replayed with exactly the same key",
  );

  assert.ok(
    new Set(keys).size < keys.length,
    "A complete replay must reuse previously issued chunk keys",
  );

  assertEverySessionClosed(store);
}

async function verifiesProcessWideFifo(
  batch: GraphBatch,
): Promise<void> {
  const firstMutationEntered = createGate();
  const releaseFirstMutation = createGate();

  let firstMutationBlocked = false;

  const firstStore = new FakeHydraStore(
    async (call) => {
      if (
        !firstMutationBlocked &&
        call.mutationKind !== undefined
      ) {
        firstMutationBlocked = true;
        firstMutationEntered.release();

        await releaseFirstMutation.promise;
      }
    },
  );

  const secondStore = new FakeHydraStore();

  /*
   * Use different service instances. The queue is required to be
   * process-wide, not merely scoped to one service object.
   */
  const firstService =
    new HydraPersistenceService(
      UNUSED_DRIVER,
    );

  const secondService =
    new HydraPersistenceService(
      UNUSED_DRIVER,
    );

  const firstPersistence =
    firstService.persist(
      batch,
      serviceOptions(
        firstStore,
        "service-smoke-fifo-first",
        "service-smoke-fifo-first-correlation",
      ),
    );

  await firstMutationEntered.promise;

  const secondPersistence =
    secondService.persist(
      batch,
      serviceOptions(
        secondStore,
        "service-smoke-fifo-second",
        "service-smoke-fifo-second-correlation",
      ),
    );

  /*
   * Allow queued promise callbacks an opportunity to run. The second
   * operation must still not create a session while the first writer
   * remains blocked.
   */
  await Promise.resolve();
  await Promise.resolve();

  const secondSessionsBeforeRelease =
    secondStore.sessionsCreated;

  releaseFirstMutation.release();

  const [firstResult, secondResult] =
    await Promise.all([
      firstPersistence,
      secondPersistence,
    ]);

  assert.equal(
    secondSessionsBeforeRelease,
    0,
    "A second service instance must wait for the active writer",
  );

  assert.equal(firstResult.result.ok, true);
  assert.equal(secondResult.result.ok, true);

  assert.ok(
    secondStore.sessionsCreated > 0,
    "The second writer must execute after the first writer releases the queue",
  );

  assertEverySessionClosed(firstStore);
  assertEverySessionClosed(secondStore);
}

async function verifiesAnalysisGating(
  batch: GraphBatch,
): Promise<void> {
  const failingStore = new FakeHydraStore();

  /*
   * Fail the initial canonical write and its one permitted replay.
   * Node mutations complete first, so both failures produce explicit
   * partial results.
   */
  failingStore.addFailure({
    remaining: 2,
    matches: (call) =>
      call.mutationKind === "canonical",
    createError: () =>
      new FakeNeo4jError(
        "Deliberate persistent canonical-write failure",
        "Neo.ClientError.Statement.ExecutionFailed",
      ),
  });

  const failingService =
    new HydraPersistenceService(
      UNUSED_DRIVER,
    );

  let failedPathAnalysisCalls = 0;

  await assert.rejects(
    failingService.persistThenAnalyze(
      batch,
      () => {
        failedPathAnalysisCalls += 1;
        return "analysis-must-not-run";
      },
      serviceOptions(
        failingStore,
        "service-smoke-analysis-failure",
        "service-smoke-analysis-failure-correlation",
        {
          maxPartialReplays: 1,
        },
      ),
    ),
    (error: unknown) => {
      assert.ok(
        error instanceof PersistenceServiceError,
      );

      assert.equal(
        error.persistenceAttempts,
        2,
      );

      assert.equal(
        error.result.ok,
        false,
      );

      assert.equal(
        error.result.status,
        "partial",
      );

      assert.equal(
        error.result.partialWrites,
        true,
      );

      return true;
    },
  );

  assert.equal(
    failedPathAnalysisCalls,
    0,
    "Analysis must never run after failed persistence",
  );

  assertEverySessionClosed(failingStore);

  /*
   * Confirm the queue remains usable after a rejected operation and
   * that successful analysis receives the persistence capability.
   */
  const successfulStore =
    new FakeHydraStore();

  const successfulService =
    new HydraPersistenceService(
      UNUSED_DRIVER,
    );

  let successfulAnalysisCalls = 0;

  const report =
    await successfulService.persistThenAnalyze(
      batch,
      (persisted) => {
        successfulAnalysisCalls += 1;

        assert.equal(
          persisted.batch,
          batch,
        );

        assert.equal(
          persisted.result.ok,
          true,
        );

        assert.equal(
          persisted.result.phases.find(
            (phase) =>
              phase.phase === "verify",
          )?.status,
          "succeeded",
        );

        return {
          batchHash: persisted.batchHash,
          persistenceAttempts:
            persisted.persistenceAttempts,
        };
      },
      serviceOptions(
        successfulStore,
        "service-smoke-analysis-success",
        "service-smoke-analysis-success-correlation",
      ),
    );

  assert.equal(
    successfulAnalysisCalls,
    1,
  );

  assert.equal(
    report.persistenceAttempts,
    1,
  );

  assert.match(
    report.batchHash,
    /^[a-f0-9]{64}$/,
  );

  assertEverySessionClosed(successfulStore);
}

async function main(): Promise<void> {
  const batch = createBatch();

  await verifiesMandatorySafetyPolicy(batch);
  await verifiesStablePartialReplay(batch);
  await verifiesProcessWideFifo(batch);
  await verifiesAnalysisGating(batch);

  console.log(
    "HydraDB persistence service smoke passed",
  );

  console.log(
    "- verification and guarded upserts cannot be disabled",
  );

  console.log(
    "- partial batches replay with stable idempotency and correlation identities",
  );

  console.log(
    "- separate service instances share one process-wide FIFO writer",
  );

  console.log(
    "- failed persistence never reaches analysis",
  );

  console.log(
    "- successful analysis receives a verified PersistedGraphBatch",
  );

  console.log(
    "- every writer-owned fake session is closed",
  );
}

await main();
