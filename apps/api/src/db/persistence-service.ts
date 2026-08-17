import { randomUUID } from "node:crypto";

import type { Driver } from "neo4j-driver";

import type { GraphBatch } from "../ingest/graph-batch.js";

import {
  serializeGraphBatch,
} from "./hydra-serializer.js";

import {
  persistGraphBatch,
} from "./hydra-writer.js";

import type {
  HydraWriterOptions,
} from "./hydra-writer.js";

import type {
  PersistenceResult,
} from "./persistence-result.js";

/**
 * This symbol makes PersistedGraphBatch a capability type.
 *
 * Analysis functions should accept PersistedGraphBatch instead of accepting
 * a raw GraphBatch. Only this module can construct the branded object.
 */
const persistedGraphBatchBrand: unique symbol =
  Symbol("PersistedGraphBatch");

export interface PersistedGraphBatch {
  readonly [persistedGraphBatchBrand]: true;

  /**
   * The exact immutable object passed to every persistence attempt.
   */
  readonly batch: GraphBatch;

  readonly batchHash: string;
  readonly idempotencyKey: string;
  readonly correlationId: string;

  /**
   * Includes the initial attempt and any complete-batch replays.
   */
  readonly persistenceAttempts: number;

  readonly result: PersistenceResult;
}

export type PersistedBatchAnalysis<T> = (
  persisted: PersistedGraphBatch,
) => Promise<T> | T;

/**
 * Verification, update guards and idempotency identity are controlled by
 * this service and therefore cannot be disabled by its callers.
 */
export interface PersistenceServiceOptions
  extends Omit<
    HydraWriterOptions,
    | "verify"
    | "guardedUpserts"
    | "idempotencyKey"
    | "correlationId"
  > {
  /**
   * Stable root identity for one logical graph batch.
   *
   * When omitted, it is derived from the deterministic serialized batch hash.
   */
  readonly idempotencyKey?: string;

  /**
   * Preserved across every replay of this logical batch.
   */
  readonly correlationId?: string;

  /**
   * Number of complete-batch replays permitted after the initial attempt.
   *
   * Defaults to 2, meaning at most 3 calls to persistGraphBatch().
   */
  readonly maxPartialReplays?: number;

  /**
   * Base delay before replaying a partial batch.
   *
   * Replays use bounded exponential backoff.
   */
  readonly partialReplayDelayMs?: number;
}

export class PersistenceServiceError extends Error {
  constructor(
    readonly result: PersistenceResult,
    readonly persistenceAttempts: number,
  ) {
    const code =
      result.failure?.code ?? "UNKNOWN_PERSISTENCE_FAILURE";

    super(
      `HydraDB persistence did not complete after ` +
        `${persistenceAttempts} attempt(s): ${code}`,
    );

    this.name = "PersistenceServiceError";
  }
}

/**
 * Process-wide queue shared by every HydraPersistenceService instance.
 *
 * This is intentionally module-level rather than instance-level: creating
 * two service objects in the same Node.js process must not create two
 * simultaneous ingestion writers.
 *
 * It does not coordinate separate Node.js processes. The hackathon runtime
 * must run one API/ingestion process.
 */
let processWriterTail: Promise<void> = Promise.resolve();

function runWithExclusiveWriter<T>(
  operation: () => Promise<T>,
): Promise<T> {
  const result = processWriterTail.then(
    operation,
    operation,
  );

  /*
   * Keep the queue usable even if this operation rejects.
   * The original result still preserves the rejection for its caller.
   */
  processWriterTail = result.then(
    () => undefined,
    () => undefined,
  );

  return result;
}

export async function drainPersistenceQueue(): Promise<void> {
  await processWriterTail;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function assertIntegerOption(
  value: number,
  field: string,
  minimum: number,
  maximum: number,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error(
      `${field} must be a safe integer between ` +
        `${minimum} and ${maximum}`,
    );
  }
}

/**
 * The persistence service deliberately accepts only deeply frozen graph
 * batches. mergeGraphFragments() already provides this guarantee.
 *
 * Requiring it here proves that every replay receives the exact same
 * immutable graph state.
 */
function assertImmutableBatch(batch: GraphBatch): void {
  if (
    !Object.isFrozen(batch) ||
    !Object.isFrozen(batch.nodes) ||
    !Object.isFrozen(batch.edges) ||
    !Object.isFrozen(batch.fragmentSources) ||
    !Object.isFrozen(batch.statistics) ||
    !Object.isFrozen(batch.validation)
  ) {
    throw new Error(
      "HydraPersistenceService requires a GraphBatch returned by " +
        "mergeGraphFragments(); the batch is not deeply frozen",
    );
  }

  for (const node of batch.nodes) {
    if (
      !Object.isFrozen(node) ||
      !Object.isFrozen(node.evidenceIds)
    ) {
      throw new Error(
        "HydraPersistenceService received a mutable graph node",
      );
    }
  }

  for (const edge of batch.edges) {
    if (!Object.isFrozen(edge)) {
      throw new Error(
        "HydraPersistenceService received a mutable graph edge",
      );
    }

    if (
      edge.kind !== "USED_BY" &&
      !Object.isFrozen(edge.evidenceIds)
    ) {
      throw new Error(
        "HydraPersistenceService received mutable edge evidence",
      );
    }
  }
}

function assertVerifiedSuccess(
  result: PersistenceResult,
  expectedBatchHash: string,
  expectedIdempotencyKey: string,
): void {
  if (
    !result.ok ||
    result.status !== "succeeded" ||
    result.partialWrites
  ) {
    throw new Error(
      "Persistence result violates the successful persistence contract",
    );
  }

  if (result.metadata.batchHash !== expectedBatchHash) {
    throw new Error(
      "Persistence result batch hash does not match the submitted batch",
    );
  }

  if (
    result.metadata.idempotencyBaseKey !==
    expectedIdempotencyKey
  ) {
    throw new Error(
      "Persistence result idempotency identity does not match the request",
    );
  }

  if (
    result.metadata.verificationRequested !== true ||
    result.metadata.guardedUpserts !== true
  ) {
    throw new Error(
      "Persistence completed without mandatory verification or guards",
    );
  }

  const verification = result.phases.find(
    (phase) => phase.phase === "verify",
  );

  if (verification?.status !== "succeeded") {
    throw new Error(
      "Persistence returned success without a successful verification phase",
    );
  }
}

export class HydraPersistenceService {
  constructor(private readonly driver: Driver) {}

  /**
   * Persists exactly one immutable batch through the process-wide writer
   * queue. The driver remains caller-owned and is not closed here.
   */
  persist(
    batch: GraphBatch,
    options: PersistenceServiceOptions = {},
  ): Promise<PersistedGraphBatch> {
    return runWithExclusiveWriter(() =>
      this.persistExclusively(batch, options),
    );
  }

  /**
   * This should be the normal analysis entry point.
   *
   * The callback cannot execute until persistence has succeeded and the
   * writer's verification phase has completed.
   */
  async persistThenAnalyze<T>(
    batch: GraphBatch,
    analysis: PersistedBatchAnalysis<T>,
    options: PersistenceServiceOptions = {},
  ): Promise<T> {
    const persisted = await this.persist(batch, options);
    return analysis(persisted);
  }

  private async persistExclusively(
    batch: GraphBatch,
    options: PersistenceServiceOptions,
  ): Promise<PersistedGraphBatch> {
    assertImmutableBatch(batch);

    const {
      idempotencyKey: requestedIdempotencyKey,
      correlationId: requestedCorrelationId,
      maxPartialReplays = 2,
      partialReplayDelayMs = 100,
      ...writerOptions
    } = options;

    assertIntegerOption(
      maxPartialReplays,
      "maxPartialReplays",
      0,
      10,
    );

    assertIntegerOption(
      partialReplayDelayMs,
      "partialReplayDelayMs",
      0,
      60_000,
    );

    /*
     * Serialization is pure. Calculating it once establishes the stable
     * identity used by every complete-batch replay.
     */
    const serialized = serializeGraphBatch(batch);

    const idempotencyKey =
      requestedIdempotencyKey ??
      `hg-${serialized.batchHash.slice(0, 40)}`;

    /*
     * Preserve one correlation ID across the initial write and every replay.
     * This makes the complete recovery sequence traceable as one operation.
     */
    const correlationId =
      requestedCorrelationId ?? randomUUID();

    const maximumAttempts = maxPartialReplays + 1;

    let latestResult: PersistenceResult | undefined;

    for (
      let persistenceAttempt = 1;
      persistenceAttempt <= maximumAttempts;
      persistenceAttempt += 1
    ) {
      /*
       * The same batch object, idempotency key and correlation ID are used on
       * every iteration. Do not clone or rebuild the GraphBatch here.
       */
      latestResult = await persistGraphBatch(
        this.driver,
        batch,
        {
          ...writerOptions,

          /*
           * These values are deliberately placed after writerOptions so a
           * caller cannot override the mandatory safety policy.
           */
          idempotencyKey,
          correlationId,
          guardedUpserts: true,
          verify: true,
        },
      );

      if (latestResult.ok) {
        assertVerifiedSuccess(
          latestResult,
          serialized.batchHash,
          idempotencyKey,
        );

        return Object.freeze({
          [persistedGraphBatchBrand]: true as const,
          batch,
          batchHash: serialized.batchHash,
          idempotencyKey,
          correlationId,
          persistenceAttempts: persistenceAttempt,
          result: latestResult,
        });
      }

      const canReplay =
        latestResult.status === "partial" &&
        persistenceAttempt < maximumAttempts;

      if (!canReplay) {
        throw new PersistenceServiceError(
          latestResult,
          persistenceAttempt,
        );
      }

      /*
       * persistGraphBatch() has already retried retryable individual
       * statements. This delay is for replaying the complete logical batch
       * after a partial multi-statement outcome.
       */
      const replayNumber = persistenceAttempt;

      const replayDelay = Math.min(
        partialReplayDelayMs *
          2 ** (replayNumber - 1),
        30_000,
      );

      await delay(replayDelay);
    }

    /*
     * Defensive exhaustiveness guard. The loop always returns or throws.
     */
    if (latestResult === undefined) {
      throw new Error(
        "Persistence service executed no persistence attempt",
      );
    }

    throw new PersistenceServiceError(
      latestResult,
      maximumAttempts,
    );
  }
}
