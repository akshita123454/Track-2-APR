import {
  GraphBatchError,
  mergeGraphFragments,
} from "../../ingest/graph-batch.js";

import {
  collectPackageLock,
} from "../../ingest/lockfile/collector.js";

import {
  orchestrateNpmIngestion,
} from "../../ingest/npm/orchestrator.js";

import {
  HydraPersistenceService,
  PersistenceServiceError,
} from "../../db/persistence-service.js";

import type {
  GraphBatch,
} from "../../ingest/graph-batch.js";

import type {
  RegistryFetchOptions,
} from "../../ingest/npm/registry-client.js";

import type {
  PersistenceServiceOptions,
} from "../../db/persistence-service.js";

import type {
  TyposquattingService,
} from "../../typosquatting/service.js";

import type {
  LockfileIngestionRequestBody,
  NpmIngestionRequestBody,
} from "../schemas/ingestions.js";

import {
  LOCKFILE_INGESTION_LIMITS,
  NPM_INGESTION_LIMITS,
} from "../schemas/ingestions.js";

import type {
  JobFailureCode,
  JobManager,
} from "./job-manager.js";

import type {
  WorkerTask,
  WorkerTaskContext,
} from "./worker-dispatcher.js";

/**
 * Persistence settings that may be controlled by trusted server
 * configuration.
 *
 * Worker callers cannot replace the logical job's idempotency or correlation
 * identities. Those values always come from WorkerTaskContext.
 */
export type WorkerPersistenceOptions =
  Omit<
    PersistenceServiceOptions,
    | "idempotencyKey"
    | "correlationId"
  >;

/**
 * Dependencies shared by npm and lockfile workers.
 *
 * Pick<> keeps the persistence dependency small and makes future worker smoke
 * tests possible without constructing a real HydraDB driver.
 */
export interface IngestionWorkerDependencies {
  readonly jobManager: JobManager;

  readonly persistence: Pick<
    HydraPersistenceService,
    "persist"
  >;

  /**
   * Optional post-persistence scanner. The production server supplies this;
   * keeping the seam optional preserves focused ingestion worker fixtures.
   * It runs only after the lockfile graph has been verified.
   */
  readonly typosquatting?: Pick<
    TyposquattingService,
    "scanLockfile"
  >;

  /**
   * Trusted npm registry configuration.
   *
   * These options must come from server configuration, never from the HTTP
   * request body.
   */
  readonly npmRegistry?: RegistryFetchOptions;

  /**
   * Maximum package metadata requests performed concurrently inside one npm
   * ingestion.
   *
   * The orchestrator validates the final range as 1..20.
   */
  readonly npmConcurrency?: number;

  /**
   * Trusted HydraDB retry, chunking and timeout configuration.
   *
   * HydraPersistenceService still forces guarded upserts and verification.
   */
  readonly persistenceOptions?:
    WorkerPersistenceOptions;
}

/**
 * Internal error used when a request passes structural HTTP validation but
 * cannot be converted safely into collector input.
 *
 * Its raw message remains server-side because JobManager returns only its
 * predefined safe public failure messages.
 */
class WorkerInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkerInputError";
  }
}

/**
 * Fail immediately at safe stage boundaries when shutdown cancellation has
 * been requested.
 *
 * We deliberately rethrow the original Error reason when possible. The
 * dispatcher and JobManager redact it before any HTTP response is produced.
 */
function throwIfAborted(
  signal: AbortSignal,
): void {
  if (!signal.aborted) {
    return;
  }

  const reason = signal.reason;

  if (reason instanceof Error) {
    throw reason;
  }

  throw new Error(
    "The ingestion worker was cancelled",
  );
}

function assertWorkerKind(
  context: WorkerTaskContext,
  expectedKind: "npm" | "lockfile",
): void {
  if (context.kind !== expectedKind) {
    throw new Error(
      `Worker contract violation: expected ${expectedKind} ` +
        `job but received ${context.kind}`,
    );
  }
}

function parseObservedAt(
  value: string,
): number {
  const observedAt = Date.parse(value);

  if (
    !Number.isSafeInteger(observedAt) ||
    observedAt < 0
  ) {
    throw new WorkerInputError(
      "provenance.observedAt must be a valid nonnegative timestamp",
    );
  }

  return observedAt;
}

function persistenceFailureCode(
  error: PersistenceServiceError,
): JobFailureCode {
  return (
    error.result.status === "partial" ||
    error.result.partialWrites
  )
    ? "PERSISTENCE_PARTIAL"
    : "PERSISTENCE_FAILED";
}

function failJob(
  dependencies: IngestionWorkerDependencies,
  context: WorkerTaskContext,
  errorCode: JobFailureCode,
  cause: unknown,
  batch?: GraphBatch,
): void {
  dependencies.jobManager.updateJob(
    context.ingestionId,
    {
      status: "failed",
      errorCode,
      cause,

      ...(batch === undefined
        ? {}
        : {
            nodeCount: batch.nodes.length,
            edgeCount: batch.edges.length,
          }),
    },
  );
}

async function persistBatch(
  dependencies: IngestionWorkerDependencies,
  context: WorkerTaskContext,
  batch: GraphBatch,
): Promise<void> {
  /*
   * Cancellation is checked immediately before persistence. Once persistence
   * starts, we allow it to finish and record its result because interrupting
   * after durable writes may incorrectly label a persisted graph as absent.
   */
  throwIfAborted(context.signal);

  await dependencies.persistence.persist(
    batch,
    {
      ...(dependencies.persistenceOptions ??
        {}),

      /*
       * These assignments intentionally come after configured options.
       * Runtime object spreading therefore cannot replace the job identities.
       */
      idempotencyKey:
        context.persistenceIdempotencyKey,

      correlationId:
        context.correlationId,
    },
  );
}

function completeJob(
  dependencies: IngestionWorkerDependencies,
  context: WorkerTaskContext,
  batch: GraphBatch,
): void {
  dependencies.jobManager.updateJob(
    context.ingestionId,
    {
      status: "completed",
      nodeCount: batch.nodes.length,
      edgeCount: batch.edges.length,
    },
  );
}

function partiallyCompleteJob(
  dependencies: IngestionWorkerDependencies,
  context: WorkerTaskContext,
  batch: GraphBatch,
  errorCodes: readonly JobFailureCode[],
): void {
  dependencies.jobManager.updateJob(
    context.ingestionId,
    {
      status: "partially-completed",
      nodeCount: batch.nodes.length,
      edgeCount: batch.edges.length,
      errorCodes,
    },
  );
}

function npmPartialFailureCodes(
  issueCodes: readonly string[],
): readonly JobFailureCode[] {
  const failureCodes =
    new Set<JobFailureCode>([
      "PARTIAL_COLLECTION",
    ]);

  if (
    issueCodes.includes(
      "PACKAGE_COLLECTION_FAILED",
    )
  ) {
    failureCodes.add(
      "REGISTRY_REQUEST_FAILED",
    );
  }

  return Object.freeze([
    ...failureCodes,
  ]);
}

/**
 * Creates the task dispatched for POST /ingestions/npm.
 *
 * Security and correctness guarantees:
 *
 * - registry settings are trusted server configuration;
 * - traversal and package counts remain bounded;
 * - registry declarations remain candidate-only facts;
 * - no analysis runs before verified persistence;
 * - partial package collection is represented explicitly;
 * - raw registry and database errors never enter the public job response.
 */
export function createNpmIngestionWorker(
  request: NpmIngestionRequestBody,
  dependencies: IngestionWorkerDependencies,
): WorkerTask {
  return async (
    context: WorkerTaskContext,
  ): Promise<void> => {
    assertWorkerKind(context, "npm");
    throwIfAborted(context.signal);

    let batch: GraphBatch | undefined;

    try {
      const result =
        await orchestrateNpmIngestion({
          roots: request.roots,

          maxPackages:
            request.maxPackages,

          maxDepth:
            request.maxDepth,

          includeDevDependencies:
            request.includeDevDependencies ??
            false,

          /*
           * The HTTP schema permits up to 100 explicitly requested versions
           * for one root. Passing the same bound prevents the orchestrator's
           * lower default from unexpectedly rejecting a schema-valid request.
           */
          maxVersionsPerPackage:
            NPM_INGESTION_LIMITS
              .maxVersionsPerRoot,

          ...(dependencies.npmConcurrency ===
          undefined
            ? {}
            : {
                concurrency:
                  dependencies
                    .npmConcurrency,
              }),

          ...(dependencies.npmRegistry ===
          undefined
            ? {}
            : {
                registry:
                  dependencies.npmRegistry,
              }),
        });

      throwIfAborted(context.signal);

      if (
        result.status === "failed" ||
        result.batch === null
      ) {
        failJob(
          dependencies,
          context,
          "REGISTRY_REQUEST_FAILED",
          new WorkerInputError(
            "npm orchestration produced no persistable graph batch",
          ),
        );

        return;
      }

      batch = result.batch;

      await persistBatch(
        dependencies,
        context,
        batch,
      );

      /*
       * Do not check cancellation after successful persistence. At this point
       * the durable, verified graph is authoritative and the job must record
       * that result instead of being changed to a cancellation failure.
       */
      if (
        result.status ===
        "partially-completed"
      ) {
        partiallyCompleteJob(
          dependencies,
          context,
          batch,
          npmPartialFailureCodes(
            result.issues.map(
              (issue) => issue.code,
            ),
          ),
        );

        return;
      }

      completeJob(
        dependencies,
        context,
        batch,
      );
    } catch (error: unknown) {
      /*
       * Let WorkerDispatcher own cancellation settlement. It records a safe,
       * redacted failure and prevents private shutdown reasons from entering
       * the public job result.
       */
      if (context.signal.aborted) {
        throw (
          context.signal.reason ??
          error
        );
      }

      if (
        error instanceof
        PersistenceServiceError
      ) {
        failJob(
          dependencies,
          context,
          persistenceFailureCode(error),
          error,
          batch,
        );

        return;
      }

      if (error instanceof GraphBatchError) {
        failJob(
          dependencies,
          context,
          "GRAPH_VALIDATION_FAILED",
          error,
          batch,
        );

        return;
      }

      failJob(
        dependencies,
        context,
        "INGESTION_FAILED",
        error,
        batch,
      );
    }
  };
}

/**
 * Creates the task dispatched for POST /ingestions/lockfile.
 *
 * The collector creates exact DEPENDS_ON relationships only from the supplied
 * package-lock resolution and emits matching USED_BY traversal indexes.
 */
export function createLockfileIngestionWorker(
  request: LockfileIngestionRequestBody,
  dependencies: IngestionWorkerDependencies,
): WorkerTask {
  return async (
    context: WorkerTaskContext,
  ): Promise<void> => {
    assertWorkerKind(
      context,
      "lockfile",
    );

    throwIfAborted(context.signal);

    let batch: GraphBatch | undefined;

    try {
      const observedAt =
        parseObservedAt(
          request.provenance.observedAt,
        );

      /*
       * collectPackageLock is synchronous and performs deep semantic
       * package-lock validation. The route schema performs only the bounded
       * structural validation required before queue admission.
       */
      const collected =
        collectPackageLock(
          request.lockfile,
          {
            serviceLogicalId:
              request.serviceLogicalId,

            serviceName:
              request.serviceName,

            serviceCriticality:
              request.serviceCriticality,

            sourceUri:
              request.provenance.sourceUri,

            observedAt,

            confidence:
              request.provenance.confidence,

            synthetic:
              request.provenance.synthetic,

            maxPackages:
              LOCKFILE_INGESTION_LIMITS
                .maxPackages,
          },
        );

      throwIfAborted(context.signal);

      /*
       * The collector returns validated nodes and edges, while
       * mergeGraphFragments supplies the deeply frozen GraphBatch capability
       * required by HydraPersistenceService.
       *
       * repositoryLogicalId is included in the diagnostic source identity but
       * is not fabricated into a Repository node: the current lockfile
       * collector does not have trusted provider URL metadata required by the
       * Repository domain type.
       */
      const repositoryIdentity =
        request.repositoryLogicalId ??
        "repository-unbound";

      batch = mergeGraphFragments([
        {
          source:
            `package-lock:${request.format}:` +
            `${request.serviceLogicalId}:` +
            `${repositoryIdentity}:` +
            collected.contentSha256,

          nodes: collected.nodes,
          edges: collected.edges,
        },
      ]);

      await persistBatch(
        dependencies,
        context,
        batch,
      );

      /*
       * Detection is deliberately downstream of verified lockfile
       * persistence. It consumes only collector-owned metadata and graph
       * facts; it never installs or executes package code. Finding writes use
       * a separate deterministic idempotency suffix, so retries cannot alter
       * the already-verified dependency batch.
       */
      if (
        dependencies.typosquatting !==
        undefined
      ) {
        throwIfAborted(context.signal);

        try {
          await dependencies
            .typosquatting
            .scanLockfile({
              collected,
              observedAt,
              persistenceIdempotencyKey:
                context
                  .persistenceIdempotencyKey,
              correlationId:
                context.correlationId,
            });
        } catch (error: unknown) {
          partiallyCompleteJob(
            dependencies,
            context,
            batch,
            [
              "TYPOSQUATTING_SCAN_FAILED",
              ...(collected.issues.length > 0
                ? [
                    "PARTIAL_COLLECTION" as const,
                  ]
                : []),
            ],
          );

          return;
        }
      }

      /*
       * Nonfatal parser issues mean the verified graph is useful but the
       * ingestion should not be presented as fully complete.
       */
      if (collected.issues.length > 0) {
        partiallyCompleteJob(
          dependencies,
          context,
          batch,
          ["PARTIAL_COLLECTION"],
        );

        return;
      }

      completeJob(
        dependencies,
        context,
        batch,
      );
    } catch (error: unknown) {
      if (context.signal.aborted) {
        throw (
          context.signal.reason ??
          error
        );
      }

      if (
        error instanceof
        PersistenceServiceError
      ) {
        failJob(
          dependencies,
          context,
          persistenceFailureCode(error),
          error,
          batch,
        );

        return;
      }

      if (error instanceof GraphBatchError) {
        failJob(
          dependencies,
          context,
          "GRAPH_VALIDATION_FAILED",
          error,
          batch,
        );

        return;
      }

      /*
       * This includes malformed package-lock semantics, invalid timestamps and
       * collector failures. The raw cause is available only to JobManager's
       * private onInternalError hook.
       */
      failJob(
        dependencies,
        context,
        "LOCKFILE_INVALID",
        error,
        batch,
      );
    }
  };
}
