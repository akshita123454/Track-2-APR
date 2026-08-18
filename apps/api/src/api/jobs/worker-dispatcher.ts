import type {
  JobExecutionContext,
  IngestionJobStatus,
} from "./job-manager.js";

import {
  JobManager,
} from "./job-manager.js";

export type WorkerDispatcherState =
  | "accepting"
  | "draining"
  | "cancelling"
  | "closed";

export type WorkerDispatcherErrorCode =
  | "INVALID_DISPATCHER_OPTION"
  | "INVALID_WORKER_TASK"
  | "DISPATCHER_CAPACITY_REACHED"
  | "DUPLICATE_JOB_DISPATCH"
  | "JOB_NOT_QUEUED"
  | "DISPATCHER_SHUTTING_DOWN";

export type WorkerFailurePhase =
  | "start"
  | "execute"
  | "contract"
  | "cancel";

export class WorkerDispatcherError
  extends Error {
  constructor(
    readonly code:
      WorkerDispatcherErrorCode,
    readonly httpStatusCode: number,
    message: string,
  ) {
    super(message);
    this.name =
      "WorkerDispatcherError";
  }
}

class WorkerContractError
  extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkerContractError";
  }
}

class WorkerTaskCancelledError
  extends Error {
  constructor(message: string) {
    super(message);
    this.name =
      "WorkerTaskCancelledError";
  }
}

export type WorkerTaskContext = Readonly<
  Omit<
    JobExecutionContext,
    "status"
  > & {
    readonly status: "running";

    /**
     * Workers should check this signal:
     *
     * - before network requests;
     * - between collection stages;
     * - before persistence;
     * - before analysis.
     *
     * A future registry-client update should combine this signal with its
     * request timeout signal.
     */
    readonly signal: AbortSignal;

    readonly enqueuedAt: string;
    readonly startedAt: string;
    readonly queueDelayMs: number;
  }
>;

export type WorkerTask = (
  context: WorkerTaskContext,
) => Promise<void> | void;

export interface DispatchAccepted {
  readonly ingestionId: string;

  /**
   * One-based location in the pending FIFO at acceptance time.
   *
   * The value is diagnostic only. Jobs may begin before it is observed.
   */
  readonly queuePosition: number;

  readonly acceptedAt: string;
}

export interface WorkerDispatcherInternalErrorEvent {
  readonly ingestionId: string;
  readonly phase: WorkerFailurePhase;
  readonly occurredAt: string;

  /**
   * Raw errors are passed only to an injected private logger.
   * They are never returned by the JobManager HTTP representation.
   */
  readonly cause: unknown;
}

export interface WorkerDispatcherOptions {
  /**
   * Maximum task functions executing simultaneously.
   *
   * This value must not exceed JobManager.maxRunningJobs.
   * Defaults to the smaller of 4 or the JobManager limit.
   */
  readonly maxConcurrentJobs?: number;

  /**
   * Test seam for deterministic timestamps.
   */
  readonly now?: () => number;

  /**
   * Optional private logging hook.
   *
   * Failures thrown by this callback are isolated.
   */
  readonly onInternalError?: (
    event:
      WorkerDispatcherInternalErrorEvent,
  ) => void;
}

export interface WorkerDispatcherStats {
  readonly state:
    WorkerDispatcherState;

  readonly pending: number;
  readonly running: number;
  readonly active: number;

  readonly maxConcurrentJobs: number;

  /**
   * The complete active-task bound is inherited from JobManager capacity.
   */
  readonly maxActiveJobs: number;

  /**
   * Approximate maximum waiting jobs after all execution slots are occupied.
   */
  readonly maxQueuedJobs: number;

  readonly acceptedTasks: number;
  readonly startedTasks: number;

  /**
   * Tasks that resolved and left their JobManager record in a terminal state.
   */
  readonly settledTasks: number;

  /**
   * Tasks that threw, failed to start, or violated the worker contract.
   */
  readonly failedTasks: number;

  readonly cancelledTasks: number;
}

export interface CloseDispatcherOptions {
  /**
   * drain:
   *   Finish all pending and running work.
   *
   * cancel-pending:
   *   Fail jobs that have not started, then wait for running work.
   */
  readonly mode?:
    | "drain"
    | "cancel-pending";

  /**
   * Only applies to cancel-pending mode.
   *
   * Running tasks receive an aborted signal. They must cooperate with it.
   */
  readonly abortRunning?: boolean;

  /**
   * Private diagnostic reason. JobManager exposes only a redacted message.
   */
  readonly reason?: string;
}

interface QueuedTask {
  readonly ingestionId: string;
  readonly task: WorkerTask;
  readonly enqueuedAtMs: number;
}

interface RunningTask {
  readonly controller:
    AbortController;
}

const DEFAULT_MAX_CONCURRENT_JOBS = 4;

function readPositiveInteger(
  value: number | undefined,
  fallback: number,
  name: string,
  maximum: number,
): number {
  const selected =
    value ?? fallback;

  if (
    !Number.isSafeInteger(selected) ||
    selected < 1 ||
    selected > maximum
  ) {
    throw new WorkerDispatcherError(
      "INVALID_DISPATCHER_OPTION",
      500,
      `${name} must be a safe integer between 1 and ${maximum}`,
    );
  }

  return selected;
}

function isTerminalStatus(
  status: IngestionJobStatus,
): boolean {
  return (
    status === "completed" ||
    status ===
      "partially-completed" ||
    status === "failed"
  );
}

/**
 * Bounded process-local FIFO execution queue.
 *
 * Responsibilities:
 *
 * - start jobs in FIFO order;
 * - enforce bounded concurrency;
 * - move jobs from queued to running;
 * - provide stable persistence/correlation identities;
 * - prevent unhandled worker rejections;
 * - fail workers that resolve without producing a terminal job state;
 * - support graceful process shutdown.
 *
 * This does not coordinate separate Node.js processes. HydraGuard's
 * hackathon runtime must use one API process.
 */
export class WorkerDispatcher {
  private readonly queue:
    QueuedTask[] = [];

  private readonly running =
    new Map<string, RunningTask>();

  /**
   * Contains queued and running ingestion IDs.
   */
  private readonly activeJobIds =
    new Set<string>();

  private readonly idleWaiters =
    new Set<() => void>();

  private readonly maxConcurrentJobs:
    number;

  private readonly maxActiveJobs:
    number;

  private readonly nowProvider:
    () => number;

  private readonly onInternalError?: (
    event:
      WorkerDispatcherInternalErrorEvent,
  ) => void;

  private state:
    WorkerDispatcherState =
      "accepting";

  private pumpScheduled = false;

  private closePromise:
    Promise<void> | undefined;

  private acceptedTasks = 0;
  private startedTasks = 0;
  private settledTasks = 0;
  private failedTasks = 0;
  private cancelledTasks = 0;

  constructor(
    private readonly jobManager:
      JobManager,
    options:
      WorkerDispatcherOptions = {},
  ) {
    const managerStats =
      jobManager.getStats();

    const defaultConcurrency =
      Math.min(
        DEFAULT_MAX_CONCURRENT_JOBS,
        managerStats.maxRunningJobs,
      );

    this.maxConcurrentJobs =
      readPositiveInteger(
        options.maxConcurrentJobs,
        defaultConcurrency,
        "maxConcurrentJobs",
        managerStats.maxRunningJobs,
      );

    if (
      this.maxConcurrentJobs >
      managerStats.capacity
    ) {
      throw new WorkerDispatcherError(
        "INVALID_DISPATCHER_OPTION",
        500,
        "maxConcurrentJobs cannot exceed JobManager capacity",
      );
    }

    /*
     * JobManager is already the authoritative process-memory bound.
     * Deriving the dispatcher bound from it prevents two conflicting queue
     * capacities and guarantees accepted tasks remain bounded.
     */
    this.maxActiveJobs =
      managerStats.capacity;

    this.nowProvider =
      options.now ?? Date.now;

    this.onInternalError =
      options.onInternalError;
  }

  /**
   * Throws before a route creates a new JobManager record when this
   * dispatcher cannot accept more active work.
   *
   * Routes should still avoid this check for idempotent replays that do not
   * need to enqueue a new task.
   */
  assertCanAccept(): void {
    this.assertAccepting();

    if (
      this.activeJobIds.size >=
      this.maxActiveJobs
    ) {
      throw new WorkerDispatcherError(
        "DISPATCHER_CAPACITY_REACHED",
        503,
        "The ingestion worker queue is temporarily at capacity",
      );
    }
  }

  enqueue(
    ingestionId: string,
    task: WorkerTask,
  ): DispatchAccepted {
    this.assertCanAccept();

    if (typeof task !== "function") {
      throw new WorkerDispatcherError(
        "INVALID_WORKER_TASK",
        500,
        "A worker task function is required",
      );
    }

    if (
      this.activeJobIds.has(
        ingestionId,
      )
    ) {
      throw new WorkerDispatcherError(
        "DUPLICATE_JOB_DISPATCH",
        409,
        `Ingestion ${ingestionId} is already queued or running`,
      );
    }

    const executionContext =
      this.jobManager
        .getExecutionContext(
          ingestionId,
        );

    if (
      executionContext.status !==
      "queued"
    ) {
      throw new WorkerDispatcherError(
        "JOB_NOT_QUEUED",
        409,
        `Ingestion ${ingestionId} must be queued before dispatch`,
      );
    }

    const enqueuedAtMs =
      this.readNow();

    this.queue.push({
      ingestionId,
      task,
      enqueuedAtMs,
    });

    this.activeJobIds.add(
      ingestionId,
    );

    this.acceptedTasks += 1;

    const accepted =
      Object.freeze({
        ingestionId,
        queuePosition:
          this.queue.length,
        acceptedAt:
          new Date(
            enqueuedAtMs,
          ).toISOString(),
      });

    /*
     * Defer worker startup until the current call stack finishes. This lets
     * an HTTP route construct and return its 202 response without executing
     * registry or persistence work inline.
     */
    this.schedulePump();

    return accepted;
  }

  getStats(): WorkerDispatcherStats {
    return Object.freeze({
      state: this.state,

      pending:
        this.queue.length,

      running:
        this.running.size,

      active:
        this.activeJobIds.size,

      maxConcurrentJobs:
        this.maxConcurrentJobs,

      maxActiveJobs:
        this.maxActiveJobs,

      maxQueuedJobs:
        Math.max(
          0,
          this.maxActiveJobs -
            this.maxConcurrentJobs,
        ),

      acceptedTasks:
        this.acceptedTasks,

      startedTasks:
        this.startedTasks,

      settledTasks:
        this.settledTasks,

      failedTasks:
        this.failedTasks,

      cancelledTasks:
        this.cancelledTasks,
    });
  }

  /**
   * Resolves when there is no queued or running work at that instant.
   *
   * Calling this while the dispatcher is still accepting jobs does not stop
   * later enqueue() calls. Use close() for process shutdown.
   */
  waitForIdle(): Promise<void> {
    if (this.isIdle()) {
      return Promise.resolve();
    }

    return new Promise<void>(
      (resolve) => {
        this.idleWaiters.add(
          resolve,
        );
      },
    );
  }

  /**
   * Stops accepting work and returns one stable shutdown promise.
   *
   * The first close call defines shutdown behavior. Repeated calls return the
   * same promise, making duplicate SIGINT/SIGTERM handling safe.
   */
  close(
    options:
      CloseDispatcherOptions = {},
  ): Promise<void> {
    if (
      this.closePromise !==
      undefined
    ) {
      return this.closePromise;
    }

    const mode =
      options.mode ?? "drain";

    this.state =
      mode === "drain"
        ? "draining"
        : "cancelling";

    this.closePromise =
      this.performClose(
        mode,
        options,
      );

    return this.closePromise;
  }

  private async performClose(
    mode:
      | "drain"
      | "cancel-pending",
    options:
      CloseDispatcherOptions,
  ): Promise<void> {
    if (
      mode === "cancel-pending"
    ) {
      const reason =
        options.reason ??
        "The API server is shutting down";

      this.cancelPending(reason);

      if (
        options.abortRunning ===
        true
      ) {
        const abortReason =
          new WorkerTaskCancelledError(
            reason,
          );

        for (
          const running
          of this.running.values()
        ) {
          if (
            !running.controller
              .signal.aborted
          ) {
            running.controller.abort(
              abortReason,
            );
          }
        }
      }
    } else {
      this.schedulePump();
    }

    this.resolveIdleWaiters();

    await this.waitForIdle();

    this.state = "closed";
  }

  private schedulePump(): void {
    if (
      this.pumpScheduled ||
      this.state === "closed"
    ) {
      return;
    }

    this.pumpScheduled = true;

    queueMicrotask(() => {
      this.pumpScheduled = false;

      try {
        this.pump();
      } catch (error: unknown) {
        /*
         * pump() is deliberately synchronous and simple, but this boundary
         * prevents an unexpected scheduler error from becoming an uncaught
         * microtask exception.
         */
        this.reportInternalError(
          "dispatcher",
          "start",
          error,
          this.safeNow(),
        );
      }
    });
  }

  private pump(): void {
    while (
      this.mayStartQueuedWork() &&
      this.running.size <
        this.maxConcurrentJobs &&
      this.queue.length > 0
    ) {
      const queued =
        this.queue.shift();

      if (queued === undefined) {
        break;
      }

      const controller =
        new AbortController();

      this.running.set(
        queued.ingestionId,
        {
          controller,
        },
      );

      /*
       * executeTask() catches every failure internally. The returned promise
       * therefore cannot become an unhandled rejection.
       */
      void this.executeTask(
        queued,
        controller,
      );
    }

    this.resolveIdleWaiters();
  }

  private async executeTask(
    queued: QueuedTask,
    controller: AbortController,
  ): Promise<void> {
    let phase:
      WorkerFailurePhase =
        "start";

    try {
      this.jobManager.updateJob(
        queued.ingestionId,
        {
          status: "running",
        },
      );

      this.startedTasks += 1;

      const startedAtMs =
        this.readNow();

      const executionContext =
        this.jobManager
          .getExecutionContext(
            queued.ingestionId,
          );

      if (
        executionContext.status !==
        "running"
      ) {
        throw new WorkerContractError(
          `Ingestion ${queued.ingestionId} did not enter running state`,
        );
      }

      const taskContext:
        WorkerTaskContext =
          Object.freeze({
            ingestionId:
              executionContext
                .ingestionId,

            kind:
              executionContext.kind,

            status:
              "running" as const,

            persistenceIdempotencyKey:
              executionContext
                .persistenceIdempotencyKey,

            correlationId:
              executionContext
                .correlationId,

            requestFingerprint:
              executionContext
                .requestFingerprint,

            version:
              executionContext.version,

            signal:
              controller.signal,

            enqueuedAt:
              new Date(
                queued.enqueuedAtMs,
              ).toISOString(),

            startedAt:
              new Date(
                startedAtMs,
              ).toISOString(),

            queueDelayMs:
              Math.max(
                0,
                startedAtMs -
                  queued.enqueuedAtMs,
              ),
          });

      phase = "execute";

      await queued.task(
        taskContext,
      );

      phase = "contract";

      const resultingJob =
        this.jobManager.getJob(
          queued.ingestionId,
        );

      if (resultingJob === null) {
        throw new WorkerContractError(
          `Ingestion ${queued.ingestionId} disappeared before worker settlement`,
        );
      }

      if (
        !isTerminalStatus(
          resultingJob.status,
        )
      ) {
        throw new WorkerContractError(
          `Worker for ingestion ${queued.ingestionId} resolved while ` +
            `job status remained ${resultingJob.status}`,
        );
      }

      this.settledTasks += 1;
    } catch (error: unknown) {
      this.failedTasks += 1;

      /*
       * If the worker already recorded a legitimate terminal failure, do not
       * overwrite it. Otherwise fail closed with JobManager's redacted
       * INTERNAL_JOB_ERROR message.
       */
      this.failJobIfActive(
        queued.ingestionId,
        error,
      );

      this.reportInternalError(
        queued.ingestionId,
        phase,
        error,
        this.safeNow(
          queued.enqueuedAtMs,
        ),
      );
    } finally {
      this.running.delete(
        queued.ingestionId,
      );

      this.activeJobIds.delete(
        queued.ingestionId,
      );

      this.schedulePump();
      this.resolveIdleWaiters();
    }
  }

  private cancelPending(
    reason: string,
  ): void {
    const cancellation =
      new WorkerTaskCancelledError(
        reason,
      );

    while (
      this.queue.length > 0
    ) {
      const queued =
        this.queue.shift();

      if (queued === undefined) {
        break;
      }

      this.activeJobIds.delete(
        queued.ingestionId,
      );

      this.cancelledTasks += 1;

      this.failJobIfActive(
        queued.ingestionId,
        cancellation,
      );

      this.reportInternalError(
        queued.ingestionId,
        "cancel",
        cancellation,
        this.safeNow(
          queued.enqueuedAtMs,
        ),
      );
    }
  }

  private failJobIfActive(
    ingestionId: string,
    cause: unknown,
  ): void {
    try {
      const current =
        this.jobManager.getJob(
          ingestionId,
        );

      if (
        current === null ||
        isTerminalStatus(
          current.status,
        )
      ) {
        return;
      }

      this.jobManager.updateJob(
        ingestionId,
        {
          status: "failed",
          errorCode:
            "INTERNAL_JOB_ERROR",
          cause,
        },
      );
    } catch (failureError: unknown) {
      /*
       * A closed JobManager or invalid external transition must not escape
       * executeTask() and become an unhandled rejection.
       */
      this.reportInternalError(
        ingestionId,
        "contract",
        failureError,
        this.safeNow(),
      );
    }
  }

  private reportInternalError(
    ingestionId: string,
    phase: WorkerFailurePhase,
    cause: unknown,
    occurredAtMs: number,
  ): void {
    if (
      this.onInternalError ===
      undefined
    ) {
      return;
    }

    const event:
      WorkerDispatcherInternalErrorEvent =
        Object.freeze({
          ingestionId,
          phase,
          occurredAt:
            new Date(
              occurredAtMs,
            ).toISOString(),
          cause,
        });

    try {
      this.onInternalError(event);
    } catch {
      /*
       * Logging and telemetry failures cannot alter queue or job state.
       */
    }
  }

  private mayStartQueuedWork(): boolean {
    return (
      this.state ===
        "accepting" ||
      this.state ===
        "draining"
    );
  }

  private isIdle(): boolean {
    return (
      this.queue.length === 0 &&
      this.running.size === 0
    );
  }

  private resolveIdleWaiters(): void {
    if (!this.isIdle()) {
      return;
    }

    for (
      const resolve
      of this.idleWaiters
    ) {
      resolve();
    }

    this.idleWaiters.clear();
  }

  private assertAccepting(): void {
    if (
      this.state !==
      "accepting"
    ) {
      throw new WorkerDispatcherError(
        "DISPATCHER_SHUTTING_DOWN",
        503,
        "The ingestion worker dispatcher is shutting down",
      );
    }
  }

  private readNow(): number {
    const value =
      this.nowProvider();

    if (
      !Number.isSafeInteger(value) ||
      value < 0 ||
      value >
        8_640_000_000_000_000
    ) {
      throw new WorkerDispatcherError(
        "INVALID_DISPATCHER_OPTION",
        500,
        "The dispatcher clock returned an invalid timestamp",
      );
    }

    return value;
  }

  private safeNow(
    fallback: number = 0,
  ): number {
    try {
      return this.readNow();
    } catch {
      return fallback;
    }
  }
}
