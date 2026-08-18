import assert from "node:assert/strict";

import {
  JobManager,
  createRequestFingerprint,
} from "./job-manager.js";

import {
  WorkerDispatcher,
  WorkerDispatcherError,
} from "./worker-dispatcher.js";

import type {
  IngestionKind,
} from "./job-manager.js";

import type {
  WorkerDispatcherErrorCode,
  WorkerDispatcherInternalErrorEvent,
  WorkerTask,
  WorkerTaskContext,
} from "./worker-dispatcher.js";

const BASE_TIME = Date.parse(
  "2026-08-15T12:00:00.000Z",
);

class FakeClock {
  constructor(
    private currentTime: number = BASE_TIME,
  ) {}

  readonly now = (): number =>
    this.currentTime;

  advance(milliseconds: number): void {
    assert.ok(
      Number.isSafeInteger(milliseconds) &&
        milliseconds >= 0,
      "Fake-clock advancement must be a nonnegative safe integer",
    );

    this.currentTime += milliseconds;
  }
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  readonly resolve: (
    value: T | PromiseLike<T>,
  ) => void;
  readonly reject: (
    reason?: unknown,
  ) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (
    value: T | PromiseLike<T>,
  ) => void;

  let reject!: (
    reason?: unknown,
  ) => void;

  const promise = new Promise<T>(
    (promiseResolve, promiseReject) => {
      resolve = promiseResolve;
      reject = promiseReject;
    },
  );

  return {
    promise,
    resolve,
    reject,
  };
}

function createSequentialIdFactory(
  prefix: string,
): () => string {
  let sequence = 0;

  return () => {
    sequence += 1;

    return (
      `${prefix}-` +
      String(sequence).padStart(4, "0")
    );
  };
}

function createManager(
  clock: FakeClock,
  prefix: string,
  options: {
    readonly maxJobs?: number;
    readonly maxRunningJobs?: number;
  } = {},
): JobManager {
  return new JobManager({
    maxJobs:
      options.maxJobs ?? 20,

    maxRunningJobs:
      options.maxRunningJobs ?? 4,

    /*
     * These tests control completion explicitly. Long boundaries ensure the
     * JobManager's timeout policy does not interfere with dispatcher tests.
     */
    activeJobTimeoutMs: 60_000,
    terminalRetentionMs: 60_000,

    sweepIntervalMs: 0,
    now: clock.now,

    idFactory:
      createSequentialIdFactory(prefix),
  });
}

function createQueuedJob(
  manager: JobManager,
  label: string,
  kind: IngestionKind = "npm",
): string {
  const created = manager.createJob({
    kind,

    requestFingerprint:
      createRequestFingerprint({
        smoke: "worker-dispatcher",
        label,
        kind,
      }),
  });

  return created.accepted.ingestionId;
}

function completeJob(
  manager: JobManager,
  ingestionId: string,
  nodeCount: number = 1,
  edgeCount: number = 1,
): void {
  manager.updateJob(
    ingestionId,
    {
      status: "completed",
      nodeCount,
      edgeCount,
    },
  );
}

function expectDispatcherError(
  operation: () => unknown,
  expectedCode:
    WorkerDispatcherErrorCode,
  expectedHttpStatus: number,
): WorkerDispatcherError {
  try {
    operation();
  } catch (error: unknown) {
    if (
      !(
        error instanceof
        WorkerDispatcherError
      )
    ) {
      throw error;
    }

    assert.equal(
      error.code,
      expectedCode,
    );

    assert.equal(
      error.httpStatusCode,
      expectedHttpStatus,
    );

    return error;
  }

  assert.fail(
    `Expected WorkerDispatcherError ${expectedCode}`,
  );
}

async function verifiesFifoAndConcurrency(): Promise<void> {
  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "fifo-job",
    {
      maxJobs: 10,
      maxRunningJobs: 2,
    },
  );

  const dispatcher =
    new WorkerDispatcher(
      manager,
      {
        maxConcurrentJobs: 2,
        now: clock.now,
      },
    );

  await dispatcher.waitForIdle();

  const ingestionIds = [
    createQueuedJob(
      manager,
      "fifo-first",
    ),
    createQueuedJob(
      manager,
      "fifo-second",
    ),
    createQueuedJob(
      manager,
      "fifo-third",
    ),
    createQueuedJob(
      manager,
      "fifo-fourth",
    ),
  ];

  const originalContexts =
    new Map(
      ingestionIds.map(
        (ingestionId) => [
          ingestionId,
          manager.getExecutionContext(
            ingestionId,
          ),
        ],
      ),
    );

  const startedSignals =
    ingestionIds.map(() =>
      createDeferred<void>(),
    );

  const releaseSignals =
    ingestionIds.map(() =>
      createDeferred<void>(),
    );

  const startOrder: string[] = [];

  const taskContexts:
    WorkerTaskContext[] = [];

  let activeTasks = 0;
  let maximumActiveTasks = 0;

  const accepted = ingestionIds.map(
    (ingestionId, index) =>
      dispatcher.enqueue(
        ingestionId,
        async (context) => {
          activeTasks += 1;

          maximumActiveTasks =
            Math.max(
              maximumActiveTasks,
              activeTasks,
            );

          startOrder.push(
            ingestionId,
          );

          taskContexts.push(
            context,
          );

          startedSignals[
            index
          ].resolve();

          await releaseSignals[
            index
          ].promise;

          completeJob(
            manager,
            ingestionId,
            index + 1,
            index + 2,
          );

          activeTasks -= 1;
        },
      ),
  );

  assert.deepEqual(
    accepted.map(
      (result) =>
        result.queuePosition,
    ),
    [1, 2, 3, 4],
  );

  assert.ok(
    accepted.every((result) =>
      Object.isFrozen(result),
    ),
  );

  /*
   * No task executes inline inside enqueue().
   */
  assert.deepEqual(
    startOrder,
    [],
  );

  await Promise.all([
    startedSignals[0].promise,
    startedSignals[1].promise,
  ]);

  assert.deepEqual(
    startOrder,
    ingestionIds.slice(0, 2),
    "The first two jobs must start in FIFO order",
  );

  assert.equal(
    manager.getJob(
      ingestionIds[2],
    )?.status,
    "queued",
  );

  assert.equal(
    manager.getJob(
      ingestionIds[3],
    )?.status,
    "queued",
  );

  const runningStats =
    dispatcher.getStats();

  assert.equal(
    Object.isFrozen(runningStats),
    true,
  );

  assert.equal(
    runningStats.running,
    2,
  );

  assert.equal(
    runningStats.pending,
    2,
  );

  /*
   * Release only the first worker. The third must claim the newly available
   * slot before the fourth.
   */
  releaseSignals[0].resolve();

  await startedSignals[2].promise;

  assert.deepEqual(
    startOrder,
    ingestionIds.slice(0, 3),
  );

  releaseSignals[1].resolve();

  await startedSignals[3].promise;

  assert.deepEqual(
    startOrder,
    ingestionIds,
    "All jobs must begin in exact FIFO order",
  );

  releaseSignals[2].resolve();
  releaseSignals[3].resolve();

  await dispatcher.waitForIdle();

  assert.equal(
    maximumActiveTasks,
    2,
    "The dispatcher must never exceed configured concurrency",
  );

  assert.equal(
    activeTasks,
    0,
  );

  assert.equal(
    taskContexts.length,
    4,
  );

  for (const context of taskContexts) {
    assert.equal(
      Object.isFrozen(context),
      true,
    );

    assert.equal(
      context.status,
      "running",
    );

    assert.equal(
      context.signal.aborted,
      false,
    );

    assert.equal(
      context.version,
      2,
      "Dispatcher start must increment the JobManager revision",
    );

    assert.match(
      context.persistenceIdempotencyKey,
      /^hg-api-[a-f0-9]{40}$/,
    );

    assert.match(
      context.correlationId,
      /^hg-job-[a-f0-9]{32}$/,
    );

    const original =
      originalContexts.get(
        context.ingestionId,
      );

    assert.ok(original);

    assert.equal(
      context.persistenceIdempotencyKey,
      original.persistenceIdempotencyKey,
      "Persistence identity must remain stable across queue startup",
    );

    assert.equal(
      context.correlationId,
      original.correlationId,
      "Correlation identity must remain stable across queue startup",
    );
  }

  for (const ingestionId of ingestionIds) {
    assert.equal(
      manager.getJob(
        ingestionId,
      )?.status,
      "completed",
    );
  }

  const finalStats =
    dispatcher.getStats();

  assert.equal(
    finalStats.pending,
    0,
  );

  assert.equal(
    finalStats.running,
    0,
  );

  assert.equal(
    finalStats.active,
    0,
  );

  assert.equal(
    finalStats.acceptedTasks,
    4,
  );

  assert.equal(
    finalStats.startedTasks,
    4,
  );

  assert.equal(
    finalStats.settledTasks,
    4,
  );

  assert.equal(
    finalStats.failedTasks,
    0,
  );

  assert.equal(
    finalStats.cancelledTasks,
    0,
  );

  await dispatcher.close();
  manager.close();
}

async function verifiesFailureContainmentAndContracts(): Promise<void> {
  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "failure-job",
    {
      maxJobs: 10,
      maxRunningJobs: 1,
    },
  );

  const internalEvents:
    WorkerDispatcherInternalErrorEvent[] =
      [];

  const dispatcher =
    new WorkerDispatcher(
      manager,
      {
        maxConcurrentJobs: 1,
        now: clock.now,

        onInternalError: (
          event,
        ) => {
          internalEvents.push(
            event,
          );

          /*
           * Observer failures must not stall the queue.
           */
          throw new Error(
            "deliberate telemetry failure",
          );
        },
      },
    );

  const throwingJob =
    createQueuedJob(
      manager,
      "throwing-worker",
    );

  const contractViolationJob =
    createQueuedJob(
      manager,
      "contract-violation",
    );

  const handledFailureJob =
    createQueuedJob(
      manager,
      "handled-failure",
    );

  const recoveryJob =
    createQueuedJob(
      manager,
      "queue-recovery",
    );

  const secret =
    "TOP_SECRET_WORKER_VALUE";

  dispatcher.enqueue(
    throwingJob,
    async () => {
      throw new Error(
        `Worker failed with ${secret}`,
      );
    },
  );

  dispatcher.enqueue(
    contractViolationJob,
    async () => {
      /*
       * Deliberately resolve without setting a terminal JobManager state.
       */
    },
  );

  dispatcher.enqueue(
    handledFailureJob,
    async (context) => {
      manager.updateJob(
        context.ingestionId,
        {
          status: "failed",
          errorCode:
            "INGESTION_FAILED",
          cause: new Error(
            "expected handled failure",
          ),
        },
      );
    },
  );

  dispatcher.enqueue(
    recoveryJob,
    async (context) => {
      completeJob(
        manager,
        context.ingestionId,
        7,
        9,
      );
    },
  );

  await dispatcher.waitForIdle();

  const throwingResult =
    manager.getJob(throwingJob);

  const contractResult =
    manager.getJob(
      contractViolationJob,
    );

  const handledResult =
    manager.getJob(
      handledFailureJob,
    );

  const recoveryResult =
    manager.getJob(recoveryJob);

  assert.equal(
    throwingResult?.status,
    "failed",
  );

  assert.equal(
    contractResult?.status,
    "failed",
  );

  assert.equal(
    handledResult?.status,
    "failed",
  );

  assert.equal(
    recoveryResult?.status,
    "completed",
  );

  assert.equal(
    JSON.stringify(
      throwingResult,
    ).includes(secret),
    false,
    "Thrown worker secrets must not enter public job snapshots",
  );

  assert.match(
    throwingResult?.errors?.[0] ??
      "",
    /^The ingestion could not be completed because of an internal error\. Reference: /,
  );

  assert.match(
    contractResult?.errors?.[0] ??
      "",
    /^The ingestion could not be completed because of an internal error\. Reference: /,
  );

  assert.match(
    handledResult?.errors?.[0] ??
      "",
    /^The ingestion pipeline could not be completed\. Reference: /,
  );

  assert.equal(
    recoveryResult?.nodeCount,
    7,
  );

  assert.equal(
    recoveryResult?.edgeCount,
    9,
  );

  assert.equal(
    internalEvents.length,
    2,
    "Only the thrown task and contract violation are dispatcher failures",
  );

  assert.ok(
    internalEvents.every(
      (event) =>
        Object.isFrozen(event),
    ),
  );

  assert.deepEqual(
    internalEvents.map(
      (event) => event.phase,
    ),
    [
      "execute",
      "contract",
    ],
  );

  const stats =
    dispatcher.getStats();

  assert.equal(
    stats.startedTasks,
    4,
  );

  assert.equal(
    stats.failedTasks,
    2,
  );

  assert.equal(
    stats.settledTasks,
    2,
    "Handled terminal failure and successful completion both settle correctly",
  );

  assert.equal(
    stats.active,
    0,
  );

  await dispatcher.close();
  manager.close();
}

async function verifiesBoundaryFailuresAndCapacity(): Promise<void> {
  const optionClock =
    new FakeClock();

  const optionManager =
    createManager(
      optionClock,
      "option-job",
      {
        maxJobs: 4,
        maxRunningJobs: 1,
      },
    );

  expectDispatcherError(
    () =>
      new WorkerDispatcher(
        optionManager,
        {
          maxConcurrentJobs: 2,
          now: optionClock.now,
        },
      ),
    "INVALID_DISPATCHER_OPTION",
    500,
  );

  optionManager.close();

  const statusClock =
    new FakeClock();

  const statusManager =
    createManager(
      statusClock,
      "status-job",
      {
        maxJobs: 4,
        maxRunningJobs: 1,
      },
    );

  const statusDispatcher =
    new WorkerDispatcher(
      statusManager,
      {
        maxConcurrentJobs: 1,
        now: statusClock.now,
      },
    );

  const terminalJob =
    createQueuedJob(
      statusManager,
      "already-terminal",
    );

  statusManager.updateJob(
    terminalJob,
    {
      status: "failed",
      errorCode:
        "INGESTION_FAILED",
    },
  );

  expectDispatcherError(
    () =>
      statusDispatcher.enqueue(
        terminalJob,
        async () => {
          assert.fail(
            "Terminal job must not run",
          );
        },
      ),
    "JOB_NOT_QUEUED",
    409,
  );

  await statusDispatcher.close();
  statusManager.close();

  const capacityClock =
    new FakeClock();

  const capacityManager =
    createManager(
      capacityClock,
      "capacity-job",
      {
        maxJobs: 2,
        maxRunningJobs: 1,
      },
    );

  const capacityDispatcher =
    new WorkerDispatcher(
      capacityManager,
      {
        maxConcurrentJobs: 1,
        now: capacityClock.now,
      },
    );

  const first =
    createQueuedJob(
      capacityManager,
      "capacity-first",
    );

  const second =
    createQueuedJob(
      capacityManager,
      "capacity-second",
    );

  expectDispatcherError(
    () =>
      capacityDispatcher.enqueue(
        first,
        undefined as unknown as WorkerTask,
      ),
    "INVALID_WORKER_TASK",
    500,
  );

  const mustNotRun:
    WorkerTask = async () => {
      assert.fail(
        "Cancelled pending task must not execute",
      );
    };

  capacityDispatcher.enqueue(
    first,
    mustNotRun,
  );

  expectDispatcherError(
    () =>
      capacityDispatcher.enqueue(
        first,
        mustNotRun,
      ),
    "DUPLICATE_JOB_DISPATCH",
    409,
  );

  capacityDispatcher.enqueue(
    second,
    mustNotRun,
  );

  expectDispatcherError(
    () =>
      capacityDispatcher
        .assertCanAccept(),
    "DISPATCHER_CAPACITY_REACHED",
    503,
  );

  /*
   * close() is called in the same turn, before the scheduled pump, proving
   * pending cancellation is deterministic and does not start work inline.
   */
  await capacityDispatcher.close({
    mode: "cancel-pending",
    reason:
      "capacity smoke cleanup",
  });

  assert.equal(
    capacityManager.getJob(
      first,
    )?.status,
    "failed",
  );

  assert.equal(
    capacityManager.getJob(
      second,
    )?.status,
    "failed",
  );

  const capacityStats =
    capacityDispatcher.getStats();

  assert.equal(
    capacityStats.state,
    "closed",
  );

  assert.equal(
    Object.isFrozen(
      capacityStats,
    ),
    true,
  );

  assert.equal(
    capacityStats.startedTasks,
    0,
  );

  assert.equal(
    capacityStats.cancelledTasks,
    2,
  );

  expectDispatcherError(
    () =>
      capacityDispatcher.enqueue(
        first,
        mustNotRun,
      ),
    "DISPATCHER_SHUTTING_DOWN",
    503,
  );

  capacityManager.close();

  const invalidClockManager =
    createManager(
      new FakeClock(),
      "invalid-clock-job",
      {
        maxJobs: 2,
        maxRunningJobs: 1,
      },
    );

  const invalidClockDispatcher =
    new WorkerDispatcher(
      invalidClockManager,
      {
        maxConcurrentJobs: 1,
        now: () => Number.NaN,
      },
    );

  const invalidClockJob =
    createQueuedJob(
      invalidClockManager,
      "invalid-clock",
    );

  expectDispatcherError(
    () =>
      invalidClockDispatcher.enqueue(
        invalidClockJob,
        async () => {
          assert.fail(
            "Invalid-clock task must not run",
          );
        },
      ),
    "INVALID_DISPATCHER_OPTION",
    500,
  );

  await invalidClockDispatcher.close();
  invalidClockManager.close();
}

async function verifiesDrainShutdown(): Promise<void> {
  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "drain-job",
    {
      maxJobs: 6,
      maxRunningJobs: 1,
    },
  );

  const dispatcher =
    new WorkerDispatcher(
      manager,
      {
        maxConcurrentJobs: 1,
        now: clock.now,
      },
    );

  const ingestionIds = [
    createQueuedJob(
      manager,
      "drain-first",
    ),
    createQueuedJob(
      manager,
      "drain-second",
    ),
    createQueuedJob(
      manager,
      "drain-third",
    ),
  ];

  const started =
    ingestionIds.map(() =>
      createDeferred<void>(),
    );

  const release =
    ingestionIds.map(() =>
      createDeferred<void>(),
    );

  for (
    let index = 0;
    index < ingestionIds.length;
    index += 1
  ) {
    const ingestionId =
      ingestionIds[index];

    dispatcher.enqueue(
      ingestionId,
      async (context) => {
        started[index].resolve();

        await release[index].promise;

        completeJob(
          manager,
          context.ingestionId,
          index + 1,
          index + 1,
        );
      },
    );
  }

  const firstClose =
    dispatcher.close({
      mode: "drain",
    });

  const repeatedClose =
    dispatcher.close({
      mode: "cancel-pending",
      abortRunning: true,
    });

  assert.equal(
    firstClose,
    repeatedClose,
    "Repeated close calls must return the same shutdown promise",
  );

  assert.equal(
    dispatcher.getStats().state,
    "draining",
  );

  expectDispatcherError(
    () =>
      dispatcher.assertCanAccept(),
    "DISPATCHER_SHUTTING_DOWN",
    503,
  );

  await started[0].promise;
  release[0].resolve();

  await started[1].promise;
  release[1].resolve();

  await started[2].promise;
  release[2].resolve();

  await firstClose;

  for (const ingestionId of ingestionIds) {
    assert.equal(
      manager.getJob(
        ingestionId,
      )?.status,
      "completed",
    );
  }

  const stats =
    dispatcher.getStats();

  assert.equal(
    stats.state,
    "closed",
  );

  assert.equal(
    stats.settledTasks,
    3,
  );

  assert.equal(
    stats.failedTasks,
    0,
  );

  assert.equal(
    stats.cancelledTasks,
    0,
  );

  assert.equal(
    stats.active,
    0,
  );

  manager.close();
}

async function verifiesCancellationAndAbort(): Promise<void> {
  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "cancel-job",
    {
      maxJobs: 6,
      maxRunningJobs: 1,
    },
  );

  const events:
    WorkerDispatcherInternalErrorEvent[] =
      [];

  const dispatcher =
    new WorkerDispatcher(
      manager,
      {
        maxConcurrentJobs: 1,
        now: clock.now,

        onInternalError: (
          event,
        ) => {
          events.push(event);
        },
      },
    );

  const runningJob =
    createQueuedJob(
      manager,
      "abort-running",
    );

  const firstPendingJob =
    createQueuedJob(
      manager,
      "cancel-pending-first",
    );

  const secondPendingJob =
    createQueuedJob(
      manager,
      "cancel-pending-second",
    );

  const runningStarted =
    createDeferred<AbortSignal>();

  dispatcher.enqueue(
    runningJob,
    async (context) => {
      runningStarted.resolve(
        context.signal,
      );

      await new Promise<void>(
        (_resolve, reject) => {
          const rejectForAbort =
            (): void => {
              reject(
                context.signal.reason ??
                  new Error(
                    "Worker was aborted",
                  ),
              );
            };

          if (
            context.signal.aborted
          ) {
            rejectForAbort();
            return;
          }

          context.signal
            .addEventListener(
              "abort",
              rejectForAbort,
              {
                once: true,
              },
            );
        },
      );
    },
  );

  const mustNotStart:
    WorkerTask = async () => {
      assert.fail(
        "Pending cancelled worker must not start",
      );
    };

  dispatcher.enqueue(
    firstPendingJob,
    mustNotStart,
  );

  dispatcher.enqueue(
    secondPendingJob,
    mustNotStart,
  );

  const signal =
    await runningStarted.promise;

  const privateShutdownReason =
    "PRIVATE_SHUTDOWN_DETAIL";

  await dispatcher.close({
    mode: "cancel-pending",
    abortRunning: true,
    reason: privateShutdownReason,
  });

  assert.equal(
    signal.aborted,
    true,
    "The running worker must receive an aborted signal",
  );

  for (const ingestionId of [
    runningJob,
    firstPendingJob,
    secondPendingJob,
  ]) {
    const job =
      manager.getJob(
        ingestionId,
      );

    assert.equal(
      job?.status,
      "failed",
    );

    assert.equal(
      JSON.stringify(job).includes(
        privateShutdownReason,
      ),
      false,
      "Private shutdown details must not enter public job snapshots",
    );

    assert.match(
      job?.errors?.[0] ?? "",
      /^The ingestion could not be completed because of an internal error\. Reference: /,
    );
  }

  const stats =
    dispatcher.getStats();

  assert.equal(
    stats.state,
    "closed",
  );

  assert.equal(
    stats.acceptedTasks,
    3,
  );

  assert.equal(
    stats.startedTasks,
    1,
  );

  assert.equal(
    stats.failedTasks,
    1,
  );

  assert.equal(
    stats.cancelledTasks,
    2,
  );

  assert.equal(
    stats.settledTasks,
    0,
  );

  assert.equal(
    stats.active,
    0,
  );

  assert.equal(
    events.filter(
      (event) =>
        event.phase === "cancel",
    ).length,
    2,
  );

  assert.equal(
    events.filter(
      (event) =>
        event.phase === "execute",
    ).length,
    1,
  );

  assert.ok(
    events.every(
      (event) =>
        Object.isFrozen(event),
    ),
  );

  manager.close();
}

async function main(): Promise<void> {
  await verifiesFifoAndConcurrency();

  await verifiesFailureContainmentAndContracts();

  await verifiesBoundaryFailuresAndCapacity();

  await verifiesDrainShutdown();

  await verifiesCancellationAndAbort();

  console.log(
    "HydraGuard WorkerDispatcher smoke passed",
  );

  console.log(
    "- worker tasks start in deterministic FIFO order",
  );

  console.log(
    "- configured concurrency is never exceeded",
  );

  console.log(
    "- stable persistence and correlation identities reach workers",
  );

  console.log(
    "- thrown tasks cannot stop later queued work",
  );

  console.log(
    "- workers must produce a terminal JobManager state before resolving",
  );

  console.log(
    "- duplicate, invalid, nonqueued, and over-capacity dispatches fail closed",
  );

  console.log(
    "- drain shutdown completes accepted work in order",
  );

  console.log(
    "- cancel shutdown fails pending jobs and aborts running work",
  );

  console.log(
    "- raw worker and shutdown details remain outside public job snapshots",
  );

  console.log(
    "- observer failures and repeated shutdown calls are isolated",
  );
}

await main();
