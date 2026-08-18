import assert from "node:assert/strict";

import {
  JobManager,
  JobManagerError,
  assertValidIdempotencyKey,
  createRequestFingerprint,
} from "./job-manager.js";

import type {
  JobInternalErrorEvent,
  JobManagerErrorCode,
  JobManagerOptions,
} from "./job-manager.js";

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
  overrides: Partial<
    JobManagerOptions
  > = {},
): JobManager {
  return new JobManager({
    maxJobs: 20,
    maxRunningJobs: 4,
    terminalRetentionMs: 10_000,
    activeJobTimeoutMs: 10_000,
    sweepIntervalMs: 0,
    now: clock.now,
    idFactory:
      createSequentialIdFactory(prefix),
    ...overrides,
  });
}

function expectJobManagerError(
  operation: () => unknown,
  expectedCode: JobManagerErrorCode,
  expectedHttpStatus: number,
): JobManagerError {
  try {
    operation();
  } catch (error: unknown) {
    if (!(error instanceof JobManagerError)) {
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
    `Expected JobManagerError ${expectedCode}`,
  );
}

function verifiesCanonicalRequestFingerprints(): void {
  const first = {
    maxDepth: 5,
    roots: [
      "react",
      "@tanstack/query-core",
    ],
    options: {
      includeDevDependencies: false,
      maxPackages: 250,
    },
  };

  const reordered = {
    options: {
      maxPackages: 250,
      includeDevDependencies: false,
    },
    roots: [
      "react",
      "@tanstack/query-core",
    ],
    maxDepth: 5,
  };

  const firstFingerprint =
    createRequestFingerprint(first);

  const reorderedFingerprint =
    createRequestFingerprint(reordered);

  assert.equal(
    firstFingerprint,
    reorderedFingerprint,
    "Object-key ordering must not affect request identity",
  );

  assert.match(
    firstFingerprint,
    /^[a-f0-9]{64}$/,
  );

  assert.notEqual(
    createRequestFingerprint({
      roots: ["react", "fastify"],
    }),
    createRequestFingerprint({
      roots: ["fastify", "react"],
    }),
    "Array order must remain part of request identity",
  );

  assert.equal(
    createRequestFingerprint({
      value: -0,
    }),
    createRequestFingerprint({
      value: 0,
    }),
    "Negative zero and zero have the same JSON meaning",
  );

  expectJobManagerError(
    () =>
      createRequestFingerprint({
        invalid: undefined,
      }),
    "INVALID_REQUEST_BODY",
    400,
  );

  expectJobManagerError(
    () =>
      createRequestFingerprint({
        invalid: Number.NaN,
      }),
    "INVALID_REQUEST_BODY",
    400,
  );

  const circular:
    Record<string, unknown> = {};

  circular.self = circular;

  expectJobManagerError(
    () =>
      createRequestFingerprint(circular),
    "INVALID_REQUEST_BODY",
    400,
  );

  expectJobManagerError(
    () =>
      createRequestFingerprint(
        new Date(BASE_TIME),
      ),
    "INVALID_REQUEST_BODY",
    400,
  );
}

function verifiesIdempotencyValidationAndReuse(): void {
  assert.doesNotThrow(() =>
    assertValidIdempotencyKey(
      "abcdefgh",
    ),
  );

  assert.doesNotThrow(() =>
    assertValidIdempotencyKey(
      "A.b_c-123",
    ),
  );

  assert.doesNotThrow(() =>
    assertValidIdempotencyKey(
      "a".repeat(80),
    ),
  );

  expectJobManagerError(
    () =>
      assertValidIdempotencyKey(
        "short",
      ),
    "INVALID_IDEMPOTENCY_KEY",
    400,
  );

  expectJobManagerError(
    () =>
      assertValidIdempotencyKey(
        "contains/slash",
      ),
    "INVALID_IDEMPOTENCY_KEY",
    400,
  );

  expectJobManagerError(
    () =>
      assertValidIdempotencyKey(
        "a".repeat(81),
      ),
    "INVALID_IDEMPOTENCY_KEY",
    400,
  );

  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "idem-job",
  );

  const request = {
    roots: ["@tanstack/query-core"],
    maxPackages: 100,
    maxDepth: 4,
    includeDevDependencies: false,
  };

  const fingerprint =
    createRequestFingerprint(request);

  const rawKey =
    "npm-tanstack-request-001";

  const first = manager.createJob({
    kind: "npm",
    requestFingerprint: fingerprint,
    idempotencyKey: rawKey,
  });

  assert.equal(first.reused, false);
  assert.equal(
    first.accepted.status,
    "queued",
  );
  assert.equal(
    first.current.status,
    "queued",
  );

  assert.equal(
    Object.isFrozen(first),
    true,
  );

  assert.equal(
    Object.isFrozen(first.accepted),
    true,
  );

  assert.equal(
    Object.isFrozen(first.current),
    true,
  );

  const context =
    manager.getExecutionContext(
      first.accepted.ingestionId,
    );

  assert.equal(
    Object.isFrozen(context),
    true,
  );

  assert.match(
    context.persistenceIdempotencyKey,
    /^hg-api-[a-f0-9]{40}$/,
  );

  assert.ok(
    context.persistenceIdempotencyKey
      .length <= 80,
  );

  assert.match(
    context.correlationId,
    /^hg-job-[a-f0-9]{32}$/,
  );

  const exposedIdentityJson =
    JSON.stringify({
      first,
      context,
    });

  assert.equal(
    exposedIdentityJson.includes(rawKey),
    false,
    "Raw HTTP idempotency keys must never be exposed",
  );

  const reorderedFingerprint =
    createRequestFingerprint({
      includeDevDependencies: false,
      maxDepth: 4,
      maxPackages: 100,
      roots: ["@tanstack/query-core"],
    });

  const replay = manager.createJob({
    kind: "npm",
    requestFingerprint:
      reorderedFingerprint,
    idempotencyKey: rawKey,
  });

  assert.equal(replay.reused, true);

  assert.equal(
    replay.accepted.ingestionId,
    first.accepted.ingestionId,
  );

  assert.equal(
    replay.current.ingestionId,
    first.current.ingestionId,
  );

  const differentFingerprint =
    createRequestFingerprint({
      ...request,
      maxDepth: 5,
    });

  expectJobManagerError(
    () =>
      manager.createJob({
        kind: "npm",
        requestFingerprint:
          differentFingerprint,
        idempotencyKey: rawKey,
      }),
    "IDEMPOTENCY_CONFLICT",
    409,
  );

  expectJobManagerError(
    () =>
      manager.createJob({
        kind: "lockfile",
        requestFingerprint:
          fingerprint,
        idempotencyKey: rawKey,
      }),
    "IDEMPOTENCY_CONFLICT",
    409,
  );

  expectJobManagerError(
    () =>
      manager.createJob({
        kind: "npm",
        requestFingerprint:
          "not-a-sha256-value",
      }),
    "INVALID_REQUEST_FINGERPRINT",
    400,
  );

  const withoutKeyOne =
    manager.createJob({
      kind: "npm",
      requestFingerprint: fingerprint,
    });

  const withoutKeyTwo =
    manager.createJob({
      kind: "npm",
      requestFingerprint: fingerprint,
    });

  assert.notEqual(
    withoutKeyOne.accepted.ingestionId,
    withoutKeyTwo.accepted.ingestionId,
    "Requests without an Idempotency-Key are distinct jobs",
  );

  manager.close();
}

function verifiesLifecycleAndImmutableSnapshots(): void {
  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "lifecycle-job",
  );

  const created = manager.createJob({
    kind: "lockfile",
    requestFingerprint:
      createRequestFingerprint({
        serviceLogicalId:
          "service:payment-api",
        format:
          "npm-package-lock-v3",
      }),
    idempotencyKey:
      "lockfile-payment-001",
  });

  const ingestionId =
    created.accepted.ingestionId;

  const originalSnapshot =
    created.current;

  assert.equal(
    originalSnapshot.status,
    "queued",
  );

  assert.equal(
    manager.getExecutionContext(
      ingestionId,
    ).version,
    1,
  );

  const running = manager.updateJob(
    ingestionId,
    {
      status: "running",
    },
  );

  assert.equal(
    running.status,
    "running",
  );

  assert.equal(
    Object.isFrozen(running),
    true,
  );

  assert.equal(
    originalSnapshot.status,
    "queued",
    "Previously returned snapshots must not mutate",
  );

  const runningContext =
    manager.getExecutionContext(
      ingestionId,
    );

  assert.equal(
    runningContext.status,
    "running",
  );

  assert.equal(
    runningContext.version,
    2,
  );

  expectJobManagerError(
    () =>
      manager.updateJob(
        ingestionId,
        {
          status: "running",
        },
      ),
    "INVALID_JOB_TRANSITION",
    409,
  );

  clock.advance(250);

  const completed = manager.updateJob(
    ingestionId,
    {
      status: "completed",
      nodeCount: 42,
      edgeCount: 64,
    },
  );

  assert.equal(
    completed.status,
    "completed",
  );

  assert.equal(
    completed.nodeCount,
    42,
  );

  assert.equal(
    completed.edgeCount,
    64,
  );

  assert.equal(
    completed.completedAt,
    new Date(
      BASE_TIME + 250,
    ).toISOString(),
  );

  assert.equal(
    completed.errors,
    undefined,
  );

  const completedContext =
    manager.getExecutionContext(
      ingestionId,
    );

  assert.equal(
    completedContext.version,
    3,
  );

  expectJobManagerError(
    () =>
      manager.updateJob(
        ingestionId,
        {
          status: "completed",
          nodeCount: 42,
          edgeCount: 64,
        },
      ),
    "INVALID_JOB_TRANSITION",
    409,
  );

  const fetched =
    manager.getJob(ingestionId);

  assert.ok(fetched);

  assert.equal(
    Object.isFrozen(fetched),
    true,
  );

  assert.equal(
    manager.getJob(
      "missing-job-0001",
    ),
    null,
  );

  expectJobManagerError(
    () =>
      manager.getExecutionContext(
        "missing-job-0001",
      ),
    "JOB_NOT_FOUND",
    404,
  );

  const stats = manager.getStats();

  assert.equal(
    Object.isFrozen(stats),
    true,
  );

  assert.deepEqual(stats, {
    total: 1,
    queued: 0,
    running: 0,
    completed: 1,
    partiallyCompleted: 0,
    failed: 0,
    capacity: 20,
    maxRunningJobs: 4,
  });

  manager.close();
}

function verifiesPartialResultsAndErrorRedaction(): void {
  const clock = new FakeClock();

  let loggedEvent:
    | JobInternalErrorEvent
    | undefined;

  const manager = createManager(
    clock,
    "result-job",
    {
      onInternalError: (event) => {
        loggedEvent = event;

        /*
         * Logging failures must not change the public job result.
         */
        throw new Error(
          "deliberate logger failure",
        );
      },
    },
  );

  const partial = manager.createJob({
    kind: "npm",
    requestFingerprint:
      createRequestFingerprint({
        roots: ["partial-package"],
      }),
  });

  manager.updateJob(
    partial.accepted.ingestionId,
    {
      status: "running",
    },
  );

  const partialResult =
    manager.updateJob(
      partial.accepted.ingestionId,
      {
        status:
          "partially-completed",
        nodeCount: 10,
        edgeCount: 12,
        errorCodes: [
          "PARTIAL_COLLECTION",
          "REGISTRY_REQUEST_FAILED",
          "PARTIAL_COLLECTION",
        ],
      },
    );

  assert.equal(
    partialResult.status,
    "partially-completed",
  );

  assert.equal(
    partialResult.errors?.length,
    2,
    "Duplicate safe error codes must be deduplicated",
  );

  assert.ok(partialResult.errors);

  assert.equal(
    Object.isFrozen(
      partialResult.errors,
    ),
    true,
  );

  assert.equal(
    JSON.stringify(
      partialResult.errors,
    ).includes("Reference:"),
    false,
    "Partial warnings do not need internal diagnostic references",
  );

  const invalidPartial =
    manager.createJob({
      kind: "npm",
      requestFingerprint:
        createRequestFingerprint({
          roots: ["invalid-partial"],
        }),
    });

  manager.updateJob(
    invalidPartial.accepted.ingestionId,
    {
      status: "running",
    },
  );

  expectJobManagerError(
    () =>
      manager.updateJob(
        invalidPartial.accepted.ingestionId,
        {
          status:
            "partially-completed",
          nodeCount: 1,
          edgeCount: 1,
          errorCodes: [],
        },
      ),
    "INVALID_JOB_RESULT",
    500,
  );

  assert.equal(
    manager.getJob(
      invalidPartial.accepted.ingestionId,
    )?.status,
    "running",
    "Rejected updates must not create a false terminal state",
  );

  const secret =
    "TOP_SECRET_DATABASE_TOKEN";

  const rawCause = new Error(
    `HydraDB failed with ${secret}`,
  );

  const failed =
    manager.updateJob(
      invalidPartial.accepted.ingestionId,
      {
        status: "failed",
        errorCode:
          "PERSISTENCE_FAILED",
        cause: rawCause,
        nodeCount: 1,
        edgeCount: 0,
      },
    );

  assert.equal(
    failed.status,
    "failed",
  );

  assert.equal(
    failed.nodeCount,
    1,
  );

  assert.equal(
    failed.edgeCount,
    0,
  );

  assert.ok(failed.errors);

  assert.equal(
    failed.errors.length,
    1,
  );

  assert.equal(
    JSON.stringify(failed).includes(
      secret,
    ),
    false,
    "Raw failure details must not enter public snapshots",
  );

  assert.match(
    failed.errors[0],
    /^The graph could not be safely persisted and verified\. Reference: [0-9a-f-]{36}\.$/,
  );

  assert.ok(loggedEvent);

  assert.equal(
    Object.isFrozen(loggedEvent),
    true,
  );

  assert.equal(
    loggedEvent.ingestionId,
    invalidPartial.accepted.ingestionId,
  );

  assert.equal(
    loggedEvent.code,
    "PERSISTENCE_FAILED",
  );

  assert.equal(
    loggedEvent.cause,
    rawCause,
    "The injected private logger should receive the original cause",
  );

  manager.close();
}

function verifiesCapacityAndConcurrencyLimits(): void {
  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "limit-job",
    {
      maxJobs: 2,
      maxRunningJobs: 1,
    },
  );

  const first = manager.createJob({
    kind: "npm",
    requestFingerprint:
      createRequestFingerprint({
        roots: ["first"],
      }),
  });

  const second = manager.createJob({
    kind: "npm",
    requestFingerprint:
      createRequestFingerprint({
        roots: ["second"],
      }),
  });

  expectJobManagerError(
    () =>
      manager.createJob({
        kind: "npm",
        requestFingerprint:
          createRequestFingerprint({
            roots: ["third"],
          }),
      }),
    "JOB_CAPACITY_REACHED",
    503,
  );

  manager.updateJob(
    first.accepted.ingestionId,
    {
      status: "running",
    },
  );

  expectJobManagerError(
    () =>
      manager.updateJob(
        second.accepted.ingestionId,
        {
          status: "running",
        },
      ),
    "JOB_CONCURRENCY_LIMIT",
    503,
  );

  assert.equal(
    manager.getJob(
      second.accepted.ingestionId,
    )?.status,
    "queued",
    "Concurrency rejection must leave the waiting job queued",
  );

  manager.updateJob(
    first.accepted.ingestionId,
    {
      status: "completed",
      nodeCount: 5,
      edgeCount: 4,
    },
  );

  const secondRunning =
    manager.updateJob(
      second.accepted.ingestionId,
      {
        status: "running",
      },
    );

  assert.equal(
    secondRunning.status,
    "running",
  );

  const stats = manager.getStats();

  assert.equal(stats.total, 2);
  assert.equal(stats.completed, 1);
  assert.equal(stats.running, 1);

  manager.close();
}

function verifiesTimeoutTtlAndIdempotencyRelease(): void {
  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "expiry-job",
    {
      activeJobTimeoutMs: 1_000,
      terminalRetentionMs: 2_000,
    },
  );

  const requestFingerprint =
    createRequestFingerprint({
      roots: ["expiring-package"],
    });

  const idempotencyKey =
    "expiry-request-0001";

  const original = manager.createJob({
    kind: "npm",
    requestFingerprint,
    idempotencyKey,
  });

  clock.advance(999);

  assert.deepEqual(
    manager.sweep(),
    {
      timedOut: 0,
      removed: 0,
    },
  );

  assert.equal(
    manager.getJob(
      original.accepted.ingestionId,
    )?.status,
    "queued",
  );

  clock.advance(1);

  const timeoutSweep =
    manager.sweep();

  assert.deepEqual(
    timeoutSweep,
    {
      timedOut: 1,
      removed: 0,
    },
  );

  const timedOut =
    manager.getJob(
      original.accepted.ingestionId,
    );

  assert.ok(timedOut);

  assert.equal(
    timedOut.status,
    "failed",
  );

  assert.ok(timedOut.errors);

  assert.match(
    timedOut.errors[0],
    /^The ingestion exceeded its permitted execution time\. Reference: /,
  );

  clock.advance(1_999);

  assert.deepEqual(
    manager.sweep(),
    {
      timedOut: 0,
      removed: 0,
    },
  );

  clock.advance(1);

  assert.deepEqual(
    manager.sweep(),
    {
      timedOut: 0,
      removed: 1,
    },
  );

  assert.equal(
    manager.getJob(
      original.accepted.ingestionId,
    ),
    null,
  );

  const recreated =
    manager.createJob({
      kind: "npm",
      requestFingerprint,
      idempotencyKey,
    });

  assert.equal(
    recreated.reused,
    false,
    "Expiration must release the old idempotency mapping",
  );

  assert.notEqual(
    recreated.accepted.ingestionId,
    original.accepted.ingestionId,
  );

  manager.close();

  /*
   * Running-job timeout must begin from startedAt, not submittedAt.
   */
  const runningClock =
    new FakeClock();

  const runningManager =
    createManager(
      runningClock,
      "running-expiry-job",
      {
        activeJobTimeoutMs: 1_000,
        terminalRetentionMs: 2_000,
      },
    );

  const runningJob =
    runningManager.createJob({
      kind: "lockfile",
      requestFingerprint:
        createRequestFingerprint({
          serviceLogicalId:
            "service:timeout-check",
        }),
    });

  runningClock.advance(900);

  runningManager.updateJob(
    runningJob.accepted.ingestionId,
    {
      status: "running",
    },
  );

  runningClock.advance(999);

  assert.equal(
    runningManager.sweep()
      .timedOut,
    0,
  );

  runningClock.advance(1);

  assert.equal(
    runningManager.sweep()
      .timedOut,
    1,
  );

  assert.equal(
    runningManager.getJob(
      runningJob.accepted.ingestionId,
    )?.status,
    "failed",
  );

  runningManager.close();
}

function verifiesBoundaryFailuresAndShutdown(): void {
  expectJobManagerError(
    () =>
      new JobManager({
        maxJobs: 0,
        sweepIntervalMs: 0,
      }),
    "INVALID_JOB_MANAGER_OPTION",
    500,
  );

  expectJobManagerError(
    () =>
      new JobManager({
        maxJobs: 1,
        maxRunningJobs: 2,
        sweepIntervalMs: 0,
      }),
    "INVALID_JOB_MANAGER_OPTION",
    500,
  );

  const invalidClockManager =
    new JobManager({
      sweepIntervalMs: 0,
      now: () => Number.NaN,
      idFactory: () =>
        "invalid-clock-job-0001",
    });

  expectJobManagerError(
    () =>
      invalidClockManager.getStats(),
    "INVALID_JOB_MANAGER_OPTION",
    500,
  );

  invalidClockManager.close();

  const invalidIdManager =
    new JobManager({
      sweepIntervalMs: 0,
      idFactory: () => "bad/id",
    });

  expectJobManagerError(
    () =>
      invalidIdManager.createJob({
        kind: "npm",
        requestFingerprint:
          createRequestFingerprint({
            roots: ["invalid-id"],
          }),
      }),
    "JOB_ID_GENERATION_FAILED",
    500,
  );

  invalidIdManager.close();

  const duplicateIdManager =
    new JobManager({
      maxJobs: 2,
      maxRunningJobs: 1,
      sweepIntervalMs: 0,
      idFactory: () =>
        "duplicate-job-0001",
    });

  duplicateIdManager.createJob({
    kind: "npm",
    requestFingerprint:
      createRequestFingerprint({
        roots: ["first-duplicate"],
      }),
  });

  expectJobManagerError(
    () =>
      duplicateIdManager.createJob({
        kind: "npm",
        requestFingerprint:
          createRequestFingerprint({
            roots: [
              "second-duplicate",
            ],
          }),
      }),
    "JOB_ID_GENERATION_FAILED",
    500,
  );

  duplicateIdManager.close();

  const clock = new FakeClock();

  const manager = createManager(
    clock,
    "closed-job",
  );

  const created = manager.createJob({
    kind: "npm",
    requestFingerprint:
      createRequestFingerprint({
        roots: ["close-check"],
      }),
  });

  manager.close();

  /*
   * Closing twice must be safe for repeated shutdown signals.
   */
  assert.doesNotThrow(() =>
    manager.close(),
  );

  expectJobManagerError(
    () =>
      manager.getJob(
        created.accepted.ingestionId,
      ),
    "JOB_MANAGER_CLOSED",
    503,
  );

  expectJobManagerError(
    () =>
      manager.createJob({
        kind: "npm",
        requestFingerprint:
          createRequestFingerprint({
            roots: ["after-close"],
          }),
      }),
    "JOB_MANAGER_CLOSED",
    503,
  );

  expectJobManagerError(
    () => manager.sweep(),
    "JOB_MANAGER_CLOSED",
    503,
  );
}

function main(): void {
  verifiesCanonicalRequestFingerprints();
  verifiesIdempotencyValidationAndReuse();
  verifiesLifecycleAndImmutableSnapshots();
  verifiesPartialResultsAndErrorRedaction();
  verifiesCapacityAndConcurrencyLimits();
  verifiesTimeoutTtlAndIdempotencyRelease();
  verifiesBoundaryFailuresAndShutdown();

  console.log(
    "HydraGuard JobManager smoke passed",
  );

  console.log(
    "- request fingerprints are canonical and reject non-JSON values",
  );

  console.log(
    "- idempotency keys reuse identical requests and reject conflicts",
  );

  console.log(
    "- public snapshots are immutable and persistence identities are redacted",
  );

  console.log(
    "- lifecycle transitions, revisions, and result counts are enforced",
  );

  console.log(
    "- partial and failed outcomes expose only safe error messages",
  );

  console.log(
    "- retained-job capacity and running-job concurrency are bounded",
  );

  console.log(
    "- queued and running jobs time out deterministically",
  );

  console.log(
    "- terminal TTL cleanup releases idempotency mappings",
  );

  console.log(
    "- invalid configuration, clocks, IDs, and shutdown use fail-closed behavior",
  );
}

main();
