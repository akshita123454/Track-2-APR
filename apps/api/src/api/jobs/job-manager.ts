import {
  createHash,
  randomUUID,
} from "node:crypto";

/**
 * These statuses intentionally match contracts/openapi.yaml.
 *
 * Do not rename "completed" to "succeeded" without updating the
 * public OpenAPI contract and dashboard consumers.
 */
export type IngestionJobStatus =
  | "queued"
  | "running"
  | "completed"
  | "partially-completed"
  | "failed";

export type IngestionKind =
  | "npm"
  | "lockfile";

export interface IngestionAccepted {
  readonly ingestionId: string;
  readonly status: "queued";
  readonly submittedAt: string;
}

/**
 * Exact public response shape declared by the OpenAPI IngestionJob schema.
 *
 * Internal fields such as request fingerprints, idempotency identities,
 * correlation IDs and diagnostic causes are deliberately excluded.
 */
export interface IngestionJob {
  readonly ingestionId: string;
  readonly status: IngestionJobStatus;
  readonly submittedAt: string;
  readonly completedAt?: string | null;
  readonly nodeCount?: number;
  readonly edgeCount?: number;
  readonly errors?: readonly string[];
}

export type JobFailureCode =
  | "REGISTRY_REQUEST_FAILED"
  | "LOCKFILE_INVALID"
  | "INGESTION_FAILED"
  | "GRAPH_VALIDATION_FAILED"
  | "PERSISTENCE_FAILED"
  | "PERSISTENCE_PARTIAL"
  | "JOB_TIMED_OUT"
  | "PARTIAL_COLLECTION"
  | "INTERNAL_JOB_ERROR";

const SAFE_FAILURE_MESSAGES: Readonly<
  Record<JobFailureCode, string>
> = {
  REGISTRY_REQUEST_FAILED:
    "The npm registry request could not be completed.",
  LOCKFILE_INVALID:
    "The supplied lockfile could not be validated.",
  INGESTION_FAILED:
    "The ingestion pipeline could not be completed.",
  GRAPH_VALIDATION_FAILED:
    "The collected dependency graph did not pass validation.",
  PERSISTENCE_FAILED:
    "The graph could not be safely persisted and verified.",
  PERSISTENCE_PARTIAL:
    "HydraDB persistence did not complete after safe replay attempts.",
  JOB_TIMED_OUT:
    "The ingestion exceeded its permitted execution time.",
  PARTIAL_COLLECTION:
    "The ingestion completed with one or more unavailable inputs.",
  INTERNAL_JOB_ERROR:
    "The ingestion could not be completed because of an internal error.",
};

export interface CreateJobInput {
  readonly kind: IngestionKind;

  /**
   * SHA-256 fingerprint produced by createRequestFingerprint().
   *
   * The request body itself is intentionally not retained in the JobManager.
   */
  readonly requestFingerprint: string;

  /**
   * Optional caller-provided HTTP Idempotency-Key.
   *
   * The raw key is validated but never stored. Only a SHA-256 digest is
   * retained in memory.
   */
  readonly idempotencyKey?: string;
}

export interface JobCreationResult {
  /**
   * Exact 202 response declared by IngestionAccepted.
   *
   * For an idempotent replay, this remains the original acceptance response.
   * Clients should use GET /ingestions/{id} for current state.
   */
  readonly accepted: IngestionAccepted;

  /**
   * Current state, which may already be running or terminal when reused.
   */
  readonly current: IngestionJob;

  /**
   * True when the same idempotency key and same normalized request resolved
   * to an existing logical job.
   */
  readonly reused: boolean;
}

export interface JobExecutionContext {
  readonly ingestionId: string;
  readonly kind: IngestionKind;
  readonly status: IngestionJobStatus;

  /**
   * Writer-compatible key containing only [A-Za-z0-9._-] and fewer than
   * 80 characters. This is stable for the complete logical job.
   */
  readonly persistenceIdempotencyKey: string;

  /**
   * Stable across persistence attempts and partial replays.
   */
  readonly correlationId: string;

  readonly requestFingerprint: string;

  /**
   * Monotonic in-memory revision. This may later support ETag responses.
   */
  readonly version: number;
}

export interface JobInternalErrorEvent {
  readonly ingestionId: string;
  readonly kind: IngestionKind;
  readonly diagnosticId: string;
  readonly code: JobFailureCode;
  readonly occurredAt: string;

  /**
   * Raw errors are available only to an injected server-side logger.
   * They are never retained in the job record or returned through HTTP.
   */
  readonly cause: unknown;
}

export interface JobManagerOptions {
  /**
   * Maximum retained jobs, including terminal jobs awaiting expiration.
   *
   * Defaults to 1,000.
   */
  readonly maxJobs?: number;

  /**
   * Maximum jobs permitted in the running state simultaneously.
   *
   * Defaults to 4. workers.ts must retry queued work when capacity becomes
   * available rather than starting every accepted request immediately.
   */
  readonly maxRunningJobs?: number;

  /**
   * Completed jobs are retained for this duration.
   *
   * Defaults to one hour.
   */
  readonly terminalRetentionMs?: number;

  /**
   * Queued or running jobs older than this duration fail closed.
   *
   * Defaults to 15 minutes.
   */
  readonly activeJobTimeoutMs?: number;

  /**
   * Automatic cleanup frequency. Set to 0 to disable automatic cleanup,
   * which is useful for deterministic smoke tests.
   *
   * Defaults to 30 seconds.
   */
  readonly sweepIntervalMs?: number;

  /**
   * Test seam for deterministic clocks.
   */
  readonly now?: () => number;

  /**
   * Test seam for deterministic job identifiers.
   */
  readonly idFactory?: () => string;

  /**
   * Optional server-side logging hook.
   *
   * A failure in this callback is isolated and cannot alter job state.
   */
  readonly onInternalError?: (
    event: JobInternalErrorEvent,
  ) => void;
}

export type JobUpdate =
  | {
      readonly status: "running";
    }
  | {
      readonly status: "completed";
      readonly nodeCount: number;
      readonly edgeCount: number;
    }
  | {
      readonly status: "partially-completed";
      readonly nodeCount: number;
      readonly edgeCount: number;
      readonly errorCodes: readonly JobFailureCode[];
    }
  | {
      readonly status: "failed";
      readonly errorCode: JobFailureCode;
      readonly cause?: unknown;
      readonly nodeCount?: number;
      readonly edgeCount?: number;
    };

export interface JobManagerStats {
  readonly total: number;
  readonly queued: number;
  readonly running: number;
  readonly completed: number;
  readonly partiallyCompleted: number;
  readonly failed: number;
  readonly capacity: number;
  readonly maxRunningJobs: number;
}

export interface JobSweepResult {
  readonly timedOut: number;
  readonly removed: number;
}

export type JobManagerErrorCode =
  | "INVALID_JOB_MANAGER_OPTION"
  | "INVALID_REQUEST_BODY"
  | "INVALID_REQUEST_FINGERPRINT"
  | "INVALID_IDEMPOTENCY_KEY"
  | "IDEMPOTENCY_CONFLICT"
  | "JOB_CAPACITY_REACHED"
  | "JOB_CONCURRENCY_LIMIT"
  | "JOB_NOT_FOUND"
  | "INVALID_JOB_TRANSITION"
  | "INVALID_JOB_RESULT"
  | "JOB_ID_GENERATION_FAILED"
  | "JOB_MANAGER_CLOSED";

export class JobManagerError extends Error {
  constructor(
    readonly code: JobManagerErrorCode,
    readonly httpStatusCode: number,
    message: string,
  ) {
    super(message);
    this.name = "JobManagerError";
  }
}

interface StoredJob {
  readonly ingestionId: string;
  readonly kind: IngestionKind;
  readonly submittedAtMs: number;
  readonly requestFingerprint: string;
  readonly persistenceIdempotencyKey: string;
  readonly correlationId: string;
  readonly idempotencyToken?: string;

  status: IngestionJobStatus;
  version: number;

  startedAtMs?: number;
  completedAtMs?: number;
  expiresAtMs?: number;

  nodeCount?: number;
  edgeCount?: number;
  errors: string[];
}

const DEFAULT_MAX_JOBS = 1_000;
const DEFAULT_MAX_RUNNING_JOBS = 4;
const DEFAULT_TERMINAL_RETENTION_MS = 60 * 60_000;
const DEFAULT_ACTIVE_JOB_TIMEOUT_MS = 15 * 60_000;
const DEFAULT_SWEEP_INTERVAL_MS = 30_000;

const REQUEST_FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const JOB_ID_PATTERN = /^[A-Za-z0-9._-]{8,128}$/;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._-]{8,80}$/;

function sha256(value: string): string {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

function readIntegerOption(
  value: number | undefined,
  fallback: number,
  name: string,
  minimum: number,
  maximum: number,
): number {
  const selected = value ?? fallback;

  if (
    !Number.isSafeInteger(selected) ||
    selected < minimum ||
    selected > maximum
  ) {
    throw new JobManagerError(
      "INVALID_JOB_MANAGER_OPTION",
      500,
      `${name} must be a safe integer between ` +
        `${minimum} and ${maximum}`,
    );
  }

  return selected;
}

function assertRequestFingerprint(
  value: string,
): void {
  if (!REQUEST_FINGERPRINT_PATTERN.test(value)) {
    throw new JobManagerError(
      "INVALID_REQUEST_FINGERPRINT",
      400,
      "The request fingerprint must be a lowercase SHA-256 value",
    );
  }
}

/**
 * Enforces the shared HTTP-to-persistence idempotency contract.
 *
 * The current OpenAPI file still permits up to 200 characters and needs to
 * be reconciled to this stricter 8..80 character policy.
 */
export function assertValidIdempotencyKey(
  value: string,
): void {
  if (!IDEMPOTENCY_KEY_PATTERN.test(value)) {
    throw new JobManagerError(
      "INVALID_IDEMPOTENCY_KEY",
      400,
      "Idempotency-Key must contain 8 to 80 ASCII letters, digits, " +
        "periods, underscores, or hyphens",
    );
  }
}

function assertJobKind(
  value: string,
): asserts value is IngestionKind {
  if (value !== "npm" && value !== "lockfile") {
    throw new JobManagerError(
      "INVALID_REQUEST_BODY",
      400,
      "Unsupported ingestion kind",
    );
  }
}

function assertNonnegativeCount(
  value: number,
  field: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new JobManagerError(
      "INVALID_JOB_RESULT",
      500,
      `${field} must be a nonnegative safe integer`,
    );
  }
}

function isTerminalStatus(
  status: IngestionJobStatus,
): status is
  | "completed"
  | "partially-completed"
  | "failed" {
  return (
    status === "completed" ||
    status === "partially-completed" ||
    status === "failed"
  );
}

function encodeJsonString(value: string): string {
  const encoded = JSON.stringify(value);

  if (encoded === undefined) {
    throw new JobManagerError(
      "INVALID_REQUEST_BODY",
      400,
      "The request contains a value that cannot be represented as JSON",
    );
  }

  return encoded;
}

/**
 * Produces a canonical JSON representation:
 *
 * - object keys are sorted;
 * - array order is preserved;
 * - cycles and non-JSON values are rejected;
 * - objects with custom prototypes are rejected.
 *
 * This prevents semantically identical JSON objects with different key order
 * from creating different idempotency fingerprints.
 */
function canonicalJson(
  value: unknown,
  ancestors: Set<object>,
): string {
  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "string":
      return encodeJsonString(value);

    case "boolean":
      return value ? "true" : "false";

    case "number":
      if (!Number.isFinite(value)) {
        throw new JobManagerError(
          "INVALID_REQUEST_BODY",
          400,
          "The request contains a non-finite number",
        );
      }

      return Object.is(value, -0)
        ? "0"
        : String(value);

    case "undefined":
    case "bigint":
    case "function":
    case "symbol":
      throw new JobManagerError(
        "INVALID_REQUEST_BODY",
        400,
        "The request contains a value that cannot be represented as JSON",
      );

    case "object":
      break;
  }

  if (ancestors.has(value)) {
    throw new JobManagerError(
      "INVALID_REQUEST_BODY",
      400,
      "The request contains a circular value",
    );
  }

  ancestors.add(value);

  try {
    if (Array.isArray(value)) {
      return (
        "[" +
        value
          .map((entry) =>
            canonicalJson(entry, ancestors),
          )
          .join(",") +
        "]"
      );
    }

    const prototype = Object.getPrototypeOf(value);

    if (
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      throw new JobManagerError(
        "INVALID_REQUEST_BODY",
        400,
        "The request must contain only plain JSON objects",
      );
    }

    const record =
      value as Record<string, unknown>;

    const fields = Object.keys(record)
      .sort()
      .map((key) => {
        const entry = record[key];

        if (entry === undefined) {
          throw new JobManagerError(
            "INVALID_REQUEST_BODY",
            400,
            "The request contains an undefined property",
          );
        }

        return (
          `${encodeJsonString(key)}:` +
          canonicalJson(entry, ancestors)
        );
      });

    return `{${fields.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

/**
 * Routes should call this only after Fastify schema validation and default
 * application. The resulting fingerprint represents the normalized request.
 */
export function createRequestFingerprint(
  request: unknown,
): string {
  return sha256(
    canonicalJson(request, new Set<object>()),
  );
}

function freezeAccepted(
  record: StoredJob,
): IngestionAccepted {
  return Object.freeze({
    ingestionId: record.ingestionId,
    status: "queued" as const,
    submittedAt:
      new Date(record.submittedAtMs).toISOString(),
  });
}

function freezeJob(
  record: StoredJob,
): IngestionJob {
  const errors =
    record.errors.length === 0
      ? undefined
      : Object.freeze([...record.errors]);

  const snapshot: IngestionJob = {
    ingestionId: record.ingestionId,
    status: record.status,
    submittedAt:
      new Date(record.submittedAtMs).toISOString(),

    ...(record.completedAtMs === undefined
      ? {}
      : {
          completedAt:
            new Date(
              record.completedAtMs,
            ).toISOString(),
        }),

    ...(record.nodeCount === undefined
      ? {}
      : { nodeCount: record.nodeCount }),

    ...(record.edgeCount === undefined
      ? {}
      : { edgeCount: record.edgeCount }),

    ...(errors === undefined
      ? {}
      : { errors }),
  };

  return Object.freeze(snapshot);
}

export class JobManager {
  private readonly jobs =
    new Map<string, StoredJob>();

  /**
   * SHA-256(raw Idempotency-Key) -> ingestionId.
   *
   * Raw HTTP keys are never retained.
   */
  private readonly jobsByIdempotencyToken =
    new Map<string, string>();

  private readonly maxJobs: number;
  private readonly maxRunningJobs: number;
  private readonly terminalRetentionMs: number;
  private readonly activeJobTimeoutMs: number;
  private readonly sweepIntervalMs: number;

  private readonly nowProvider: () => number;
  private readonly idFactory: () => string;

  private readonly onInternalError?: (
    event: JobInternalErrorEvent,
  ) => void;

  private sweepTimer?: NodeJS.Timeout;
  private closed = false;

  constructor(
    options: JobManagerOptions = {},
  ) {
    this.maxJobs = readIntegerOption(
      options.maxJobs,
      DEFAULT_MAX_JOBS,
      "maxJobs",
      1,
      10_000,
    );

    this.maxRunningJobs = readIntegerOption(
      options.maxRunningJobs,
      DEFAULT_MAX_RUNNING_JOBS,
      "maxRunningJobs",
      1,
      1_000,
    );

    if (
      this.maxRunningJobs >
      this.maxJobs
    ) {
      throw new JobManagerError(
        "INVALID_JOB_MANAGER_OPTION",
        500,
        "maxRunningJobs cannot exceed maxJobs",
      );
    }

    this.terminalRetentionMs =
      readIntegerOption(
        options.terminalRetentionMs,
        DEFAULT_TERMINAL_RETENTION_MS,
        "terminalRetentionMs",
        1_000,
        7 * 24 * 60 * 60_000,
      );

    this.activeJobTimeoutMs =
      readIntegerOption(
        options.activeJobTimeoutMs,
        DEFAULT_ACTIVE_JOB_TIMEOUT_MS,
        "activeJobTimeoutMs",
        1_000,
        24 * 60 * 60_000,
      );

    this.sweepIntervalMs =
      readIntegerOption(
        options.sweepIntervalMs,
        DEFAULT_SWEEP_INTERVAL_MS,
        "sweepIntervalMs",
        0,
        60 * 60_000,
      );

    this.nowProvider =
      options.now ?? Date.now;

    this.idFactory =
      options.idFactory ?? randomUUID;

    this.onInternalError =
      options.onInternalError;

    if (this.sweepIntervalMs > 0) {
      this.sweepTimer = setInterval(
        () => {
          if (this.closed) {
            return;
          }

          try {
            this.sweepAt(this.readNow());
          } catch {
            /*
             * Timer failures must not terminate the API process.
             * Public methods will retry cleanup on their next operation.
             */
          }
        },
        this.sweepIntervalMs,
      );

      /*
       * The cleanup timer must not keep Node.js alive during shutdown.
       */
      this.sweepTimer.unref();
    }
  }

  createJob(
    input: CreateJobInput,
  ): JobCreationResult {
    this.assertOpen();

    const now = this.readNow();
    this.sweepAt(now);

    assertJobKind(input.kind);
    assertRequestFingerprint(
      input.requestFingerprint,
    );

    let idempotencyToken:
      | string
      | undefined;

    if (input.idempotencyKey !== undefined) {
      assertValidIdempotencyKey(
        input.idempotencyKey,
      );

      idempotencyToken = sha256(
        `http-idempotency:${input.idempotencyKey}`,
      );

      const existingId =
        this.jobsByIdempotencyToken.get(
          idempotencyToken,
        );

      if (existingId !== undefined) {
        const existing =
          this.jobs.get(existingId);

        if (existing === undefined) {
          /*
           * Defensive repair for an impossible stale index.
           */
          this.jobsByIdempotencyToken.delete(
            idempotencyToken,
          );
        } else {
          const sameLogicalRequest =
            existing.kind === input.kind &&
            existing.requestFingerprint ===
              input.requestFingerprint;

          if (!sameLogicalRequest) {
            throw new JobManagerError(
              "IDEMPOTENCY_CONFLICT",
              409,
              "The Idempotency-Key is already associated with a different request",
            );
          }

          return Object.freeze({
            accepted:
              freezeAccepted(existing),
            current: freezeJob(existing),
            reused: true,
          });
        }
      }
    }

    if (this.jobs.size >= this.maxJobs) {
      throw new JobManagerError(
        "JOB_CAPACITY_REACHED",
        503,
        "The ingestion queue is temporarily at capacity",
      );
    }

    const ingestionId =
      this.createUniqueJobId();

    /*
     * The caller's raw key is not placed in HydraDB transaction metadata.
     * Both identities are deterministic, writer-compatible and redacted.
     */
    const persistenceSeed =
      idempotencyToken ??
      sha256(`job:${ingestionId}`);

    const persistenceIdempotencyKey =
      `hg-api-${persistenceSeed.slice(0, 40)}`;

    const correlationId =
      `hg-job-${sha256(ingestionId).slice(0, 32)}`;

    const record: StoredJob = {
      ingestionId,
      kind: input.kind,
      submittedAtMs: now,
      requestFingerprint:
        input.requestFingerprint,
      persistenceIdempotencyKey,
      correlationId,
      ...(idempotencyToken === undefined
        ? {}
        : { idempotencyToken }),

      status: "queued",
      version: 1,
      errors: [],
    };

    this.jobs.set(ingestionId, record);

    if (idempotencyToken !== undefined) {
      this.jobsByIdempotencyToken.set(
        idempotencyToken,
        ingestionId,
      );
    }

    return Object.freeze({
      accepted: freezeAccepted(record),
      current: freezeJob(record),
      reused: false,
    });
  }

  getJob(
    ingestionId: string,
  ): IngestionJob | null {
    this.assertOpen();

    this.sweepAt(this.readNow());

    const record =
      this.jobs.get(ingestionId);

    return record === undefined
      ? null
      : freezeJob(record);
  }

  getExecutionContext(
    ingestionId: string,
  ): JobExecutionContext {
    this.assertOpen();

    this.sweepAt(this.readNow());

    const record =
      this.requireJob(ingestionId);

    return Object.freeze({
      ingestionId: record.ingestionId,
      kind: record.kind,
      status: record.status,
      persistenceIdempotencyKey:
        record.persistenceIdempotencyKey,
      correlationId: record.correlationId,
      requestFingerprint:
        record.requestFingerprint,
      version: record.version,
    });
  }

  updateJob(
    ingestionId: string,
    update: JobUpdate,
  ): IngestionJob {
    this.assertOpen();

    const now = this.readNow();
    this.sweepAt(now);

    const record =
      this.requireJob(ingestionId);

    switch (update.status) {
      case "running":
        this.startJob(record, now);
        break;

      case "completed":
        this.assertRunning(record);

        assertNonnegativeCount(
          update.nodeCount,
          "nodeCount",
        );

        assertNonnegativeCount(
          update.edgeCount,
          "edgeCount",
        );

        record.nodeCount =
          update.nodeCount;

        record.edgeCount =
          update.edgeCount;

        record.errors = [];

        this.finishJob(
          record,
          "completed",
          now,
        );
        break;

      case "partially-completed": {
        this.assertRunning(record);

        assertNonnegativeCount(
          update.nodeCount,
          "nodeCount",
        );

        assertNonnegativeCount(
          update.edgeCount,
          "edgeCount",
        );

        if (update.errorCodes.length === 0) {
          throw new JobManagerError(
            "INVALID_JOB_RESULT",
            500,
            "A partially-completed job must include at least one safe error code",
          );
        }

        record.nodeCount =
          update.nodeCount;

        record.edgeCount =
          update.edgeCount;

        record.errors = [
          ...new Set(
            update.errorCodes.map(
              (code) =>
                SAFE_FAILURE_MESSAGES[code],
            ),
          ),
        ];

        this.finishJob(
          record,
          "partially-completed",
          now,
        );
        break;
      }

      case "failed":
        if (
          record.status !== "queued" &&
          record.status !== "running"
        ) {
          this.throwInvalidTransition(
            record,
            "failed",
          );
        }

        if (
          update.nodeCount !== undefined
        ) {
          assertNonnegativeCount(
            update.nodeCount,
            "nodeCount",
          );

          record.nodeCount =
            update.nodeCount;
        }

        if (
          update.edgeCount !== undefined
        ) {
          assertNonnegativeCount(
            update.edgeCount,
            "edgeCount",
          );

          record.edgeCount =
            update.edgeCount;
        }

        this.failJob(
          record,
          update.errorCode,
          update.cause,
          now,
        );
        break;
    }

    return freezeJob(record);
  }

  getStats(): JobManagerStats {
    this.assertOpen();

    this.sweepAt(this.readNow());

    let queued = 0;
    let running = 0;
    let completed = 0;
    let partiallyCompleted = 0;
    let failed = 0;

    for (const record of this.jobs.values()) {
      switch (record.status) {
        case "queued":
          queued += 1;
          break;

        case "running":
          running += 1;
          break;

        case "completed":
          completed += 1;
          break;

        case "partially-completed":
          partiallyCompleted += 1;
          break;

        case "failed":
          failed += 1;
          break;
      }
    }

    return Object.freeze({
      total: this.jobs.size,
      queued,
      running,
      completed,
      partiallyCompleted,
      failed,
      capacity: this.maxJobs,
      maxRunningJobs:
        this.maxRunningJobs,
    });
  }

  sweep(): JobSweepResult {
    this.assertOpen();
    return this.sweepAt(this.readNow());
  }

  /**
   * Stops automatic cleanup.
   *
   * The server shutdown hook should call this method. It does not terminate
   * or cancel worker promises; workers.ts owns worker lifecycle.
   */
  close(): void {
    if (this.closed) {
      return;
    }

    this.closed = true;

    if (this.sweepTimer !== undefined) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = undefined;
    }
  }

  private startJob(
    record: StoredJob,
    now: number,
  ): void {
    if (record.status !== "queued") {
      this.throwInvalidTransition(
        record,
        "running",
      );
    }

    if (
      this.countRunningJobs() >=
      this.maxRunningJobs
    ) {
      throw new JobManagerError(
        "JOB_CONCURRENCY_LIMIT",
        503,
        "The worker concurrency limit has been reached",
      );
    }

    record.status = "running";
    record.startedAtMs = now;
    record.version += 1;
  }

  private finishJob(
    record: StoredJob,
    status:
      | "completed"
      | "partially-completed",
    now: number,
  ): void {
    record.status = status;
    record.completedAtMs = now;
    record.expiresAtMs =
      now + this.terminalRetentionMs;
    record.version += 1;
  }

  private failJob(
    record: StoredJob,
    code: JobFailureCode,
    cause: unknown,
    now: number,
  ): void {
    const diagnosticId = randomUUID();

    record.status = "failed";
    record.completedAtMs = now;
    record.expiresAtMs =
      now + this.terminalRetentionMs;

    record.errors = [
      `${SAFE_FAILURE_MESSAGES[code]} ` +
        `Reference: ${diagnosticId}.`,
    ];

    record.version += 1;

    if (
      cause !== undefined &&
      this.onInternalError !== undefined
    ) {
      const event: JobInternalErrorEvent =
        Object.freeze({
          ingestionId:
            record.ingestionId,
          kind: record.kind,
          diagnosticId,
          code,
          occurredAt:
            new Date(now).toISOString(),
          cause,
        });

      try {
        this.onInternalError(event);
      } catch {
        /*
         * Logging failures must never overwrite the primary job outcome.
         */
      }
    }
  }

  private assertRunning(
    record: StoredJob,
  ): void {
    if (record.status !== "running") {
      this.throwInvalidTransition(
        record,
        "completed",
      );
    }
  }

  private throwInvalidTransition(
    record: StoredJob,
    nextStatus: IngestionJobStatus,
  ): never {
    throw new JobManagerError(
      "INVALID_JOB_TRANSITION",
      409,
      `Ingestion ${record.ingestionId} cannot transition ` +
        `from ${record.status} to ${nextStatus}`,
    );
  }

  private requireJob(
    ingestionId: string,
  ): StoredJob {
    const record =
      this.jobs.get(ingestionId);

    if (record === undefined) {
      throw new JobManagerError(
        "JOB_NOT_FOUND",
        404,
        "The requested ingestion job was not found",
      );
    }

    return record;
  }

  private countRunningJobs(): number {
    let running = 0;

    for (const record of this.jobs.values()) {
      if (record.status === "running") {
        running += 1;
      }
    }

    return running;
  }

  private createUniqueJobId(): string {
    for (
      let attempt = 0;
      attempt < 5;
      attempt += 1
    ) {
      const candidate =
        this.idFactory();

      if (
        !JOB_ID_PATTERN.test(candidate)
      ) {
        throw new JobManagerError(
          "JOB_ID_GENERATION_FAILED",
          500,
          "The job ID factory returned an unsafe identifier",
        );
      }

      if (!this.jobs.has(candidate)) {
        return candidate;
      }
    }

    throw new JobManagerError(
      "JOB_ID_GENERATION_FAILED",
      500,
      "A unique ingestion ID could not be generated",
    );
  }

  private sweepAt(
    now: number,
  ): JobSweepResult {
    let timedOut = 0;
    let removed = 0;

    /*
     * First fail stale active work. This prevents abandoned jobs from
     * consuming queue capacity forever.
     */
    for (const record of this.jobs.values()) {
      if (
        record.status !== "queued" &&
        record.status !== "running"
      ) {
        continue;
      }

      const activeSince =
        record.startedAtMs ??
        record.submittedAtMs;

      if (
        now - activeSince >=
        this.activeJobTimeoutMs
      ) {
        this.failJob(
          record,
          "JOB_TIMED_OUT",
          undefined,
          now,
        );

        timedOut += 1;
      }
    }

    /*
     * Remove expired terminal jobs and their idempotency index entries.
     */
    for (
      const [ingestionId, record]
      of this.jobs
    ) {
      if (
        !isTerminalStatus(
          record.status,
        ) ||
        record.expiresAtMs === undefined ||
        record.expiresAtMs > now
      ) {
        continue;
      }

      this.jobs.delete(ingestionId);

      if (
        record.idempotencyToken !==
        undefined &&
        this.jobsByIdempotencyToken.get(
          record.idempotencyToken,
        ) === ingestionId
      ) {
        this.jobsByIdempotencyToken.delete(
          record.idempotencyToken,
        );
      }

      removed += 1;
    }

    return Object.freeze({
      timedOut,
      removed,
    });
  }

  private readNow(): number {
    const value = this.nowProvider();

    if (
      !Number.isSafeInteger(value) ||
      value < 0 ||
      value > 8_640_000_000_000_000
    ) {
      throw new JobManagerError(
        "INVALID_JOB_MANAGER_OPTION",
        500,
        "The configured clock returned an invalid timestamp",
      );
    }

    return value;
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new JobManagerError(
        "JOB_MANAGER_CLOSED",
        503,
        "The ingestion job manager is shutting down",
      );
    }
  }
}
