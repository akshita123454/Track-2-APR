import type {
  FastifyInstance,
} from "fastify";

import type {
  Driver,
} from "neo4j-driver";

import type {
  JobManager,
} from "../jobs/job-manager.js";

import type {
  WorkerDispatcher,
} from "../jobs/worker-dispatcher.js";

export interface HealthRoutesOptions {
  readonly database: Pick<
    Driver,
    "session"
  >;

  readonly jobManager: JobManager;

  readonly dispatcher:
    WorkerDispatcher;

  readonly serviceName?: string;
  readonly serviceVersion?: string;

  /**
   * Maximum time readiness waits for HydraDB connectivity.
   *
   * Defaults to three seconds.
   */
  readonly databaseTimeoutMs?: number;

  /**
   * Test seam for deterministic server-smoke timestamps.
   */
  readonly now?: () => number;
}

const DEFAULT_DATABASE_TIMEOUT_MS =
  3_000;

const HEALTH_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,

  required: [
    "status",
    "service",
    "version",
    "timestamp",
    "uptimeSeconds",
    "database",
    "jobs",
    "workers",
  ],

  properties: {
    status: {
      type: "string",
      enum: [
        "ok",
        "ready",
        "not-ready",
      ],
    },

    service: {
      type: "string",
      minLength: 1,
      maxLength: 128,
    },

    version: {
      type: "string",
      minLength: 1,
      maxLength: 64,
    },

    timestamp: {
      type: "string",
      format: "date-time",
    },

    uptimeSeconds: {
      type: "number",
      minimum: 0,
    },

    database: {
      type: "string",
      enum: [
        "not-checked",
        "available",
        "unavailable",
      ],
    },

    jobs: {
      type: "object",
      additionalProperties: false,

      required: [
        "total",
        "queued",
        "running",
        "completed",
        "partiallyCompleted",
        "failed",
        "capacity",
      ],

      properties: {
        total: {
          type: "integer",
          minimum: 0,
        },

        queued: {
          type: "integer",
          minimum: 0,
        },

        running: {
          type: "integer",
          minimum: 0,
        },

        completed: {
          type: "integer",
          minimum: 0,
        },

        partiallyCompleted: {
          type: "integer",
          minimum: 0,
        },

        failed: {
          type: "integer",
          minimum: 0,
        },

        capacity: {
          type: "integer",
          minimum: 1,
        },
      },
    },

    workers: {
      type: "object",
      additionalProperties: false,

      required: [
        "state",
        "pending",
        "running",
        "active",
        "maxConcurrentJobs",
      ],

      properties: {
        state: {
          type: "string",
          enum: [
            "accepting",
            "draining",
            "cancelling",
            "closed",
          ],
        },

        pending: {
          type: "integer",
          minimum: 0,
        },

        running: {
          type: "integer",
          minimum: 0,
        },

        active: {
          type: "integer",
          minimum: 0,
        },

        maxConcurrentJobs: {
          type: "integer",
          minimum: 1,
        },
      },
    },
  },
} as const;

const HEALTH_ROUTE_SCHEMA = {
  response: {
    200: HEALTH_RESPONSE_SCHEMA,
  },
} as const;

const READINESS_ROUTE_SCHEMA = {
  response: {
    200: HEALTH_RESPONSE_SCHEMA,
    503: HEALTH_RESPONSE_SCHEMA,
  },
} as const;

function readTimestamp(
  nowProvider: () => number,
): string {
  const timestamp = nowProvider();

  if (
    !Number.isSafeInteger(timestamp) ||
    timestamp < 0 ||
    timestamp >
      8_640_000_000_000_000
  ) {
    throw new Error(
      "The health-check clock returned an invalid timestamp",
    );
  }

  return new Date(
    timestamp,
  ).toISOString();
}

async function checkDatabase(
  database: Pick<Driver, "session">,
  timeoutMs: number,
): Promise<boolean> {
  const session =
    database.session();

  try {
    /*
     * The label is required: HydraDB cannot execute an unlabelled full scan,
     * so a bare MATCH (n) would report the database as unavailable even when
     * it is healthy.
     */
    await session.run(
      "MATCH (n:Evidence) RETURN n.id AS id LIMIT 1",
      {},
      {
        timeout: timeoutMs,
      },
    );

    return true;
  } catch {
    return false;
  } finally {
    await session.close();
  }
}

function createHealthSnapshot(
  options: HealthRoutesOptions,
  status:
    | "ok"
    | "ready"
    | "not-ready",
  database:
    | "not-checked"
    | "available"
    | "unavailable",
) {
  const jobStats =
    options.jobManager.getStats();

  const workerStats =
    options.dispatcher.getStats();

  return {
    status,

    service:
      options.serviceName ??
      "hydraguard-api",

    version:
      options.serviceVersion ??
      "0.1.0",

    timestamp:
      readTimestamp(
        options.now ?? Date.now,
      ),

    uptimeSeconds:
      Math.max(
        0,
        process.uptime(),
      ),

    database,

    jobs: {
      total: jobStats.total,
      queued: jobStats.queued,
      running: jobStats.running,
      completed: jobStats.completed,
      partiallyCompleted:
        jobStats.partiallyCompleted,
      failed: jobStats.failed,
      capacity: jobStats.capacity,
    },

    workers: {
      state: workerStats.state,
      pending: workerStats.pending,
      running: workerStats.running,
      active: workerStats.active,
      maxConcurrentJobs:
        workerStats.maxConcurrentJobs,
    },
  };
}

/**
 * Registers:
 *
 * GET /health
 *   Process liveness. Does not contact HydraDB.
 *
 * GET /ready
 *   Traffic readiness. Requires HydraDB connectivity and an accepting worker
 *   dispatcher.
 */
export async function registerHealthRoutes(
  app: FastifyInstance,
  options: HealthRoutesOptions,
): Promise<void> {
  const databaseTimeoutMs =
    options.databaseTimeoutMs ??
    DEFAULT_DATABASE_TIMEOUT_MS;

  if (
    !Number.isSafeInteger(
      databaseTimeoutMs,
    ) ||
    databaseTimeoutMs < 100 ||
    databaseTimeoutMs > 30_000
  ) {
    throw new Error(
      "databaseTimeoutMs must be an integer between 100 and 30000",
    );
  }

  app.get(
    "/health",
    {
      schema:
        HEALTH_ROUTE_SCHEMA,
    },
    async (_request, reply) => {
      return reply.code(200).send(
        createHealthSnapshot(
          options,
          "ok",
          "not-checked",
        ),
      );
    },
  );

  app.get(
    "/ready",
    {
      schema:
        READINESS_ROUTE_SCHEMA,
    },
    async (_request, reply) => {
      const databaseAvailable =
        await checkDatabase(
          options.database,
          databaseTimeoutMs,
        );

      const workerState =
        options.dispatcher
          .getStats()
          .state;

      const ready =
        databaseAvailable &&
        workerState === "accepting";

      return reply
        .code(ready ? 200 : 503)
        .send(
          createHealthSnapshot(
            options,
            ready
              ? "ready"
              : "not-ready",
            databaseAvailable
              ? "available"
              : "unavailable",
          ),
        );
    },
  );
}
