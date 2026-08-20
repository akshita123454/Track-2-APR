import type {
  FastifyInstance,
} from "fastify";

import {
  createRequestFingerprint,
} from "../jobs/job-manager.js";

import {
  createLockfileIngestionWorker,
  createNpmIngestionWorker,
} from "../jobs/workers.js";

import {
  CREATE_LOCKFILE_INGESTION_ROUTE_SCHEMA,
  CREATE_NPM_INGESTION_ROUTE_SCHEMA,
  GET_INGESTION_ROUTE_SCHEMA,
} from "../schemas/ingestions.js";

import type {
  IngestionKind,
  JobManager,
} from "../jobs/job-manager.js";

import type {
  WorkerDispatcher,
  WorkerTask,
} from "../jobs/worker-dispatcher.js";

import type {
  IngestionWorkerDependencies,
} from "../jobs/workers.js";

import type {
  IdempotencyHeaders,
  IngestionIdParams,
  LockfileIngestionRequestBody,
  NpmIngestionRequestBody,
} from "../schemas/ingestions.js";

export interface IngestionRoutesOptions {
  readonly jobManager: JobManager;

  readonly dispatcher:
    WorkerDispatcher;

  readonly workerDependencies:
    IngestionWorkerDependencies;
}

export interface CreateAndDispatchInput {
  readonly kind:
    IngestionKind;

  readonly requestBody: unknown;

  readonly idempotencyKey?:
    string;

  readonly createWorker:
    () => WorkerTask;
}

/**
 * If dispatch fails after JobManager has accepted a new job, fail that job
 * closed so it cannot remain queued forever.
 *
 * The original dispatch error is still rethrown for centralized HTTP error
 * handling.
 */
function failUndispatchedJob(
  jobManager: JobManager,
  ingestionId: string,
  cause: unknown,
): void {
  try {
    const current =
      jobManager.getJob(
        ingestionId,
      );

    if (
      current === null ||
      current.status !== "queued"
    ) {
      return;
    }

    jobManager.updateJob(
      ingestionId,
      {
        status: "failed",
        errorCode:
          "INTERNAL_JOB_ERROR",
        cause,
      },
    );
  } catch {
    /*
     * Preserve the dispatcher failure as the primary route error. The
     * centralized private logger should record that error.
     */
  }
}

export function createAndDispatch(
  options: IngestionRoutesOptions,
  input: CreateAndDispatchInput,
) {
  const requestFingerprint =
    createRequestFingerprint({
      operation:
        "create-ingestion",
      kind: input.kind,
      body: input.requestBody,
    });

  const creation =
    options.jobManager.createJob({
      kind: input.kind,
      requestFingerprint,

      ...(input.idempotencyKey ===
      undefined
        ? {}
        : {
            idempotencyKey:
              input.idempotencyKey,
          }),
    });

  /*
   * Replayed requests return the original acceptance response and must not
   * enqueue a duplicate worker. Current state remains available through GET.
   */
  if (creation.reused) {
    return creation.accepted;
  }

  try {
    options.dispatcher.enqueue(
      creation.accepted.ingestionId,
      input.createWorker(),
    );
  } catch (error: unknown) {
    failUndispatchedJob(
      options.jobManager,
      creation.accepted.ingestionId,
      error,
    );

    throw error;
  }

  return creation.accepted;
}

/**
 * Registers:
 *
 * POST /ingestions/npm
 * POST /ingestions/lockfile
 * GET  /ingestions/:ingestionId
 */
export async function registerIngestionRoutes(
  app: FastifyInstance,
  options: IngestionRoutesOptions,
): Promise<void> {
  /*
   * Workers must update the exact same JobManager instance used by routes and
   * the dispatcher. Failing at server construction is safer than discovering
   * this mismatch after accepting work.
   */
  if (
    options
      .workerDependencies
      .jobManager !==
    options.jobManager
  ) {
    throw new Error(
      "Ingestion routes and workers must share one JobManager instance",
    );
  }

  app.post<{
    Headers: IdempotencyHeaders;
    Body: NpmIngestionRequestBody;
  }>(
    "/ingestions/npm",
    {
      schema:
        CREATE_NPM_INGESTION_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const accepted =
        createAndDispatch(
          options,
          {
            kind: "npm",

            requestBody:
              request.body,

            idempotencyKey:
              request.headers[
                "idempotency-key"
              ],

            createWorker: () =>
              createNpmIngestionWorker(
                request.body,
                options
                  .workerDependencies,
              ),
          },
        );

      return reply
        .code(202)
        .send(accepted);
    },
  );

  app.post<{
    Headers: IdempotencyHeaders;
    Body:
      LockfileIngestionRequestBody;
  }>(
    "/ingestions/lockfile",
    {
      schema:
        CREATE_LOCKFILE_INGESTION_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const accepted =
        createAndDispatch(
          options,
          {
            kind: "lockfile",

            requestBody:
              request.body,

            idempotencyKey:
              request.headers[
                "idempotency-key"
              ],

            createWorker: () =>
              createLockfileIngestionWorker(
                request.body,
                options
                  .workerDependencies,
              ),
          },
        );

      return reply
        .code(202)
        .send(accepted);
    },
  );

  app.get<{
    Params: IngestionIdParams;
  }>(
    "/ingestions/:ingestionId",
    {
      schema:
        GET_INGESTION_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const job =
        options.jobManager.getJob(
          request.params
            .ingestionId,
        );

      if (job === null) {
        return reply
          .code(404)
          .send({
            code:
              "INGESTION_NOT_FOUND",

            message:
              "The requested ingestion job was not found.",
          });
      }

      return reply
        .code(200)
        .send(job);
    },
  );
}