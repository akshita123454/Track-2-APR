import cors from "@fastify/cors";

import Fastify from "fastify";

import neo4j from "neo4j-driver";

import type {
  Driver,
} from "neo4j-driver";
import {
  registerAnalysisSchemas,
} from "./schemas/analysis.js";
import type {
    LiveBlastRadiusRunner,
  } from "./routes/analysis.js";

import {
  registerAnalysisRoutes,
} from "./routes/analysis.js";

import {
  HydraPersistenceService,
} from "../db/persistence-service.js";

import {
  HydraIncidentService,
} from "../incidents/incident-service.js";

import {
  JobManager,
} from "./jobs/job-manager.js";

import {
  WorkerDispatcher,
} from "./jobs/worker-dispatcher.js";

import {
  registerCommonSchemas,
} from "./schemas/common.js";

import {
  registerErrorHandling,
} from "./errors.js";

import {
  registerHealthRoutes,
} from "./routes/health.js";

import {
  registerIngestionRoutes,
} from "./routes/ingestions.js";

import {
  registerIncidentRoutes,
} from "./routes/incidents.js";

import {
  loadApiConfig,
} from "./config.js";

import type {
  FastifyInstance,
} from "fastify";

import type {
  ApiConfig,
} from "./config.js";

import type {
  IncidentCreator,
} from "./routes/incidents.js";

export interface BuildServerOptions {
  readonly config?: ApiConfig;
  readonly driver?: Driver;
  
  
  readonly persistenceService?:
    HydraPersistenceService;

  readonly incidentCreator?:
    IncidentCreator;
  readonly analysisRunner?:
    LiveBlastRadiusRunner;

  /**
   * Injected drivers remain caller-owned by default.
   */
  readonly closeInjectedDriver?:
    boolean;
}

export interface HydraGuardServer {
  readonly app: FastifyInstance;
  readonly config: ApiConfig;
  readonly driver: Driver;
  readonly jobManager: JobManager;
  readonly dispatcher:
    WorkerDispatcher;
}

async function createDriver(
  config: ApiConfig,
): Promise<Driver> {
  return neo4j.driver(
    config.hydra.uri,
    neo4j.auth.basic(
      config.hydra.user,
      config.hydra.token,
    ),
  );
}

export async function buildServer(
  options:
    BuildServerOptions = {},
): Promise<HydraGuardServer> {
  const config =
    options.config ??
    loadApiConfig();

  const ownsDriver =
    options.driver ===
    undefined;

  const driver =
    options.driver ??
    await createDriver(config);

  const jobManager =
    new JobManager({
      ...config.jobs,

      onInternalError: (
        event,
      ) => {
        /*
         * Raw causes stay in private server logs.
         */
        console.error(
          "Ingestion job failure",
          event,
        );
      },
    });

  const dispatcher =
    new WorkerDispatcher(
      jobManager,
      {
        maxConcurrentJobs:
          config.workers
            .maxConcurrentJobs,

        onInternalError: (
          event,
        ) => {
          console.error(
            "Worker dispatcher failure",
            event,
          );
        },
      },
    );

  const persistence =
    options
      .persistenceService ??
    new HydraPersistenceService(
      driver,
    );

  const incidentCreator =
    options.incidentCreator ??
    new HydraIncidentService(
      driver,
      persistence,
      {
        maxVersionsScannedPerPackage:
          config.incidents
            .maxVersionsScannedPerPackage,

        affectedEdgeChunkSize:
          config.incidents
            .affectedEdgeChunkSize,

        statementTimeoutMs:
          config.incidents
            .statementTimeoutMs,

        persistenceOptions:
          config.persistence,
      },
    );

    const app =
    Fastify({
      /*
       * Test smoke runs should stay quiet. Development and production logging
       * remain controlled by API_LOGGING.
       */
      logger:
        config.environment ===
        "test"
          ? false
          : config.logging,

      bodyLimit:
        config.bodyLimitBytes,
    });


  registerCommonSchemas(app);
  registerAnalysisSchemas(app);
  registerErrorHandling(app);

  await app.register(
    cors,
    {
      origin:
        config.corsOrigins.includes(
          "*",
        )
          ? true
          : [
              ...config
                .corsOrigins,
            ],

      methods: [
        "GET",
        "POST",
        "OPTIONS",
      ],
    },
  );

  await app.register(
    registerHealthRoutes,
    {
      database: driver,
      jobManager,
      dispatcher,
      serviceName:
        "hydraguard-api",
      serviceVersion:
        "0.1.0",
    },
  );

  await app.register(
    registerIngestionRoutes,
    {
      jobManager,
      dispatcher,

      workerDependencies: {
        jobManager,
        persistence,

        npmRegistry: {
          registryUrl:
            config.npmRegistry
              .registryUrl,

          timeoutMs:
            config.npmRegistry
              .timeoutMs,

          retries:
            config.npmRegistry
              .retries,

          maxResponseBytes:
            config.npmRegistry
              .maxResponseBytes,
        },

        npmConcurrency:
          config.npmRegistry
            .concurrency,

        persistenceOptions:
          config.persistence,
      },
    },
  );

  await app.register(
    registerIncidentRoutes,
    {
      incidentCreator,
    },
  );
  await app.register(
    registerAnalysisRoutes,
    {
      driver,

      ...(options.analysisRunner ===
      undefined
        ? {}
        : {
            runAnalysis:
              options.analysisRunner,
          }),
    },
  );


  app.addHook(
    "onClose",
    async () => {
      await dispatcher.close({
        mode:
          "cancel-pending",
        abortRunning: true,
        reason:
          "HydraGuard API shutdown",
      });

      jobManager.close();

      if (
        ownsDriver ||
        options
          .closeInjectedDriver ===
          true
      ) {
        await driver.close();
      }
    },
  );

  return Object.freeze({
    app,
    config,
    driver,
    jobManager,
    dispatcher,
  });
}
