import assert from "node:assert/strict";

import type {
  Driver,
} from "neo4j-driver";

import type {
  HydraPersistenceService,
} from "../db/persistence-service.js";

import type {
  IncidentCreator,
} from "./routes/incidents.js";

import {
  loadApiConfig,
} from "./config.js";

import {
  buildServer,
} from "./server.js";

const fakeDriver = {
  verifyConnectivity:
    async () => ({
      address: "smoke",
      agent: "smoke",
      protocolVersion: 1,
    }),

  close:
    async () => undefined,

  session: () => {
    throw new Error(
      "Smoke driver session must not be used",
    );
  },
} as unknown as Driver;

const fakePersistence = {
  persist: async () =>
    Object.freeze({}),
} as unknown as
  HydraPersistenceService;

const fakeIncidentCreator:
  IncidentCreator = {
    createIncident:
      async () =>
        Object.freeze({
          incidentId: 123,
          logicalId:
            "incident:server-smoke",
          status:
            "active" as const,
        }),
  };

async function main(): Promise<void> {
  const config =
    loadApiConfig({
      NODE_ENV: "test",
      API_LOGGING: "false",
      API_HOST: "127.0.0.1",
      API_PORT: "3000",
      HYDRADB_URI:
        "bolt://localhost:7687",
      HYDRADB_USER: "neo4j",
      HYDRADB_TOKEN:
        "server-smoke-token",
    });

  const runtime =
    await buildServer({
      config,
      driver: fakeDriver,
      persistenceService:
        fakePersistence,
      incidentCreator:
        fakeIncidentCreator,
    });

  const health =
    await runtime.app.inject({
      method: "GET",
      url: "/health",
    });

  assert.equal(
    health.statusCode,
    200,
  );

  assert.equal(
    health.json().status,
    "ok",
  );

  const ready =
    await runtime.app.inject({
      method: "GET",
      url: "/ready",
    });

  assert.equal(
    ready.statusCode,
    200,
  );

  assert.equal(
    ready.json().status,
    "ready",
  );

  const invalidNpm =
    await runtime.app.inject({
      method: "POST",
      url: "/ingestions/npm",
      payload: {
        roots: [],
        maxPackages: 100,
        maxDepth: 3,
      },
    });

  assert.equal(
    invalidNpm.statusCode,
    400,
  );

  assert.equal(
    invalidNpm.json().code,
    "REQUEST_VALIDATION_FAILED",
  );

  const missingJob =
    await runtime.app.inject({
      method: "GET",
      url:
        "/ingestions/missing-job-0001",
    });

  assert.equal(
    missingJob.statusCode,
    404,
  );

  const incident =
    await runtime.app.inject({
      method: "POST",
      url: "/incidents",
      headers: {
        "idempotency-key":
          "server-smoke-incident-001",
      },
      payload: {
        title:
          "Synthetic server smoke incident",

        intervalStart:
          "2026-08-15T12:00:00.000Z",

        affectedReleases: [
          {
            packageName:
              "bad-lib",
            exactVersions: [
              "1.2.4",
            ],
          },
        ],

        provenance: {
          sourceType:
            "synthetic-fixture",
          sourceUri:
            "https://example.test/server-smoke",
          observedAt:
            "2026-08-15T12:05:00.000Z",
          collectorVersion:
            "server-smoke-1",
          confidence: 1,
          synthetic: true,
        },
      },
    });

  assert.equal(
    incident.statusCode,
    201,
  );

  assert.deepEqual(
    incident.json(),
    {
      incidentId: 123,
      logicalId:
        "incident:server-smoke",
      status: "active",
    },
  );

  const unknown =
    await runtime.app.inject({
      method: "GET",
      url: "/unknown",
    });

  assert.equal(
    unknown.statusCode,
    404,
  );

  assert.equal(
    unknown.json().code,
    "ROUTE_NOT_FOUND",
  );

  await runtime.app.close();

  assert.equal(
    runtime.dispatcher
      .getStats()
      .state,
    "closed",
  );

  console.log(
    "HydraGuard API server smoke passed",
  );
}

await main();
