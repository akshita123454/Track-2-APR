import assert from "node:assert/strict";

import type {
  Driver,
} from "neo4j-driver";
import type {
  LiveBlastRadiusRunner,
} from "./routes/analysis.js";

import {
  HydraGraphReaderError,
} from "../analysis/readers/hydra-graph-reader.js";

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
const unsafeEvidenceEntry = {
  id: 789,
  sourceType:
    "synthetic-fixture" as const,
  confidence: 0.96,
  observedAt:
    1_700_000_000_000,
  synthetic: true,
  incidentLinked: true,

  /*
   * These fields intentionally test response-schema redaction.
   */
  sourceUri:
    "fixture://must-not-leak",
  detail:
    "must-not-leak",
  collectorVersion:
    "must-not-leak",
};

const fakeAnalysisRunner:
  LiveBlastRadiusRunner =
    async (
      _driver,
      incidentId,
      options,
    ) => {
      if (incidentId === 999) {
        throw new HydraGraphReaderError(
          "INCIDENT_NOT_FOUND",
          "Private database lookup detail",
        );
      }

      return {
        incidentId,

        incident: {
          id: incidentId,
          title:
            "Synthetic server analysis incident",
          status: "active",
          intervalStart:
            1_700_000_000_000,
          intervalEnd: null,
          synthetic: true,
        },

        affectedVersions: [
          {
            id: 456,
            packageName:
              "poisoned-demo-lib",
            version: "1.2.4",
            synthetic: true,
          },
        ],

        evidenceCatalog: [
          unsafeEvidenceEntry,
        ],

        affectedVersionLookup: {
          limit:
            options
              ?.maxAffectedVersions ??
            1_000,
          returnedCount: 1,
          truncated: false,
        },

        affectedVersionIds: [
          456,
        ],

        services: [],
        totalPathCount: 0,
        truncated: false,

        limits: {
          maxDepth:
            options
              ?.blastRadius
              ?.maxDepth ??
            12,

          maxServices:
            options
              ?.blastRadius
              ?.maxServices ??
            100,

          maxPathsPerService:
            options
              ?.blastRadius
              ?.maxPathsPerService ??
            10,

          maxTotalPaths:
            options
              ?.blastRadius
              ?.maxTotalPaths ??
            1_000,

          maxTraversalStates:
            options
              ?.blastRadius
              ?.maxTraversalStates ??
            10_000,

          maxDependentsPerNode:
            options
              ?.blastRadius
              ?.maxDependentsPerNode ??
            1_000,

          maxWarnings:
            options
              ?.blastRadius
              ?.maxWarnings ??
            100,
        },

        warnings: [],

        evidenceFunnel: {
          affectedVersionCount: 1,
          candidatePathCount: 0,
          candidateServiceCount: 0,
          highConfidenceThreshold: 0.8,

          stages: [
            {
              id:
                "structural-candidate",
              label:
                "Structural candidates",
              description:
                "No candidate paths were returned.",
              pathCount: 0,
              serviceCount: 0,
              pathPercentage: 0,
              servicePercentage: 0,
            },
            {
              id:
                "evidence-verified",
              label:
                "Evidence verified",
              description:
                "No candidate paths were returned.",
              pathCount: 0,
              serviceCount: 0,
              pathPercentage: 0,
              servicePercentage: 0,
            },
            {
              id:
                "high-confidence-evidence",
              label:
                "High confidence",
              description:
                "No candidate paths were returned.",
              pathCount: 0,
              serviceCount: 0,
              pathPercentage: 0,
              servicePercentage: 0,
            },
          ],

          evidenceLookup: {
            referencedEvidenceCount: 0,
            requestedEvidenceCount: 0,
            resolvedEvidenceCount: 0,
            missingEvidenceCount: 0,
            missingEvidenceIds: [],
            omittedEvidenceCount: 0,
            complete: true,
          },

          sources: [],
          completeForReturnedCandidates: true,
          completeForIncident: true,

          limitations: [
            "Dependency evidence does not prove runtime execution.",
          ],
        },

        hydraRead: {
          readEpoch:
            "2023-11-14T22:13:20.000Z",
          readEpochMs:
            1_700_000_000_000,
          queryCount: 4,
          rowsRead: 4,
          startedAt:
            "2023-11-14T22:13:20.000Z",
          completedAt:
            "2023-11-14T22:13:20.012Z",
          latencyMs: 12,
          consistencyModel:
            "bounded-multi-statement-read",
          engine: "HydraDB",
        },
      };
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
      analysisRunner:
        fakeAnalysisRunner,

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
  const analysis =
    await runtime.app.inject({
      method: "GET",
      url:
        "/incidents/123/blast-radius?maxDepth=4",
    });

  assert.equal(
    analysis.statusCode,
    200,
  );

  const analysisBody =
    analysis.json();

  assert.equal(
    analysisBody.incident.id,
    123,
  );

  assert.equal(
    analysisBody.incident.title,
    "Synthetic server analysis incident",
  );

  assert.equal(
    analysisBody.affectedVersions[0]
      .packageName,
    "poisoned-demo-lib",
  );

  assert.equal(
    analysisBody.hydraRead.engine,
    "HydraDB",
  );

  assert.equal(
    analysisBody.limits.maxDepth,
    4,
  );

  const evidence =
    analysisBody.evidenceCatalog[0];

  assert.ok(
    evidence,
    "Analysis response must contain the synthetic evidence entry",
  );

  assert.equal(
    "sourceUri" in evidence,
    false,
  );

  assert.equal(
    "detail" in evidence,
    false,
  );

  assert.equal(
    "collectorVersion" in evidence,
    false,
  );

  const serializedAnalysis =
    JSON.stringify(
      analysisBody,
    );

  assert.equal(
    serializedAnalysis.includes(
      "fixture://must-not-leak",
    ),
    false,
  );

  assert.equal(
    serializedAnalysis.includes(
      "must-not-leak",
    ),
    false,
  );
  const invalidAnalysis =
  await runtime.app.inject({
    method: "GET",
    url:
      "/incidents/123/blast-radius?maxDepth=0",
  });

assert.equal(
  invalidAnalysis.statusCode,
  400,
);

assert.equal(
  invalidAnalysis.json().code,
  "REQUEST_VALIDATION_FAILED",
);
  const missingAnalysis =
  await runtime.app.inject({
    method: "GET",
    url:
      "/incidents/999/blast-radius",
  });

assert.equal(
  missingAnalysis.statusCode,
  404,
);

assert.deepEqual(
  missingAnalysis.json(),
  {
    code:
      "INCIDENT_NOT_FOUND",
    message:
      "The requested incident was not found.",
  },
);

assert.equal(
  JSON.stringify(
    missingAnalysis.json(),
  ).includes(
    "Private database lookup detail",
  ),
  false,
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
