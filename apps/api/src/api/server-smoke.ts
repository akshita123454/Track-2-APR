import assert from "node:assert/strict";

import type {
  Driver,
} from "neo4j-driver";
import type {
  LiveBlastRadiusRunner,
  PersistedReleaseFirewallRunner,
} from "./routes/analysis.js";

import {
  ReleaseInfluenceStoreError,
} from "../analysis/release-trust/hydra-release-influence-store.js";

import {
  HydraGraphReaderError,
} from "../analysis/readers/hydra-graph-reader.js";

import type {
  HydraPersistenceService,
} from "../db/persistence-service.js";

import type {
  IncidentCreator,
} from "./routes/incidents.js";

import type {
  TyposquattingService,
} from "../typosquatting/service.js";

import {
  loadApiConfig,
} from "./config.js";

import {
  buildServer,
} from "./server.js";

const fakeDriver = {
  close:
    async () => undefined,

  session: () => ({
    run: async () => ({
      records: [],
    }),

    close: async () =>
      undefined,
  }),
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
const fakeFinding = Object.freeze({
  id: 321,
  logicalId:
    "finding:typosquatting:server-smoke",
  kind: "Finding" as const,
  evidenceIds: [654],
  synthetic: false,
  observedAt: 1_700_000_000_000,
  findingType: "typosquatting" as const,
  status: "suspicious" as const,
  score: 72,
  detectorVersion: "detector-v1",
  policyVersion: "policy-v1",
  corpusId: "corpus-v1",
  comparisonVersion: "comparison-v1",
  indexVersion: "index-v1",
  candidatePackageName: "lodahs",
  targetPackageName: "lodash",
  summary: "Heuristic lockfile-backed name similarity finding.",
  transformations: ["adjacent-transposition" as const],
  reasonCodes: ["EXPOSURE_LOCKFILE"],
  detectedAt: 1_700_000_000_000,
});

const reviewCommands: Array<{
  readonly action: "dismiss" | "promote";
  readonly reviewer: string;
}> = [];

const fakeTyposquattingService = {
  listFindings: async () => ({
    findings: [fakeFinding],
    truncated: false,
  }),
  getFindingDetail: async () => ({
    finding: fakeFinding,
    candidate: {
      id: 111,
      logicalId: "pkg:npm:lodahs",
      kind: "Package" as const,
      evidenceIds: [654],
      synthetic: false,
      observedAt: 1_700_000_000_000,
      ecosystem: "npm" as const,
      name: "lodahs",
    },
    target: {
      id: 112,
      logicalId: "pkg:npm:lodash",
      kind: "Package" as const,
      evidenceIds: [655],
      synthetic: false,
      observedAt: 1_700_000_000_000,
      ecosystem: "npm" as const,
      name: "lodash",
    },
    evidence: [{
      id: 654,
      logicalId: "evidence:server-smoke-typo",
      kind: "Evidence" as const,
      evidenceIds: [] as const,
      synthetic: false,
      observedAt: 1_700_000_000_000,
      sourceType: "package-lock" as const,
      sourceUri: "fixture://private-source-must-not-leak",
      collectorVersion: "fixture-v1",
      confidence: 1,
      detail: "private-detail-must-not-leak",
    }],
    exactVersions: {
      versions: [{
        id: 113,
        logicalId: "pkgver:npm:lodahs@1.0.0",
        kind: "PackageVersion" as const,
        evidenceIds: [654],
        synthetic: false,
        observedAt: 1_700_000_000_000,
        ecosystem: "npm" as const,
        packageName: "lodahs",
        version: "1.0.0",
      }],
      scannedCount: 1,
      truncated: false,
    },
    exposure: {
      services: [{
        serviceId: 114,
        serviceLogicalId: "service:server-smoke",
        serviceName: "server-smoke",
        serviceCriticality: "high" as const,
        packageVersionIds: [113],
        evidenceIds: [654],
      }],
      truncated: false,
      traversalStates: 1,
      limits: {
        maxDepth: 12,
        maxServices: 100,
        maxTraversalStates: 2_000,
        maxDependentsPerNode: 250,
      },
    },
    incidentIds: [],
  }),
  reviewFinding: async (command: {
    readonly action: "dismiss" | "promote";
    readonly reviewer: string;
  }) => {
    reviewCommands.push(command);
    return ({
      finding: {
        ...fakeFinding,
        status: command.action === "dismiss" ? "dismissed" as const : "confirmed" as const,
        decidedAt: 1_700_000_001_000,
        decisionReason: "Reviewed in server smoke",
      },
      ...(command.action === "promote" ? { incidentId: 999 } : {}),
      replayed: false,
    });
  },
  scanLockfile: async () => ({
    sourceFingerprint: "0".repeat(64),
    corpusId: "corpus-v1",
    packageCount: 0,
    findingCount: 0,
    findingIds: [],
    diagnostics: {},
  }),
} as unknown as TyposquattingService;

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

        serviceImpacts: [],

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

const fakeReleaseFirewallRunner:
  PersistedReleaseFirewallRunner =
    async (_reader, snapshotId) => {
      switch (snapshotId) {
        case "missing-snapshot":
          throw new ReleaseInfluenceStoreError(
            "SNAPSHOT_NOT_FOUND",
            "Private missing snapshot detail",
          );

        case "writing-snapshot":
          throw new ReleaseInfluenceStoreError(
            "SNAPSHOT_NOT_READY",
            "Private writing snapshot detail",
          );

        case "database-unavailable":
          throw new ReleaseInfluenceStoreError(
            "DATABASE_QUERY_FAILED",
            "Private database failure detail",
          );

        case "corrupt-snapshot":
          throw new ReleaseInfluenceStoreError(
            "SNAPSHOT_CORRUPT",
            "Private corrupt graph detail",
          );
      }

      return {
        snapshotId,
        persistedAt: 1_700_000_000_000,
        firewall: {
          decisions: [
            {
              releaseNodeId: 7,
              subject: {
                ecosystem: "npm",
                packageName: "@example/router",
                version: "1.0.0",
                artifactDigest: "sha256:fixture",
              },
              verdict: "block",
              reason:
                "An untrusted workflow crossed a cache boundary.",
              findings: [
                {
                  code: "cross-boundary-cache",
                  severity: "block",
                  message:
                    "Untrusted cache influence reached the release workflow.",
                  nodeId: 3,
                  edgeId: 103,
                  pathKey: "1>2>3>4>6>7",
                },
              ],
              riskPaths: [
                {
                  pathKey: "1>2>3>4>6>7",
                  nodeIds: [1, 2, 3, 4, 6, 7],
                  edgeIds: [101, 102, 103, 105, 106],
                  depth: 5,
                },
              ],
              truncated: false,
              inspectedNodeCount: 7,
              inspectedEdgeCount: 7,
            },
          ],
          summary: {
            evaluated: 1,
            allowed: 0,
            quarantined: 0,
            blocked: 1,
            truncated: 0,
          },
          options: {
            maxDepth: 16,
            maxTraversalStatesPerRelease: 10_000,
            maxIncomingEdgesPerNode: 1_000,
            maxRiskPathsPerRelease: 100,
            maxFindingsPerRelease: 250,
            requireEvidence: true,
            untrustedDisposition: "block",
            unknownDisposition: "quarantine",
            crossBoundaryCacheDisposition: "block",
            unknownCacheBoundaryDisposition: "quarantine",
          },
        },
        consistencyModel:
          "verified-release-influence-snapshot",
        engine: "HydraDB",
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
      TYPOSQUATTING_ANALYST_BEARER_TOKEN:
        "server-smoke-analyst-token",
      TYPOSQUATTING_ANALYST_PRINCIPAL:
        "server-smoke-trusted-analyst",
    });

  const runtime =
    await buildServer({
      config,
      driver: fakeDriver,
      persistenceService:
        fakePersistence,
      incidentCreator:
        fakeIncidentCreator,
      typosquattingService:
        fakeTyposquattingService,
      analysisRunner:
        fakeAnalysisRunner,
      releaseFirewallRunner:
        fakeReleaseFirewallRunner,

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

  assert.deepEqual(
    analysisBody.serviceImpacts,
    [],
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

  const findings =
    await runtime.app.inject({
      method: "GET",
      url: "/typosquatting/findings?limit=10",
    });

  assert.equal(findings.statusCode, 200);
  assert.equal(findings.json().findings[0].findingId, 321);
  assert.equal(findings.json().findings[0].scoreMeaning, "heuristic-ranking-not-probability");

  const invalidCursor =
    await runtime.app.inject({
      method: "GET",
      url: "/typosquatting/findings?cursorDetectedAt=1",
    });

  assert.equal(invalidCursor.statusCode, 400);
  assert.equal(invalidCursor.json().code, "INVALID_FINDING_CURSOR");

  const findingDetail =
    await runtime.app.inject({
      method: "GET",
      url: "/typosquatting/findings/321",
    });

  assert.equal(findingDetail.statusCode, 200);
  assert.equal(findingDetail.json().exactVersions[0].version, "1.0.0");
  assert.equal(findingDetail.json().exposure.services[0].serviceName, "server-smoke");
  const serializedFinding = JSON.stringify(findingDetail.json());
  assert.equal(serializedFinding.includes("private-source-must-not-leak"), false);
  assert.equal(serializedFinding.includes("private-detail-must-not-leak"), false);

  const missingReviewKey =
    await runtime.app.inject({
      method: "POST",
      url: "/typosquatting/findings/321/dismiss",
      payload: {
        reason: "Reviewed fixture",
      },
    });

  assert.equal(missingReviewKey.statusCode, 400);

  const unauthorizedPromotion =
    await runtime.app.inject({
      method: "POST",
      url: "/typosquatting/findings/321/promote",
      headers: {
        "idempotency-key": "server-smoke-unauthorized-001",
      },
      payload: {
        reason: "Untrusted confirmation attempt",
      },
    });

  assert.equal(unauthorizedPromotion.statusCode, 401);
  assert.equal(
    unauthorizedPromotion.json().code,
    "ANALYST_AUTHENTICATION_REQUIRED",
  );
  assert.equal(
    unauthorizedPromotion.headers["www-authenticate"],
    'Bearer realm="hydraguard-analyst"',
  );

  const dismissed =
    await runtime.app.inject({
      method: "POST",
      url: "/typosquatting/findings/321/dismiss",
      headers: {
        authorization: "Bearer server-smoke-analyst-token",
        "idempotency-key": "server-smoke-dismiss-001",
      },
      payload: {
        reason: "Reviewed fixture",
      },
    });

  assert.equal(dismissed.statusCode, 200);
  assert.equal(dismissed.json().finding.status, "dismissed");

  const promoted =
    await runtime.app.inject({
      method: "POST",
      url: "/typosquatting/findings/321/promote",
      headers: {
        authorization: "Bearer server-smoke-analyst-token",
        "idempotency-key": "server-smoke-promote-001",
      },
      payload: {
        reason: "Confirmed fixture",
      },
    });

  assert.equal(promoted.statusCode, 200);
  assert.equal(promoted.json().finding.status, "confirmed");
  assert.equal(promoted.json().incidentId, 999);
  assert.deepEqual(
    reviewCommands.map((command) => command.reviewer),
    [
      "server-smoke-trusted-analyst",
      "server-smoke-trusted-analyst",
    ],
  );

  const releaseFirewall =
    await runtime.app.inject({
      method: "GET",
      url:
        "/release-influence/snapshots/tanstack-style-demo/firewall",
    });

  assert.equal(
    releaseFirewall.statusCode,
    200,
  );

  const releaseFirewallBody =
    releaseFirewall.json();

  assert.equal(
    releaseFirewallBody.snapshotId,
    "tanstack-style-demo",
  );
  assert.equal(
    releaseFirewallBody.engine,
    "HydraDB",
  );
  assert.equal(
    releaseFirewallBody.consistencyModel,
    "verified-release-influence-snapshot",
  );
  assert.equal(
    releaseFirewallBody.firewall.summary.blocked,
    1,
  );
  assert.equal(
    releaseFirewallBody.firewall.decisions[0].verdict,
    "block",
  );
  assert.equal(
    releaseFirewallBody.firewall.decisions[0]
      .findings[0].code,
    "cross-boundary-cache",
  );

  const invalidReleaseSnapshot =
    await runtime.app.inject({
      method: "GET",
      url:
        "/release-influence/snapshots/bad$id/firewall",
    });

  assert.equal(
    invalidReleaseSnapshot.statusCode,
    400,
  );
  assert.equal(
    invalidReleaseSnapshot.json().code,
    "REQUEST_VALIDATION_FAILED",
  );

  const missingReleaseSnapshot =
    await runtime.app.inject({
      method: "GET",
      url:
        "/release-influence/snapshots/missing-snapshot/firewall",
    });

  assert.equal(
    missingReleaseSnapshot.statusCode,
    404,
  );
  assert.deepEqual(
    missingReleaseSnapshot.json(),
    {
      code:
        "RELEASE_INFLUENCE_SNAPSHOT_NOT_FOUND",
      message:
        "The requested release-influence snapshot was not found.",
    },
  );
  assert.equal(
    JSON.stringify(
      missingReleaseSnapshot.json(),
    ).includes(
      "Private missing snapshot detail",
    ),
    false,
  );

  const writingReleaseSnapshot =
    await runtime.app.inject({
      method: "GET",
      url:
        "/release-influence/snapshots/writing-snapshot/firewall",
    });

  assert.equal(
    writingReleaseSnapshot.statusCode,
    409,
  );
  assert.equal(
    writingReleaseSnapshot.json().code,
    "RELEASE_INFLUENCE_SNAPSHOT_NOT_READY",
  );

  const unavailableReleaseSnapshot =
    await runtime.app.inject({
      method: "GET",
      url:
        "/release-influence/snapshots/database-unavailable/firewall",
    });

  assert.equal(
    unavailableReleaseSnapshot.statusCode,
    503,
  );
  assert.equal(
    unavailableReleaseSnapshot.json().code,
    "RELEASE_FIREWALL_DATABASE_UNAVAILABLE",
  );

  const corruptReleaseSnapshot =
    await runtime.app.inject({
      method: "GET",
      url:
        "/release-influence/snapshots/corrupt-snapshot/firewall",
    });

  assert.equal(
    corruptReleaseSnapshot.statusCode,
    503,
  );
  assert.equal(
    corruptReleaseSnapshot.json().code,
    "RELEASE_FIREWALL_DATA_UNAVAILABLE",
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
