import { pathToFileURL } from "node:url";

import type { Driver } from "neo4j-driver";

import { createHydraDriver } from "../hydra-client.js";
import { generateFixture } from "../domain/fixture.js";
import type { GraphEdge, GraphNode } from "../domain/schema.js";
import { mergeGraphFragments } from "../ingest/graph-batch.js";
import type { GraphBatch } from "../ingest/graph-batch.js";
import {
  HydraPersistenceService,
  PersistenceServiceError,
} from "../db/persistence-service.js";
import type { PersistedGraphBatch } from "../db/persistence-service.js";
import { HydraIncidentService } from "../incidents/incident-service.js";
import { createRequestFingerprint } from "../api/jobs/job-manager.js";
import type { IncidentCreateCommand } from "../api/routes/incidents.js";
import type {
  IncidentCreateRequestBody,
  IncidentCreatedResponse,
} from "../api/schemas/incidents.js";

const DEMO_OBSERVED_AT = Date.parse("2026-01-15T12:00:00.000Z");
const DEMO_OBSERVED_AT_ISO = new Date(DEMO_OBSERVED_AT).toISOString();
const DEMO_REPLAY_NAME = "TanStack-inspired synthetic supply-chain incident replay";
const DEMO_IDEMPOTENCY_KEY = "hydraguard.demo.tanstack-inspired.v1";
const DEMO_INCIDENT_IDEMPOTENCY_KEY = "hydraguard-demo-incident-v1";
const DEFAULT_DASHBOARD_URL = "http://localhost:5173/";

const DEMO_INCIDENT_REQUEST: IncidentCreateRequestBody = Object.freeze({
  title: "Poisoned transitive dependency",
  intervalStart: DEMO_OBSERVED_AT_ISO,
  intervalEnd: null,
  affectedReleases: Object.freeze([
    Object.freeze({
      packageName: "bad-lib",
      exactVersions: Object.freeze(["1.2.4"]),
    }),
  ]),
  provenance: Object.freeze({
    sourceType: "synthetic-fixture",
    sourceUri: "fixture://hydraguard/tanstack-inspired-advisory",
    observedAt: DEMO_OBSERVED_AT_ISO,
    collectorVersion: "hydraguard-demo-1.0.0",
    confidence: 1,
    synthetic: true,
  }),
});

export interface DemoBootstrapResult {
  readonly persisted: PersistedGraphBatch;
  readonly incident: IncidentCreatedResponse;
  readonly dashboardUrl: string;
}

function withDeterministicNodeTime(node: GraphNode): GraphNode {
  return { ...node, observedAt: DEMO_OBSERVED_AT };
}

function withDeterministicEdgeTime(edge: GraphEdge): GraphEdge {
  if (edge.kind === "USED_BY") {
    return {
      ...edge,
      observedAt: DEMO_OBSERVED_AT,
      generatedAt: DEMO_OBSERVED_AT,
    };
  }

  return { ...edge, observedAt: DEMO_OBSERVED_AT };
}

export function buildDeterministicDemoBatch(): GraphBatch {
  const fixture = generateFixture();

  if (!fixture.validation.valid) {
    throw new Error("Source fixture is invalid and cannot be used for demo preload");
  }

  const batch = mergeGraphFragments([
    {
      source: `demo:${DEMO_REPLAY_NAME}:v1`,
      nodes: fixture.nodes.map(withDeterministicNodeTime),
      edges: fixture.edges.map(withDeterministicEdgeTime),
    },
  ]);

  if (!batch.validation.valid) {
    throw new Error("Deterministic demo batch failed graph validation");
  }

  return batch;
}

async function persistDemoGraph(
  persistence: HydraPersistenceService,
): Promise<PersistedGraphBatch> {
  return persistence.persist(buildDeterministicDemoBatch(), {
    idempotencyKey: DEMO_IDEMPOTENCY_KEY,
    correlationId: "hydraguard-demo-preload-v1",
    maxPartialReplays: 2,
    partialReplayDelayMs: 100,
    chunkSize: 250,
    maxAttempts: 3,
    retryDelayMs: 100,
    statementTimeoutMs: 20_000,
  });
}

/**
 * Backward-compatible graph-only preload used by focused tooling.
 * The command-line entry point below uses bootstrapDemo instead.
 */
export async function preloadDemoGraph(): Promise<PersistedGraphBatch> {
  const driver = await createHydraDriver();

  try {
    return await persistDemoGraph(new HydraPersistenceService(driver));
  } finally {
    await driver.close();
  }
}

function buildDemoIncidentCommand(): IncidentCreateCommand {
  return Object.freeze({
    request: DEMO_INCIDENT_REQUEST,
    requestFingerprint: createRequestFingerprint({
      operation: "create-incident",
      body: DEMO_INCIDENT_REQUEST,
    }),
    intervalStart: DEMO_OBSERVED_AT,
    intervalEnd: null,
    provenanceObservedAt: DEMO_OBSERVED_AT,
    totalExactVersions: 1,
    idempotencyKey: DEMO_INCIDENT_IDEMPOTENCY_KEY,
  });
}

function dashboardUrlFor(incidentId: number): string {
  const configured = process.env.DASHBOARD_URL ?? DEFAULT_DASHBOARD_URL;
  const url = new URL(configured);

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("DASHBOARD_URL must use http or https");
  }

  url.searchParams.set("incidentId", String(incidentId));
  return url.toString();
}

/**
 * Creates the complete, deterministic demo in one driver-owned operation:
 * dependency graph first, then the evidence-backed Incident and AFFECTS edge.
 */
export async function bootstrapDemo(
  driverFactory: () => Promise<Driver> = createHydraDriver,
): Promise<DemoBootstrapResult> {
  const driver = await driverFactory();

  try {
    const persistence = new HydraPersistenceService(driver);
    const persisted = await persistDemoGraph(persistence);
    const incidentService = new HydraIncidentService(driver, persistence);
    const incident = await incidentService.createIncident(buildDemoIncidentCommand());

    return Object.freeze({
      persisted,
      incident,
      dashboardUrl: dashboardUrlFor(incident.incidentId),
    });
  } finally {
    await driver.close();
  }
}

function describeFailure(error: unknown): string {
  if (error instanceof PersistenceServiceError) {
    const failure = error.result.failure;
    return [
      error.message,
      `status=${error.result.status}`,
      `partialWrites=${error.result.partialWrites}`,
      `phase=${failure?.phase ?? "unknown"}`,
      `code=${failure?.code ?? "unknown"}`,
      `shape=${failure?.queryShapeId ?? "unknown"}`,
      `retryable=${failure?.retryable ?? false}`,
    ].join(" ");
  }

  return error instanceof Error ? error.message : "Unknown demo bootstrap failure";
}

async function main(): Promise<void> {
  console.log(`Bootstrapping ${DEMO_REPLAY_NAME}...`);

  try {
    const result = await bootstrapDemo();

    console.log("HydraGuard demo bootstrap succeeded");
    console.log(`Batch hash: ${result.persisted.batchHash}`);
    console.log(`Persistence attempts: ${result.persisted.persistenceAttempts}`);
    console.log(`Nodes: ${result.persisted.result.totals.nodesPlanned}`);
    console.log(`Canonical edges: ${result.persisted.result.totals.canonicalEdgesPlanned}`);
    console.log(`Derived USED_BY edges: ${result.persisted.result.totals.derivedEdgesPlanned}`);
    console.log("Verification: succeeded");
    console.log(`Incident ID: ${result.incident.incidentId}`);
    console.log(`Incident status: ${result.incident.status}`);
    console.log(`Dashboard: ${result.dashboardUrl}`);
  } catch (error) {
    console.error(`HydraGuard demo bootstrap failed: ${describeFailure(error)}`);
    process.exitCode = 1;
  }
}

const isExecutedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isExecutedDirectly) await main();
