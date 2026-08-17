import { pathToFileURL } from "node:url";

import {
  createHydraDriver,
} from "../hydra-client.js";

import {
  generateFixture,
} from "../domain/fixture.js";

import type {
  GraphEdge,
  GraphNode,
} from "../domain/schema.js";

import {
  mergeGraphFragments,
} from "../ingest/graph-batch.js";

import type {
  GraphBatch,
} from "../ingest/graph-batch.js";

import {
  HydraPersistenceService,
  PersistenceServiceError,
} from "../db/persistence-service.js";

import type {
  PersistedGraphBatch,
} from "../db/persistence-service.js";

/**
 * This is a synthetic replay timestamp, not a claim about the date of any
 * real-world incident event.
 *
 * Do not replace it with Date.now(): the demo batch must remain byte-for-byte
 * deterministic across retries and preload runs.
 */
const DEMO_OBSERVED_AT =
  Date.parse("2026-01-15T12:00:00.000Z");

const DEMO_REPLAY_NAME =
  "TanStack-inspired synthetic supply-chain incident replay";

const DEMO_IDEMPOTENCY_KEY =
  "hydraguard.demo.tanstack-inspired.v1";

function withDeterministicNodeTime(
  node: GraphNode,
): GraphNode {
  return {
    ...node,
    observedAt: DEMO_OBSERVED_AT,
  };
}

function withDeterministicEdgeTime(
  edge: GraphEdge,
): GraphEdge {
  if (edge.kind === "USED_BY") {
    return {
      ...edge,
      observedAt: DEMO_OBSERVED_AT,
      generatedAt: DEMO_OBSERVED_AT,
    };
  }

  return {
    ...edge,
    observedAt: DEMO_OBSERVED_AT,
  };
}

/**
 * Produces a deeply frozen, evidence-backed and parity-validated graph batch.
 *
 * The source name deliberately labels the replay as synthetic.
 */
export function buildDeterministicDemoBatch(): GraphBatch {
  const fixture = generateFixture();

  if (!fixture.validation.valid) {
    throw new Error(
      "Source fixture is invalid and cannot be used for demo preload",
    );
  }

  const nodes = fixture.nodes.map(
    withDeterministicNodeTime,
  );

  const edges = fixture.edges.map(
    withDeterministicEdgeTime,
  );

  const batch = mergeGraphFragments([
    {
      source:
        `demo:${DEMO_REPLAY_NAME}:v1`,
      nodes,
      edges,
    },
  ]);

  if (!batch.validation.valid) {
    throw new Error(
      "Deterministic demo batch failed graph validation",
    );
  }

  return batch;
}

/**
 * Preloads the demo graph without clearing existing data.
 *
 * Existing matching identities are replayed idempotently. Existing conflicting
 * identities cause a fail-closed persistence error.
 */
export async function preloadDemoGraph(): Promise<
  PersistedGraphBatch
> {
  const batch = buildDeterministicDemoBatch();
  const driver = await createHydraDriver();

  try {
    const persistence =
      new HydraPersistenceService(driver);

    return await persistence.persist(
      batch,
      {
        idempotencyKey: DEMO_IDEMPOTENCY_KEY,
        correlationId:
          "hydraguard-demo-preload-v1",

        /*
         * Initial attempt plus at most two complete-batch replays.
         * The service forces verify=true and guardedUpserts=true.
         */
        maxPartialReplays: 2,
        partialReplayDelayMs: 100,

        chunkSize: 250,
        maxAttempts: 3,
        retryDelayMs: 100,
        statementTimeoutMs: 20_000,
      },
    );
  } finally {
    /*
     * HydraPersistenceService owns its sessions but not the driver.
     * The preload command owns this driver and must close it.
     */
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
      `retryable=${failure?.retryable ?? false}`,
    ].join(" ");
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "Unknown demo preload failure";
}

async function main(): Promise<void> {
  console.log(
    `Preloading ${DEMO_REPLAY_NAME}...`,
  );

  try {
    const persisted = await preloadDemoGraph();

    console.log("HydraGuard demo preload succeeded");
    console.log(`Batch hash: ${persisted.batchHash}`);
    console.log(
      `Idempotency key: ${persisted.idempotencyKey}`,
    );
    console.log(
      `Persistence attempts: ${persisted.persistenceAttempts}`,
    );
    console.log(
      `Nodes: ${persisted.result.totals.nodesPlanned}`,
    );
    console.log(
      `Canonical edges: ` +
        `${persisted.result.totals.canonicalEdgesPlanned}`,
    );
    console.log(
      `Derived USED_BY edges: ` +
        `${persisted.result.totals.derivedEdgesPlanned}`,
    );
    console.log(
      "Verification: succeeded",
    );
  } catch (error) {
    console.error(
      `HydraGuard demo preload failed: ` +
        describeFailure(error),
    );

    /*
     * The demo must not continue into analysis after preload failure.
     */
    process.exitCode = 1;
  }
}

const isExecutedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url ===
    pathToFileURL(process.argv[1]).href;

if (isExecutedDirectly) {
  await main();
}
