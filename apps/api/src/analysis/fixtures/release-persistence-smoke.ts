import assert from "node:assert/strict";

import neo4j from "neo4j-driver";
import type {
  Driver,
  Session,
} from "neo4j-driver";

import {
  HydraReleaseInfluenceStore,
  ReleaseInfluenceStoreError,
} from "../release-trust/hydra-release-influence-store.js";
import {
  runPersistedReleaseFirewall,
} from "../release-trust/persisted-release-firewall.js";
import type {
  ReleaseFirewallInput,
  ReleaseInfluenceEdge,
  ReleaseInfluenceNode,
  ReleaseNode,
} from "../release-trust/release-influence-types.js";

const OBSERVED_AT = 1_778_502_000_000;
const EVIDENCE_ID = 91_001;

interface StoredSnapshot {
  readonly writeToken: string;
  state: "writing" | "ready" | "failed";
  readonly schemaVersion: number;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly releaseIdsJson: string;
  readonly persistedAt: number;
  readonly nodes: Map<number, Record<string, unknown>>;
  readonly edges: Map<number, Record<string, unknown>>;
}

interface FakeDatabase {
  readonly snapshots: Map<string, StoredSnapshot>;
  openedSessions: number;
  closedSessions: number;
}

function toNumber(value: unknown): number {
  if (typeof value === "number") {
    return value;
  }

  if (neo4j.isInt(value)) {
    return value.toNumber();
  }

  throw new Error("Expected a numeric HydraDB parameter");
}

function normalizeValue(value: unknown): unknown {
  if (neo4j.isInt(value)) {
    return value.toNumber();
  }

  if (Array.isArray(value)) {
    return value.map(normalizeValue);
  }

  if (
    typeof value === "object" &&
    value !== null
  ) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        normalizeValue(entry),
      ]),
    );
  }

  return value;
}

function record(
  values: Readonly<Record<string, unknown>>,
): { get(key: string): unknown } {
  return {
    get: (key: string) => values[key],
  };
}

function createSessionFactory(
  database: FakeDatabase,
): () => Session {
  return () => {
    database.openedSessions += 1;
    let closed = false;

    const session = {
      run: async (
        _query: string,
        rawParameters: Record<string, unknown> = {},
        config?: {
          readonly metadata?: Readonly<Record<string, unknown>>;
        },
      ) => {
        const parameters = normalizeValue(
          rawParameters,
        ) as Record<string, unknown>;
        const operation = config?.metadata?.[
          "hydradb.caller.step"
        ];
        const snapshotId = String(
          parameters.snapshot_id ?? "",
        );

        switch (operation) {
          case "claim-release-influence-snapshot": {
            let snapshot = database.snapshots.get(snapshotId);

            if (snapshot === undefined) {
              snapshot = {
                writeToken: String(parameters.write_token),
                state: "writing",
                schemaVersion: 1,
                nodeCount: toNumber(parameters.node_count),
                edgeCount: toNumber(parameters.edge_count),
                releaseIdsJson: String(parameters.release_ids_json),
                persistedAt: toNumber(parameters.persisted_at),
                nodes: new Map(),
                edges: new Map(),
              };
              database.snapshots.set(snapshotId, snapshot);
            }

            return {
              records: [
                record({
                  write_token: snapshot.writeToken,
                  state: snapshot.state,
                }),
              ],
            };
          }

          case "write-release-influence-nodes": {
            const snapshot = database.snapshots.get(snapshotId);
            assert.ok(snapshot);
            assert.equal(snapshot.state, "writing");
            assert.equal(
              parameters.write_token,
              snapshot.writeToken,
            );
            const rows = parameters.rows as Array<Record<string, unknown>>;

            for (const row of rows) {
              snapshot.nodes.set(toNumber(row.id), { ...row });
            }

            return {
              records: [record({ written: rows.length })],
            };
          }

          case "write-release-influence-edges": {
            const snapshot = database.snapshots.get(snapshotId);
            assert.ok(snapshot);
            assert.equal(snapshot.state, "writing");
            const rows = parameters.rows as Array<Record<string, unknown>>;

            for (const row of rows) {
              assert.ok(snapshot.nodes.has(toNumber(row.source_id)));
              assert.ok(snapshot.nodes.has(toNumber(row.target_id)));
              snapshot.edges.set(toNumber(row.id), { ...row });
            }

            return {
              records: [record({ written: rows.length })],
            };
          }

          case "finalize-release-influence-snapshot": {
            const snapshot = database.snapshots.get(snapshotId);
            assert.ok(snapshot);
            assert.equal(parameters.write_token, snapshot.writeToken);
            snapshot.state = "ready";
            return {
              records: [record({ state: "ready" })],
            };
          }

          case "fail-release-influence-snapshot": {
            const snapshot = database.snapshots.get(snapshotId);
            if (snapshot !== undefined) {
              snapshot.state = "failed";
            }
            return {
              records: [record({ state: "failed" })],
            };
          }

          case "read-release-influence-snapshot": {
            const snapshot = database.snapshots.get(snapshotId);

            return {
              records:
                snapshot === undefined
                  ? []
                  : [
                      record({
                        state: snapshot.state,
                        schema_version: snapshot.schemaVersion,
                        node_count: snapshot.nodeCount,
                        edge_count: snapshot.edgeCount,
                        release_ids_json: snapshot.releaseIdsJson,
                        persisted_at: snapshot.persistedAt,
                      }),
                    ],
            };
          }

          case "read-release-influence-nodes": {
            const snapshot = database.snapshots.get(snapshotId);
            assert.ok(snapshot);
            const rows = [...snapshot.nodes.values()].sort(
              (left, right) =>
                toNumber(left.id) - toNumber(right.id),
            );
            return {
              records: rows.map((row) => record(row)),
            };
          }

          case "read-release-influence-edges": {
            const snapshot = database.snapshots.get(snapshotId);
            assert.ok(snapshot);
            const rows = [...snapshot.edges.values()].sort(
              (left, right) =>
                toNumber(left.id) - toNumber(right.id),
            );
            return {
              records: rows.map((row) => record(row)),
            };
          }

          default:
            throw new Error(`Unexpected fake operation ${String(operation)}`);
        }
      },

      close: async () => {
        if (!closed) {
          closed = true;
          database.closedSessions += 1;
        }
      },
    };

    return session as unknown as Session;
  };
}

function releaseNode(
  id: number,
  packageName: string,
): ReleaseNode {
  return {
    id,
    kind: "release",
    label: `${packageName}@1.0.0`,
    trust: "trusted",
    evidenceIds: [EVIDENCE_ID],
    observedAt: OBSERVED_AT,
    subject: {
      ecosystem: "npm",
      packageName,
      version: "1.0.0",
      artifactDigest: `sha256:${String(id)}`,
    },
  };
}

function createFixture(): ReleaseFirewallInput {
  const nodes: ReleaseInfluenceNode[] = [
    {
      id: 1,
      kind: "source-change",
      label: "external pull request",
      trust: "untrusted",
      evidenceIds: [EVIDENCE_ID],
      observedAt: OBSERVED_AT,
    },
    {
      id: 2,
      kind: "workflow-run",
      label: "pull request workflow",
      trust: "untrusted",
      evidenceIds: [EVIDENCE_ID],
      observedAt: OBSERVED_AT,
    },
    {
      id: 3,
      kind: "cache-entry",
      label: "shared cache",
      trust: "unknown",
      evidenceIds: [EVIDENCE_ID],
      observedAt: OBSERVED_AT,
    },
    {
      id: 4,
      kind: "workflow-run",
      label: "release workflow",
      trust: "trusted",
      evidenceIds: [EVIDENCE_ID],
      observedAt: OBSERVED_AT,
    },
    {
      id: 5,
      kind: "credential",
      label: "valid OIDC publisher",
      trust: "trusted",
      evidenceIds: [EVIDENCE_ID],
      observedAt: OBSERVED_AT,
    },
    {
      id: 6,
      kind: "artifact",
      label: "release artifact",
      trust: "trusted",
      evidenceIds: [EVIDENCE_ID],
      observedAt: OBSERVED_AT,
    },
    releaseNode(7, "@example/router"),
  ];

  const edge = (
    id: number,
    kind: ReleaseInfluenceEdge["kind"],
    sourceId: number,
    targetId: number,
    trust: ReleaseInfluenceEdge["trust"] = "trusted",
    boundary: ReleaseInfluenceEdge["boundary"] = "same-trust-zone",
  ): ReleaseInfluenceEdge => ({
    id,
    kind,
    sourceId,
    targetId,
    trust,
    boundary,
    evidenceIds: [EVIDENCE_ID],
    observedAt: OBSERVED_AT,
  });

  const edges: ReleaseInfluenceEdge[] = [
    edge(101, "checks-out", 1, 2, "untrusted"),
    edge(
      102,
      "writes-cache",
      2,
      3,
      "untrusted",
      "cross-trust-boundary",
    ),
    edge(
      103,
      "restores-cache",
      3,
      4,
      "unknown",
      "cross-trust-boundary",
    ),
    edge(104, "mints-credential", 4, 5),
    edge(105, "produces", 4, 6),
    edge(106, "publishes", 6, 7),
    edge(107, "authorizes-publish", 5, 7),
  ];

  return {
    graph: { nodes, edges },
    releaseNodeIds: [7],
  };
}

async function main(): Promise<void> {
  const database: FakeDatabase = {
    snapshots: new Map(),
    openedSessions: 0,
    closedSessions: 0,
  };
  const sessionFactory = createSessionFactory(database);
  const fakeDriver = {
    session: sessionFactory,
    close: async () => undefined,
  } as unknown as Driver;
  const store = new HydraReleaseInfluenceStore(
    fakeDriver,
    {
      sessionFactory,
      clock: () => OBSERVED_AT,
      writeTokenFactory: () => "fixture-write-token",
    },
  );
  const fixture = createFixture();
  const before = JSON.stringify(fixture);

  const persisted = await store.persistSnapshot(
    "tanstack-style-demo",
    fixture,
  );

  assert.deepEqual(persisted, {
    snapshotId: "tanstack-style-demo",
    persistedAt: OBSERVED_AT,
    nodeCount: 7,
    edgeCount: 7,
    state: "ready",
  });

  const loaded = await store.readSnapshot(
    "tanstack-style-demo",
  );

  assert.equal(loaded.snapshotId, "tanstack-style-demo");
  assert.equal(loaded.input.graph.nodes.length, 7);
  assert.equal(loaded.input.graph.edges.length, 7);

  const result = await runPersistedReleaseFirewall(
    store,
    "tanstack-style-demo",
  );

  assert.equal(result.engine, "HydraDB");
  assert.equal(
    result.consistencyModel,
    "verified-release-influence-snapshot",
  );
  assert.equal(result.firewall.summary.blocked, 1);
  assert.equal(result.firewall.decisions[0]?.verdict, "block");
  assert.ok(
    result.firewall.decisions[0]?.findings.some(
      (finding) => finding.code === "cross-boundary-cache",
    ),
  );

  await assert.rejects(
    store.persistSnapshot("tanstack-style-demo", fixture),
    (error: unknown) =>
      error instanceof ReleaseInfluenceStoreError &&
      error.code === "SNAPSHOT_EXISTS",
  );

  await assert.rejects(
    store.readSnapshot("missing-snapshot"),
    (error: unknown) =>
      error instanceof ReleaseInfluenceStoreError &&
      error.code === "SNAPSHOT_NOT_FOUND",
  );

  const boundedStore = new HydraReleaseInfluenceStore(
    fakeDriver,
    {
      sessionFactory,
      maxNodes: 2,
      clock: () => OBSERVED_AT,
      writeTokenFactory: () => "bounded-write-token",
    },
  );

  await assert.rejects(
    boundedStore.persistSnapshot("oversized-snapshot", fixture),
    (error: unknown) =>
      error instanceof ReleaseInfluenceStoreError &&
      error.code === "SNAPSHOT_LIMIT_EXCEEDED",
  );

  const stored = database.snapshots.get("tanstack-style-demo");
  assert.ok(stored);
  const source = stored.nodes.get(1);
  assert.ok(source);
  source.trust = "corrupt-trust";

  await assert.rejects(
    store.readSnapshot("tanstack-style-demo"),
    (error: unknown) =>
      error instanceof ReleaseInfluenceStoreError &&
      error.code === "SNAPSHOT_CORRUPT",
  );

  assert.equal(database.openedSessions, database.closedSessions);
  assert.equal(JSON.stringify(fixture), before);

  console.log("Release influence persistence smoke passed");
  console.log("- immutable snapshots claimed, written, finalized, and reread");
  console.log("- persisted TanStack-style path remained blocked");
  console.log("- duplicate IDs and oversized snapshots failed closed");
  console.log("- corrupt stored trust data was rejected");
  console.log("- every store-owned HydraDB session was closed");
  console.log("- source graph remained unchanged");
}

await main();
