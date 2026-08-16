import { pathToFileURL } from "node:url";

import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../domain/identity.js";

import {
  createDependencyPair,
} from "../domain/factories.js";

import {
  GraphBatchError,
  mergeGraphFragments,
} from "./graph-batch.js";

import type {
  EvidenceNode,
  PackageNode,
  PackageVersionNode,
  ServiceNode,
  StandardCanonicalEdge,
} from "../domain/schema.js";

import type {
  GraphBatch,
  GraphFragment,
} from "./graph-batch.js";

interface SmokeFixture {
  readonly registryFragment: GraphFragment;
  readonly lockfileFragment: GraphFragment;
  readonly registryEvidence: EvidenceNode;
  readonly lockfileEvidence: EvidenceNode;
  readonly packageNode: PackageNode;
  readonly versionNode: PackageVersionNode;
}

function assert(
  condition: unknown,
  message: string,
): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function assertNumberArrayEquals(
  actual: readonly number[],
  expected: readonly number[],
  message: string,
): void {
  assert(
    actual.length === expected.length &&
      actual.every((value, index) => value === expected[index]),
    `${message}: expected [${expected.join(", ")}], received ` +
      `[${actual.join(", ")}]`,
  );
}

function stableSerialize(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableSerialize).join(",")}]`;
  }

  if (typeof value === "object") {
    const record = value as Record<string, unknown>;

    return `{${Object.keys(record)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableSerialize(record[key])}`,
      )
      .join(",")}}`;
  }

  throw new Error(
    `Cannot serialize smoke-test value of type ${typeof value}`,
  );
}

function createHasVersionEdge(input: {
  readonly packageNode: PackageNode;
  readonly versionNode: PackageVersionNode;
  readonly evidenceId: number;
  readonly observedAt: number;
}): StandardCanonicalEdge {
  const discriminator = "default";

  const identity = createEdgeIdentity({
    kind: "HAS_VERSION",
    sourceLogicalId: input.packageNode.logicalId,
    targetLogicalId: input.versionNode.logicalId,
    discriminator,
  });

  return {
    ...identity,
    sourceId: input.packageNode.id,
    targetId: input.versionNode.id,
    kind: "HAS_VERSION",
    observedAt: input.observedAt,
    derived: false,
    identityDiscriminator: discriminator,
    evidenceIds: [input.evidenceId],
  };
}

function createSmokeFixture(): SmokeFixture {
  const registryObservedAt = 1_720_000_000_000;
  const lockfileObservedAt = registryObservedAt + 1_000;

  const registryEvidenceIdentity = createEntityIdentity(
    "evidence:npm-registry:auth-lib:smoke-v1",
  );

  const registryEvidence: EvidenceNode = {
    ...registryEvidenceIdentity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: false,
    observedAt: registryObservedAt,
    sourceType: "npm-registry",
    sourceUri: "https://registry.npmjs.org/auth-lib",
    collectorVersion: "0.1.0-smoke",
    confidence: 1,
    detail: "Registry observation used by graph-batch smoke validation",
  };

  const lockfileEvidenceIdentity = createEntityIdentity(
    "evidence:package-lock:payment-api:smoke-v1",
  );

  const lockfileEvidence: EvidenceNode = {
    ...lockfileEvidenceIdentity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt: lockfileObservedAt,
    sourceType: "package-lock",
    sourceUri: "fixture://payment-api/package-lock.json",
    collectorVersion: "0.1.0-smoke",
    confidence: 1,
    detail: "Synthetic lockfile observation used by graph-batch smoke validation",
  };

  const packageIdentity = createEntityIdentity(
    "pkg:npm:auth-lib",
  );

  const registryPackageNode: PackageNode = {
    ...packageIdentity,
    kind: "Package",
    evidenceIds: [registryEvidence.id],
    synthetic: false,
    observedAt: registryObservedAt,
    ecosystem: "npm",
    name: "auth-lib",
  };

  const lockfilePackageNode: PackageNode = {
    ...packageIdentity,
    kind: "Package",
    evidenceIds: [lockfileEvidence.id],
    synthetic: true,
    observedAt: lockfileObservedAt,
    ecosystem: "npm",
    name: "auth-lib",
  };

  const versionIdentity = createEntityIdentity(
    "pkgver:npm:auth-lib@2.0.0",
  );

  const registryVersionNode: PackageVersionNode = {
    ...versionIdentity,
    kind: "PackageVersion",
    evidenceIds: [registryEvidence.id],
    synthetic: false,
    observedAt: registryObservedAt,
    ecosystem: "npm",
    packageName: "auth-lib",
    version: "2.0.0",
    publishedAt: 1_719_000_000_000,
  };

  const lockfileVersionNode: PackageVersionNode = {
    ...versionIdentity,
    kind: "PackageVersion",
    evidenceIds: [lockfileEvidence.id],
    synthetic: true,
    observedAt: lockfileObservedAt,
    ecosystem: "npm",
    packageName: "auth-lib",
    version: "2.0.0",
  };

  const registryHasVersion = createHasVersionEdge({
    packageNode: registryPackageNode,
    versionNode: registryVersionNode,
    evidenceId: registryEvidence.id,
    observedAt: registryObservedAt,
  });

  const lockfileHasVersion = createHasVersionEdge({
    packageNode: lockfilePackageNode,
    versionNode: lockfileVersionNode,
    evidenceId: lockfileEvidence.id,
    observedAt: lockfileObservedAt,
  });

  const serviceIdentity = createEntityIdentity(
    "service:demo-org:payment-api",
  );

  const serviceNode: ServiceNode = {
    ...serviceIdentity,
    kind: "Service",
    evidenceIds: [lockfileEvidence.id],
    synthetic: true,
    observedAt: lockfileObservedAt,
    name: "payment-api",
    criticality: "critical",
  };

  const dependencyPair = createDependencyPair({
    source: serviceNode,
    target: lockfileVersionNode,
    discriminator: "package-lock:<root>->node_modules/auth-lib:production",
    dependencyType: "production",
    evidenceIds: [lockfileEvidence.id],
    observedAt: lockfileObservedAt,
    generatorVersion: "0.1.0-smoke",
    declaredRange: "2.0.0",
    lockfilePath: "node_modules/auth-lib",
    integrity: "sha512-auth-lib-smoke",
  });

  return {
    registryEvidence,
    lockfileEvidence,
    packageNode: registryPackageNode,
    versionNode: registryVersionNode,
    registryFragment: {
      source: "npm-registry:auth-lib@2.0.0",
      nodes: [
        registryEvidence,
        registryPackageNode,
        registryVersionNode,
      ],
      edges: [registryHasVersion],
    },
    lockfileFragment: {
      source: "package-lock:payment-api",
      nodes: [
        lockfileEvidence,
        serviceNode,
        lockfilePackageNode,
        lockfileVersionNode,
      ],
      edges: [
        lockfileHasVersion,
        dependencyPair.canonical,
        dependencyPair.reverseIndex,
      ],
    },
  };
}

function assertMergedEvidence(
  batch: GraphBatch,
  fixture: SmokeFixture,
): void {
  const expectedEvidenceIds = [
    fixture.registryEvidence.id,
    fixture.lockfileEvidence.id,
  ].sort((left, right) => left - right);

  const packageNode = batch.nodes.find(
    (node) => node.logicalId === fixture.packageNode.logicalId,
  );

  assert(packageNode !== undefined, "Merged Package node is missing");
  assertNumberArrayEquals(
    packageNode.evidenceIds,
    expectedEvidenceIds,
    "Package evidence fusion failed",
  );
  assert(
    packageNode.synthetic === false,
    "Real registry evidence must upgrade the merged Package to non-synthetic",
  );

  const versionNode = batch.nodes.find(
    (node) => node.logicalId === fixture.versionNode.logicalId,
  );

  assert(
    versionNode?.kind === "PackageVersion",
    "Merged PackageVersion node is missing",
  );
  assertNumberArrayEquals(
    versionNode.evidenceIds,
    expectedEvidenceIds,
    "PackageVersion evidence fusion failed",
  );
  assert(
    versionNode.publishedAt === 1_719_000_000_000,
    "Complementary registry publication metadata was lost",
  );

  const hasVersion = batch.edges.find(
    (edge) => edge.kind === "HAS_VERSION",
  );

  assert(
    hasVersion !== undefined && hasVersion.kind !== "USED_BY",
    "Merged HAS_VERSION edge is missing",
  );
  assertNumberArrayEquals(
    hasVersion.evidenceIds,
    expectedEvidenceIds,
    "Canonical edge evidence fusion failed",
  );
}

function assertBatchShape(batch: GraphBatch): void {
  assert(batch.validation.valid, "Merged graph batch must be valid");
  assert(batch.nodes.length === 5, "Expected exactly 5 merged nodes");
  assert(batch.edges.length === 3, "Expected exactly 3 merged edges");

  assert(
    batch.statistics.fragmentCount === 2,
    "Expected two source fragments",
  );
  assert(
    batch.statistics.inputNodeCount === 7 &&
      batch.statistics.outputNodeCount === 5 &&
      batch.statistics.deduplicatedNodeCount === 2,
    "Node deduplication statistics are incorrect",
  );
  assert(
    batch.statistics.inputEdgeCount === 4 &&
      batch.statistics.outputEdgeCount === 3 &&
      batch.statistics.deduplicatedEdgeCount === 1,
    "Edge deduplication statistics are incorrect",
  );
  assert(
    batch.statistics.canonicalEdgeCount === 2 &&
      batch.statistics.derivedEdgeCount === 1,
    "Canonical/derived edge statistics are incorrect",
  );

  const dependsOnCount = batch.edges.filter(
    (edge) => edge.kind === "DEPENDS_ON",
  ).length;

  const usedByCount = batch.edges.filter(
    (edge) => edge.kind === "USED_BY",
  ).length;

  assert(dependsOnCount === 1, "Expected one DEPENDS_ON edge");
  assert(usedByCount === 1, "Expected exactly one derived USED_BY edge");
}

function assertDeeplyFrozen(batch: GraphBatch): void {
  assert(Object.isFrozen(batch), "Graph batch must be frozen");
  assert(Object.isFrozen(batch.nodes), "Node array must be frozen");
  assert(Object.isFrozen(batch.edges), "Edge array must be frozen");
  assert(
    Object.isFrozen(batch.statistics),
    "Statistics must be frozen",
  );

  for (const node of batch.nodes) {
    assert(Object.isFrozen(node), `Node ${node.logicalId} must be frozen`);
    assert(
      Object.isFrozen(node.evidenceIds),
      `Evidence IDs for ${node.logicalId} must be frozen`,
    );
  }

  for (const edge of batch.edges) {
    assert(Object.isFrozen(edge), `Edge ${edge.logicalId} must be frozen`);

    if (edge.kind !== "USED_BY") {
      assert(
        Object.isFrozen(edge.evidenceIds),
        `Evidence IDs for ${edge.logicalId} must be frozen`,
      );
    }
  }
}

function assertDeterministicOrdering(fixture: SmokeFixture): void {
  const forward = mergeGraphFragments([
    fixture.registryFragment,
    fixture.lockfileFragment,
  ]);

  const reversed = mergeGraphFragments([
    fixture.lockfileFragment,
    fixture.registryFragment,
  ]);

  assert(
    stableSerialize(forward.nodes) === stableSerialize(reversed.nodes),
    "Reversing fragment order changed merged nodes",
  );

  assert(
    stableSerialize(forward.edges) === stableSerialize(reversed.edges),
    "Reversing fragment order changed merged edges",
  );
}

function assertConflictRejected(fixture: SmokeFixture): void {
  const originalVersion = fixture.lockfileFragment.nodes.find(
    (node) => node.logicalId === fixture.versionNode.logicalId,
  );

  assert(
    originalVersion?.kind === "PackageVersion",
    "Lockfile PackageVersion fixture is missing",
  );

  const conflictingVersion: PackageVersionNode = {
    ...originalVersion,
    version: "9.9.9",
  };

  const conflictingFragment: GraphFragment = {
    ...fixture.lockfileFragment,
    source: "package-lock:conflicting-payment-api",
    nodes: fixture.lockfileFragment.nodes.map(
      (node) =>
        node.logicalId === conflictingVersion.logicalId
          ? conflictingVersion
          : node,
    ),
  };

  let rejected = false;

  try {
    mergeGraphFragments([
      fixture.registryFragment,
      conflictingFragment,
    ]);
  } catch (error) {
    assert(
      error instanceof GraphBatchError,
      "Conflict must produce a GraphBatchError",
    );
    assert(
      error.code === "PROPERTY_CONFLICT",
      `Expected PROPERTY_CONFLICT, received ${error.code}`,
    );

    rejected = true;
  }

  assert(rejected, "Contradictory package facts were not rejected");
}

function run(): void {
  console.log("Validating graph-batch evidence fusion...");

  const fixture = createSmokeFixture();
  const registrySnapshot = stableSerialize(fixture.registryFragment);
  const lockfileSnapshot = stableSerialize(fixture.lockfileFragment);

  const batch = mergeGraphFragments([
    fixture.registryFragment,
    fixture.lockfileFragment,
  ]);

  assertBatchShape(batch);
  assertMergedEvidence(batch, fixture);
  assertDeeplyFrozen(batch);
  assertDeterministicOrdering(fixture);
  assertConflictRejected(fixture);

  assert(
    stableSerialize(fixture.registryFragment) === registrySnapshot,
    "Registry fragment was mutated during merge",
  );
  assert(
    stableSerialize(fixture.lockfileFragment) === lockfileSnapshot,
    "Lockfile fragment was mutated during merge",
  );

  console.log("✅ Overlapping graph entities deduplicated");
  console.log("✅ Registry and lockfile Evidence IDs fused");
  console.log("✅ Complementary provenance properties preserved");
  console.log("✅ Canonical DEPENDS_ON and derived USED_BY parity preserved");
  console.log("✅ Collector inputs remained unchanged");
  console.log("✅ Output graph batch is deeply immutable");
  console.log("✅ Fragment order produced deterministic graph output");
  console.log("✅ Contradictory facts failed closed");
  console.log(
    `✅ ${batch.statistics.inputNodeCount} input nodes → ` +
      `${batch.statistics.outputNodeCount} merged nodes`,
  );
  console.log(
    `✅ ${batch.statistics.inputEdgeCount} input edges → ` +
      `${batch.statistics.outputEdgeCount} merged edges`,
  );
}

const isExecutedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isExecutedDirectly) {
  try {
    run();
  } catch (error) {
    console.error(
      "❌ Graph-batch smoke validation failed:",
      error instanceof Error ? error.message : String(error),
    );

    process.exitCode = 1;
  }
}
