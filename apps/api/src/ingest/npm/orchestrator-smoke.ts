import { pathToFileURL } from "node:url";

import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../../domain/identity.js";

import {
  validateGraph,
} from "../../domain/validator.js";

import {
  orchestrateNpmIngestion,
} from "./orchestrator.js";

import type {
  CollectorResult,
  CollectPackageOptions,
} from "./collector.js";

import type {
  NpmCollectorCache,
  NpmOrchestrationResult,
  NpmPackageCollector,
} from "./orchestrator.js";

import type {
  DependencyDeclarationEdge,
  EvidenceNode,
  GraphEdge,
  GraphNode,
  PackageNode,
  PackageVersionNode,
  StandardCanonicalEdge,
} from "../../domain/schema.js";

interface FakePackageDefinition {
  readonly version: string;
  readonly dependencies: Readonly<Record<string, string>>;
}

interface FakeCollectorState {
  readonly calls: string[];
  readonly callCountByPackage: Map<string, number>;

  activeRequests: number;
  maximumActiveRequests: number;
}

interface FakeCollectorOptions {
  readonly delays?: Readonly<Record<string, number>>;
  readonly failingPackages?: ReadonlySet<string>;
}

interface FakeCollectorHarness {
  readonly collector: NpmPackageCollector;
  readonly state: FakeCollectorState;
}

const PACKAGE_DEFINITIONS: Readonly<
  Record<string, FakePackageDefinition>
> = {
  root: {
    version: "1.0.0",
    dependencies: {
      zeta: "^1.0.0",
      alpha: "^1.0.0",
      cycle: "^1.0.0",
    },
  },

  alpha: {
    version: "1.0.0",
    dependencies: {
      shared: "^1.0.0",
    },
  },

  cycle: {
    version: "1.0.0",
    dependencies: {
      root: "^1.0.0",
    },
  },

  zeta: {
    version: "1.0.0",
    dependencies: {
      shared: "^1.0.0",
      "fail-package": "^1.0.0",
    },
  },

  shared: {
    version: "1.0.0",
    dependencies: {
      leaf: "^1.0.0",
    },
  },

  leaf: {
    version: "1.0.0",
    dependencies: {},
  },
};

function assert(
  condition: unknown,
  message: string,
): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function assertArrayEquals<T>(
  actual: readonly T[],
  expected: readonly T[],
  message: string,
): void {
  assert(
    actual.length === expected.length &&
      actual.every(
        (value, index) =>
          Object.is(value, expected[index]),
      ),
    `${message}: expected [${expected.join(", ")}], ` +
      `received [${actual.join(", ")}]`,
  );
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function deterministicObservedAt(
  packageName: string,
): number {
  const packageNames = Object.keys(
    PACKAGE_DEFINITIONS,
  ).sort((left, right) => left.localeCompare(right));

  const index = packageNames.indexOf(packageName);

  return 1_720_000_000_000 +
    Math.max(index, 0) * 1_000;
}

function getPackageDefinition(
  packageName: string,
): FakePackageDefinition {
  const definition =
    PACKAGE_DEFINITIONS[packageName];

  if (definition === undefined) {
    throw new Error(
      `Fake registry has no package named ${packageName}`,
    );
  }

  return definition;
}

function createPackageNode(
  packageName: string,
  evidenceId: number,
  observedAt: number,
): PackageNode {
  const identity = createEntityIdentity(
    `pkg:npm:${packageName}`,
  );

  return {
    ...identity,
    kind: "Package",
    evidenceIds: [evidenceId],
    synthetic: true,
    observedAt,
    ecosystem: "npm",
    name: packageName,
  };
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
    sourceLogicalId:
      input.packageNode.logicalId,
    targetLogicalId:
      input.versionNode.logicalId,
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

function createDeclarationEdge(input: {
  readonly source: PackageVersionNode;
  readonly target: PackageNode;
  readonly declaredRange: string;
  readonly evidenceId: number;
  readonly observedAt: number;
}): DependencyDeclarationEdge {
  const discriminator =
    `npm-registry:${input.source.packageName}@` +
    `${input.source.version}:production:${input.target.name}`;

  const identity = createEdgeIdentity({
    kind: "DECLARES_DEPENDENCY",
    sourceLogicalId:
      input.source.logicalId,
    targetLogicalId:
      input.target.logicalId,
    discriminator,
  });

  return {
    ...identity,
    sourceId: input.source.id,
    targetId: input.target.id,
    kind: "DECLARES_DEPENDENCY",
    observedAt: input.observedAt,
    derived: false,
    identityDiscriminator: discriminator,
    evidenceIds: [input.evidenceId],
    declaredRange: input.declaredRange,
    dependencyType: "production",
  };
}

/**
 * Builds a valid CollectorResult without performing an HTTP request.
 */
function buildFakeCollectorResult(
  packageName: string,
  options: CollectPackageOptions = {},
): CollectorResult {
  const definition =
    getPackageDefinition(packageName);

  const selectedVersions =
    options.versions === undefined
      ? [definition.version]
      : [...new Set(options.versions)];

  if (selectedVersions.length === 0) {
    throw new Error(
      `No versions selected for ${packageName}`,
    );
  }

  for (const version of selectedVersions) {
    if (version !== definition.version) {
      throw new Error(
        `Fake registry does not contain ` +
          `${packageName}@${version}`,
      );
    }
  }

  const observedAt =
    deterministicObservedAt(packageName);

  const evidenceIdentity = createEntityIdentity(
    `evidence:synthetic:npm-registry:` +
      `${packageName}:orchestrator-smoke-v1`,
  );

  const evidence: EvidenceNode = {
    ...evidenceIdentity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt,
    sourceType: "synthetic-fixture",
    sourceUri:
      `fixture://npm-registry/${encodeURIComponent(packageName)}`,
    collectorVersion:
      "orchestrator-smoke-1.0.0",
    confidence: 1,
    detail:
      `Synthetic npm metadata for ${packageName}`,
  };

  const nodesByLogicalId =
    new Map<string, GraphNode>();

  const edges: GraphEdge[] = [];

  const packageNode = createPackageNode(
    packageName,
    evidence.id,
    observedAt,
  );

  nodesByLogicalId.set(
    evidence.logicalId,
    evidence,
  );

  nodesByLogicalId.set(
    packageNode.logicalId,
    packageNode,
  );

  for (const version of selectedVersions) {
    const versionIdentity = createEntityIdentity(
      `pkgver:npm:${packageName}@${version}`,
    );

    const versionNode: PackageVersionNode = {
      ...versionIdentity,
      kind: "PackageVersion",
      evidenceIds: [evidence.id],
      synthetic: true,
      observedAt,
      ecosystem: "npm",
      packageName,
      version,
      publishedAt: observedAt - 10_000,
    };

    nodesByLogicalId.set(
      versionNode.logicalId,
      versionNode,
    );

    edges.push(
      createHasVersionEdge({
        packageNode,
        versionNode,
        evidenceId: evidence.id,
        observedAt,
      }),
    );

    for (
      const [dependencyName, declaredRange] of
      Object.entries(definition.dependencies)
    ) {
      let dependencyPackage =
        nodesByLogicalId.get(
          `pkg:npm:${dependencyName}`,
        );

      if (dependencyPackage === undefined) {
        dependencyPackage = createPackageNode(
          dependencyName,
          evidence.id,
          observedAt,
        );

        nodesByLogicalId.set(
          dependencyPackage.logicalId,
          dependencyPackage,
        );
      }

      assert(
        dependencyPackage.kind === "Package",
        `Dependency ${dependencyName} did not resolve to a Package node`,
      );

      edges.push(
        createDeclarationEdge({
          source: versionNode,
          target: dependencyPackage,
          declaredRange,
          evidenceId: evidence.id,
          observedAt,
        }),
      );
    }
  }

  const nodes = [
    ...nodesByLogicalId.values(),
  ];

  const validation = validateGraph(
    nodes,
    edges,
  );

  if (!validation.valid) {
    throw new Error(
      `Fake collector produced an invalid graph for ${packageName}:\n` +
        validation.errors
          .map((error) => `- ${error}`)
          .join("\n"),
    );
  }

  return {
    nodes,
    edges,
    evidenceId: evidence.id,
    packageLogicalId:
      packageNode.logicalId,
  };
}

function createFakeCollector(
  options: FakeCollectorOptions = {},
): FakeCollectorHarness {
  const state: FakeCollectorState = {
    calls: [],
    callCountByPackage:
      new Map<string, number>(),
    activeRequests: 0,
    maximumActiveRequests: 0,
  };

  const failingPackages =
    options.failingPackages ??
    new Set<string>();

  const collector: NpmPackageCollector =
    async (
      packageName,
      collectorOptions = {},
    ): Promise<CollectorResult> => {
      /*
       * This executes synchronously before the delay, so calls records
       * deterministic worker start order rather than completion order.
       */
      state.calls.push(packageName);

      state.callCountByPackage.set(
        packageName,
        (
          state.callCountByPackage.get(packageName) ??
          0
        ) + 1,
      );

      state.activeRequests += 1;

      state.maximumActiveRequests = Math.max(
        state.maximumActiveRequests,
        state.activeRequests,
      );

      try {
        await delay(
          options.delays?.[packageName] ?? 1,
        );

        if (failingPackages.has(packageName)) {
          throw new Error(
            `Synthetic registry failure for ${packageName}`,
          );
        }

        return buildFakeCollectorResult(
          packageName,
          collectorOptions,
        );
      } finally {
        state.activeRequests -= 1;
      }
    };

  return {
    collector,
    state,
  };
}

function packageRecordNames(
  result: NpmOrchestrationResult,
): readonly string[] {
  return result.records.map(
    (record) => record.packageName,
  );
}

function assertCandidateOnlyGraph(
  result: NpmOrchestrationResult,
): void {
  assert(
    result.batch !== null,
    "Expected a merged graph batch",
  );

  assert(
    result.batch.validation.valid,
    "Final graph batch must be valid",
  );

  assert(
    result.batch.edges.every(
      (edge) =>
        edge.kind !== "DEPENDS_ON" &&
        edge.kind !== "USED_BY",
    ),
    "npm registry orchestration must not create resolved dependencies",
  );

  assert(
    result.batch.edges.some(
      (edge) =>
        edge.kind === "DECLARES_DEPENDENCY",
    ),
    "Expected candidate DECLARES_DEPENDENCY edges",
  );

  assert(
    result.selectionPolicy ===
      "explicit-root-versions-or-latest-candidate-expansion",
    "Unexpected npm selection policy",
  );
}

async function verifyBreadthFirstTraversalAndPartialFailure(): Promise<void> {
  const harness = createFakeCollector({
    delays: {
      root: 2,
      alpha: 20,
      cycle: 8,
      zeta: 2,
      shared: 10,
      "fail-package": 4,
    },
    failingPackages:
      new Set(["fail-package"]),
  });

  const result = await orchestrateNpmIngestion({
    roots: [
      {
        name: "root",
        versions: ["1.0.0"],
      },
    ],
    maxDepth: 2,
    maxPackages: 20,
    concurrency: 2,
    collector: harness.collector,
  });

  assertArrayEquals(
    packageRecordNames(result),
    [
      "root",
      "alpha",
      "cycle",
      "zeta",
      "fail-package",
      "shared",
    ],
    "Breadth-first package record order is incorrect",
  );

  assertArrayEquals(
    result.records.map(
      (record) => record.depth,
    ),
    [0, 1, 1, 1, 2, 2],
    "Breadth-first depths are incorrect",
  );

  assert(
    result.status ===
      "partially-completed",
    "A dependency failure must produce partially-completed status",
  );

  assert(
    result.statistics.failedPackageCount === 1,
    "Expected exactly one failed package",
  );

  assert(
    result.issues.some(
      (issue) =>
        issue.code ===
          "PACKAGE_COLLECTION_FAILED" &&
        issue.packageName ===
          "fail-package",
    ),
    "Missing partial-failure issue",
  );

  assert(
    harness.state.maximumActiveRequests === 2,
    `Expected concurrency 2, observed ` +
      `${harness.state.maximumActiveRequests}`,
  );

  assert(
    (
      harness.state.callCountByPackage.get(
        "root",
      ) ?? 0
    ) === 1,
    "Cycle protection failed: root was collected more than once",
  );

  assert(
    result.statistics.maximumProcessedDepth === 2,
    "Expected maximum processed depth 2",
  );

  assertCandidateOnlyGraph(result);
}

async function verifyDepthLimit(): Promise<void> {
  const harness = createFakeCollector();

  const result = await orchestrateNpmIngestion({
    roots: [
      {
        name: "root",
        versions: ["1.0.0"],
      },
    ],
    maxDepth: 1,
    maxPackages: 20,
    concurrency: 3,
    collector: harness.collector,
  });

  assertArrayEquals(
    packageRecordNames(result),
    [
      "root",
      "alpha",
      "cycle",
      "zeta",
    ],
    "Depth-limited traversal collected unexpected packages",
  );

  assert(
    result.records.every(
      (record) => record.depth <= 1,
    ),
    "Package was collected beyond maxDepth=1",
  );

  assert(
    !harness.state.calls.includes("shared") &&
      !harness.state.calls.includes(
        "fail-package",
      ),
    "Depth limit did not prevent depth-2 collection",
  );

  assert(
    result.status === "completed",
    "A clean depth-limited traversal should complete",
  );

  assertCandidateOnlyGraph(result);
}

async function runPackageCapScenario(
  delays: Readonly<Record<string, number>>,
): Promise<NpmOrchestrationResult> {
  const harness = createFakeCollector({
    delays,
    failingPackages:
      new Set(["fail-package"]),
  });

  return orchestrateNpmIngestion({
    roots: [
      {
        name: "root",
        versions: ["1.0.0"],
      },
    ],
    maxDepth: 3,
    maxPackages: 5,
    concurrency: 3,
    collector: harness.collector,
  });
}

async function verifyPackageCapAndDeterministicAdmission(): Promise<void> {
  /*
   * alpha and zeta finish in opposite orders between these runs.
   * Sorted breadth-first admission must still select the same packages.
   */
  const first = await runPackageCapScenario({
    root: 1,
    alpha: 25,
    cycle: 10,
    zeta: 2,
    "fail-package": 1,
  });

  const second = await runPackageCapScenario({
    root: 1,
    alpha: 2,
    cycle: 10,
    zeta: 25,
    "fail-package": 1,
  });

  const expectedAdmission = [
    "root",
    "alpha",
    "cycle",
    "zeta",
    "fail-package",
  ];

  assertArrayEquals(
    packageRecordNames(first),
    expectedAdmission,
    "First package-cap admission was not deterministic",
  );

  assertArrayEquals(
    packageRecordNames(second),
    expectedAdmission,
    "Network completion order changed package admission",
  );

  assert(
    first.statistics.scheduledPackageCount === 5 &&
      second.statistics.scheduledPackageCount === 5,
    "maxPackages=5 was not enforced",
  );

  assert(
    first.issues.some(
      (issue) =>
        issue.code ===
        "PACKAGE_CAP_REACHED",
    ),
    "First run did not report the package cap",
  );

  assert(
    second.issues.some(
      (issue) =>
        issue.code ===
        "PACKAGE_CAP_REACHED",
    ),
    "Second run did not report the package cap",
  );

  assert(
    !packageRecordNames(first).includes("shared") &&
      !packageRecordNames(second).includes("shared"),
    "Alphabetically later package bypassed the package cap",
  );

  assertCandidateOnlyGraph(first);
  assertCandidateOnlyGraph(second);
}

async function verifyCacheReuse(): Promise<void> {
  const harness = createFakeCollector();

  const cache: NpmCollectorCache =
    new Map();

  const options = {
    roots: [
      {
        name: "root",
        versions: ["1.0.0"],
      },
    ],
    maxDepth: 1,
    maxPackages: 20,
    concurrency: 3,
    collector: harness.collector,
    cache,
  } as const;

  const first = await orchestrateNpmIngestion(
    options,
  );

  const callsAfterFirstRun =
    harness.state.calls.length;

  assert(
    callsAfterFirstRun === 4,
    `Expected four initial collector calls, received ` +
      `${callsAfterFirstRun}`,
  );

  assert(
    first.statistics.cacheHitCount === 0,
    "The first run should not contain cache hits",
  );

  const second = await orchestrateNpmIngestion(
    options,
  );

  assert(
    harness.state.calls.length ===
      callsAfterFirstRun,
    "The second run unexpectedly called the collector",
  );

  assert(
    second.statistics.cacheHitCount === 4,
    `Expected four cache hits, received ` +
      `${second.statistics.cacheHitCount}`,
  );

  assert(
    second.records.every(
      (record) => record.cacheHit,
    ),
    "Every second-run package should come from cache",
  );

  assertCandidateOnlyGraph(second);
}

async function run(): Promise<void> {
  console.log(
    "Validating bounded npm orchestration...",
  );

  await verifyBreadthFirstTraversalAndPartialFailure();

  console.log(
    "✅ Breadth-first traversal and depth records verified",
  );
  console.log(
    "✅ Cycle protection and partial failure reporting verified",
  );
  console.log(
    "✅ Concurrency limit verified",
  );

  await verifyDepthLimit();

  console.log(
    "✅ Maximum traversal depth verified",
  );

  await verifyPackageCapAndDeterministicAdmission();

  console.log(
    "✅ Global package cap verified",
  );
  console.log(
    "✅ Deterministic package admission verified under different delays",
  );

  await verifyCacheReuse();

  console.log(
    "✅ Successful result cache reuse verified",
  );
  console.log(
    "✅ Final graph-batch validation verified",
  );
  console.log(
    "✅ Registry recursion remained candidate-only",
  );
  console.log(
    "✅ No external network requests were performed",
  );
}

const isExecutedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url ===
    pathToFileURL(process.argv[1]).href;

if (isExecutedDirectly) {
  run().catch((error: unknown) => {
    console.error(
      "❌ npm orchestrator smoke validation failed:",
      error instanceof Error
        ? error.message
        : String(error),
    );

    process.exitCode = 1;
  });
}
