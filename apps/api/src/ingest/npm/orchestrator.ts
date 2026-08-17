import {
  mergeGraphFragments,
} from "../graph-batch.js";

import {
  collectPackage,
} from "./collector.js";

import type {
  GraphBatch,
  GraphFragment,
} from "../graph-batch.js";

import type {
  CollectPackageOptions,
  CollectorResult,
} from "./collector.js";

import type {
  RegistryFetchOptions,
} from "./registry-client.js";

export interface NpmRootRequest {
  readonly name: string;

  /**
   * Explicit versions are recommended for roots.
   *
   * When omitted, collector.ts selects the current npm latest
   * dist-tag. Recursively discovered package names also use latest
   * metadata, but only to expand candidate declarations.
   */
  readonly versions?: readonly string[];
}

export type NpmOrchestrationStatus =
  | "completed"
  | "partially-completed"
  | "failed";

export type NpmOrchestrationIssueCode =
  | "PACKAGE_COLLECTION_FAILED"
  | "PACKAGE_CAP_REACHED";

export interface NpmOrchestrationIssue {
  readonly code: NpmOrchestrationIssueCode;
  readonly message: string;
  readonly packageName?: string;
  readonly depth?: number;
  readonly root: boolean;
}

export interface NpmPackageCollectionRecord {
  readonly packageName: string;
  readonly requestedVersions: readonly string[] | null;
  readonly depth: number;
  readonly root: boolean;
  readonly status: "completed" | "failed";
  readonly cacheHit: boolean;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly error?: string;
}

export interface NpmOrchestrationStatistics {
  /**
   * Unique package names accepted into the bounded traversal.
   * Includes packages whose collection later failed.
   */
  readonly scheduledPackageCount: number;

  readonly attemptedPackageCount: number;
  readonly successfulPackageCount: number;
  readonly failedPackageCount: number;
  readonly cacheHitCount: number;

  readonly fragmentCount: number;
  readonly maximumProcessedDepth: number;

  readonly mergedNodeCount: number;
  readonly mergedEdgeCount: number;
}

export interface NpmOrchestrationResult {
  readonly status: NpmOrchestrationStatus;

  /**
   * Null only when every package collection failed.
   */
  readonly batch: GraphBatch | null;

  readonly records: readonly NpmPackageCollectionRecord[];
  readonly issues: readonly NpmOrchestrationIssue[];
  readonly statistics: NpmOrchestrationStatistics;

  /**
   * Makes the candidate-only recursive policy explicit to callers.
   */
  readonly selectionPolicy:
    "explicit-root-versions-or-latest-candidate-expansion";
}

export type NpmPackageCollector = (
  packageName: string,
  options?: CollectPackageOptions,
) => Promise<CollectorResult>;

/**
 * Successful CollectorResults can be retained between orchestration
 * calls. This is currently an in-memory cache; a future implementation
 * can replace it with a disk-backed cache using the same key.
 */
export type NpmCollectorCache = Map<string, CollectorResult>;

export interface NpmOrchestratorOptions {
  readonly roots: readonly NpmRootRequest[];

  /**
   * Root packages are depth 0.
   */
  readonly maxDepth?: number;

  /**
   * Maximum number of unique package names scheduled across the run.
   */
  readonly maxPackages?: number;

  /**
   * Number of registry requests processed concurrently.
   */
  readonly concurrency?: number;

  /**
   * Maximum explicit versions collected for one package.
   */
  readonly maxVersionsPerPackage?: number;

  readonly includeDevDependencies?: boolean;
  readonly registry?: RegistryFetchOptions;

  /**
   * Dependency injection makes network-free smoke validation possible.
   */
  readonly collector?: NpmPackageCollector;

  readonly cache?: NpmCollectorCache;
}

interface QueueItem {
  readonly packageName: string;
  readonly requestedVersions?: readonly string[];
  readonly depth: number;
  readonly root: boolean;
}

interface SuccessfulCollection {
  readonly ok: true;
  readonly item: QueueItem;
  readonly result: CollectorResult;
  readonly cacheHit: boolean;
}

interface FailedCollection {
  readonly ok: false;
  readonly item: QueueItem;
  readonly error: string;
}

type CollectionOutcome =
  | SuccessfulCollection
  | FailedCollection;

interface NormalizedConfiguration {
  readonly maxDepth: number;
  readonly maxPackages: number;
  readonly concurrency: number;
  readonly maxVersionsPerPackage: number;
  readonly includeDevDependencies: boolean;
}

function requireBoundedInteger(
  name: string,
  value: number,
  minimum: number,
  maximum: number,
): number {
  if (
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error(
      `${name} must be an integer between ${minimum} and ${maximum}`,
    );
  }

  return value;
}

function normalizeConfiguration(
  options: NpmOrchestratorOptions,
): NormalizedConfiguration {
  return {
    maxDepth: requireBoundedInteger(
      "maxDepth",
      options.maxDepth ?? 3,
      0,
      10,
    ),
    maxPackages: requireBoundedInteger(
      "maxPackages",
      options.maxPackages ?? 100,
      1,
      1_000,
    ),
    concurrency: requireBoundedInteger(
      "concurrency",
      options.concurrency ?? 4,
      1,
      20,
    ),
    maxVersionsPerPackage: requireBoundedInteger(
      "maxVersionsPerPackage",
      options.maxVersionsPerPackage ?? 25,
      1,
      100,
    ),
    includeDevDependencies:
      options.includeDevDependencies ?? false,
  };
}

function normalizePackageName(packageName: string): string {
  const normalized = packageName.normalize("NFC");

  if (
    normalized.length === 0 ||
    normalized.trim() !== normalized
  ) {
    throw new Error(
      `npm package name must be nonempty without surrounding ` +
        `whitespace: "${packageName}"`,
    );
  }

  return normalized;
}

function normalizeVersions(
  packageName: string,
  versions: readonly string[] | undefined,
): readonly string[] | undefined {
  if (versions === undefined) {
    return undefined;
  }

  if (versions.length === 0) {
    throw new Error(
      `Root package ${packageName} has an empty versions array`,
    );
  }

  const normalizedVersions = [
    ...new Set(
      versions.map((version) => {
        const normalized = version.normalize("NFC");

        if (
          normalized.length === 0 ||
          normalized.trim() !== normalized
        ) {
          throw new Error(
            `Invalid version for ${packageName}: "${version}"`,
          );
        }

        return normalized;
      }),
    ),
  ].sort((left, right) => left.localeCompare(right));

  return normalizedVersions;
}

/**
 * Duplicate roots are merged deterministically. Mixing an implicit
 * latest root with explicit versions for the same package is rejected
 * because it would make traversal intent ambiguous.
 */
function normalizeRoots(
  roots: readonly NpmRootRequest[],
): readonly QueueItem[] {
  if (roots.length === 0) {
    throw new Error("At least one npm root package is required");
  }

  interface RootAccumulator {
    readonly packageName: string;
    latest: boolean;
    readonly versions: Set<string>;
  }

  const rootByPackageName =
    new Map<string, RootAccumulator>();

  for (const root of roots) {
    const packageName = normalizePackageName(root.name);
    const versions = normalizeVersions(
      packageName,
      root.versions,
    );

    let accumulator =
      rootByPackageName.get(packageName);

    if (accumulator === undefined) {
      accumulator = {
        packageName,
        latest: versions === undefined,
        versions: new Set(versions ?? []),
      };

      rootByPackageName.set(
        packageName,
        accumulator,
      );

      continue;
    }

    if (
      accumulator.latest !==
      (versions === undefined)
    ) {
      throw new Error(
        `Root package ${packageName} mixes implicit latest ` +
          `selection with explicit versions`,
      );
    }

    for (const version of versions ?? []) {
      accumulator.versions.add(version);
    }
  }

  return [...rootByPackageName.values()]
    .sort(
      (left, right) =>
        left.packageName.localeCompare(
          right.packageName,
        ),
    )
    .map((root) => ({
      packageName: root.packageName,
      depth: 0,
      root: true,
      ...(root.latest
        ? {}
        : {
            requestedVersions: [
              ...root.versions,
            ].sort(
              (left, right) =>
                left.localeCompare(right),
            ),
          }),
    }));
}

function createCacheKey(
  item: QueueItem,
  configuration: NormalizedConfiguration,
  registry: RegistryFetchOptions | undefined,
): string {
  return JSON.stringify({
    packageName: item.packageName,
    versions: item.requestedVersions ?? null,
    includeDevDependencies:
      configuration.includeDevDependencies,
    maxVersionsPerPackage:
      configuration.maxVersionsPerPackage,
    registryUrl: registry?.registryUrl ?? null,
    timeoutMs: registry?.timeoutMs ?? null,
    retries: registry?.retries ?? null,
    maxResponseBytes:
      registry?.maxResponseBytes ?? null,
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : String(error);
}

async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  mapper: (item: T) => Promise<R>,
): Promise<readonly R[]> {
  if (items.length === 0) {
    return [];
  }

  const results = new Array<R>(items.length);
  let nextIndex = 0;

  const worker = async (): Promise<void> => {
    while (true) {
      const currentIndex = nextIndex;
      nextIndex += 1;

      if (currentIndex >= items.length) {
        return;
      }

      const item = items[currentIndex];

      if (item === undefined) {
        throw new Error(
          `Missing concurrency item at index ${currentIndex}`,
        );
      }

      results[currentIndex] =
        await mapper(item);
    }
  };

  const workerCount = Math.min(
    concurrency,
    items.length,
  );

  await Promise.all(
    Array.from(
      { length: workerCount },
      () => worker(),
    ),
  );

  return results;
}

function declaredDependencyNames(
  result: CollectorResult,
): readonly string[] {
  const nodeById = new Map(
    result.nodes.map(
      (node) => [node.id, node] as const,
    ),
  );

  const names = new Set<string>();

  for (const edge of result.edges) {
    if (edge.kind !== "DECLARES_DEPENDENCY") {
      continue;
    }

    const target = nodeById.get(edge.targetId);

    if (target?.kind !== "Package") {
      throw new Error(
        `DECLARES_DEPENDENCY edge ${edge.logicalId} does not ` +
          `target a Package node`,
      );
    }

    names.add(target.name);
  }

  return [...names].sort(
    (left, right) => left.localeCompare(right),
  );
}

function fragmentSource(item: QueueItem): string {
  const versionSelection =
    item.requestedVersions === undefined
      ? "latest"
      : item.requestedVersions.join(",");

  return (
    `npm-registry:${item.packageName}:` +
    `${versionSelection}:depth-${item.depth}`
  );
}

/**
 * Executes deterministic, bounded, breadth-first npm metadata
 * collection.
 *
 * Security semantics:
 * - Registry recursion creates candidate DECLARES_DEPENDENCY facts.
 * - It never creates concrete DEPENDS_ON relationships.
 * - Exact resolved dependencies remain the responsibility of
 *   package-lock/SBOM collectors.
 */
export async function orchestrateNpmIngestion(
  options: NpmOrchestratorOptions,
): Promise<NpmOrchestrationResult> {
  const configuration =
    normalizeConfiguration(options);

  const roots = normalizeRoots(options.roots);

  if (roots.length > configuration.maxPackages) {
    throw new Error(
      `Root package count ${roots.length} exceeds maxPackages ` +
        `${configuration.maxPackages}`,
    );
  }

  const collector =
    options.collector ?? collectPackage;

  const cache =
    options.cache ?? new Map<string, CollectorResult>();

  const visitedPackageNames = new Set<string>(
    roots.map((root) => root.packageName),
  );

  const fragments: GraphFragment[] = [];
  const records: NpmPackageCollectionRecord[] = [];
  const issues: NpmOrchestrationIssue[] = [];

  let currentDepthItems: readonly QueueItem[] =
    roots;

  let maximumProcessedDepth = 0;
  let cacheHitCount = 0;

  while (currentDepthItems.length > 0) {
    /*
     * Breadth-first waves are sorted before concurrent execution.
     * Network completion order therefore cannot change which packages
     * are admitted before the global package cap.
     */
    const orderedItems = [
      ...currentDepthItems,
    ].sort(
      (left, right) =>
        left.packageName.localeCompare(
          right.packageName,
        ),
    );

    const outcomes = await mapWithConcurrency(
      orderedItems,
      configuration.concurrency,
      async (
        item,
      ): Promise<CollectionOutcome> => {
        const cacheKey = createCacheKey(
          item,
          configuration,
          options.registry,
        );

        const cached = cache.get(cacheKey);

        if (cached !== undefined) {
          return {
            ok: true,
            item,
            result: cached,
            cacheHit: true,
          };
        }

        const collectorOptions: CollectPackageOptions = {
          maxVersions:
            configuration.maxVersionsPerPackage,
          includeDevDependencies:
            configuration.includeDevDependencies,

          ...(item.requestedVersions === undefined
            ? {}
            : {
                versions:
                  item.requestedVersions,
              }),

          ...(options.registry === undefined
            ? {}
            : {
                registry:
                  options.registry,
              }),
        };

        try {
          const result = await collector(
            item.packageName,
            collectorOptions,
          );

          /*
           * Cache only successful results. Failed promises/results must
           * not poison later retry attempts.
           */
          cache.set(cacheKey, result);

          return {
            ok: true,
            item,
            result,
            cacheHit: false,
          };
        } catch (error) {
          return {
            ok: false,
            item,
            error: errorMessage(error),
          };
        }
      },
    );

    const nextDependencyNames =
      new Set<string>();

    for (const outcome of outcomes) {
      maximumProcessedDepth = Math.max(
        maximumProcessedDepth,
        outcome.item.depth,
      );

      if (!outcome.ok) {
        records.push({
          packageName:
            outcome.item.packageName,
          requestedVersions:
            outcome.item.requestedVersions ?? null,
          depth: outcome.item.depth,
          root: outcome.item.root,
          status: "failed",
          cacheHit: false,
          nodeCount: 0,
          edgeCount: 0,
          error: outcome.error,
        });

        issues.push({
          code: "PACKAGE_COLLECTION_FAILED",
          packageName:
            outcome.item.packageName,
          depth: outcome.item.depth,
          root: outcome.item.root,
          message:
            `Failed to collect ${outcome.item.packageName}: ` +
            outcome.error,
        });

        continue;
      }

      if (outcome.cacheHit) {
        cacheHitCount += 1;
      }

      records.push({
        packageName:
          outcome.item.packageName,
        requestedVersions:
          outcome.item.requestedVersions ?? null,
        depth: outcome.item.depth,
        root: outcome.item.root,
        status: "completed",
        cacheHit: outcome.cacheHit,
        nodeCount:
          outcome.result.nodes.length,
        edgeCount:
          outcome.result.edges.length,
      });

      fragments.push({
        source: fragmentSource(outcome.item),
        nodes: outcome.result.nodes,
        edges: outcome.result.edges,
      });

      if (
        outcome.item.depth >=
        configuration.maxDepth
      ) {
        continue;
      }

      for (
        const dependencyName of
        declaredDependencyNames(outcome.result)
      ) {
        if (
          !visitedPackageNames.has(
            dependencyName,
          )
        ) {
          nextDependencyNames.add(
            dependencyName,
          );
        }
      }
    }

    const orderedDependencyNames = [
      ...nextDependencyNames,
    ].sort(
      (left, right) =>
        left.localeCompare(right),
    );

    const remainingCapacity =
      configuration.maxPackages -
      visitedPackageNames.size;

    const admittedNames =
      orderedDependencyNames.slice(
        0,
        Math.max(remainingCapacity, 0),
      );

    const omittedNames =
      orderedDependencyNames.slice(
        admittedNames.length,
      );

    if (omittedNames.length > 0) {
      const preview = omittedNames
        .slice(0, 20)
        .join(", ");

      const remainder =
        omittedNames.length > 20
          ? ` and ${omittedNames.length - 20} more`
          : "";

      issues.push({
        code: "PACKAGE_CAP_REACHED",
        root: false,
        depth:
          orderedItems[0] === undefined
            ? undefined
            : orderedItems[0].depth + 1,
        message:
          `maxPackages=${configuration.maxPackages} prevented ` +
          `collection of ${omittedNames.length} discovered packages: ` +
          `${preview}${remainder}`,
      });
    }

    for (const packageName of admittedNames) {
      visitedPackageNames.add(packageName);
    }

    const nextDepth =
      orderedItems[0] === undefined
        ? 0
        : orderedItems[0].depth + 1;

    currentDepthItems = admittedNames.map(
      (packageName) => ({
        packageName,
        depth: nextDepth,
        root: false,

        /*
         * Recursive latest selection is candidate metadata expansion,
         * not proof of installation.
         */
      }),
    );
  }

  const successfulPackageCount =
    records.filter(
      (record) =>
        record.status === "completed",
    ).length;

  const failedPackageCount =
    records.length -
    successfulPackageCount;

  const batch =
    fragments.length === 0
      ? null
      : mergeGraphFragments(fragments);

  const status: NpmOrchestrationStatus =
    fragments.length === 0
      ? "failed"
      : issues.length === 0
        ? "completed"
        : "partially-completed";

  return {
    status,
    batch,
    records: Object.freeze([...records]),
    issues: Object.freeze([...issues]),
    statistics: Object.freeze({
      scheduledPackageCount:
        visitedPackageNames.size,
      attemptedPackageCount:
        records.length,
      successfulPackageCount,
      failedPackageCount,
      cacheHitCount,
      fragmentCount: fragments.length,
      maximumProcessedDepth,
      mergedNodeCount:
        batch?.nodes.length ?? 0,
      mergedEdgeCount:
        batch?.edges.length ?? 0,
    }),
    selectionPolicy:
      "explicit-root-versions-or-latest-candidate-expansion",
  };
}
