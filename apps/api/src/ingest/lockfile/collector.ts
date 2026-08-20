import { createHash } from "node:crypto";

import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../../domain/identity.js";

import {
  createDependencyPair,
} from "../../domain/factories.js";

import {
  validateGraph,
} from "../../domain/validator.js";

import {
  parsePackageLock,
} from "./package-lock-parser.js";

import type {
  GraphEdge,
  GraphNode,
  LockfileSnapshotNode,
  PackageNode,
  PackageVersionNode,
  ServiceCriticality,
  ServiceNode,
  StandardCanonicalEdge,
} from "../../domain/schema.js";

import type {
  LockfileIssue,
  ParsedLockPackage,
} from "./package-lock-types.js";

const LOCKFILE_COLLECTOR_VERSION = "0.1.0";

export interface LockfileCollectorOptions {
  readonly serviceLogicalId: string;
  readonly serviceName: string;
  readonly serviceCriticality: ServiceCriticality;
  readonly sourceUri: string;

  readonly observedAt?: number;
  readonly confidence?: number;
  readonly synthetic?: boolean;
  readonly maxPackages?: number;

  /**
   * When this lockfile state became true, which is not necessarily when it
   * was observed. Supply the commit or deploy timestamp when it is known so
   * temporal questions are answered against reality rather than scan time.
   *
   * Defaults to observedAt.
   */
  readonly validFrom?: number;

  /**
   * Commit that produced this lockfile state, when known.
   */
  readonly commitSha?: string;
}

export interface LockfileCollectorResult {
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];
  readonly evidenceId: number;
  readonly serviceId: number;
  readonly serviceLogicalId: string;
  readonly contentSha256: string;
  readonly issues: readonly LockfileIssue[];

  /**
   * Identity of the LockfileSnapshot describing this exact lockfile state.
   *
   * Callers persist the graph and then close any earlier open snapshot for
   * the same service, which is what turns a sequence of ingestions into
   * queryable history.
   */
  readonly snapshotId: number;
  readonly snapshotLogicalId: string;
  readonly validFrom: number;
}

function stableSerialize(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Lockfile contains a non-finite number");
    }

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
    `Lockfile contains unsupported value type: ${typeof value}`,
  );
}

function createHasVersionEdge(input: {
  readonly packageNode: PackageNode;
  readonly versionNode: PackageVersionNode;
  readonly evidenceId: number;
  readonly observedAt: number;
}): StandardCanonicalEdge {
  /*
   * "default" gives HAS_VERSION one semantic identity regardless
   * of whether registry metadata or a lockfile supplied the evidence.
   */
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

export function collectPackageLock(
  lockfileValue: unknown,
  options: LockfileCollectorOptions,
): LockfileCollectorResult {
  if (!options.serviceLogicalId.startsWith("service:")) {
    throw new Error(
      'serviceLogicalId must begin with "service:"',
    );
  }

  if (options.sourceUri.trim().length === 0) {
    throw new Error("sourceUri must not be empty");
  }

  const confidence = options.confidence ?? 1;

  if (
    !Number.isFinite(confidence) ||
    confidence < 0 ||
    confidence > 1
  ) {
    throw new Error("confidence must be between 0 and 1");
  }

  const observedAt = options.observedAt ?? Date.now();
  const synthetic = options.synthetic ?? false;

  const canonicalContent = stableSerialize(lockfileValue);

  const contentSha256 = createHash("sha256")
    .update(canonicalContent, "utf8")
    .digest("hex");

  const parsed = parsePackageLock(lockfileValue, {
    maxPackages: options.maxPackages,
  });

  const fatalIssues = parsed.issues.filter(
    (issue) => issue.severity === "error",
  );

  if (fatalIssues.length > 0) {
    throw new Error(
      "package-lock resolution failed:\n" +
        fatalIssues
          .map((issue) => `- ${issue.message}`)
          .join("\n"),
    );
  }

  const evidenceIdentity = createEntityIdentity(
    `evidence:package-lock:${options.serviceLogicalId}:` +
      contentSha256,
  );

  const evidenceNode: GraphNode = {
    ...evidenceIdentity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic,
    observedAt,
    sourceType: "package-lock",
    sourceUri: options.sourceUri,
    collectorVersion: LOCKFILE_COLLECTOR_VERSION,
    confidence,
    detail:
      `package-lock v${parsed.lockfileVersion} snapshot for ` +
      `${options.serviceLogicalId}; SHA-256 ${contentSha256}`,
  };

  const serviceIdentity = createEntityIdentity(
    options.serviceLogicalId,
  );

  const serviceNode: ServiceNode = {
    ...serviceIdentity,
    kind: "Service",
    evidenceIds: [evidenceNode.id],
    synthetic,
    observedAt,
    name: options.serviceName,
    criticality: options.serviceCriticality,
  };

  const validFrom =
    options.validFrom ?? observedAt;

  if (
    !Number.isSafeInteger(validFrom) ||
    validFrom < 0
  ) {
    throw new Error(
      "validFrom must be a nonnegative safe integer epoch",
    );
  }

  if (
    options.commitSha !== undefined &&
    options.commitSha.trim().length === 0
  ) {
    throw new Error(
      "commitSha must not be empty when supplied",
    );
  }

  /*
   * Snapshot identity is content-addressed per service, so re-ingesting the
   * same bytes is idempotent while different bytes always produce a new
   * snapshot that can supersede the previous one.
   */
  const snapshotIdentity = createEntityIdentity(
    `lockfile-snapshot:${options.serviceLogicalId}:` +
      contentSha256,
  );

  const snapshotNode: LockfileSnapshotNode = {
    ...snapshotIdentity,
    kind: "LockfileSnapshot",
    evidenceIds: [evidenceNode.id],
    synthetic,
    observedAt,
    serviceId: serviceNode.id,
    contentSha256,
    lockfileVersion: parsed.lockfileVersion,
    validFrom,
    validUntil: null,

    ...(options.commitSha === undefined
      ? {}
      : { commitSha: options.commitSha }),
  };

  const nodesByLogicalId = new Map<string, GraphNode>();
  const edgesById = new Map<number, GraphEdge>();
  const versionNodeByPath = new Map<
    string,
    PackageVersionNode
  >();

  nodesByLogicalId.set(evidenceNode.logicalId, evidenceNode);
  nodesByLogicalId.set(serviceNode.logicalId, serviceNode);
  nodesByLogicalId.set(
    snapshotNode.logicalId,
    snapshotNode,
  );

  const addNode = (node: GraphNode): void => {
    const existing = nodesByLogicalId.get(node.logicalId);

    if (existing !== undefined) {
      if (existing.id !== node.id || existing.kind !== node.kind) {
        throw new Error(
          `Conflicting node identity ${node.logicalId}`,
        );
      }

      return;
    }

    nodesByLogicalId.set(node.logicalId, node);
  };

  const addEdge = (edge: GraphEdge): void => {
    const existing = edgesById.get(edge.id);

    if (existing !== undefined) {
      if (existing.logicalId !== edge.logicalId) {
        throw new Error(
          `Edge ID collision ${edge.id}: ${existing.logicalId} ` +
            `versus ${edge.logicalId}`,
        );
      }

      return;
    }

    edgesById.set(edge.id, edge);
  };

  const getOrCreatePackageAndVersion = (
    lockPackage: ParsedLockPackage,
  ): PackageVersionNode => {
    const packageIdentity = createEntityIdentity(
      `pkg:npm:${lockPackage.name}`,
    );

    const packageNode: PackageNode = {
      ...packageIdentity,
      kind: "Package",
      evidenceIds: [evidenceNode.id],
      synthetic,
      observedAt,
      ecosystem: "npm",
      name: lockPackage.name,
    };

    addNode(packageNode);

    const versionIdentity = createEntityIdentity(
      `pkgver:npm:${lockPackage.name}@${lockPackage.version}`,
    );

    const versionNode: PackageVersionNode = {
      ...versionIdentity,
      kind: "PackageVersion",
      evidenceIds: [evidenceNode.id],
      synthetic,
      observedAt,
      ecosystem: "npm",
      packageName: lockPackage.name,
      version: lockPackage.version,
    };

    addNode(versionNode);

    addEdge(
      createHasVersionEdge({
        packageNode,
        versionNode,
        evidenceId: evidenceNode.id,
        observedAt,
      }),
    );

    return versionNode;
  };

  for (const lockPackage of parsed.packages) {
    const versionNode =
      getOrCreatePackageAndVersion(lockPackage);

    versionNodeByPath.set(
      lockPackage.installPath,
      versionNode,
    );

    /*
     * RESOLVED_IN records that this snapshot resolved this exact version.
     * The install path is the discriminator because one version can legally
     * appear at several locations in a single lockfile.
     */
    const resolvedDiscriminator =
      `package-lock:${lockPackage.installPath}`;

    addEdge({
      ...createEdgeIdentity({
        kind: "RESOLVED_IN",
        sourceLogicalId:
          snapshotNode.logicalId,
        targetLogicalId:
          versionNode.logicalId,
        discriminator: resolvedDiscriminator,
      }),
      kind: "RESOLVED_IN",
      sourceId: snapshotNode.id,
      targetId: versionNode.id,
      observedAt,
      derived: false,
      identityDiscriminator:
        resolvedDiscriminator,
      evidenceIds: [evidenceNode.id],
    });
  }

  const packageByPath = new Map(
    parsed.packages.map(
      (lockPackage) =>
        [lockPackage.installPath, lockPackage] as const,
    ),
  );

  for (const resolution of parsed.resolutions) {
    const sourceNode =
      resolution.sourcePath === ""
        ? serviceNode
        : versionNodeByPath.get(resolution.sourcePath);

    if (sourceNode === undefined) {
      throw new Error(
        `Missing source node for lockfile path ` +
          `${resolution.sourcePath}`,
      );
    }

    const targetNode =
      versionNodeByPath.get(resolution.targetPath);

    const targetPackage =
      packageByPath.get(resolution.targetPath);

    if (targetNode === undefined || targetPackage === undefined) {
      throw new Error(
        `Missing target node for lockfile path ` +
          `${resolution.targetPath}`,
      );
    }

    /*
     * Installation paths are included because separate lockfile
     * locations can represent distinct dependency resolutions.
     */
    const discriminator =
      `package-lock:${resolution.sourcePath || "<root>"}->` +
      `${resolution.targetPath}:${resolution.dependencyName}:` +
      `${resolution.dependencyType}`;

    const pair = createDependencyPair({
      source: sourceNode,
      target: targetNode,
      discriminator,
      dependencyType: resolution.dependencyType,
      evidenceIds: [evidenceNode.id],
      observedAt,
      generatorVersion: LOCKFILE_COLLECTOR_VERSION,
      declaredRange: resolution.declaredRange,
      lockfilePath: resolution.targetPath,

      /*
       * The resolution inherits the snapshot's validity so temporal queries
       * can filter dependency edges directly instead of joining through the
       * snapshot on every traversal hop. validUntil stays absent because this
       * snapshot is current until a later ingestion supersedes it.
       */
      snapshotId: snapshotNode.id,
      validFrom,

      ...(targetPackage.integrity === undefined
        ? {}
        : { integrity: targetPackage.integrity }),
    });

    addEdge(pair.canonical);
    addEdge(pair.reverseIndex);
  }

  const nodes = [...nodesByLogicalId.values()];
  const edges = [...edgesById.values()];

  const validation = validateGraph(nodes, edges);

  if (!validation.valid) {
    throw new Error(
      "Lockfile collector generated an invalid graph:\n" +
        validation.errors
          .map((error) => `- ${error}`)
          .join("\n"),
    );
  }

  return {
    nodes,
    edges,
    evidenceId: evidenceNode.id,
    serviceId: serviceNode.id,
    serviceLogicalId: serviceNode.logicalId,
    contentSha256,
    issues: parsed.issues,
    snapshotId: snapshotNode.id,
    snapshotLogicalId: snapshotNode.logicalId,
    validFrom,
  };
}
