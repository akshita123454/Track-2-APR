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
}

export interface LockfileCollectorResult {
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];
  readonly evidenceId: number;
  readonly serviceLogicalId: string;
  readonly contentSha256: string;
  readonly issues: readonly LockfileIssue[];
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

  const nodesByLogicalId = new Map<string, GraphNode>();
  const edgesById = new Map<number, GraphEdge>();
  const versionNodeByPath = new Map<
    string,
    PackageVersionNode
  >();

  nodesByLogicalId.set(evidenceNode.logicalId, evidenceNode);
  nodesByLogicalId.set(serviceNode.logicalId, serviceNode);

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
    serviceLogicalId: serviceNode.logicalId,
    contentSha256,
    issues: parsed.issues,
  };
}
