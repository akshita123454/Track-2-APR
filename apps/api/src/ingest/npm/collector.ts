import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../../domain/identity.js";

import { validateGraph } from "../../domain/validator.js";
import { fetchPackageMetadata } from "./registry-client.js";

import type {
  RegistryFetchOptions,
} from "./registry-client.js";

import type {
  NpmRegistryPackage,
  NpmRegistryVersion,
} from "./registry-types.js";

import type {
  CanonicalRelKind,
  DependencyDeclarationEdge,
  DependencyType,
  EvidenceNode,
  GraphEdge,
  GraphNode,
  MaintainerNode,
  PackageNode,
  PackageVersionNode,
  StandardCanonicalEdge,
} from "../../domain/schema.js";

const COLLECTOR_VERSION = "0.1.0";

type StandardRelationshipKind = Exclude<
  CanonicalRelKind,
  "DECLARES_DEPENDENCY" | "DEPENDS_ON" | "LOOKALIKE_OF"
>;

export interface CollectPackageOptions {
  readonly versions?: readonly string[];
  readonly maxVersions?: number;
  readonly includeDevDependencies?: boolean;
  readonly registry?: RegistryFetchOptions;
}

export interface CollectorResult {
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];
  readonly evidenceId: number;
  readonly packageLogicalId: string;
}

interface DependencyDeclaration {
  readonly packageName: string;
  readonly range: string;
  readonly dependencyType: DependencyType;
}

function parsePublishedAt(value: string | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function selectVersions(
  metadata: NpmRegistryPackage,
  requestedVersions: readonly string[] | undefined,
  maxVersions: number,
): readonly string[] {
  const selected =
    requestedVersions === undefined
      ? (
          metadata.distTags?.latest === undefined
            ? []
            : [metadata.distTags.latest]
        )
      : [...new Set(requestedVersions)];

  if (selected.length === 0) {
    throw new Error(
      `No versions were requested and ${metadata.name} has no latest dist-tag`,
    );
  }

  if (selected.length > maxVersions) {
    throw new Error(
      `Requested ${selected.length} versions of ${metadata.name}; ` +
        `maximum is ${maxVersions}`,
    );
  }

  for (const version of selected) {
    if (metadata.versions[version] === undefined) {
      throw new Error(
        `Version ${metadata.name}@${version} does not exist ` +
          `in the registry response`,
      );
    }
  }

  return selected;
}

function collectDeclarations(
  version: NpmRegistryVersion,
  includeDevDependencies: boolean,
): readonly DependencyDeclaration[] {
  const declarations = new Map<
    string,
    DependencyDeclaration
  >();

  const add = (
    values: Readonly<Record<string, string>> | undefined,
    dependencyType: DependencyType,
  ): void => {
    if (values === undefined) {
      return;
    }

    for (const [packageName, range] of Object.entries(values)) {
      if (range.length === 0) {
        throw new Error(
          `Empty dependency range for ${packageName} in ` +
            `${version.name}@${version.version}`,
        );
      }

      declarations.set(packageName, {
        packageName,
        range,
        dependencyType,
      });
    }
  };

  /*
   * Later entries deliberately override earlier entries when npm
   * metadata lists the same package in multiple dependency sections.
   */
  if (includeDevDependencies) {
    add(version.devDependencies, "development");
  }

  add(version.peerDependencies, "peer");
  add(version.dependencies, "production");
  add(version.optionalDependencies, "optional");

  return [...declarations.values()];
}

function createStandardEdge(input: {
  readonly kind: StandardRelationshipKind;
  readonly source: GraphNode;
  readonly target: GraphNode;
  readonly discriminator: string;
  readonly evidenceId: number;
  readonly observedAt: number;
}): StandardCanonicalEdge {
  const identity = createEdgeIdentity({
    kind: input.kind,
    sourceLogicalId: input.source.logicalId,
    targetLogicalId: input.target.logicalId,
    discriminator: input.discriminator,
  });

  return {
    ...identity,
    sourceId: input.source.id,
    targetId: input.target.id,
    kind: input.kind,
    observedAt: input.observedAt,
    derived: false,
    identityDiscriminator: input.discriminator,
    evidenceIds: [input.evidenceId],
  };
}

function createDeclarationEdge(input: {
  readonly source: PackageVersionNode;
  readonly target: PackageNode;
  readonly declaration: DependencyDeclaration;
  readonly evidenceId: number;
  readonly observedAt: number;
}): DependencyDeclarationEdge {
  const discriminator =
    `npm-registry:${input.source.packageName}@${input.source.version}:` +
    `${input.declaration.dependencyType}:${input.target.name}`;

  const identity = createEdgeIdentity({
    kind: "DECLARES_DEPENDENCY",
    sourceLogicalId: input.source.logicalId,
    targetLogicalId: input.target.logicalId,
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
    declaredRange: input.declaration.range,
    dependencyType: input.declaration.dependencyType,
  };
}

export async function collectPackage(
  packageName: string,
  options: CollectPackageOptions = {},
): Promise<CollectorResult> {
  const maxVersions = options.maxVersions ?? 25;

  if (
    !Number.isInteger(maxVersions) ||
    maxVersions < 1 ||
    maxVersions > 100
  ) {
    throw new Error("maxVersions must be an integer between 1 and 100");
  }

  const fetched = await fetchPackageMetadata(
    packageName,
    options.registry,
  );

  const {
    metadata,
    observedAt,
    sourceUri,
    contentSha256,
  } = fetched;

  const nodesByLogicalId = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  const evidenceIdentity = createEntityIdentity(
    `evidence:npm-registry:${metadata.name}:${contentSha256}`,
  );

  const evidence: EvidenceNode = {
    ...evidenceIdentity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: false,
    observedAt,
    sourceType: "npm-registry",
    sourceUri,
    collectorVersion: COLLECTOR_VERSION,
    confidence: 1,
    detail:
      `npm registry metadata snapshot for ${metadata.name}; ` +
      `SHA-256 ${contentSha256}`,
  };

  nodesByLogicalId.set(evidence.logicalId, evidence);

  function getOrCreatePackage(name: string): PackageNode {
    const identity = createEntityIdentity(`pkg:npm:${name}`);
    const existing = nodesByLogicalId.get(identity.logicalId);

    if (existing !== undefined) {
      if (existing.kind !== "Package") {
        throw new Error(
          `Logical identity ${identity.logicalId} has conflicting kinds`,
        );
      }

      return existing;
    }

    const node: PackageNode = {
      ...identity,
      kind: "Package",
      evidenceIds: [evidence.id],
      synthetic: false,
      observedAt,
      ecosystem: "npm",
      name,
    };

    nodesByLogicalId.set(node.logicalId, node);
    return node;
  }

  const packageNode = getOrCreatePackage(metadata.name);

  const selectedVersions = selectVersions(
    metadata,
    options.versions,
    maxVersions,
  );

  for (const versionString of selectedVersions) {
    const versionMetadata = metadata.versions[versionString];

    if (versionMetadata === undefined) {
      throw new Error(
        `Missing selected version ${metadata.name}@${versionString}`,
      );
    }

    const versionIdentity = createEntityIdentity(
      `pkgver:npm:${metadata.name}@${versionString}`,
    );

    const publishedAt = parsePublishedAt(
      metadata.time?.[versionString],
    );

    const versionNode: PackageVersionNode = {
      ...versionIdentity,
      kind: "PackageVersion",
      evidenceIds: [evidence.id],
      synthetic: false,
      observedAt,
      ecosystem: "npm",
      packageName: metadata.name,
      version: versionString,
      ...(publishedAt === undefined ? {} : { publishedAt }),
    };

    nodesByLogicalId.set(versionNode.logicalId, versionNode);

    edges.push(
      createStandardEdge({
        kind: "HAS_VERSION",
        source: packageNode,
        target: versionNode,
        discriminator: "default",
        evidenceId: evidence.id,
        observedAt,
      }),
    );

    const declarations = collectDeclarations(
      versionMetadata,
      options.includeDevDependencies ?? false,
    );

    for (const declaration of declarations) {
      const dependencyPackage = getOrCreatePackage(
        declaration.packageName,
      );

      edges.push(
        createDeclarationEdge({
          source: versionNode,
          target: dependencyPackage,
          declaration,
          evidenceId: evidence.id,
          observedAt,
        }),
      );
    }
  }

  for (const maintainer of metadata.maintainers ?? []) {
    const maintainerKey = encodeURIComponent(
      maintainer.name.normalize("NFC").toLowerCase(),
    );

    const identity = createEntityIdentity(
      `maintainer:npm:${maintainerKey}`,
    );

    let maintainerNode = nodesByLogicalId.get(identity.logicalId);

    if (maintainerNode === undefined) {
      const newMaintainer: MaintainerNode = {
        ...identity,
        kind: "Maintainer",
        evidenceIds: [evidence.id],
        synthetic: false,
        observedAt,
        handle: maintainer.name,
        ...(maintainer.email === undefined
          ? {}
          : { email: maintainer.email }),
      };

      nodesByLogicalId.set(
        newMaintainer.logicalId,
        newMaintainer,
      );

      maintainerNode = newMaintainer;
    }

    if (maintainerNode.kind !== "Maintainer") {
      throw new Error(
        `Logical identity ${identity.logicalId} has conflicting kinds`,
      );
    }

    edges.push(
      createStandardEdge({
        kind: "MAINTAINS",
        source: maintainerNode,
        target: packageNode,
        discriminator: `npm-registry:${metadata.name}`,
        evidenceId: evidence.id,
        observedAt,
      }),
    );
  }

  const nodes = [...nodesByLogicalId.values()];
  const validation = validateGraph(nodes, edges);

  if (!validation.valid) {
    throw new Error(
      "npm collector generated an invalid graph:\n" +
        validation.errors.map((error: string) => `- ${error}`).join("\n"),
    );
  }

  return {
    nodes,
    edges,
    evidenceId: evidence.id,
    packageLogicalId: packageNode.logicalId,
  };
}
