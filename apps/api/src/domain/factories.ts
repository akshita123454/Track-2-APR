import {
  createDerivedEdgeIdentity,
  createEdgeIdentity,
} from "./identity.js";

import type {
  DependencyEdge,
  DependencyType,
  DerivedEdge,
  PackageVersionNode,
  ServiceNode,
  UnixEpochMilliseconds,
} from "./schema.js";

export type DependencySourceNode =
  | ServiceNode
  | PackageVersionNode;

export interface CreateDependencyPairInput {
  readonly source: DependencySourceNode;
  readonly target: PackageVersionNode;

  /**
   * Must be stable across ingestion runs.
   * Do not include Date.now() or another changing value.
   */
  readonly discriminator: string;

  readonly dependencyType: DependencyType;
  readonly evidenceIds: readonly number[];
  readonly observedAt: UnixEpochMilliseconds;
  readonly generatorVersion: string;

  readonly declaredRange?: string;
  readonly lockfilePath?: string;
  readonly integrity?: string;

  /**
   * Temporal validity of this resolution.
   *
   * Supplying validUntil without validFrom is rejected because a closing
   * timestamp alone cannot be placed on the time axis.
   */
  readonly snapshotId?: number;
  readonly validFrom?: UnixEpochMilliseconds;
  readonly validUntil?: UnixEpochMilliseconds;
}

export interface DependencyPair {
  readonly canonical: DependencyEdge;
  readonly reverseIndex: DerivedEdge;
}

export function createDependencyPair(
  input: CreateDependencyPairInput,
): DependencyPair {
  if (input.evidenceIds.length === 0) {
    throw new Error(
      "A canonical DEPENDS_ON edge requires at least one Evidence node",
    );
  }

  if (input.discriminator.trim().length === 0) {
    throw new Error(
      "A dependency edge requires a stable identity discriminator",
    );
  }

  if (
    input.validUntil !== undefined &&
    input.validFrom === undefined
  ) {
    throw new Error(
      "A dependency edge validUntil requires validFrom",
    );
  }

  if (
    input.validFrom !== undefined &&
    input.validUntil !== undefined &&
    input.validUntil < input.validFrom
  ) {
    throw new Error(
      "A dependency edge validUntil cannot precede validFrom",
    );
  }

  const canonicalIdentity = createEdgeIdentity({
    kind: "DEPENDS_ON",
    sourceLogicalId: input.source.logicalId,
    targetLogicalId: input.target.logicalId,
    discriminator: input.discriminator,
  });

  const canonical: DependencyEdge = {
    ...canonicalIdentity,
    sourceId: input.source.id,
    targetId: input.target.id,
    kind: "DEPENDS_ON",
    observedAt: input.observedAt,
    derived: false,
    identityDiscriminator: input.discriminator,
    evidenceIds: [...input.evidenceIds],
    dependencyType: input.dependencyType,

    ...(input.declaredRange === undefined
      ? {}
      : { declaredRange: input.declaredRange }),

    ...(input.lockfilePath === undefined
      ? {}
      : { lockfilePath: input.lockfilePath }),

    ...(input.integrity === undefined
      ? {}
      : { integrity: input.integrity }),

    ...(input.snapshotId === undefined
      ? {}
      : { snapshotId: input.snapshotId }),

    ...(input.validFrom === undefined
      ? {}
      : { validFrom: input.validFrom }),

    ...(input.validUntil === undefined
      ? {}
      : { validUntil: input.validUntil }),
  };

  const reverseIdentity = createDerivedEdgeIdentity(
    canonical.logicalId,
  );

  const reverseIndex: DerivedEdge = {
    ...reverseIdentity,
    sourceId: input.target.id,
    targetId: input.source.id,
    kind: "USED_BY",
    observedAt: input.observedAt,
    derived: true,
    derivedFrom: canonical.id,
    derivedFromLogicalId: canonical.logicalId,
    generatedAt: input.observedAt,
    generatorVersion: input.generatorVersion,
  };

  return {
    canonical,
    reverseIndex,
  };
}
