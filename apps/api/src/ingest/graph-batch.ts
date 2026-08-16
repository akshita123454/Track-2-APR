import {
  IdentityRegistry,
} from "../domain/identity.js";

import {
  validateGraph,
} from "../domain/validator.js";

import type {
  CanonicalEdge,
  DerivedEdge,
  GraphEdge,
  GraphNode,
} from "../domain/schema.js";

import type {
  ValidationResult,
} from "../domain/validator.js";

/**
 * One independently collected graph fragment.
 *
 * Examples:
 * - npm registry metadata for auth-lib
 * - package-lock data for payment-api
 * - a future CycloneDX SBOM
 * - a synthetic deployment fixture
 */
export interface GraphFragment {
  /**
   * Human-readable diagnostic identity.
   *
   * This value does not become graph evidence by itself.
   */
  readonly source: string;
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];
}

export interface GraphBatchStatistics {
  readonly fragmentCount: number;

  readonly inputNodeCount: number;
  readonly outputNodeCount: number;
  readonly deduplicatedNodeCount: number;

  readonly inputEdgeCount: number;
  readonly outputEdgeCount: number;
  readonly deduplicatedEdgeCount: number;

  readonly canonicalEdgeCount: number;
  readonly derivedEdgeCount: number;

  readonly inputEvidenceReferenceCount: number;
  readonly outputEvidenceReferenceCount: number;
}

export interface GraphBatch {
  /**
   * Deterministically ordered and deeply frozen.
   */
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];

  readonly fragmentSources: readonly string[];
  readonly statistics: GraphBatchStatistics;

  /**
   * This is always valid when mergeGraphFragments returns.
   * Invalid batches cause an exception instead.
   */
  readonly validation: ValidationResult;
}

export type GraphBatchErrorCode =
  | "EMPTY_BATCH"
  | "INVALID_FRAGMENT"
  | "IDENTITY_COLLISION"
  | "LOGICAL_ID_CONFLICT"
  | "NODE_KIND_CONFLICT"
  | "PROPERTY_CONFLICT"
  | "EDGE_KIND_CONFLICT"
  | "DERIVED_INDEX_CONFLICT"
  | "GRAPH_VALIDATION_FAILED";

export class GraphBatchError extends Error {
  constructor(
    readonly code: GraphBatchErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "GraphBatchError";
  }
}

function isRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

/**
 * Clone collector values before merging so the batch builder never
 * mutates collector-owned nodes, edges, or arrays.
 */
function cloneValue<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((entry) => cloneValue(entry)) as T;
  }

  if (isRecord(value)) {
    const clone: Record<string, unknown> = {};

    for (const [key, entry] of Object.entries(value)) {
      clone[key] = cloneValue(entry);
    }

    return clone as T;
  }

  return value;
}

function deepFreeze<T>(value: T): T {
  if (
    typeof value === "object" &&
    value !== null &&
    !Object.isFrozen(value)
  ) {
    for (
      const nestedValue of Object.values(
        value as Record<string, unknown>,
      )
    ) {
      deepFreeze(nestedValue);
    }

    Object.freeze(value);
  }

  return value;
}

function valuesEqual(
  left: unknown,
  right: unknown,
): boolean {
  if (Object.is(left, right)) {
    return true;
  }

  if (Array.isArray(left) && Array.isArray(right)) {
    return (
      left.length === right.length &&
      left.every(
        (value, index) =>
          valuesEqual(value, right[index]),
      )
    );
  }

  if (isRecord(left) && isRecord(right)) {
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();

    if (
      leftKeys.length !== rightKeys.length ||
      !leftKeys.every(
        (key, index) => key === rightKeys[index],
      )
    ) {
      return false;
    }

    return leftKeys.every(
      (key) => valuesEqual(left[key], right[key]),
    );
  }

  return false;
}

function mergeEvidenceIds(
  left: readonly number[],
  right: readonly number[],
): readonly number[] {
  return [...new Set([...left, ...right])]
    .sort((first, second) => first - second);
}

/**
 * Merges complementary optional properties but rejects contradictory
 * values.
 *
 * Example:
 * - registry has publishedAt
 * - lockfile does not
 * Result: publishedAt is retained.
 *
 * If two sources provide different nonempty versions for the same
 * PackageVersion identity, the merge fails instead of guessing.
 */
function mergeCompatibleProperties(
  leftValue: object,
  rightValue: object,
  ignoredProperties: ReadonlySet<string>,
  ownerDescription: string,
): Record<string, unknown> {
  const left = leftValue as Record<string, unknown>;
  const right = rightValue as Record<string, unknown>;
  const merged = cloneValue(left);

  const propertyNames = new Set([
    ...Object.keys(left),
    ...Object.keys(right),
  ]);

  for (const propertyName of propertyNames) {
    if (ignoredProperties.has(propertyName)) {
      continue;
    }

    const leftHasProperty =
      Object.prototype.hasOwnProperty.call(
        left,
        propertyName,
      );

    const rightHasProperty =
      Object.prototype.hasOwnProperty.call(
        right,
        propertyName,
      );

    if (!leftHasProperty && rightHasProperty) {
      merged[propertyName] = cloneValue(
        right[propertyName],
      );

      continue;
    }

    if (leftHasProperty && !rightHasProperty) {
      continue;
    }

    const leftProperty = left[propertyName];
    const rightProperty = right[propertyName];

    if (
      leftProperty === undefined &&
      rightProperty !== undefined
    ) {
      merged[propertyName] = cloneValue(rightProperty);
      continue;
    }

    if (
      rightProperty === undefined &&
      leftProperty !== undefined
    ) {
      continue;
    }

    if (!valuesEqual(leftProperty, rightProperty)) {
      throw new GraphBatchError(
        "PROPERTY_CONFLICT",
        `${ownerDescription} has conflicting values for ` +
          `property "${propertyName}"`,
      );
    }
  }

  return merged;
}

function registerIdentity(
  registry: IdentityRegistry,
  id: number,
  logicalId: string,
  ownerDescription: string,
): void {
  try {
    registry.registerKnown(id, logicalId);
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : String(error);

    throw new GraphBatchError(
      "IDENTITY_COLLISION",
      `${ownerDescription}: ${message}`,
    );
  }
}

function mergeNodes(
  existing: GraphNode,
  incoming: GraphNode,
  existingSources: readonly string[],
  incomingSource: string,
): GraphNode {
  if (existing.id !== incoming.id) {
    throw new GraphBatchError(
      "IDENTITY_COLLISION",
      `Cannot merge node IDs ${existing.id} and ${incoming.id}`,
    );
  }

  if (existing.logicalId !== incoming.logicalId) {
    throw new GraphBatchError(
      "LOGICAL_ID_CONFLICT",
      `Node ID ${existing.id} maps to both ` +
        `"${existing.logicalId}" and "${incoming.logicalId}"`,
    );
  }

  if (existing.kind !== incoming.kind) {
    throw new GraphBatchError(
      "NODE_KIND_CONFLICT",
      `Node ${existing.logicalId} is ${existing.kind} in ` +
        `${existingSources.join(", ")} but ${incoming.kind} in ` +
        `${incomingSource}`,
    );
  }

  /*
   * Evidence records are content-addressed. Two records with the same
   * identity must agree on whether they are synthetic.
   */
  if (
    existing.kind === "Evidence" &&
    existing.synthetic !== incoming.synthetic
  ) {
    throw new GraphBatchError(
      "PROPERTY_CONFLICT",
      `Evidence node ${existing.logicalId} has conflicting ` +
        `synthetic classifications`,
    );
  }

  const merged = mergeCompatibleProperties(
    existing,
    incoming,
    new Set([
      "evidenceIds",
      "observedAt",
      "synthetic",
    ]),
    `Node ${existing.logicalId}`,
  );

  merged.id = existing.id;
  merged.logicalId = existing.logicalId;
  merged.kind = existing.kind;

  merged.evidenceIds = mergeEvidenceIds(
    existing.evidenceIds,
    incoming.evidenceIds,
  );

  /*
   * A graph entity is considered synthetic only when every merged
   * observation says it is synthetic.
   *
   * Real registry evidence therefore upgrades a package previously
   * seen only in a synthetic fixture to non-synthetic.
   */
  merged.synthetic =
    existing.kind === "Evidence"
      ? existing.synthetic
      : existing.synthetic && incoming.synthetic;

  /*
   * Keep the most recent observation on the entity. Individual
   * Evidence nodes retain their own observation timestamps.
   */
  merged.observedAt = Math.max(
    existing.observedAt,
    incoming.observedAt,
  );

  return merged as unknown as GraphNode;
}

function mergeCanonicalEdges(
  existing: CanonicalEdge,
  incoming: CanonicalEdge,
  existingSources: readonly string[],
  incomingSource: string,
): CanonicalEdge {
  if (
    existing.logicalId !== incoming.logicalId ||
    existing.sourceId !== incoming.sourceId ||
    existing.targetId !== incoming.targetId
  ) {
    throw new GraphBatchError(
      "IDENTITY_COLLISION",
      `Canonical edge ID ${existing.id} has conflicting identity or ` +
        `endpoints between ${existingSources.join(", ")} and ` +
        `${incomingSource}`,
    );
  }

  if (existing.kind !== incoming.kind) {
    throw new GraphBatchError(
      "EDGE_KIND_CONFLICT",
      `Canonical edge ${existing.logicalId} is ${existing.kind} in ` +
        `${existingSources.join(", ")} but ${incoming.kind} in ` +
        `${incomingSource}`,
    );
  }

  const merged = mergeCompatibleProperties(
    existing,
    incoming,
    new Set([
      "evidenceIds",
      "observedAt",
    ]),
    `Canonical edge ${existing.logicalId}`,
  );

  merged.evidenceIds = mergeEvidenceIds(
    existing.evidenceIds,
    incoming.evidenceIds,
  );

  merged.observedAt = Math.max(
    existing.observedAt,
    incoming.observedAt,
  );

  return merged as unknown as CanonicalEdge;
}

function mergeDerivedEdges(
  existing: DerivedEdge,
  incoming: DerivedEdge,
  existingSources: readonly string[],
  incomingSource: string,
): DerivedEdge {
  const identityMatches =
    existing.logicalId === incoming.logicalId &&
    existing.sourceId === incoming.sourceId &&
    existing.targetId === incoming.targetId &&
    existing.derivedFrom === incoming.derivedFrom &&
    existing.derivedFromLogicalId ===
      incoming.derivedFromLogicalId;

  if (!identityMatches) {
    throw new GraphBatchError(
      "DERIVED_INDEX_CONFLICT",
      `Derived edge ID ${existing.id} has conflicting canonical ` +
        `references between ${existingSources.join(", ")} and ` +
        `${incomingSource}`,
    );
  }

  if (
    !Number.isSafeInteger(existing.generatedAt) ||
    !Number.isSafeInteger(incoming.generatedAt) ||
    existing.generatedAt < 0 ||
    incoming.generatedAt < 0
  ) {
    throw new GraphBatchError(
      "DERIVED_INDEX_CONFLICT",
      `Derived edge ${existing.logicalId} has an invalid generatedAt`,
    );
  }

  if (
    existing.generatorVersion.length === 0 ||
    incoming.generatorVersion.length === 0
  ) {
    throw new GraphBatchError(
      "DERIVED_INDEX_CONFLICT",
      `Derived edge ${existing.logicalId} has an empty generatorVersion`,
    );
  }

  /*
   * Select regeneration metadata deterministically:
   * - latest generatedAt wins
   * - generatorVersion breaks timestamp ties
   */
  const incomingIsNewer =
    incoming.generatedAt > existing.generatedAt ||
    (
      incoming.generatedAt === existing.generatedAt &&
      incoming.generatorVersion.localeCompare(
        existing.generatorVersion,
      ) > 0
    );

  const preferred =
    incomingIsNewer ? incoming : existing;

  return {
    ...cloneValue(preferred),
    observedAt: Math.max(
      existing.observedAt,
      incoming.observedAt,
    ),
    generatedAt: Math.max(
      existing.generatedAt,
      incoming.generatedAt,
    ),
  };
}

function countEvidenceReferences(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
): number {
  const nodeReferences = nodes.reduce(
    (total, node) =>
      total + node.evidenceIds.length,
    0,
  );

  const edgeReferences = edges.reduce(
    (total, edge) =>
      edge.kind === "USED_BY"
        ? total
        : total + edge.evidenceIds.length,
    0,
  );

  return nodeReferences + edgeReferences;
}

function compareByIdentity(
  left: { readonly id: number; readonly logicalId: string },
  right: { readonly id: number; readonly logicalId: string },
): number {
  if (left.id !== right.id) {
    return left.id - right.id;
  }

  return left.logicalId.localeCompare(right.logicalId);
}

/**
 * Combines independently collected graph fragments into one
 * immutable, evidence-preserving, validated graph batch.
 *
 * The function fails closed: contradictory facts never silently
 * overwrite one another.
 */
export function mergeGraphFragments(
  fragments: readonly GraphFragment[],
): GraphBatch {
  if (fragments.length === 0) {
    throw new GraphBatchError(
      "EMPTY_BATCH",
      "At least one graph fragment is required",
    );
  }

  const nodeRegistry = new IdentityRegistry();
  const edgeRegistry = new IdentityRegistry();

  const nodesById = new Map<number, GraphNode>();
  const nodeIdByLogicalId = new Map<string, number>();
  const nodeSourcesById = new Map<number, Set<string>>();

  const edgesById = new Map<number, GraphEdge>();
  const edgeIdByLogicalId = new Map<string, number>();
  const edgeSourcesById = new Map<number, Set<string>>();

  let inputNodeCount = 0;
  let inputEdgeCount = 0;
  let inputEvidenceReferenceCount = 0;

  for (const fragment of fragments) {
    if (fragment.source.trim().length === 0) {
      throw new GraphBatchError(
        "INVALID_FRAGMENT",
        "Every graph fragment must have a nonempty source",
      );
    }

    inputNodeCount += fragment.nodes.length;
    inputEdgeCount += fragment.edges.length;

    inputEvidenceReferenceCount +=
      countEvidenceReferences(
        fragment.nodes,
        fragment.edges,
      );

    for (const incomingNode of fragment.nodes) {
      registerIdentity(
        nodeRegistry,
        incomingNode.id,
        incomingNode.logicalId,
        `Node from ${fragment.source}`,
      );

      const existingId =
        nodeIdByLogicalId.get(incomingNode.logicalId);

      if (
        existingId !== undefined &&
        existingId !== incomingNode.id
      ) {
        throw new GraphBatchError(
          "LOGICAL_ID_CONFLICT",
          `Logical node identity "${incomingNode.logicalId}" maps to ` +
            `IDs ${existingId} and ${incomingNode.id}`,
        );
      }

      nodeIdByLogicalId.set(
        incomingNode.logicalId,
        incomingNode.id,
      );

      const existingNode =
        nodesById.get(incomingNode.id);

      const existingSources =
        nodeSourcesById.get(incomingNode.id) ??
        new Set<string>();

      if (existingNode === undefined) {
        nodesById.set(
          incomingNode.id,
          cloneValue(incomingNode),
        );
      } else {
        nodesById.set(
          incomingNode.id,
          mergeNodes(
            existingNode,
            incomingNode,
            [...existingSources],
            fragment.source,
          ),
        );
      }

      existingSources.add(fragment.source);
      nodeSourcesById.set(
        incomingNode.id,
        existingSources,
      );
    }

    for (const incomingEdge of fragment.edges) {
      registerIdentity(
        edgeRegistry,
        incomingEdge.id,
        incomingEdge.logicalId,
        `Edge from ${fragment.source}`,
      );

      const existingId =
        edgeIdByLogicalId.get(incomingEdge.logicalId);

      if (
        existingId !== undefined &&
        existingId !== incomingEdge.id
      ) {
        throw new GraphBatchError(
          "LOGICAL_ID_CONFLICT",
          `Logical edge identity "${incomingEdge.logicalId}" maps to ` +
            `IDs ${existingId} and ${incomingEdge.id}`,
        );
      }

      edgeIdByLogicalId.set(
        incomingEdge.logicalId,
        incomingEdge.id,
      );

      const existingEdge =
        edgesById.get(incomingEdge.id);

      const existingSources =
        edgeSourcesById.get(incomingEdge.id) ??
        new Set<string>();

      if (existingEdge === undefined) {
        edgesById.set(
          incomingEdge.id,
          cloneValue(incomingEdge),
        );
      } else if (
        existingEdge.kind === "USED_BY" &&
        incomingEdge.kind === "USED_BY"
      ) {
        edgesById.set(
          incomingEdge.id,
          mergeDerivedEdges(
            existingEdge,
            incomingEdge,
            [...existingSources],
            fragment.source,
          ),
        );
      } else if (
        existingEdge.kind !== "USED_BY" &&
        incomingEdge.kind !== "USED_BY"
      ) {
        edgesById.set(
          incomingEdge.id,
          mergeCanonicalEdges(
            existingEdge,
            incomingEdge,
            [...existingSources],
            fragment.source,
          ),
        );
      } else {
        throw new GraphBatchError(
          "EDGE_KIND_CONFLICT",
          `Edge ID ${incomingEdge.id} is canonical in one fragment ` +
            `and derived in another`,
        );
      }

      existingSources.add(fragment.source);
      edgeSourcesById.set(
        incomingEdge.id,
        existingSources,
      );
    }
  }

  /*
   * Ensure multiple malformed derived edges cannot target the same
   * canonical edge under different derived IDs.
   */
  const derivedEdgeByCanonicalId =
    new Map<number, DerivedEdge>();

  for (const edge of edgesById.values()) {
    if (edge.kind !== "USED_BY") {
      continue;
    }

    const existing =
      derivedEdgeByCanonicalId.get(edge.derivedFrom);

    if (
      existing !== undefined &&
      existing.id !== edge.id
    ) {
      throw new GraphBatchError(
        "DERIVED_INDEX_CONFLICT",
        `Canonical edge ${edge.derivedFrom} has multiple derived ` +
          `USED_BY edge IDs: ${existing.id} and ${edge.id}`,
      );
    }

    derivedEdgeByCanonicalId.set(
      edge.derivedFrom,
      edge,
    );
  }

  const nodes = [...nodesById.values()]
    .sort(compareByIdentity);

  const edges = [...edgesById.values()]
    .sort(compareByIdentity);

  const validation = validateGraph(nodes, edges);

  if (!validation.valid) {
    throw new GraphBatchError(
      "GRAPH_VALIDATION_FAILED",
      "Merged graph batch failed validation:\n" +
        validation.errors
          .map((error) => `- ${error}`)
          .join("\n"),
    );
  }

  const canonicalEdgeCount = edges.filter(
    (edge) => edge.kind !== "USED_BY",
  ).length;

  const derivedEdgeCount =
    edges.length - canonicalEdgeCount;

  const statistics: GraphBatchStatistics = {
    fragmentCount: fragments.length,

    inputNodeCount,
    outputNodeCount: nodes.length,
    deduplicatedNodeCount:
      inputNodeCount - nodes.length,

    inputEdgeCount,
    outputEdgeCount: edges.length,
    deduplicatedEdgeCount:
      inputEdgeCount - edges.length,

    canonicalEdgeCount,
    derivedEdgeCount,

    inputEvidenceReferenceCount,
    outputEvidenceReferenceCount:
      countEvidenceReferences(nodes, edges),
  };

  /*
   * Freeze only cloned/merged output. Collector inputs remain untouched.
   */
  const frozenNodes = deepFreeze(nodes);
  const frozenEdges = deepFreeze(edges);
  const frozenSources = deepFreeze(
    fragments.map((fragment) => fragment.source),
  );
  const frozenStatistics = deepFreeze(statistics);
  const frozenValidation = deepFreeze(validation);

  return deepFreeze({
    nodes: frozenNodes,
    edges: frozenEdges,
    fragmentSources: frozenSources,
    statistics: frozenStatistics,
    validation: frozenValidation,
  });
}
