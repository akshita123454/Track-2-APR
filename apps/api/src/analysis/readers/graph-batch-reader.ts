import type {
  DerivedEdge,
  EvidenceNode,
  GraphEdge,
  GraphNode,
  NodeId,
} from "../../domain/schema.js";
import type {
  GraphBatch,
} from "../../ingest/graph-batch.js";
import type {
  DependencyHop,
  DependencyHopPage,
  FindDependentsOptions,
  ReadonlyGraphReader,
} from "../core/analysis-types.js";

function compareDependencyHops(
  left: DependencyHop,
  right: DependencyHop,
): number {
  return (
    left.canonicalEdge.id -
      right.canonicalEdge.id ||
    left.dependentNode.id -
      right.dependentNode.id
  );
}

/**
 * Keeps only the deterministically smallest `limit` hops.
 *
 * Memory remains O(limit), even when a node has substantially more reverse
 * dependencies.
 */
function insertBoundedHop(
  hops: DependencyHop[],
  hop: DependencyHop,
  limit: number,
): void {
  let low = 0;
  let high = hops.length;

  while (low < high) {
    const middle = Math.floor(
      (low + high) / 2,
    );

    const existing = hops[middle];

    if (
      existing !== undefined &&
      compareDependencyHops(existing, hop) <= 0
    ) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }

  hops.splice(low, 0, hop);

  if (hops.length > limit) {
    hops.pop();
  }
}

function isReverseIndexForNode(
  edge: GraphEdge,
  nodeId: NodeId,
): edge is DerivedEdge {
  return (
    edge.kind === "USED_BY" &&
    edge.sourceId === nodeId
  );
}

/**
 * Internal reader over the exact immutable batch authorized by
 * PersistedGraphBatch.
 *
 * Do not export this class from the public analysis barrel.
 */
export class GraphBatchReader
  implements ReadonlyGraphReader {
  private readonly nodesById =
    new Map<NodeId, GraphNode>();

  private readonly edgesById =
    new Map<number, GraphEdge>();

  public constructor(
    private readonly batch: GraphBatch,
  ) {
    for (const node of batch.nodes) {
      this.nodesById.set(node.id, node);
    }

    for (const edge of batch.edges) {
      this.edgesById.set(edge.id, edge);
    }
  }

  public async getNode(
    nodeId: NodeId,
  ): Promise<GraphNode | null> {
    return this.nodesById.get(nodeId) ?? null;
  }

  public async findDependents(
    nodeId: NodeId,
    options: FindDependentsOptions,
  ): Promise<DependencyHopPage> {
    if (
      !Number.isSafeInteger(options.limit) ||
      options.limit < 1
    ) {
      throw new RangeError(
        "findDependents limit must be a positive safe integer",
      );
    }

    const hops: DependencyHop[] = [];
    let truncated = false;

    /*
     * Scan the immutable batch without first allocating every matching
     * reverse index. Only the best `limit` hops are retained.
     *
     * A future database reader should implement equivalent behavior using
     * deterministic ORDER BY plus LIMIT (limit + 1).
     */
    for (const edge of this.batch.edges) {
      if (!isReverseIndexForNode(edge, nodeId)) {
        continue;
      }

      const reverseIndex = edge;
      const resolved = this.edgesById.get(
        reverseIndex.derivedFrom,
      );

      if (
        resolved === undefined ||
        resolved.kind !== "DEPENDS_ON" ||
        resolved.derived !== false
      ) {
        throw new Error(
          `USED_BY ${String(reverseIndex.id)} does not resolve ` +
            "to canonical DEPENDS_ON",
        );
      }

      if (
        reverseIndex.derivedFromLogicalId !==
          resolved.logicalId ||
        resolved.sourceId !==
          reverseIndex.targetId ||
        resolved.targetId !==
          reverseIndex.sourceId
      ) {
        throw new Error(
          `USED_BY ${String(reverseIndex.id)} has invalid ` +
            "canonical identity or endpoints",
        );
      }

      const dependentNode = this.nodesById.get(
        reverseIndex.targetId,
      );

      if (dependentNode === undefined) {
        throw new Error(
          `USED_BY ${String(reverseIndex.id)} references ` +
            "a missing dependent node",
        );
      }

      if (hops.length === options.limit) {
        truncated = true;
      }

      insertBoundedHop(
        hops,
        {
          dependentNode,
          canonicalEdge: resolved,
          traversalIndexEdgeId:
            reverseIndex.id,
        },
        options.limit,
      );
    }

    return {
      hops: Object.freeze([...hops]),
      truncated,
    };
  }

  public async getEvidence(
    evidenceIds: readonly NodeId[],
  ): Promise<readonly EvidenceNode[]> {
    const evidence: EvidenceNode[] = [];

    for (const evidenceId of evidenceIds) {
      const node = this.nodesById.get(evidenceId);

      if (node?.kind === "Evidence") {
        evidence.push(node);
      }
    }

    return evidence;
  }
}
