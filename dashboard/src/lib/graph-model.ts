import type {
  LiveBlastRadiusResponse,
  NodeId,
  EdgeId,
  BlastRadiusNode,
  DependencyEdge,
  EvidenceCatalogEntry
} from './api-types';

export type EvidenceState = 'missing' | 'verified' | 'high-confidence';

export interface GraphModelNode {
  readonly id: NodeId;
  readonly node: BlastRadiusNode;
  readonly type: 'affected-root' | 'package' | 'service';
  readonly evidenceState: EvidenceState;
  readonly synthetic: boolean;
  /** Set of pathKeys that traverse this node */
  readonly pathKeys: ReadonlySet<string>;
  layer: number;
}

export interface GraphModelEdge {
  readonly id: EdgeId;
  readonly edge: DependencyEdge;
  readonly sourceId: NodeId;
  readonly targetId: NodeId;
  readonly evidenceState: EvidenceState;
  readonly synthetic: boolean;
  /** Set of pathKeys that traverse this edge */
  readonly pathKeys: ReadonlySet<string>;
}

export class GraphModel {
  public readonly nodes = new Map<NodeId, GraphModelNode>();
  public readonly edges = new Map<EdgeId, GraphModelEdge>();

  constructor(
    public readonly response: LiveBlastRadiusResponse
  ) {
    this.build();
  }

  /**
   * Returns the set of node IDs and edge IDs that are emphasized
   * (belong to the selected service/path).
   */
  public computeEmphasis(
    selectedServiceId: NodeId | null,
    selectedPathKey: string | null,
  ): { nodeIds: Set<NodeId>; edgeIds: Set<EdgeId> } {
    const nodeIds = new Set<NodeId>();
    const edgeIds = new Set<EdgeId>();

    if (selectedServiceId === null || selectedServiceId === undefined) return { nodeIds, edgeIds };

    const svc = this.response.services.find(s => s.service.id === selectedServiceId);
    if (!svc) return { nodeIds, edgeIds };

    const path = selectedPathKey
      ? svc.paths.find(p => p.pathKey === selectedPathKey) ?? svc.paths[0]
      : svc.paths[0];

    if (path) {
      for (const n of path.nodes) nodeIds.add(n.id);
      for (const e of path.canonicalEdges) edgeIds.add(e.id);
    }

    return { nodeIds, edgeIds };
  }

  private build() {
    const evidenceLookup = new Map<NodeId, EvidenceCatalogEntry>();
    for (const ev of this.response.evidenceCatalog) {
      evidenceLookup.set(ev.id, ev);
    }

    const { affectedVersionIds, services } = this.response;
    const affectedSet = new Set(affectedVersionIds);

    // Accumulate pathKeys per node and edge
    const nodePathKeys = new Map<NodeId, Set<string>>();
    const edgePathKeys = new Map<EdgeId, Set<string>>();

    const ensureNodePaths = (id: NodeId) => {
      if (!nodePathKeys.has(id)) nodePathKeys.set(id, new Set());
      return nodePathKeys.get(id)!;
    };
    const ensureEdgePaths = (id: EdgeId) => {
      if (!edgePathKeys.has(id)) edgePathKeys.set(id, new Set());
      return edgePathKeys.get(id)!;
    };

    // First pass: collect all path associations
    for (const service of services) {
      for (const path of service.paths) {
        for (const n of path.nodes) {
          ensureNodePaths(n.id).add(path.pathKey);
        }
        for (const e of path.canonicalEdges) {
          ensureEdgePaths(e.id).add(path.pathKey);
        }
      }
    }

    const resolveEvidence = (
      evidenceIds: readonly NodeId[],
      isSyntheticFallback: boolean,
    ): { state: EvidenceState, synthetic: boolean } => {
      let maxConfidence = 0;
      let hasSynthetic = isSyntheticFallback;
      let resolvedCount = 0;

      for (const evId of evidenceIds) {
        const ev = evidenceLookup.get(evId);
        if (ev) {
          resolvedCount++;
          if (ev.synthetic) hasSynthetic = true;
          maxConfidence = Math.max(maxConfidence, ev.confidence);
        }
      }

      if (resolvedCount === 0) {
        return { state: 'missing', synthetic: hasSynthetic };
      }

      const threshold = this.response.evidenceFunnel.highConfidenceThreshold;
      const state = maxConfidence >= threshold ? 'high-confidence' : 'verified';
      return { state, synthetic: hasSynthetic };
    };

    const addNode = (node: BlastRadiusNode, layer: number) => {
      if (this.nodes.has(node.id)) return;

      let type: GraphModelNode['type'] = 'package';
      if (node.kind === 'Service') {
        type = 'service';
      } else if (affectedSet.has(node.id)) {
        type = 'affected-root';
      }

      const ev = resolveEvidence(node.evidenceIds, node.synthetic);

      this.nodes.set(node.id, {
        id: node.id,
        node,
        type,
        evidenceState: ev.state,
        synthetic: ev.synthetic,
        pathKeys: nodePathKeys.get(node.id) ?? new Set(),
        layer,
      });
    };

    const addEdge = (edge: DependencyEdge) => {
      if (this.edges.has(edge.id)) return;

      const ev = resolveEvidence(edge.evidenceIds, false);

      this.edges.set(edge.id, {
        id: edge.id,
        edge,
        sourceId: edge.sourceId,
        targetId: edge.targetId,
        evidenceState: ev.state,
        synthetic: ev.synthetic,
        pathKeys: edgePathKeys.get(edge.id) ?? new Set(),
      });
    };

    // Second pass: build nodes and edges
    for (const service of services) {
      for (const path of service.paths) {
        path.nodes.forEach((n, i) => addNode(n, i));
        path.canonicalEdges.forEach(e => addEdge(e));
      }
    }
  }
}
