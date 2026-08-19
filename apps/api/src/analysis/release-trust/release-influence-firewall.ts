import type {
  EdgeId,
  NodeId,
} from "../../domain/schema.js";
import {
  RELEASE_INFLUENCE_EDGE_KINDS,
  RELEASE_INFLUENCE_NODE_KINDS,
  ReleaseFirewallInputError,
} from "./release-influence-types.js";
import type {
  AppliedReleaseFirewallOptions,
  ReleaseFirewallInput,
  ReleaseFirewallOptions,
  ReleaseFirewallResult,
  ReleaseInfluenceEdge,
  ReleaseInfluenceEdgeKind,
  ReleaseInfluenceNode,
  ReleaseInfluenceNodeKind,
  ReleaseInfluencePath,
  ReleaseNode,
  ReleaseRiskDisposition,
  ReleaseTrustDecision,
  ReleaseTrustFinding,
  ReleaseTrustFindingSeverity,
  ReleaseTrustVerdict,
} from "./release-influence-types.js";

const DEFAULT_OPTIONS: AppliedReleaseFirewallOptions = {
  maxDepth: 16,
  maxTraversalStatesPerRelease: 10_000,
  maxIncomingEdgesPerNode: 1_000,
  maxRiskPathsPerRelease: 100,
  maxFindingsPerRelease: 250,
  requireEvidence: true,
  untrustedDisposition: "block",
  unknownDisposition: "quarantine",
  crossBoundaryCacheDisposition: "block",
  unknownCacheBoundaryDisposition: "quarantine",
};

const NODE_KIND_SET = new Set<string>(
  RELEASE_INFLUENCE_NODE_KINDS,
);
const EDGE_KIND_SET = new Set<string>(
  RELEASE_INFLUENCE_EDGE_KINDS,
);
const TRUST_LEVEL_SET = new Set<string>([
  "trusted",
  "untrusted",
  "unknown",
]);
const TRUST_BOUNDARY_SET = new Set<string>([
  "same-trust-zone",
  "cross-trust-boundary",
  "unknown",
]);

function hasValidEvidenceIds(value: readonly NodeId[]): boolean {
  return (
    Array.isArray(value) &&
    value.every((evidenceId) => isValidId(evidenceId))
  );
}

interface IndexedGraph {
  readonly nodesById: ReadonlyMap<NodeId, ReleaseInfluenceNode>;
  readonly incomingByTargetId: ReadonlyMap<
    NodeId,
    readonly ReleaseInfluenceEdge[]
  >;
  readonly releases: readonly ReleaseNode[];
}

interface TraversalState {
  readonly currentNodeId: NodeId;
  /** Ordered from current node to the release. */
  readonly nodeIdsToRelease: readonly NodeId[];
  readonly edgeIdsToRelease: readonly EdgeId[];
  readonly visitedNodeIds: ReadonlySet<NodeId>;
}

function compareNumbers(left: number, right: number): number {
  return left - right;
}

function compareText(left: string, right: string): number {
  return left.localeCompare(right);
}

function readPositiveSafeInteger(
  value: number | undefined,
  fallback: number,
  name: keyof ReleaseFirewallOptions,
): number {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(
      `${String(name)} must be a positive safe integer`,
    );
  }

  return value;
}

function readDisposition(
  value: ReleaseRiskDisposition | undefined,
  fallback: ReleaseRiskDisposition,
): ReleaseRiskDisposition {
  return value ?? fallback;
}

function normalizeOptions(
  options: ReleaseFirewallOptions,
): AppliedReleaseFirewallOptions {
  return {
    maxDepth: readPositiveSafeInteger(
      options.maxDepth,
      DEFAULT_OPTIONS.maxDepth,
      "maxDepth",
    ),
    maxTraversalStatesPerRelease: readPositiveSafeInteger(
      options.maxTraversalStatesPerRelease,
      DEFAULT_OPTIONS.maxTraversalStatesPerRelease,
      "maxTraversalStatesPerRelease",
    ),
    maxIncomingEdgesPerNode: readPositiveSafeInteger(
      options.maxIncomingEdgesPerNode,
      DEFAULT_OPTIONS.maxIncomingEdgesPerNode,
      "maxIncomingEdgesPerNode",
    ),
    maxRiskPathsPerRelease: readPositiveSafeInteger(
      options.maxRiskPathsPerRelease,
      DEFAULT_OPTIONS.maxRiskPathsPerRelease,
      "maxRiskPathsPerRelease",
    ),
    maxFindingsPerRelease: readPositiveSafeInteger(
      options.maxFindingsPerRelease,
      DEFAULT_OPTIONS.maxFindingsPerRelease,
      "maxFindingsPerRelease",
    ),
    requireEvidence:
      options.requireEvidence ?? DEFAULT_OPTIONS.requireEvidence,
    untrustedDisposition: readDisposition(
      options.untrustedDisposition,
      DEFAULT_OPTIONS.untrustedDisposition,
    ),
    unknownDisposition: readDisposition(
      options.unknownDisposition,
      DEFAULT_OPTIONS.unknownDisposition,
    ),
    crossBoundaryCacheDisposition: readDisposition(
      options.crossBoundaryCacheDisposition,
      DEFAULT_OPTIONS.crossBoundaryCacheDisposition,
    ),
    unknownCacheBoundaryDisposition: readDisposition(
      options.unknownCacheBoundaryDisposition,
      DEFAULT_OPTIONS.unknownCacheBoundaryDisposition,
    ),
  };
}

function isValidId(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function isNonEmptyText(value: string): boolean {
  return value.trim().length > 0;
}

function validateNode(node: ReleaseInfluenceNode): void {
  if (
    !isValidId(node.id) ||
    !NODE_KIND_SET.has(node.kind) ||
    !TRUST_LEVEL_SET.has(node.trust) ||
    !hasValidEvidenceIds(node.evidenceIds) ||
    !isNonEmptyText(node.label) ||
    !Number.isSafeInteger(node.observedAt) ||
    node.observedAt < 0
  ) {
    throw new ReleaseFirewallInputError(
      "invalid-node",
      `Release influence node ${String(node.id)} is invalid`,
      node.id,
    );
  }

  if (node.kind === "release") {
    const { subject } = node;

    if (
      !isNonEmptyText(subject.ecosystem) ||
      !isNonEmptyText(subject.packageName) ||
      !isNonEmptyText(subject.version) ||
      (subject.artifactDigest !== undefined &&
        !isNonEmptyText(subject.artifactDigest))
    ) {
      throw new ReleaseFirewallInputError(
        "invalid-node",
        `Release node ${String(node.id)} has an invalid subject`,
        node.id,
      );
    }
  }
}

function validEndpointKinds(
  edgeKind: ReleaseInfluenceEdgeKind,
  sourceKind: ReleaseInfluenceNodeKind,
  targetKind: ReleaseInfluenceNodeKind,
): boolean {
  switch (edgeKind) {
    case "triggers":
    case "checks-out":
      return (
        sourceKind === "source-change" &&
        targetKind === "workflow-run"
      );

    case "writes-cache":
      return (
        (sourceKind === "workflow-run" ||
          sourceKind === "build") &&
        targetKind === "cache-entry"
      );

    case "restores-cache":
      return (
        sourceKind === "cache-entry" &&
        (targetKind === "workflow-run" ||
          targetKind === "build")
      );

    case "starts-build":
      return (
        sourceKind === "workflow-run" &&
        targetKind === "build"
      );

    case "mints-credential":
      return (
        (sourceKind === "workflow-run" ||
          sourceKind === "build") &&
        targetKind === "credential"
      );

    case "uses-credential":
      return (
        sourceKind === "credential" &&
        (targetKind === "workflow-run" ||
          targetKind === "build")
      );

    case "produces":
      return (
        (sourceKind === "workflow-run" ||
          sourceKind === "build") &&
        targetKind === "artifact"
      );

    case "attests":
      return (
        sourceKind === "attestation" &&
        (targetKind === "artifact" ||
          targetKind === "release")
      );

    case "publishes":
      return (
        sourceKind === "artifact" &&
        targetKind === "release"
      );

    case "authorizes-publish":
      return (
        sourceKind === "credential" &&
        targetKind === "release"
      );

    case "influences":
      return sourceKind !== "release";
  }
}

function validateAndIndexGraph(
  input: ReleaseFirewallInput,
): IndexedGraph {
  if (input.releaseNodeIds.length === 0) {
    throw new ReleaseFirewallInputError(
      "empty-release-set",
      "At least one release node must be evaluated",
    );
  }

  const nodesById = new Map<NodeId, ReleaseInfluenceNode>();

  for (const node of input.graph.nodes) {
    validateNode(node);

    if (nodesById.has(node.id)) {
      throw new ReleaseFirewallInputError(
        "duplicate-node-id",
        `Duplicate release influence node ${String(node.id)}`,
        node.id,
      );
    }

    nodesById.set(node.id, node);
  }

  const edgeIds = new Set<EdgeId>();
  const incomingByTargetId =
    new Map<NodeId, ReleaseInfluenceEdge[]>();

  for (const edge of input.graph.edges) {
    if (
      !isValidId(edge.id) ||
      !EDGE_KIND_SET.has(edge.kind) ||
      !isValidId(edge.sourceId) ||
      !isValidId(edge.targetId) ||
      edge.sourceId === edge.targetId ||
      !TRUST_LEVEL_SET.has(edge.trust) ||
      !TRUST_BOUNDARY_SET.has(edge.boundary) ||
      !hasValidEvidenceIds(edge.evidenceIds) ||
      !Number.isSafeInteger(edge.observedAt) ||
      edge.observedAt < 0
    ) {
      throw new ReleaseFirewallInputError(
        "invalid-edge",
        `Release influence edge ${String(edge.id)} is invalid`,
        undefined,
        edge.id,
      );
    }

    if (edgeIds.has(edge.id)) {
      throw new ReleaseFirewallInputError(
        "duplicate-edge-id",
        `Duplicate release influence edge ${String(edge.id)}`,
        undefined,
        edge.id,
      );
    }

    edgeIds.add(edge.id);

    const source = nodesById.get(edge.sourceId);
    const target = nodesById.get(edge.targetId);

    if (source === undefined || target === undefined) {
      throw new ReleaseFirewallInputError(
        "missing-edge-endpoint",
        `Edge ${String(edge.id)} references a missing endpoint`,
        source === undefined ? edge.sourceId : edge.targetId,
        edge.id,
      );
    }

    if (!validEndpointKinds(edge.kind, source.kind, target.kind)) {
      throw new ReleaseFirewallInputError(
        "invalid-edge-endpoints",
        `Edge ${String(edge.id)} kind ${edge.kind} cannot connect ` +
          `${source.kind} to ${target.kind}`,
        undefined,
        edge.id,
      );
    }

    const incoming = incomingByTargetId.get(edge.targetId) ?? [];
    incoming.push(edge);
    incomingByTargetId.set(edge.targetId, incoming);
  }

  for (const incoming of incomingByTargetId.values()) {
    incoming.sort((left, right) => left.id - right.id);
  }

  const seenReleaseIds = new Set<NodeId>();
  const releases: ReleaseNode[] = [];

  for (const releaseNodeId of input.releaseNodeIds) {
    if (seenReleaseIds.has(releaseNodeId)) {
      throw new ReleaseFirewallInputError(
        "duplicate-release-id",
        `Release ${String(releaseNodeId)} was requested more than once`,
        releaseNodeId,
      );
    }

    seenReleaseIds.add(releaseNodeId);
    const node = nodesById.get(releaseNodeId);

    if (node === undefined) {
      throw new ReleaseFirewallInputError(
        "missing-release-node",
        `Release node ${String(releaseNodeId)} does not exist`,
        releaseNodeId,
      );
    }

    if (node.kind !== "release") {
      throw new ReleaseFirewallInputError(
        "wrong-release-node-kind",
        `Node ${String(releaseNodeId)} is ${node.kind}, not release`,
        releaseNodeId,
      );
    }

    releases.push(node);
  }

  releases.sort((left, right) => left.id - right.id);

  return {
    nodesById,
    incomingByTargetId,
    releases,
  };
}

function severityFromDisposition(
  disposition: ReleaseRiskDisposition,
): ReleaseTrustFindingSeverity {
  return disposition;
}

function createPath(
  nodeIds: readonly NodeId[],
  edgeIds: readonly EdgeId[],
): ReleaseInfluencePath {
  return {
    pathKey: JSON.stringify([nodeIds, edgeIds]),
    nodeIds: [...nodeIds],
    edgeIds: [...edgeIds],
    depth: edgeIds.length,
  };
}

function findingSortRank(
  severity: ReleaseTrustFindingSeverity,
): number {
  switch (severity) {
    case "block":
      return 0;
    case "quarantine":
      return 1;
    case "warning":
      return 2;
  }
}

function verdictForFindings(
  findings: readonly ReleaseTrustFinding[],
  truncated: boolean,
): ReleaseTrustVerdict {
  if (findings.some((finding) => finding.severity === "block")) {
    return "block";
  }

  if (
    truncated ||
    findings.some(
      (finding) => finding.severity === "quarantine",
    )
  ) {
    return "quarantine";
  }

  return "allow";
}

function reasonForVerdict(verdict: ReleaseTrustVerdict): string {
  switch (verdict) {
    case "allow":
      return "Every inspected release influence was trusted and evidence-backed.";
    case "quarantine":
      return "The release has unknown, incomplete, or truncated influence evidence and requires review.";
    case "block":
      return "An untrusted or forbidden cross-boundary influence can reach the release.";
  }
}

function evaluateRelease(
  release: ReleaseNode,
  graph: IndexedGraph,
  options: AppliedReleaseFirewallOptions,
): ReleaseTrustDecision {
  const findings: ReleaseTrustFinding[] = [];
  const findingKeys = new Set<string>();
  const riskPaths = new Map<string, ReleaseInfluencePath>();
  const inspectedNodeIds = new Set<NodeId>([release.id]);
  const inspectedEdgeIds = new Set<EdgeId>();
  let traversalStateCount = 1;
  let truncated = false;
  let stopTraversal = false;
  let findingLimitReached = false;
  let pathLimitReached = false;

  const addFinding = (
    finding: ReleaseTrustFinding,
    path?: ReleaseInfluencePath,
  ): void => {
    const key = JSON.stringify([
      finding.code,
      finding.nodeId ?? null,
      finding.edgeId ?? null,
      finding.pathKey ?? null,
    ]);

    if (findingKeys.has(key)) {
      return;
    }

    if (
      findings.length >= options.maxFindingsPerRelease - 1 &&
      finding.code !== "finding-limit-reached"
    ) {
      truncated = true;
      stopTraversal = true;

      if (!findingLimitReached) {
        findingLimitReached = true;
        addFinding({
          code: "finding-limit-reached",
          severity: "quarantine",
          message:
            `Finding limit of ${String(options.maxFindingsPerRelease)} ` +
            "was reached; release evaluation stopped.",
        });
      }

      return;
    }

    findingKeys.add(key);
    findings.push(finding);

    if (
      path !== undefined &&
      finding.severity !== "warning" &&
      !riskPaths.has(path.pathKey)
    ) {
      if (riskPaths.size >= options.maxRiskPathsPerRelease) {
        truncated = true;

        if (!pathLimitReached) {
          pathLimitReached = true;
          addFinding({
            code: "risk-path-limit-reached",
            severity: "quarantine",
            message:
              `Risk-path limit of ${String(options.maxRiskPathsPerRelease)} ` +
              "was reached.",
          });
        }
      } else {
        riskPaths.set(path.pathKey, path);
      }
    }
  };

  if (options.requireEvidence && release.evidenceIds.length === 0) {
    addFinding({
      code: "missing-node-evidence",
      severity: "quarantine",
      message: `Release node ${String(release.id)} has no evidence.`,
      nodeId: release.id,
    });
  }

  const releaseIncoming =
    graph.incomingByTargetId.get(release.id) ?? [];

  if (!releaseIncoming.some((edge) => edge.kind === "publishes")) {
    addFinding({
      code: "missing-artifact-publication",
      severity: "quarantine",
      message:
        `Release node ${String(release.id)} has no artifact publication ` +
        "path and cannot be safely allowed.",
      nodeId: release.id,
    });
  }

  const queue: TraversalState[] = [
    {
      currentNodeId: release.id,
      nodeIdsToRelease: [release.id],
      edgeIdsToRelease: [],
      visitedNodeIds: new Set([release.id]),
    },
  ];

  for (
    let queueIndex = 0;
    queueIndex < queue.length && !stopTraversal;
    queueIndex += 1
  ) {
    const state = queue[queueIndex];
    const incoming =
      graph.incomingByTargetId.get(state.currentNodeId) ?? [];

    if (
      state.edgeIdsToRelease.length >= options.maxDepth &&
      incoming.length > 0
    ) {
      truncated = true;
      addFinding({
        code: "depth-limit-reached",
        severity: "quarantine",
        message:
          `Depth limit of ${String(options.maxDepth)} was reached at ` +
          `node ${String(state.currentNodeId)}.`,
        nodeId: state.currentNodeId,
      });
      continue;
    }

    const boundedIncoming = incoming.slice(
      0,
      options.maxIncomingEdgesPerNode,
    );

    if (incoming.length > boundedIncoming.length) {
      truncated = true;
      addFinding({
        code: "incoming-edge-limit-reached",
        severity: "quarantine",
        message:
          `Incoming-edge limit of ${String(options.maxIncomingEdgesPerNode)} ` +
          `was reached at node ${String(state.currentNodeId)}.`,
        nodeId: state.currentNodeId,
      });
    }

    for (const edge of boundedIncoming) {
      if (stopTraversal) {
        break;
      }

      inspectedEdgeIds.add(edge.id);
      const source = graph.nodesById.get(edge.sourceId);

      if (source === undefined) {
        throw new Error(
          `Validated edge ${String(edge.id)} lost source node`,
        );
      }

      if (state.visitedNodeIds.has(source.id)) {
        addFinding({
          code: "cycle-skipped",
          severity: "warning",
          message:
            `Cycle through node ${String(source.id)} was skipped.`,
          nodeId: source.id,
          edgeId: edge.id,
        });
        continue;
      }

      const path = createPath(
        [source.id, ...state.nodeIdsToRelease],
        [edge.id, ...state.edgeIdsToRelease],
      );
      inspectedNodeIds.add(source.id);

      if (options.requireEvidence && edge.evidenceIds.length === 0) {
        addFinding(
          {
            code: "missing-edge-evidence",
            severity: "quarantine",
            message: `Influence edge ${String(edge.id)} has no evidence.`,
            edgeId: edge.id,
            pathKey: path.pathKey,
          },
          path,
        );
      }

      if (edge.trust === "untrusted") {
        addFinding(
          {
            code: "untrusted-edge",
            severity: severityFromDisposition(
              options.untrustedDisposition,
            ),
            message: `Untrusted ${edge.kind} edge can influence the release.`,
            edgeId: edge.id,
            pathKey: path.pathKey,
          },
          path,
        );
      } else if (edge.trust === "unknown") {
        addFinding(
          {
            code: "unknown-edge",
            severity: severityFromDisposition(
              options.unknownDisposition,
            ),
            message: `Trust is unknown for ${edge.kind} edge ${String(edge.id)}.`,
            edgeId: edge.id,
            pathKey: path.pathKey,
          },
          path,
        );
      }

      const cacheEdge =
        edge.kind === "writes-cache" ||
        edge.kind === "restores-cache";

      if (
        cacheEdge &&
        edge.boundary === "cross-trust-boundary"
      ) {
        addFinding(
          {
            code: "cross-boundary-cache",
            severity: severityFromDisposition(
              options.crossBoundaryCacheDisposition,
            ),
            message:
              `Cache edge ${String(edge.id)} crosses a trust boundary ` +
              "and can influence the release.",
            edgeId: edge.id,
            pathKey: path.pathKey,
          },
          path,
        );
      } else if (
        cacheEdge &&
        edge.boundary === "unknown"
      ) {
        addFinding(
          {
            code: "unknown-cache-boundary",
            severity: severityFromDisposition(
              options.unknownCacheBoundaryDisposition,
            ),
            message:
              `Cache edge ${String(edge.id)} has an unknown trust boundary.`,
            edgeId: edge.id,
            pathKey: path.pathKey,
          },
          path,
        );
      }

      if (options.requireEvidence && source.evidenceIds.length === 0) {
        addFinding(
          {
            code: "missing-node-evidence",
            severity: "quarantine",
            message: `Influence node ${String(source.id)} has no evidence.`,
            nodeId: source.id,
            pathKey: path.pathKey,
          },
          path,
        );
      }

      if (source.trust === "untrusted") {
        addFinding(
          {
            code: "untrusted-node",
            severity: severityFromDisposition(
              options.untrustedDisposition,
            ),
            message:
              `Untrusted ${source.kind} node ${String(source.id)} can ` +
              "influence the release.",
            nodeId: source.id,
            pathKey: path.pathKey,
          },
          path,
        );
      } else if (source.trust === "unknown") {
        addFinding(
          {
            code: "unknown-node",
            severity: severityFromDisposition(
              options.unknownDisposition,
            ),
            message:
              `Trust is unknown for ${source.kind} node ${String(source.id)}.`,
            nodeId: source.id,
            pathKey: path.pathKey,
          },
          path,
        );
      }

      if (
        traversalStateCount >=
        options.maxTraversalStatesPerRelease
      ) {
        truncated = true;
        stopTraversal = true;
        addFinding({
          code: "traversal-state-limit-reached",
          severity: "quarantine",
          message:
            `Traversal-state limit of ` +
            `${String(options.maxTraversalStatesPerRelease)} was reached.`,
        });
        break;
      }

      traversalStateCount += 1;
      queue.push({
        currentNodeId: source.id,
        nodeIdsToRelease: path.nodeIds,
        edgeIdsToRelease: path.edgeIds,
        visitedNodeIds: new Set([
          ...state.visitedNodeIds,
          source.id,
        ]),
      });
    }
  }

  findings.sort((left, right) =>
    findingSortRank(left.severity) - findingSortRank(right.severity) ||
    compareText(left.code, right.code) ||
    compareNumbers(left.nodeId ?? 0, right.nodeId ?? 0) ||
    compareNumbers(left.edgeId ?? 0, right.edgeId ?? 0) ||
    compareText(left.pathKey ?? "", right.pathKey ?? ""),
  );

  const sortedPaths = [...riskPaths.values()].sort(
    (left, right) => compareText(left.pathKey, right.pathKey),
  );
  const verdict = verdictForFindings(findings, truncated);

  return {
    releaseNodeId: release.id,
    subject: { ...release.subject },
    verdict,
    reason: reasonForVerdict(verdict),
    findings,
    riskPaths: sortedPaths,
    truncated,
    inspectedNodeCount: inspectedNodeIds.size,
    inspectedEdgeCount: inspectedEdgeIds.size,
  };
}

/**
 * Evaluates one or many package releases without assuming an ecosystem,
 * registry, package name, or fixed graph size.
 *
 * Influence edges point from cause to effect. Evaluation walks backward from
 * each release and fails closed when evidence, trust, or traversal coverage is
 * incomplete. A legitimate publisher identity never overrides an unsafe
 * causal build path.
 */
export function evaluateReleaseFirewall(
  input: ReleaseFirewallInput,
  options: ReleaseFirewallOptions = {},
): ReleaseFirewallResult {
  const appliedOptions = normalizeOptions(options);
  const indexedGraph = validateAndIndexGraph(input);
  const decisions = indexedGraph.releases.map((release) =>
    evaluateRelease(release, indexedGraph, appliedOptions),
  );

  return {
    decisions,
    summary: {
      evaluated: decisions.length,
      allowed: decisions.filter(
        (decision) => decision.verdict === "allow",
      ).length,
      quarantined: decisions.filter(
        (decision) => decision.verdict === "quarantine",
      ).length,
      blocked: decisions.filter(
        (decision) => decision.verdict === "block",
      ).length,
      truncated: decisions.filter(
        (decision) => decision.truncated,
      ).length,
    },
    options: appliedOptions,
  };
}
