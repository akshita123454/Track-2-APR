import type {
  EdgeId,
  EvidenceNode,
  GraphNode,
  NodeId,
  StandardCanonicalEdge,
} from "../../domain/schema.js";

export const AUTHORITY_RELATION_KINDS = [
  "MAINTAINS",
  "MEMBER_OF",
  "OWNS",
  "TRIGGERS",
  "CONTROLS",
  "CAN_ACCESS",
  "CAN_PUBLISH",
] as const;

export type AuthorityRelationKind =
  (typeof AUTHORITY_RELATION_KINDS)[number];

export type AuthorityCapability =
  | "package-maintenance"
  | "organization-membership"
  | "asset-ownership"
  | "workflow-trigger"
  | "credential-control"
  | "credential-access"
  | "package-publish";

export type AuthorityCanonicalEdge =
  StandardCanonicalEdge & {
    readonly kind: AuthorityRelationKind;
  };

export interface AuthorityHop {
  readonly targetNode: GraphNode;
  readonly canonicalEdge: AuthorityCanonicalEdge;
}

export interface ReadonlyAuthorityGraphReader {
  getNode(nodeId: NodeId): Promise<GraphNode | null>;

  findOutgoingAuthorityHops(
    nodeId: NodeId,
  ): Promise<readonly AuthorityHop[]>;

  getEvidence(
    evidenceIds: readonly NodeId[],
  ): Promise<readonly EvidenceNode[]>;
}

/**
 * Explicitly supplied starting point for Wave 2 authority analysis.
 *
 * Evidence establishes why the seed is relevant to an incident. It does not
 * automatically prove that every structurally reachable authority was used.
 */
export interface Wave2AuthoritySeed {
  readonly nodeId: NodeId;
  readonly evidenceIds: readonly NodeId[];
}

export interface Wave2AuthorityOptions {
  readonly maxDepth?: number;
  readonly maxTraversalStates?: number;
  readonly maxOutgoingEdgesPerNode?: number;
  readonly maxTargets?: number;
  readonly maxPathsPerTarget?: number;
  readonly maxWarnings?: number;
}

export interface AppliedWave2AuthorityLimits {
  readonly maxDepth: number;
  readonly maxTraversalStates: number;
  readonly maxOutgoingEdgesPerNode: number;
  readonly maxTargets: number;
  readonly maxPathsPerTarget: number;
  readonly maxWarnings: number;
}

export interface Wave2AuthorityPath {
  readonly pathKey: string;
  readonly seedNodeId: NodeId;
  readonly targetNodeId: NodeId;

  /**
   * Nodes in canonical forward authority order.
   */
  readonly nodes: readonly GraphNode[];

  /**
   * Canonical, non-derived authority edges supporting this path.
   */
  readonly canonicalEdges:
    readonly AuthorityCanonicalEdge[];

  readonly capability: AuthorityCapability;
  readonly depth: number;

  /**
   * Sorted unique Evidence IDs from the seed and canonical path edges.
   */
  readonly evidenceIds: readonly NodeId[];
}

export interface Wave2AuthorityTarget {
  readonly targetNode: GraphNode;

  /**
   * Structural reachability is a candidate, not proof of malicious use,
   * credential theft, publishing, execution, or compromise.
   */
  readonly conclusion:
    "authority-reachability-candidate";

  readonly minimumDepth: number;
  readonly paths: readonly Wave2AuthorityPath[];
  readonly uncertainties: readonly string[];
}

export type Wave2AuthorityWarningCode =
  | "missing-seed-node"
  | "unsupported-seed-kind"
  | "missing-seed-evidence"
  | "invalid-authority-hop"
  | "cycle-skipped"
  | "depth-limit-reached"
  | "traversal-state-limit-reached"
  | "outgoing-edge-limit-reached"
  | "target-limit-reached"
  | "paths-per-target-limit-reached"
  | "warning-limit-reached";

export interface Wave2AuthorityWarning {
  readonly code: Wave2AuthorityWarningCode;
  readonly message: string;
  readonly nodeId?: NodeId;
  readonly edgeId?: EdgeId;
  readonly pathNodeIds?: readonly NodeId[];
}

export interface Wave2AuthorityResult {
  readonly seedNodeIds: readonly NodeId[];
  readonly targets: readonly Wave2AuthorityTarget[];
  readonly totalPathCount: number;
  readonly truncated: boolean;
  readonly limits: AppliedWave2AuthorityLimits;
  readonly warnings:
    readonly Wave2AuthorityWarning[];
}

interface NormalizedSeed {
  readonly nodeId: NodeId;
  readonly evidenceIds: readonly NodeId[];
}

interface TraversalState {
  readonly seed: NormalizedSeed;
  readonly currentNode: GraphNode;
  readonly nodes: readonly GraphNode[];
  readonly canonicalEdges:
    readonly AuthorityCanonicalEdge[];
  readonly visitedNodeIds: ReadonlySet<NodeId>;
}

interface MutableTarget {
  readonly targetNode: GraphNode;
  readonly paths: Wave2AuthorityPath[];
  readonly pathKeys: Set<string>;
}

const DEFAULT_LIMITS: AppliedWave2AuthorityLimits = {
  maxDepth: 8,
  maxTraversalStates: 5_000,
  maxOutgoingEdgesPerNode: 500,
  maxTargets: 500,
  maxPathsPerTarget: 10,
  maxWarnings: 100,
};

const TARGET_UNCERTAINTIES: readonly string[] = [
  "Structural authority reachability does not prove that the authority was exercised.",
  "This result does not prove credential theft, package publication, execution, or compromise.",
];

const SUPPORTED_SEED_KINDS: ReadonlySet<
  GraphNode["kind"]
> = new Set([
  "Maintainer",
  "Organization",
  "Repository",
  "CIWorkflow",
  "Credential",
]);

const AUTHORITY_RELATION_KIND_SET:
  ReadonlySet<string> =
    new Set(AUTHORITY_RELATION_KINDS);

function compareText(
  left: string,
  right: string,
): number {
  return left.localeCompare(right);
}

function compareNodeIds(
  left: NodeId,
  right: NodeId,
): number {
  return left - right;
}

function readPositiveSafeInteger(
  value: number | undefined,
  fallback: number,
  optionName: keyof Wave2AuthorityOptions,
): number {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(
      `${String(optionName)} must be a positive safe integer`,
    );
  }

  return value;
}

function normalizeLimits(
  options: Wave2AuthorityOptions,
): AppliedWave2AuthorityLimits {
  return {
    maxDepth: readPositiveSafeInteger(
      options.maxDepth,
      DEFAULT_LIMITS.maxDepth,
      "maxDepth",
    ),
    maxTraversalStates: readPositiveSafeInteger(
      options.maxTraversalStates,
      DEFAULT_LIMITS.maxTraversalStates,
      "maxTraversalStates",
    ),
    maxOutgoingEdgesPerNode:
      readPositiveSafeInteger(
        options.maxOutgoingEdgesPerNode,
        DEFAULT_LIMITS.maxOutgoingEdgesPerNode,
        "maxOutgoingEdgesPerNode",
      ),
    maxTargets: readPositiveSafeInteger(
      options.maxTargets,
      DEFAULT_LIMITS.maxTargets,
      "maxTargets",
    ),
    maxPathsPerTarget: readPositiveSafeInteger(
      options.maxPathsPerTarget,
      DEFAULT_LIMITS.maxPathsPerTarget,
      "maxPathsPerTarget",
    ),
    maxWarnings: readPositiveSafeInteger(
      options.maxWarnings,
      DEFAULT_LIMITS.maxWarnings,
      "maxWarnings",
    ),
  };
}

function uniqueSortedNodeIds(
  ids: readonly NodeId[],
): readonly NodeId[] {
  return [...new Set(ids)].sort(compareNodeIds);
}

function normalizeSeeds(
  seeds: readonly Wave2AuthoritySeed[],
): readonly NormalizedSeed[] {
  const evidenceByNodeId =
    new Map<NodeId, Set<NodeId>>();

  for (const seed of seeds) {
    let evidenceIds =
      evidenceByNodeId.get(seed.nodeId);

    if (evidenceIds === undefined) {
      evidenceIds = new Set<NodeId>();
      evidenceByNodeId.set(
        seed.nodeId,
        evidenceIds,
      );
    }

    for (const evidenceId of seed.evidenceIds) {
      evidenceIds.add(evidenceId);
    }
  }

  return [...evidenceByNodeId.entries()]
    .map(([nodeId, evidenceIds]) => ({
      nodeId,
      evidenceIds: [...evidenceIds].sort(
        compareNodeIds,
      ),
    }))
    .sort((left, right) =>
      compareNodeIds(
        left.nodeId,
        right.nodeId,
      ),
    );
}

function capabilityForRelation(
  kind: AuthorityRelationKind,
): AuthorityCapability {
  switch (kind) {
    case "MAINTAINS":
      return "package-maintenance";
    case "MEMBER_OF":
      return "organization-membership";
    case "OWNS":
      return "asset-ownership";
    case "TRIGGERS":
      return "workflow-trigger";
    case "CONTROLS":
      return "credential-control";
    case "CAN_ACCESS":
      return "credential-access";
    case "CAN_PUBLISH":
      return "package-publish";
  }
}

function isAuthorityRelationKind(
  kind: string,
): kind is AuthorityRelationKind {
  return AUTHORITY_RELATION_KIND_SET.has(kind);
}

function isValidAuthorityTransition(
  source: GraphNode,
  target: GraphNode,
  edge: AuthorityCanonicalEdge,
): boolean {
  if (
    !isAuthorityRelationKind(edge.kind) ||
    edge.derived !== false ||
    edge.sourceId !== source.id ||
    edge.targetId !== target.id ||
    edge.evidenceIds.length === 0
  ) {
    return false;
  }

  switch (edge.kind) {
    case "MAINTAINS":
      return (
        source.kind === "Maintainer" &&
        target.kind === "Package"
      );

    case "MEMBER_OF":
      return (
        source.kind === "Maintainer" &&
        target.kind === "Organization"
      );

    case "OWNS":
      return (
        source.kind === "Organization" &&
        (
          target.kind === "Package" ||
          target.kind === "Repository" ||
          target.kind === "Service"
        )
      );

    case "TRIGGERS":
      return (
        source.kind === "Repository" &&
        target.kind === "CIWorkflow"
      );

    case "CONTROLS":
      return (
        (
          source.kind === "Maintainer" ||
          source.kind === "Organization"
        ) &&
        target.kind === "Credential"
      );

    case "CAN_ACCESS":
      return (
        source.kind === "CIWorkflow" &&
        target.kind === "Credential"
      );

    case "CAN_PUBLISH":
      return (
        source.kind === "Credential" &&
        target.kind === "Package"
      );
  }
}

function createTraversalKey(
  seedNodeId: NodeId,
  edges: readonly AuthorityCanonicalEdge[],
): string {
  return JSON.stringify([
    seedNodeId,
    ...edges.map((edge) => edge.id),
  ]);
}

function createPathKey(
  seedNodeId: NodeId,
  targetNodeId: NodeId,
  edges: readonly AuthorityCanonicalEdge[],
): string {
  return JSON.stringify([
    seedNodeId,
    targetNodeId,
    ...edges.map((edge) => edge.id),
  ]);
}

function collectPathEvidence(
  seed: NormalizedSeed,
  edges: readonly AuthorityCanonicalEdge[],
): readonly NodeId[] {
  return uniqueSortedNodeIds([
    ...seed.evidenceIds,
    ...edges.flatMap(
      (edge) => edge.evidenceIds,
    ),
  ]);
}

function createPath(
  state: TraversalState,
): Wave2AuthorityPath {
  const lastEdge =
    state.canonicalEdges[
      state.canonicalEdges.length - 1
    ];

  if (lastEdge === undefined) {
    throw new Error(
      "Wave 2 target path requires at least one authority edge",
    );
  }

  return {
    pathKey: createPathKey(
      state.seed.nodeId,
      state.currentNode.id,
      state.canonicalEdges,
    ),
    seedNodeId: state.seed.nodeId,
    targetNodeId: state.currentNode.id,
    nodes: [...state.nodes],
    canonicalEdges: [
      ...state.canonicalEdges,
    ],
    capability: capabilityForRelation(
      lastEdge.kind,
    ),
    depth: state.canonicalEdges.length,
    evidenceIds: collectPathEvidence(
      state.seed,
      state.canonicalEdges,
    ),
  };
}

function warningKey(
  warning: Wave2AuthorityWarning,
): string {
  return JSON.stringify([
    warning.code,
    warning.message,
    warning.nodeId ?? null,
    warning.edgeId ?? null,
    warning.pathNodeIds ?? [],
  ]);
}

function compareWarnings(
  left: Wave2AuthorityWarning,
  right: Wave2AuthorityWarning,
): number {
  return (
    compareText(left.code, right.code) ||
    compareNodeIds(
      left.nodeId ?? 0,
      right.nodeId ?? 0,
    ) ||
    (left.edgeId ?? 0) -
      (right.edgeId ?? 0) ||
    compareText(
      left.pathNodeIds
        ?.map((nodeId) => String(nodeId))
        .join(">") ?? "",
      right.pathNodeIds
        ?.map((nodeId) => String(nodeId))
        .join(">") ?? "",
    ) ||
    compareText(left.message, right.message)
  );
}

function compareHops(
  left: AuthorityHop,
  right: AuthorityHop,
): number {
  return (
    left.canonicalEdge.id -
      right.canonicalEdge.id ||
    compareNodeIds(
      left.targetNode.id,
      right.targetNode.id,
    )
  );
}

/**
 * Calculates structurally reachable Wave 2 authority.
 *
 * The result describes graph-backed authority candidates only. It must not be
 * presented as confirmed credential theft, malicious publishing, execution,
 * lateral movement, or compromise.
 */
export async function analyzeWave2Authority(
  reader: ReadonlyAuthorityGraphReader,
  seeds: readonly Wave2AuthoritySeed[],
  options: Wave2AuthorityOptions = {},
): Promise<Wave2AuthorityResult> {
  const limits = normalizeLimits(options);
  const normalizedSeeds = normalizeSeeds(seeds);

  const warnings: Wave2AuthorityWarning[] = [];
  const recordedWarningKeys = new Set<string>();
  const targetsById =
    new Map<NodeId, MutableTarget>();
  const hopCache =
    new Map<NodeId, readonly AuthorityHop[]>();
  const enqueuedTraversalKeys =
    new Set<string>();

  let totalPathCount = 0;
  let admittedTraversalStates = 0;
  let truncated = false;
  let warningLimitReached = false;
  let stopTraversal = false;

  const addWarning = (
    warning: Wave2AuthorityWarning,
  ): void => {
    const key = warningKey(warning);

    if (
      recordedWarningKeys.has(key) ||
      warningLimitReached
    ) {
      return;
    }

    const maximumRegularWarnings =
      limits.maxWarnings - 1;

    if (
      warnings.length >=
      maximumRegularWarnings
    ) {
      warningLimitReached = true;
      truncated = true;
      stopTraversal = true;

      const notification:
        Wave2AuthorityWarning = {
          code: "warning-limit-reached",
          message:
            `Warning limit of ${limits.maxWarnings} ` +
            "was reached; traversal stopped",
        };

      recordedWarningKeys.add(
        warningKey(notification),
      );
      warnings.push(notification);
      return;
    }

    recordedWarningKeys.add(key);
    warnings.push(warning);
  };

  const admitTraversalState = (
    nodeId: NodeId,
    pathNodeIds: readonly NodeId[],
  ): boolean => {
    if (
      admittedTraversalStates <
      limits.maxTraversalStates
    ) {
      admittedTraversalStates += 1;
      return true;
    }

    truncated = true;
    addWarning({
      code: "traversal-state-limit-reached",
      message:
        `Traversal state limit of ` +
        `${limits.maxTraversalStates} was reached`,
      nodeId,
      pathNodeIds,
    });
    stopTraversal = true;
    return false;
  };

  const findSortedHops = async (
    nodeId: NodeId,
  ): Promise<readonly AuthorityHop[]> => {
    const cached = hopCache.get(nodeId);

    if (cached !== undefined) {
      return cached;
    }

    const hops = [
      ...(await reader.findOutgoingAuthorityHops(
        nodeId,
      )),
    ].sort(compareHops);

    hopCache.set(nodeId, hops);
    return hops;
  };

  const retainTargetPath = (
    state: TraversalState,
  ): void => {
    const path = createPath(state);
    let target =
      targetsById.get(state.currentNode.id);

    if (
      target !== undefined &&
      target.pathKeys.has(path.pathKey)
    ) {
      return;
    }

    if (
      target === undefined &&
      targetsById.size >= limits.maxTargets
    ) {
      truncated = true;
      addWarning({
        code: "target-limit-reached",
        message:
          `Authority target limit of ` +
          `${limits.maxTargets} was reached`,
        nodeId: state.currentNode.id,
        pathNodeIds: state.nodes.map(
          (node) => node.id,
        ),
      });
      stopTraversal = true;
      return;
    }

    if (
      target !== undefined &&
      target.paths.length >=
        limits.maxPathsPerTarget
    ) {
      truncated = true;
      addWarning({
        code:
          "paths-per-target-limit-reached",
        message:
          `Path limit of ` +
          `${limits.maxPathsPerTarget} was reached ` +
          `for authority target ` +
          `${String(state.currentNode.id)}`,
        nodeId: state.currentNode.id,
        pathNodeIds: state.nodes.map(
          (node) => node.id,
        ),
      });
      return;
    }

    if (target === undefined) {
      target = {
        targetNode: state.currentNode,
        paths: [],
        pathKeys: new Set<string>(),
      };
      targetsById.set(
        state.currentNode.id,
        target,
      );
    }

    target.pathKeys.add(path.pathKey);
    target.paths.push(path);
    totalPathCount += 1;
  };

  rootTraversal:
  for (const seed of normalizedSeeds) {
    if (stopTraversal) {
      break;
    }

    if (seed.evidenceIds.length === 0) {
      addWarning({
        code: "missing-seed-evidence",
        message:
          `Wave 2 seed ${String(seed.nodeId)} ` +
          "has no supporting Evidence IDs",
        nodeId: seed.nodeId,
      });

      if (stopTraversal) {
        break;
      }

      continue;
    }

    const rootNode =
      await reader.getNode(seed.nodeId);

    if (rootNode === null) {
      addWarning({
        code: "missing-seed-node",
        message:
          `Wave 2 seed node ` +
          `${String(seed.nodeId)} was not found`,
        nodeId: seed.nodeId,
      });

      if (stopTraversal) {
        break;
      }

      continue;
    }

    if (
      !SUPPORTED_SEED_KINDS.has(rootNode.kind)
    ) {
      addWarning({
        code: "unsupported-seed-kind",
        message:
          `Node ${String(rootNode.id)} of kind ` +
          `${rootNode.kind} cannot seed Wave 2 authority`,
        nodeId: rootNode.id,
      });

      if (stopTraversal) {
        break;
      }

      continue;
    }

    if (
      !admitTraversalState(
        rootNode.id,
        [rootNode.id],
      )
    ) {
      break;
    }

    const rootTraversalKey =
      createTraversalKey(seed.nodeId, []);

    enqueuedTraversalKeys.add(
      rootTraversalKey,
    );

    const queue: TraversalState[] = [
      {
        seed,
        currentNode: rootNode,
        nodes: [rootNode],
        canonicalEdges: [],
        visitedNodeIds:
          new Set([rootNode.id]),
      },
    ];

    let queueIndex = 0;

    while (queueIndex < queue.length) {
      if (stopTraversal) {
        break rootTraversal;
      }

      const state = queue[queueIndex];
      queueIndex += 1;

      if (state === undefined) {
        continue;
      }

      if (state.canonicalEdges.length > 0) {
        retainTargetPath(state);

        if (stopTraversal) {
          break rootTraversal;
        }
      }

      const allHops = await findSortedHops(
        state.currentNode.id,
      );

      let hops = allHops;

      if (
        allHops.length >
        limits.maxOutgoingEdgesPerNode
      ) {
        truncated = true;
        addWarning({
          code: "outgoing-edge-limit-reached",
          message:
            `Outgoing authority edge limit of ` +
            `${limits.maxOutgoingEdgesPerNode} was ` +
            `reached for node ` +
            `${String(state.currentNode.id)}`,
          nodeId: state.currentNode.id,
          pathNodeIds: state.nodes.map(
            (node) => node.id,
          ),
        });

        if (stopTraversal) {
          break rootTraversal;
        }

        hops = allHops.slice(
          0,
          limits.maxOutgoingEdgesPerNode,
        );
      }

      if (
        state.canonicalEdges.length >=
        limits.maxDepth
      ) {
        if (hops.length > 0) {
          truncated = true;
          addWarning({
            code: "depth-limit-reached",
            message:
              `Wave 2 depth limit of ` +
              `${limits.maxDepth} was reached`,
            nodeId: state.currentNode.id,
            pathNodeIds: state.nodes.map(
              (node) => node.id,
            ),
          });
        }

        if (stopTraversal) {
          break rootTraversal;
        }

        continue;
      }

      for (const hop of hops) {
        if (stopTraversal) {
          break rootTraversal;
        }

        const edge = hop.canonicalEdge;
        const targetNode = hop.targetNode;

        if (
          !isValidAuthorityTransition(
            state.currentNode,
            targetNode,
            edge,
          )
        ) {
          addWarning({
            code: "invalid-authority-hop",
            message:
              `Edge ${String(edge.id)} is not a valid ` +
              `canonical Wave 2 authority transition`,
            nodeId: targetNode.id,
            edgeId: edge.id,
            pathNodeIds: state.nodes.map(
              (node) => node.id,
            ),
          });

          if (stopTraversal) {
            break rootTraversal;
          }

          continue;
        }

        if (
          state.visitedNodeIds.has(
            targetNode.id,
          )
        ) {
          addWarning({
            code: "cycle-skipped",
            message:
              `Authority cycle through node ` +
              `${String(targetNode.id)} was skipped`,
            nodeId: targetNode.id,
            edgeId: edge.id,
            pathNodeIds: [
              ...state.nodes.map(
                (node) => node.id,
              ),
              targetNode.id,
            ],
          });

          if (stopTraversal) {
            break rootTraversal;
          }

          continue;
        }

        const nextEdges = [
          ...state.canonicalEdges,
          edge,
        ];
        const nextTraversalKey =
          createTraversalKey(
            state.seed.nodeId,
            nextEdges,
          );

        if (
          enqueuedTraversalKeys.has(
            nextTraversalKey,
          )
        ) {
          continue;
        }

        const nextPathNodeIds = [
          ...state.nodes.map(
            (node) => node.id,
          ),
          targetNode.id,
        ];

        if (
          !admitTraversalState(
            targetNode.id,
            nextPathNodeIds,
          )
        ) {
          break rootTraversal;
        }

        enqueuedTraversalKeys.add(
          nextTraversalKey,
        );

        const nextVisitedNodeIds =
          new Set(state.visitedNodeIds);
        nextVisitedNodeIds.add(
          targetNode.id,
        );

        queue.push({
          seed: state.seed,
          currentNode: targetNode,
          nodes: [
            ...state.nodes,
            targetNode,
          ],
          canonicalEdges: nextEdges,
          visitedNodeIds:
            nextVisitedNodeIds,
        });
      }
    }
  }

  const targets = [...targetsById.values()]
    .map((target) => {
      const paths = [...target.paths].sort(
        (left, right) =>
          compareText(
            left.pathKey,
            right.pathKey,
          ),
      );

      return {
        targetNode: target.targetNode,
        conclusion:
          "authority-reachability-candidate" as const,
        minimumDepth: Math.min(
          ...paths.map((path) => path.depth),
        ),
        paths,
        uncertainties: [
          ...TARGET_UNCERTAINTIES,
        ],
      };
    })
    .sort((left, right) =>
      compareNodeIds(
        left.targetNode.id,
        right.targetNode.id,
      ),
    );

  return {
    seedNodeIds: normalizedSeeds.map(
      (seed) => seed.nodeId,
    ),
    targets,
    totalPathCount,
    truncated,
    limits,
    warnings: [...warnings].sort(
      compareWarnings,
    ),
  };
}
