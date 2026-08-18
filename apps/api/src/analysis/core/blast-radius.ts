import type {
  DependencyEdge,
  GraphNode,
  NodeId,
  ServiceNode,
} from "../../domain/schema.js";
import type {
  AnalysisWarning,
  AppliedBlastRadiusLimits,
  BlastRadiusOptions,
  BlastRadiusPath,
  BlastRadiusResult,
  DependencyHop,
  DependencyHopPage,
  ReadonlyGraphReader,
} from "./analysis-types.js";

const DEFAULT_LIMITS: AppliedBlastRadiusLimits = {
  maxDepth: 12,
  maxServices: 100,
  maxPathsPerService: 10,
  maxTotalPaths: 1_000,
  maxTraversalStates: 10_000,
  maxDependentsPerNode: 1_000,
  maxWarnings: 100,
};

interface TraversalState {
  readonly affectedVersionId: NodeId;
  readonly currentNode: GraphNode;
  readonly nodes: readonly GraphNode[];
  readonly canonicalEdges: readonly DependencyEdge[];
  readonly visitedNodeIds: ReadonlySet<NodeId>;
}

interface MutableServiceCandidate {
  readonly service: ServiceNode;
  readonly paths: BlastRadiusPath[];
  readonly pathKeys: Set<string>;
}

function compareText(left: string, right: string): number {
  return left.localeCompare(right);
}

function compareNodeIds(left: NodeId, right: NodeId): number {
  return left - right;
}

function uniqueSortedNodeIds(
  nodeIds: readonly NodeId[],
): readonly NodeId[] {
  return [...new Set(nodeIds)].sort(compareNodeIds);
}

function readPositiveSafeInteger(
  value: number | undefined,
  fallback: number,
  optionName: keyof BlastRadiusOptions,
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
  options: BlastRadiusOptions,
): AppliedBlastRadiusLimits {
  return {
    maxDepth: readPositiveSafeInteger(
      options.maxDepth,
      DEFAULT_LIMITS.maxDepth,
      "maxDepth",
    ),
    maxServices: readPositiveSafeInteger(
      options.maxServices,
      DEFAULT_LIMITS.maxServices,
      "maxServices",
    ),
    maxPathsPerService: readPositiveSafeInteger(
      options.maxPathsPerService,
      DEFAULT_LIMITS.maxPathsPerService,
      "maxPathsPerService",
    ),
    maxTotalPaths: readPositiveSafeInteger(
      options.maxTotalPaths,
      DEFAULT_LIMITS.maxTotalPaths,
      "maxTotalPaths",
    ),
    maxTraversalStates: readPositiveSafeInteger(
      options.maxTraversalStates,
      DEFAULT_LIMITS.maxTraversalStates,
      "maxTraversalStates",
    ),
    maxDependentsPerNode: readPositiveSafeInteger(
      options.maxDependentsPerNode,
      DEFAULT_LIMITS.maxDependentsPerNode,
      "maxDependentsPerNode",
    ),
    maxWarnings: readPositiveSafeInteger(
      options.maxWarnings,
      DEFAULT_LIMITS.maxWarnings,
      "maxWarnings",
    ),
  };
}

function compareDependencyHops(
  left: DependencyHop,
  right: DependencyHop,
): number {
  return (
    left.canonicalEdge.id - right.canonicalEdge.id ||
    compareNodeIds(
      left.dependentNode.id,
      right.dependentNode.id,
    )
  );
}

function createTraversalKey(
  affectedVersionId: NodeId,
  canonicalEdges: readonly DependencyEdge[],
): string {
  return JSON.stringify([
    affectedVersionId,
    ...canonicalEdges.map((edge) => edge.id),
  ]);
}

function createPathKey(
  affectedVersionId: NodeId,
  serviceId: NodeId,
  canonicalEdges: readonly DependencyEdge[],
): string {
  return JSON.stringify([
    affectedVersionId,
    serviceId,
    ...canonicalEdges.map((edge) => edge.id),
  ]);
}

function createBlastRadiusPath(
  state: TraversalState,
  service: ServiceNode,
): BlastRadiusPath {
  return {
    pathKey: createPathKey(
      state.affectedVersionId,
      service.id,
      state.canonicalEdges,
    ),
    affectedVersionId: state.affectedVersionId,
    serviceId: service.id,
    nodes: [...state.nodes],
    canonicalEdges: [...state.canonicalEdges],
    depth: state.canonicalEdges.length,
  };
}

function warningKey(
  warning: AnalysisWarning,
): string {
  return JSON.stringify([
    warning.code,
    warning.message,
    warning.nodeId ?? null,
    warning.pathNodeIds ?? [],
  ]);
}

function compareWarnings(
  left: AnalysisWarning,
  right: AnalysisWarning,
): number {
  return (
    compareText(left.code, right.code) ||
    compareNodeIds(
      left.nodeId ?? 0,
      right.nodeId ?? 0,
    ) ||
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

/**
 * Finds internal Services that structurally depend on one or more
 * incident-affected PackageVersion nodes.
 *
 * Traversal moves in reverse dependency order, but every retained edge
 * remains the canonical dependent -> dependency DEPENDS_ON relationship.
 * A derived USED_BY edge may help a reader find a hop, but it is never
 * accepted as evidence by this function.
 *
 * Returned Services are candidates only. Resolution, build, deployment,
 * runtime reachability, and execution require separate evidence
 * classification.
 */
export async function analyzeBlastRadius(
  reader: ReadonlyGraphReader,
  affectedVersionIds: readonly NodeId[],
  options: BlastRadiusOptions = {},
): Promise<BlastRadiusResult> {
  const limits = normalizeLimits(options);
  const sortedAffectedVersionIds =
    uniqueSortedNodeIds(affectedVersionIds);

  const warnings: AnalysisWarning[] = [];
  const recordedWarningKeys = new Set<string>();
  const servicesById =
    new Map<NodeId, MutableServiceCandidate>();
  const dependentsCache =
    new Map<NodeId, DependencyHopPage>();
  const enqueuedTraversalKeys = new Set<string>();

  let totalPathCount = 0;
  let admittedTraversalStates = 0;
  let truncated = false;
  let warningLimitReached = false;
  let stopTraversal = false;

  const addWarning = (
    warning: AnalysisWarning,
  ): void => {
    const key = warningKey(warning);

    if (
      recordedWarningKeys.has(key) ||
      warningLimitReached
    ) {
      return;
    }

    /*
     * Reserve the final warning slot for a deterministic notification that
     * the warning budget itself was reached.
     */
    const maximumRegularWarnings =
      limits.maxWarnings - 1;

    if (warnings.length >= maximumRegularWarnings) {
      warningLimitReached = true;
      truncated = true;
      stopTraversal = true;

      const warningLimitNotification: AnalysisWarning = {
        code: "warning-limit-reached",
        message:
          `Warning limit of ${limits.maxWarnings} was reached; ` +
          "traversal stopped",
      };

      recordedWarningKeys.add(
        warningKey(warningLimitNotification),
      );
      warnings.push(warningLimitNotification);
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

  const findSortedDependents = async (
    nodeId: NodeId,
  ): Promise<DependencyHopPage> => {
    const cached = dependentsCache.get(nodeId);

    if (cached !== undefined) {
      return cached;
    }

    const page = await reader.findDependents(
      nodeId,
      {
        limit: limits.maxDependentsPerNode,
      },
    );

    if (
      page.hops.length >
      limits.maxDependentsPerNode
    ) {
      throw new Error(
        "ReadonlyGraphReader violated the bounded " +
          "findDependents contract",
      );
    }

    /*
    * Sorting remains defensive, but the input is already bounded by the
    * reader contract.
    */
    const boundedPage: DependencyHopPage = {
      hops: [...page.hops].sort(
        compareDependencyHops,
      ),
      truncated: page.truncated,
    };

    dependentsCache.set(nodeId, boundedPage);
    return boundedPage;
  };


  rootTraversal:
  for (const affectedVersionId of sortedAffectedVersionIds) {
    if (stopTraversal) {
      break;
    }

    const rootNode = await reader.getNode(
      affectedVersionId,
    );

    if (rootNode === null) {
      addWarning({
        code: "missing-node",
        message:
          `Affected root node ${String(affectedVersionId)} ` +
          "was not found",
        nodeId: affectedVersionId,
      });

      if (stopTraversal) {
        break;
      }

      continue;
    }

    if (rootNode.kind !== "PackageVersion") {
      addWarning({
        code: "unsupported-root-node",
        message:
          `Affected root ${String(affectedVersionId)} must be ` +
          "a PackageVersion",
        nodeId: affectedVersionId,
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

    const initialTraversalKey = createTraversalKey(
      affectedVersionId,
      [],
    );

    enqueuedTraversalKeys.add(initialTraversalKey);

    const queue: TraversalState[] = [
      {
        affectedVersionId,
        currentNode: rootNode,
        nodes: [rootNode],
        canonicalEdges: [],
        visitedNodeIds: new Set([rootNode.id]),
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

      if (state.currentNode.kind === "Service") {
        const service = state.currentNode;
        const path = createBlastRadiusPath(
          state,
          service,
        );
        let candidate = servicesById.get(service.id);

        if (
          candidate !== undefined &&
          candidate.pathKeys.has(path.pathKey)
        ) {
          continue;
        }

        if (
          candidate === undefined &&
          servicesById.size >= limits.maxServices
        ) {
          truncated = true;
          addWarning({
            code: "service-limit-reached",
            message:
              `Service result limit of ` +
              `${limits.maxServices} was reached`,
            nodeId: service.id,
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
          candidate !== undefined &&
          candidate.paths.length >=
            limits.maxPathsPerService
        ) {
          truncated = true;
          addWarning({
            code: "paths-per-service-limit-reached",
            message:
              `Path limit of ` +
              `${limits.maxPathsPerService} was reached ` +
              `for Service ${String(service.id)}`,
            nodeId: service.id,
            pathNodeIds: state.nodes.map(
              (node) => node.id,
            ),
          });

          if (stopTraversal) {
            break rootTraversal;
          }

          continue;
        }

        if (totalPathCount >= limits.maxTotalPaths) {
          truncated = true;
          addWarning({
            code: "path-limit-reached",
            message:
              `Total path limit of ` +
              `${limits.maxTotalPaths} was reached`,
            nodeId: service.id,
            pathNodeIds: state.nodes.map(
              (node) => node.id,
            ),
          });
          stopTraversal = true;
          break rootTraversal;
        }

        if (candidate === undefined) {
          const newCandidate:
            MutableServiceCandidate = {
              service,
              paths: [],
              pathKeys: new Set<string>(),
            };

          servicesById.set(service.id, newCandidate);
          candidate = newCandidate;
        }

        candidate.pathKeys.add(path.pathKey);
        candidate.paths.push(path);
        totalPathCount += 1;
        continue;
      }

      const dependentPage =
        await findSortedDependents(
          state.currentNode.id,
        );

      const dependentHops =
        dependentPage.hops;

      if (dependentPage.truncated) {
        truncated = true;

        addWarning({
          code: "dependents-per-node-limit-reached",
          message:
            `Dependent limit of ` +
            `${limits.maxDependentsPerNode} was reached ` +
            `for node ${String(state.currentNode.id)}; ` +
            "remaining dependents were not expanded",
          nodeId: state.currentNode.id,
          pathNodeIds: state.nodes.map(
            (node) => node.id,
          ),
        });

        if (stopTraversal) {
          break rootTraversal;
        }
      }


      let depthWarningAdded = false;

      for (const hop of dependentHops) {
        if (stopTraversal) {
          break rootTraversal;
        }

        const canonicalEdge = hop.canonicalEdge;
        const dependentNode = hop.dependentNode;

        const isCanonicalHop =
          canonicalEdge.kind === "DEPENDS_ON" &&
          canonicalEdge.derived === false &&
          canonicalEdge.targetId ===
            state.currentNode.id &&
          canonicalEdge.sourceId ===
            dependentNode.id;

        if (!isCanonicalHop) {
          addWarning({
            code: "invalid-canonical-hop",
            message:
              `Edge ${String(canonicalEdge.id)} is not a ` +
              `canonical non-derived DEPENDS_ON hop from ` +
              `${String(dependentNode.id)} to ` +
              `${String(state.currentNode.id)}`,
            nodeId: dependentNode.id,
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
          state.visitedNodeIds.has(dependentNode.id)
        ) {
          addWarning({
            code: "cycle-skipped",
            message:
              `Cycle through node ` +
              `${String(dependentNode.id)} was skipped`,
            nodeId: dependentNode.id,
            pathNodeIds: [
              ...state.nodes.map((node) => node.id),
              dependentNode.id,
            ],
          });

          if (stopTraversal) {
            break rootTraversal;
          }

          continue;
        }

        if (
          state.canonicalEdges.length >=
          limits.maxDepth
        ) {
          truncated = true;

          if (!depthWarningAdded) {
            depthWarningAdded = true;
            addWarning({
              code: "depth-limit-reached",
              message:
                `Traversal depth limit of ` +
                `${limits.maxDepth} was reached`,
              nodeId: state.currentNode.id,
              pathNodeIds: [
                ...state.nodes.map(
                  (node) => node.id,
                ),
                dependentNode.id,
              ],
            });
          }

          if (stopTraversal) {
            break rootTraversal;
          }

          continue;
        }

        const nextCanonicalEdges = [
          ...state.canonicalEdges,
          canonicalEdge,
        ];
        const nextTraversalKey = createTraversalKey(
          state.affectedVersionId,
          nextCanonicalEdges,
        );

        if (
          enqueuedTraversalKeys.has(nextTraversalKey)
        ) {
          continue;
        }

        const nextPathNodeIds = [
          ...state.nodes.map((node) => node.id),
          dependentNode.id,
        ];

        if (
          !admitTraversalState(
            dependentNode.id,
            nextPathNodeIds,
          )
        ) {
          break rootTraversal;
        }

        enqueuedTraversalKeys.add(nextTraversalKey);

        const nextVisitedNodeIds =
          new Set(state.visitedNodeIds);
        nextVisitedNodeIds.add(dependentNode.id);

        queue.push({
          affectedVersionId:
            state.affectedVersionId,
          currentNode: dependentNode,
          nodes: [
            ...state.nodes,
            dependentNode,
          ],
          canonicalEdges: nextCanonicalEdges,
          visitedNodeIds: nextVisitedNodeIds,
        });
      }
    }
  }

  const services = [...servicesById.values()]
    .map((candidate) => {
      const paths = [...candidate.paths].sort(
        (left, right) =>
          compareText(
            left.pathKey,
            right.pathKey,
          ),
      );

      return {
        service: candidate.service,
        minimumDepth: Math.min(
          ...paths.map((path) => path.depth),
        ),
        paths,
      };
    })
    .sort((left, right) =>
      compareNodeIds(
        left.service.id,
        right.service.id,
      ),
    );

  return {
    affectedVersionIds: sortedAffectedVersionIds,
    services,
    totalPathCount,
    truncated,
    limits,
    warnings: [...warnings].sort(compareWarnings),
  };
}
