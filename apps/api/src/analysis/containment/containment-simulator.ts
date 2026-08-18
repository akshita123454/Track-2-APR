import type {
  ControlAction,
  ControlNode,
  EdgeId,
  GraphNode,
  NodeId,
} from "../../domain/schema.js";

import {
  analyzeWave2Authority,
} from "../authority/wave2-propagation.js";
import type {
  AuthorityHop,
  ReadonlyAuthorityGraphReader,
  Wave2AuthorityOptions,
  Wave2AuthorityResult,
  Wave2AuthoritySeed,
} from "../authority/wave2-propagation.js";

import type {
  BlastRadiusOptions,
  BlastRadiusResult,
  DependencyHop,
  ReadonlyGraphReader,
} from "../core/analysis-types.js";
import {
  analyzeBlastRadius,
} from "../core/blast-radius.js";

export type ContainmentPlanErrorCode =
  | "empty-plan"
  | "duplicate-control"
  | "applied-control-not-simulatable"
  | "missing-control-evidence"
  | "missing-rationale"
  | "missing-target"
  | "unexpected-node-target"
  | "unexpected-edge-target"
  | "missing-target-node"
  | "missing-target-edge"
  | "wrong-target-kind"
  | "wrong-target-edge-kind"
  | "target-evidence-mismatch";

export class ContainmentPlanError
  extends Error {
  public constructor(
    readonly code: ContainmentPlanErrorCode,
    message: string,
    readonly controlId?: NodeId,
    readonly targetId?: NodeId | EdgeId,
  ) {
    super(message);
    this.name = "ContainmentPlanError";
  }
}

/**
 * One proposed control plus its explicit simulation effect.
 *
 * The simulator never infers a destructive mutation. Node-oriented controls
 * must list blockedNodeIds. Edge-oriented controls must list blockedEdgeIds.
 */
export interface ContainmentDirective {
  readonly control: ControlNode;
  readonly rationale: string;
  readonly blockedNodeIds: readonly NodeId[];
  readonly blockedEdgeIds: readonly EdgeId[];
}

export interface ContainmentPlan {
  readonly directives:
    readonly ContainmentDirective[];
}

export interface NormalizedContainmentDirective {
  readonly control: ControlNode;
  readonly rationale: string;
  readonly blockedNodeIds: readonly NodeId[];
  readonly blockedEdgeIds: readonly EdgeId[];
}

export interface ContainmentOverlaySummary {
  readonly controlIds: readonly NodeId[];
  readonly blockedNodeIds: readonly NodeId[];
  readonly blockedEdgeIds: readonly EdgeId[];
}

export interface ContainmentSimulationInput {
  readonly plan: ContainmentPlan;
  readonly affectedVersionIds:
    readonly NodeId[];
  readonly authoritySeeds:
    readonly Wave2AuthoritySeed[];
  readonly blastRadiusOptions?: BlastRadiusOptions;
  readonly authorityOptions?:
    Wave2AuthorityOptions;
}

export interface ContainmentImpact {
  /**
   * False when any before/after traversal was truncated and a complete
   * comparison therefore cannot be made.
   */
  readonly conclusive: boolean;
  readonly effective: boolean;

  readonly serviceCandidatesBefore: number;
  readonly serviceCandidatesAfter: number;
  readonly serviceCandidatesRemoved: number;

  readonly blastPathsBefore: number;
  readonly blastPathsAfter: number;
  readonly blastPathsRemoved: number;

  readonly authorityTargetsBefore: number;
  readonly authorityTargetsAfter: number;
  readonly authorityTargetsRemoved: number;

  readonly authorityPathsBefore: number;
  readonly authorityPathsAfter: number;
  readonly authorityPathsRemoved: number;

  readonly removedServiceIds:
    readonly NodeId[];
  readonly removedAuthorityTargetIds:
    readonly NodeId[];
}

export interface ContainmentSimulationResult {
  /**
   * Always true. This report never claims controls were applied.
   */
  readonly simulationOnly: true;

  readonly conclusion:
    | "simulated-reduction"
    | "no-simulated-reduction"
    | "inconclusive";

  readonly directives:
    readonly NormalizedContainmentDirective[];

  readonly overlay: ContainmentOverlaySummary;

  readonly before: {
    readonly blastRadius: BlastRadiusResult;
    readonly authority: Wave2AuthorityResult;
  };

  readonly after: {
    readonly blastRadius: BlastRadiusResult;
    readonly authority: Wave2AuthorityResult;
  };

  readonly impact: ContainmentImpact;

  readonly uncertainties: readonly string[];
}

interface ContainmentOverlayReaders {
  readonly blastRadiusReader:
    ReadonlyGraphReader;
  readonly authorityReader:
    ReadonlyAuthorityGraphReader;
  readonly overlay: ContainmentOverlaySummary;
}

const NODE_CONTROL_ACTIONS:
  ReadonlySet<ControlAction> =
    new Set([
      "block-package-version",
      "revoke-credential",
      "disable-workflow",
      "rotate-secret",
      "rollback-artifact",
      "isolate-service",
      "restrict-network",
    ]);

const EDGE_CONTROL_ACTIONS:
  ReadonlySet<ControlAction> =
    new Set([
      "pin-dependency",
      "apply-override",
      "remove-publishing-access",
    ]);

const SIMULATION_UNCERTAINTIES:
  readonly string[] = [
    "This is an immutable simulation and does not prove that any control was applied.",
    "A reduced structural path count does not prove that runtime exposure or malicious activity was eliminated.",
    "Operational feasibility, deployment delay, rollback risk, and control cost require separate evaluation.",
  ];

function compareNumbers(
  left: number,
  right: number,
): number {
  return left - right;
}

function uniqueSortedIds<T extends number>(
  values: readonly T[],
): readonly T[] {
  return [...new Set(values)].sort(
    compareNumbers,
  );
}

function cloneControl(
  control: ControlNode,
): ControlNode {
  const evidenceIds = Object.freeze(
    [...control.evidenceIds].sort(
      compareNumbers,
    ),
  );

  return Object.freeze({
    ...control,
    evidenceIds,
  });
}

function normalizeDirective(
  directive: ContainmentDirective,
): NormalizedContainmentDirective {
  const rationale = directive.rationale.trim();
  const blockedNodeIds = uniqueSortedIds(
    directive.blockedNodeIds,
  );
  const blockedEdgeIds = uniqueSortedIds(
    directive.blockedEdgeIds,
  );
  const control = cloneControl(
    directive.control,
  );

  if (control.status === "applied") {
    throw new ContainmentPlanError(
      "applied-control-not-simulatable",
      `Control ${String(control.id)} is already applied`,
      control.id,
    );
  }

  if (control.evidenceIds.length === 0) {
    throw new ContainmentPlanError(
      "missing-control-evidence",
      `Control ${String(control.id)} requires Evidence`,
      control.id,
    );
  }

  if (rationale.length === 0) {
    throw new ContainmentPlanError(
      "missing-rationale",
      `Control ${String(control.id)} requires a rationale`,
      control.id,
    );
  }

  if (NODE_CONTROL_ACTIONS.has(control.action)) {
    if (blockedNodeIds.length === 0) {
      throw new ContainmentPlanError(
        "missing-target",
        `Node control ${String(control.id)} requires a blocked node`,
        control.id,
      );
    }

    if (blockedEdgeIds.length > 0) {
      throw new ContainmentPlanError(
        "unexpected-edge-target",
        `Node control ${String(control.id)} cannot block edges`,
        control.id,
        blockedEdgeIds[0],
      );
    }
  } else if (
    EDGE_CONTROL_ACTIONS.has(control.action)
  ) {
    if (blockedEdgeIds.length === 0) {
      throw new ContainmentPlanError(
        "missing-target",
        `Edge control ${String(control.id)} requires a blocked edge`,
        control.id,
      );
    }

    if (blockedNodeIds.length > 0) {
      throw new ContainmentPlanError(
        "unexpected-node-target",
        `Edge control ${String(control.id)} cannot block nodes`,
        control.id,
        blockedNodeIds[0],
      );
    }
  }

  return Object.freeze({
    control,
    rationale,
    blockedNodeIds: Object.freeze(
      [...blockedNodeIds],
    ),
    blockedEdgeIds: Object.freeze(
      [...blockedEdgeIds],
    ),
  });
}

function normalizePlan(
  plan: ContainmentPlan,
): readonly NormalizedContainmentDirective[] {
  if (plan.directives.length === 0) {
    throw new ContainmentPlanError(
      "empty-plan",
      "A containment simulation requires at least one control",
    );
  }

  const normalized = plan.directives
    .map(normalizeDirective)
    .sort(
      (left, right) =>
        left.control.id -
        right.control.id,
    );

  const controlIds = new Set<NodeId>();

  for (const directive of normalized) {
    if (
      controlIds.has(directive.control.id)
    ) {
      throw new ContainmentPlanError(
        "duplicate-control",
        `Control ${String(directive.control.id)} appears more than once`,
        directive.control.id,
      );
    }

    controlIds.add(directive.control.id);
  }

  return Object.freeze(normalized);
}

function createOverlaySummary(
  directives:
    readonly NormalizedContainmentDirective[],
): ContainmentOverlaySummary {
  const controlIds = uniqueSortedIds(
    directives.map(
      (directive) => directive.control.id,
    ),
  );
  const blockedNodeIds = uniqueSortedIds(
    directives.flatMap(
      (directive) =>
        directive.blockedNodeIds,
    ),
  );
  const blockedEdgeIds = uniqueSortedIds(
    directives.flatMap(
      (directive) =>
        directive.blockedEdgeIds,
    ),
  );

  return Object.freeze({
    controlIds: Object.freeze(
      [...controlIds],
    ),
    blockedNodeIds: Object.freeze(
      [...blockedNodeIds],
    ),
    blockedEdgeIds: Object.freeze(
      [...blockedEdgeIds],
    ),
  });
}

function isAllowedNodeTarget(
  action: ControlAction,
  node: GraphNode,
): boolean {
  switch (action) {
    case "block-package-version":
      return node.kind === "PackageVersion";

    case "revoke-credential":
    case "rotate-secret":
      return node.kind === "Credential";

    case "disable-workflow":
      return node.kind === "CIWorkflow";

    case "rollback-artifact":
      return node.kind === "Artifact";

    case "isolate-service":
      return node.kind === "Service";

    case "restrict-network":
      return (
        node.kind === "Service" ||
        node.kind === "Deployment"
      );

    case "pin-dependency":
    case "apply-override":
    case "remove-publishing-access":
      return false;
  }
}

async function validateNodeTargets(
  directives:
    readonly NormalizedContainmentDirective[],
  reader: ReadonlyGraphReader,
): Promise<void> {
  for (const directive of directives) {
    for (
      const targetId of
      directive.blockedNodeIds
    ) {
      const node = await reader.getNode(
        targetId,
      );

      if (node === null) {
        throw new ContainmentPlanError(
          "missing-target-node",
          `Control ${String(directive.control.id)} targets missing node ${String(targetId)}`,
          directive.control.id,
          targetId,
        );
      }

      if (
        !isAllowedNodeTarget(
          directive.control.action,
          node,
        )
      ) {
        throw new ContainmentPlanError(
          "wrong-target-kind",
          `Control ${String(directive.control.id)} action ` +
            `${directive.control.action} cannot target ${node.kind}`,
          directive.control.id,
          targetId,
        );
      }
    }
  }
}

function createReadersFromOverlay(
  blastRadiusSource: ReadonlyGraphReader,
  authoritySource:
    ReadonlyAuthorityGraphReader,
  directives:
    readonly NormalizedContainmentDirective[],
  overlay: ContainmentOverlaySummary,
): ContainmentOverlayReaders {
  const blastBlockedNodeIds =
    new Set<NodeId>();
  const blastBlockedEdgeIds =
    new Set<EdgeId>();
  const authorityBlockedNodeIds =
    new Set<NodeId>();
  const authorityBlockedEdgeIds =
    new Set<EdgeId>();

  for (const directive of directives) {
    switch (directive.control.action) {
      case "block-package-version":
      case "isolate-service":
        for (const nodeId of directive.blockedNodeIds) {
          blastBlockedNodeIds.add(nodeId);
        }
        break;

      case "pin-dependency":
      case "apply-override":
        for (const edgeId of directive.blockedEdgeIds) {
          blastBlockedEdgeIds.add(edgeId);
        }
        break;

      case "revoke-credential":
      case "disable-workflow":
      case "rotate-secret":
        for (const nodeId of directive.blockedNodeIds) {
          authorityBlockedNodeIds.add(nodeId);
        }
        break;

      case "remove-publishing-access":
        for (const edgeId of directive.blockedEdgeIds) {
          authorityBlockedEdgeIds.add(edgeId);
        }
        break;

      case "rollback-artifact":
      case "restrict-network":
        // Neither structural analyzer models runtime artifact or network state.
        break;
    }
  }

  const blastRadiusReader:
    ReadonlyGraphReader = {
      getNode: async (nodeId) => {
        if (blastBlockedNodeIds.has(nodeId)) {
          return null;
        }

        return blastRadiusSource.getNode(
          nodeId,
        );
      },

      findDependents: async (
        nodeId,
      ): Promise<readonly DependencyHop[]> => {
        if (blastBlockedNodeIds.has(nodeId)) {
          return [];
        }

        const hops =
          await blastRadiusSource.findDependents(
            nodeId,
          );

        return hops.filter(
          (hop) =>
            !blastBlockedNodeIds.has(
              hop.dependentNode.id,
            ) &&
            !blastBlockedNodeIds.has(
              hop.canonicalEdge.sourceId,
            ) &&
            !blastBlockedNodeIds.has(
              hop.canonicalEdge.targetId,
            ) &&
            !blastBlockedEdgeIds.has(
              hop.canonicalEdge.id,
            ),
        );
      },

      getEvidence: (evidenceIds) =>
        blastRadiusSource.getEvidence(
          evidenceIds,
        ),
    };

  const authorityReader:
    ReadonlyAuthorityGraphReader = {
      getNode: async (nodeId) => {
        if (authorityBlockedNodeIds.has(nodeId)) {
          return null;
        }

        return authoritySource.getNode(
          nodeId,
        );
      },

      findOutgoingAuthorityHops: async (
        nodeId,
      ): Promise<readonly AuthorityHop[]> => {
        if (authorityBlockedNodeIds.has(nodeId)) {
          return [];
        }

        const hops =
          await authoritySource
            .findOutgoingAuthorityHops(
              nodeId,
            );

        return hops.filter(
          (hop) =>
            !authorityBlockedNodeIds.has(
              hop.targetNode.id,
            ) &&
            !authorityBlockedNodeIds.has(
              hop.canonicalEdge.sourceId,
            ) &&
            !authorityBlockedNodeIds.has(
              hop.canonicalEdge.targetId,
            ) &&
            !authorityBlockedEdgeIds.has(
              hop.canonicalEdge.id,
            ),
        );
      },

      getEvidence: (evidenceIds) =>
        authoritySource.getEvidence(
          evidenceIds,
        ),
    };

  return Object.freeze({
    blastRadiusReader,
    authorityReader,
    overlay,
  });
}

function difference(
  before: readonly NodeId[],
  after: readonly NodeId[],
): readonly NodeId[] {
  const afterIds = new Set(after);

  return uniqueSortedIds(
    before.filter(
      (nodeId) => !afterIds.has(nodeId),
    ),
  );
}

function pathKeys(
  result:
    | BlastRadiusResult
    | Wave2AuthorityResult,
): readonly string[] {
  if ("services" in result) {
    return result.services.flatMap(
      (candidate) =>
        candidate.paths.map(
          (path) => path.pathKey,
        ),
    );
  }

  return result.targets.flatMap(
    (target) =>
      target.paths.map(
        (path) => path.pathKey,
      ),
  );
}

function removedCount(
  before: readonly string[],
  after: readonly string[],
): number {
  const afterKeys = new Set(after);

  return new Set(
    before.filter(
      (key) => !afterKeys.has(key),
    ),
  ).size;
}

function calculateImpact(
  beforeBlastRadius: BlastRadiusResult,
  afterBlastRadius: BlastRadiusResult,
  beforeAuthority: Wave2AuthorityResult,
  afterAuthority: Wave2AuthorityResult,
): ContainmentImpact {
  const observedRemovedServiceIds = difference(
    beforeBlastRadius.services.map(
      (candidate) => candidate.service.id,
    ),
    afterBlastRadius.services.map(
      (candidate) => candidate.service.id,
    ),
  );

  const observedRemovedAuthorityTargetIds =
    difference(
      beforeAuthority.targets.map(
        (target) => target.targetNode.id,
      ),
      afterAuthority.targets.map(
        (target) => target.targetNode.id,
      ),
    );

  const conclusive =
    !beforeBlastRadius.truncated &&
    !afterBlastRadius.truncated &&
    !beforeAuthority.truncated &&
    !afterAuthority.truncated;
  const removedServiceIds = conclusive
    ? observedRemovedServiceIds
    : [];
  const removedAuthorityTargetIds = conclusive
    ? observedRemovedAuthorityTargetIds
    : [];
  const serviceCandidatesRemoved =
    removedServiceIds.length;
  const blastPathsRemoved = conclusive
    ? removedCount(
        pathKeys(beforeBlastRadius),
        pathKeys(afterBlastRadius),
      )
    : 0;
  const authorityTargetsRemoved =
    removedAuthorityTargetIds.length;
  const authorityPathsRemoved = conclusive
    ? removedCount(
        pathKeys(beforeAuthority),
        pathKeys(afterAuthority),
      )
    : 0;

  return {
    conclusive,
    effective:
      conclusive &&
      (
        serviceCandidatesRemoved > 0 ||
        blastPathsRemoved > 0 ||
        authorityTargetsRemoved > 0 ||
        authorityPathsRemoved > 0
      ),

    serviceCandidatesBefore:
      beforeBlastRadius.services.length,
    serviceCandidatesAfter:
      afterBlastRadius.services.length,
    serviceCandidatesRemoved,

    blastPathsBefore:
      beforeBlastRadius.totalPathCount,
    blastPathsAfter:
      afterBlastRadius.totalPathCount,
    blastPathsRemoved,

    authorityTargetsBefore:
      beforeAuthority.targets.length,
    authorityTargetsAfter:
      afterAuthority.targets.length,
    authorityTargetsRemoved,

    authorityPathsBefore:
      beforeAuthority.totalPathCount,
    authorityPathsAfter:
      afterAuthority.totalPathCount,
    authorityPathsRemoved,

    removedServiceIds,
    removedAuthorityTargetIds,
  };
}

/**
 * Simulates explicit controls over immutable reader overlays.
 *
 * No source node, edge, reader, persistence result, or database state is
 * modified. The returned report describes modeled reduction only.
 */
export async function simulateContainment(
  blastRadiusSource: ReadonlyGraphReader,
  authoritySource:
    ReadonlyAuthorityGraphReader,
  input: ContainmentSimulationInput,
): Promise<ContainmentSimulationResult> {
  const directives =
    normalizePlan(input.plan);

  await validateNodeTargets(
    directives,
    blastRadiusSource,
  );

  const overlay =
    createOverlaySummary(directives);

  const beforeBlastRadius =
    await analyzeBlastRadius(
      blastRadiusSource,
      input.affectedVersionIds,
      input.blastRadiusOptions,
    );

  const beforeAuthority =
    await analyzeWave2Authority(
      authoritySource,
      input.authoritySeeds,
      input.authorityOptions,
    );

  const overlayReaders =
    createReadersFromOverlay(
      blastRadiusSource,
      authoritySource,
      directives,
      overlay,
    );

  const afterBlastRadius =
    await analyzeBlastRadius(
      overlayReaders.blastRadiusReader,
      input.affectedVersionIds,
      input.blastRadiusOptions,
    );

  const afterAuthority =
    await analyzeWave2Authority(
      overlayReaders.authorityReader,
      input.authoritySeeds,
      input.authorityOptions,
    );

  const impact = calculateImpact(
    beforeBlastRadius,
    afterBlastRadius,
    beforeAuthority,
    afterAuthority,
  );

  return {
    simulationOnly: true,
    conclusion: !impact.conclusive
      ? "inconclusive"
      : impact.effective
        ? "simulated-reduction"
        : "no-simulated-reduction",
    directives,
    overlay,
    before: {
      blastRadius: beforeBlastRadius,
      authority: beforeAuthority,
    },
    after: {
      blastRadius: afterBlastRadius,
      authority: afterAuthority,
    },
    impact,
    uncertainties: [
      ...SIMULATION_UNCERTAINTIES,
    ],
  };
}
