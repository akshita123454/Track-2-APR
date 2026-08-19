import type {
  EdgeId,
  NodeId,
  UnixEpochMilliseconds,
} from "../../domain/schema.js";

export const RELEASE_INFLUENCE_NODE_KINDS = [
  "source-change",
  "workflow-run",
  "cache-entry",
  "build",
  "credential",
  "attestation",
  "artifact",
  "release",
] as const;

export type ReleaseInfluenceNodeKind =
  (typeof RELEASE_INFLUENCE_NODE_KINDS)[number];

export const RELEASE_INFLUENCE_EDGE_KINDS = [
  "triggers",
  "checks-out",
  "writes-cache",
  "restores-cache",
  "starts-build",
  "mints-credential",
  "uses-credential",
  "produces",
  "attests",
  "publishes",
  "authorizes-publish",
  "influences",
] as const;

export type ReleaseInfluenceEdgeKind =
  (typeof RELEASE_INFLUENCE_EDGE_KINDS)[number];

export type ReleaseTrustLevel =
  | "trusted"
  | "untrusted"
  | "unknown";

export type ReleaseTrustBoundary =
  | "same-trust-zone"
  | "cross-trust-boundary"
  | "unknown";

export type ReleaseRiskDisposition =
  | "block"
  | "quarantine";

export interface ReleaseSubject {
  /**
   * Intentionally open-ended: npm, pypi, maven, cargo, nuget, an
   * internal registry, or a future ecosystem can use the same analyzer.
   */
  readonly ecosystem: string;
  readonly packageName: string;
  readonly version: string;
  readonly artifactDigest?: string;
}

interface ReleaseInfluenceNodeBase<
  K extends ReleaseInfluenceNodeKind,
> {
  readonly id: NodeId;
  readonly kind: K;
  readonly label: string;
  readonly trust: ReleaseTrustLevel;
  readonly evidenceIds: readonly NodeId[];
  readonly observedAt: UnixEpochMilliseconds;
  readonly metadata?: Readonly<
    Record<string, string | number | boolean>
  >;
}

export interface ReleasePipelineNode
  extends ReleaseInfluenceNodeBase<
    Exclude<ReleaseInfluenceNodeKind, "release">
  > {}

export interface ReleaseNode
  extends ReleaseInfluenceNodeBase<"release"> {
  readonly subject: ReleaseSubject;
}

export type ReleaseInfluenceNode =
  | ReleasePipelineNode
  | ReleaseNode;

export interface ReleaseInfluenceEdge {
  readonly id: EdgeId;
  readonly kind: ReleaseInfluenceEdgeKind;
  readonly sourceId: NodeId;
  readonly targetId: NodeId;
  readonly trust: ReleaseTrustLevel;
  readonly boundary: ReleaseTrustBoundary;
  readonly evidenceIds: readonly NodeId[];
  readonly observedAt: UnixEpochMilliseconds;
  readonly metadata?: Readonly<
    Record<string, string | number | boolean>
  >;
}

export interface ReleaseInfluenceGraph {
  readonly nodes: readonly ReleaseInfluenceNode[];
  readonly edges: readonly ReleaseInfluenceEdge[];
}

export interface ReleaseFirewallInput {
  readonly graph: ReleaseInfluenceGraph;
  readonly releaseNodeIds: readonly NodeId[];
}

export interface ReleaseFirewallOptions {
  readonly maxDepth?: number;
  readonly maxTraversalStatesPerRelease?: number;
  readonly maxIncomingEdgesPerNode?: number;
  readonly maxRiskPathsPerRelease?: number;
  readonly maxFindingsPerRelease?: number;
  readonly requireEvidence?: boolean;
  readonly untrustedDisposition?: ReleaseRiskDisposition;
  readonly unknownDisposition?: ReleaseRiskDisposition;
  readonly crossBoundaryCacheDisposition?:
    ReleaseRiskDisposition;
  readonly unknownCacheBoundaryDisposition?:
    ReleaseRiskDisposition;
}

export interface AppliedReleaseFirewallOptions {
  readonly maxDepth: number;
  readonly maxTraversalStatesPerRelease: number;
  readonly maxIncomingEdgesPerNode: number;
  readonly maxRiskPathsPerRelease: number;
  readonly maxFindingsPerRelease: number;
  readonly requireEvidence: boolean;
  readonly untrustedDisposition: ReleaseRiskDisposition;
  readonly unknownDisposition: ReleaseRiskDisposition;
  readonly crossBoundaryCacheDisposition:
    ReleaseRiskDisposition;
  readonly unknownCacheBoundaryDisposition:
    ReleaseRiskDisposition;
}

export interface ReleaseInfluencePath {
  readonly pathKey: string;
  /** Nodes are ordered from the causal source to the release. */
  readonly nodeIds: readonly NodeId[];
  /** Edges are ordered in the same forward causal direction. */
  readonly edgeIds: readonly EdgeId[];
  readonly depth: number;
}

export type ReleaseTrustFindingSeverity =
  | "block"
  | "quarantine"
  | "warning";

export type ReleaseTrustFindingCode =
  | "untrusted-node"
  | "untrusted-edge"
  | "unknown-node"
  | "unknown-edge"
  | "cross-boundary-cache"
  | "unknown-cache-boundary"
  | "missing-node-evidence"
  | "missing-edge-evidence"
  | "missing-artifact-publication"
  | "cycle-skipped"
  | "depth-limit-reached"
  | "traversal-state-limit-reached"
  | "incoming-edge-limit-reached"
  | "risk-path-limit-reached"
  | "finding-limit-reached";

export interface ReleaseTrustFinding {
  readonly code: ReleaseTrustFindingCode;
  readonly severity: ReleaseTrustFindingSeverity;
  readonly message: string;
  readonly nodeId?: NodeId;
  readonly edgeId?: EdgeId;
  readonly pathKey?: string;
}

export type ReleaseTrustVerdict =
  | "allow"
  | "quarantine"
  | "block";

export interface ReleaseTrustDecision {
  readonly releaseNodeId: NodeId;
  readonly subject: ReleaseSubject;
  readonly verdict: ReleaseTrustVerdict;
  readonly reason: string;
  readonly findings: readonly ReleaseTrustFinding[];
  readonly riskPaths: readonly ReleaseInfluencePath[];
  readonly truncated: boolean;
  readonly inspectedNodeCount: number;
  readonly inspectedEdgeCount: number;
}

export interface ReleaseFirewallSummary {
  readonly evaluated: number;
  readonly allowed: number;
  readonly quarantined: number;
  readonly blocked: number;
  readonly truncated: number;
}

export interface ReleaseFirewallResult {
  readonly decisions: readonly ReleaseTrustDecision[];
  readonly summary: ReleaseFirewallSummary;
  readonly options: AppliedReleaseFirewallOptions;
}

export type ReleaseFirewallInputErrorCode =
  | "empty-release-set"
  | "duplicate-release-id"
  | "duplicate-node-id"
  | "duplicate-edge-id"
  | "invalid-node"
  | "invalid-edge"
  | "missing-edge-endpoint"
  | "invalid-edge-endpoints"
  | "missing-release-node"
  | "wrong-release-node-kind";

export class ReleaseFirewallInputError extends Error {
  public constructor(
    readonly code: ReleaseFirewallInputErrorCode,
    message: string,
    readonly nodeId?: NodeId,
    readonly edgeId?: EdgeId,
  ) {
    super(message);
    this.name = "ReleaseFirewallInputError";
  }
}
