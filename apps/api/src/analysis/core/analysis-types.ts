import type {
  DependencyEdge,
  EdgeId,
  EvidenceNode,
  GraphNode,
  NodeId,
  ServiceNode,
} from "../../domain/schema.js";

/**
 * Detailed evidence stage reached by one candidate dependency path.
 *
 * Stages are ordered from structural possibility to directly observed
 * execution. A later stage may only be selected when its required evidence
 * is explicitly supplied.
 */
export type ExposureStage =
  | "candidate"
  | "semver-eligible"
  | "resolved"
  | "built"
  | "deployed"
  | "runtime-reachable"
  | "execution-observed";

/**
 * High-level security conclusion presented to API and dashboard consumers.
 *
 * This remains separate from ExposureStage so intermediate technical facts,
 * such as "built", are not incorrectly presented as runtime exposure.
 */
export type SecurityConclusion =
  | "candidate"
  | "affected"
  | "exposed"
  | "reachable"
  | "executed";

/**
 * One reverse-traversal hop discovered by a graph reader.
 *
 * The reader may internally use a derived USED_BY index, but it must return
 * the canonical DEPENDS_ON edge supporting the hop.
 */
export interface DependencyHop {
  readonly dependentNode: GraphNode;

  /**
   * Canonical dependent -> dependency relationship.
   *
   * This edge, rather than a derived USED_BY edge, is security evidence.
   */
  readonly canonicalEdge: DependencyEdge;

  /**
   * Optional diagnostic identity of the derived traversal index.
   *
   * It must never be included in evidenceIds or used to prove exposure.
   */
  readonly traversalIndexEdgeId?: EdgeId;
}
/**
 * Required bound for one reverse-dependency lookup.
 *
 * Readers must apply this limit while reading/querying, not after returning
 * an unbounded collection.
 */
export interface FindDependentsOptions {
  readonly limit: number;
}

/**
 * Deterministically ordered, bounded reverse-dependency result.
 */
export interface DependencyHopPage {
  readonly hops: readonly DependencyHop[];

  /**
   * True when additional valid dependents existed beyond the requested
   * limit.
   */
  readonly truncated: boolean;
}

/**
 * Read-only graph access required by the pure analysis layer.
 *
 * An in-memory fixture and a future HydraDB adapter can both implement this
 * interface. Analysis functions must never depend on a graph writer.
 */
export interface ReadonlyGraphReader {
  getNode(nodeId: NodeId): Promise<GraphNode | null>;

  /**
   * Finds nodes with canonical DEPENDS_ON edges targeting nodeId.
   */
  findDependents(
  nodeId: NodeId,
  options: FindDependentsOptions,
): Promise<DependencyHopPage>;


  getEvidence(
    evidenceIds: readonly NodeId[],
  ): Promise<readonly EvidenceNode[]>;
}

/**
 * Optional safety limits for reverse blast-radius traversal.
 */
export interface BlastRadiusOptions {
  /**
   * Maximum number of canonical dependency hops in one returned path.
   */
  readonly maxDepth?: number;

  /**
   * Maximum number of unique Service candidates returned.
   */
  readonly maxServices?: number;

  /**
   * Maximum number of distinct paths retained for one Service.
   */
  readonly maxPathsPerService?: number;

  /**
   * Maximum number of distinct paths retained across the complete result.
   */
  readonly maxTotalPaths?: number;

  /**
   * Maximum number of traversal states admitted across all roots.
   *
   * This bounds work even when traversal does not reach a Service.
   */
  readonly maxTraversalStates?: number;

  /**
   * Maximum number of deterministically sorted dependents expanded for one
   * node.
   */
  readonly maxDependentsPerNode?: number;

  /**
   * Maximum number of warnings retained before traversal stops.
   *
   * One warning slot is reserved for the warning-limit notification.
   */
  readonly maxWarnings?: number;
}

/**
 * Normalized traversal limits actually applied by the analysis.
 */
export interface AppliedBlastRadiusLimits {
  readonly maxDepth: number;
  readonly maxServices: number;
  readonly maxPathsPerService: number;
  readonly maxTotalPaths: number;
  readonly maxTraversalStates: number;
  readonly maxDependentsPerNode: number;
  readonly maxWarnings: number;
}

/**
 * One canonical reverse dependency path from an incident-affected package
 * version to an internal Service.
 */
export interface BlastRadiusPath {
  /**
   * Deterministic key built from the root ID and canonical edge IDs.
   */
  readonly pathKey: string;

  readonly affectedVersionId: NodeId;
  readonly serviceId: NodeId;

  /**
   * Nodes in reverse-traversal order:
   *
   * affected PackageVersion -> dependent nodes -> Service
   */
  readonly nodes: readonly GraphNode[];

  /**
   * Canonical DEPENDS_ON edges in the same traversal order as nodes.
   *
   * For edge index i, canonical direction is:
   * nodes[i + 1] -[:DEPENDS_ON]-> nodes[i]
   */
  readonly canonicalEdges: readonly DependencyEdge[];

  readonly depth: number;
}

/**
 * Candidate Service and every distinct canonical path retained for it.
 *
 * "Candidate" is intentional: structural traversal alone does not prove that
 * the compromised version was resolved, built, deployed, or executed.
 */
export interface BlastRadiusServiceCandidate {
  readonly service: ServiceNode;
  readonly minimumDepth: number;
  readonly paths: readonly BlastRadiusPath[];
}

export type AnalysisWarningCode =
  | "cycle-skipped"
  | "depth-limit-reached"
  | "service-limit-reached"
  | "path-limit-reached"
  | "paths-per-service-limit-reached"
  | "traversal-state-limit-reached"
  | "dependents-per-node-limit-reached"
  | "warning-limit-reached"
  | "missing-node"
  | "invalid-canonical-hop"
  | "unsupported-root-node";

/**
 * Nonfatal condition discovered during analysis.
 */
export interface AnalysisWarning {
  readonly code: AnalysisWarningCode;
  readonly message: string;
  readonly nodeId?: NodeId;
  readonly pathNodeIds?: readonly NodeId[];
}

/**
 * Complete deterministic result of one reverse blast-radius analysis.
 */
export interface BlastRadiusResult {
  /**
   * Sorted unique incident-affected PackageVersion IDs supplied as roots.
   */
  readonly affectedVersionIds: readonly NodeId[];

  readonly services: readonly BlastRadiusServiceCandidate[];

  readonly totalPathCount: number;

  /**
   * True when one or more safety limits prevented complete enumeration.
   */
  readonly truncated: boolean;

  readonly limits: AppliedBlastRadiusLimits;
  readonly warnings: readonly AnalysisWarning[];
}

/**
 * Explicit evidence signals supplied to the pure exposure classifier.
 *
 * The classifier does not discover these facts and does not infer a missing
 * signal. IDs must refer to canonical Evidence nodes.
 */
export interface ExposureEvidenceSignals {
  readonly semverEligible: boolean;

  readonly exactResolutionEvidenceIds: readonly NodeId[];
  readonly buildEvidenceIds: readonly NodeId[];
  readonly deploymentEvidenceIds: readonly NodeId[];
  readonly reachabilityEvidenceIds: readonly NodeId[];
  readonly executionEvidenceIds: readonly NodeId[];
}

/**
 * Evidence-based classification for one candidate path or Service.
 */
export interface ExposureAssessment {
  readonly stage: ExposureStage;
  readonly conclusion: SecurityConclusion;

  /**
   * Sorted unique canonical Evidence node IDs supporting the selected stage.
   */
  readonly evidenceIds: readonly NodeId[];

  /**
   * Facts that remain unproven after selecting the strongest supported stage.
   */
  readonly uncertainties: readonly string[];
}
