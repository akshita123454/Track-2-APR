// ─── Shared primitives ───────────────────────────────────────────

export type NodeId = number;
export type EdgeId = number;
export type UnixEpochMilliseconds = number;

export type ServiceCriticality = 'low' | 'medium' | 'high' | 'critical';

export type DependencyType = 'production' | 'development' | 'optional' | 'peer';

export type EvidenceSourceType =
  | 'npm-registry'
  | 'package-manifest'
  | 'package-lock'
  | 'git-commit'
  | 'cyclonedx'
  | 'spdx'
  | 'slsa'
  | 'sigstore'
  | 'runtime-telemetry'
  | 'security-advisory'
  | 'synthetic-fixture'
  | 'other';

export type IncidentStatus = 'draft' | 'active' | 'contained' | 'closed';

export type AnalysisWarningCode =
  | 'cycle-skipped'
  | 'depth-limit-reached'
  | 'service-limit-reached'
  | 'path-limit-reached'
  | 'paths-per-service-limit-reached'
  | 'traversal-state-limit-reached'
  | 'dependents-per-node-limit-reached'
  | 'warning-limit-reached'
  | 'missing-node'
  | 'invalid-canonical-hop'
  | 'unsupported-root-node';

export type EvidenceFunnelStageId =
  | 'structural-candidate'
  | 'evidence-verified'
  | 'high-confidence-evidence';

// ─── Node types ──────────────────────────────────────────────────

export interface PackageVersionNode {
  readonly id: NodeId;
  readonly logicalId: string;
  readonly kind: 'PackageVersion';
  readonly evidenceIds: readonly NodeId[];
  readonly synthetic: boolean;
  readonly observedAt: UnixEpochMilliseconds;
  readonly ecosystem: 'npm';
  readonly packageName: string;
  readonly version: string;
  readonly publishedAt?: UnixEpochMilliseconds;
}

export interface ServiceNode {
  readonly id: NodeId;
  readonly logicalId: string;
  readonly kind: 'Service';
  readonly evidenceIds: readonly NodeId[];
  readonly synthetic: boolean;
  readonly observedAt: UnixEpochMilliseconds;
  readonly name: string;
  readonly criticality: ServiceCriticality;
  readonly internetExposed?: boolean;
  readonly dataSensitivity?: ServiceCriticality;
}

export type BlastRadiusNode = PackageVersionNode | ServiceNode;

// ─── Edge type ───────────────────────────────────────────────────

export interface DependencyEdge {
  readonly id: EdgeId;
  readonly logicalId: string;
  readonly sourceId: NodeId;
  readonly targetId: NodeId;
  readonly kind: 'DEPENDS_ON';
  readonly observedAt: UnixEpochMilliseconds;
  readonly derived: false;
  readonly identityDiscriminator: string;
  readonly evidenceIds: readonly NodeId[];
  readonly dependencyType: DependencyType;
  readonly declaredRange?: string;
  readonly lockfilePath?: string;
  readonly integrity?: string;
}

// ─── Path and service candidate ──────────────────────────────────

export interface BlastRadiusPath {
  readonly pathKey: string;
  readonly affectedVersionId: NodeId;
  readonly serviceId: NodeId;
  readonly nodes: readonly BlastRadiusNode[];
  readonly canonicalEdges: readonly DependencyEdge[];
  readonly depth: number;
}

export interface ServiceCandidate {
  readonly service: ServiceNode;
  readonly minimumDepth: number;
  readonly paths: readonly BlastRadiusPath[];
}

// ─── Analysis limits ─────────────────────────────────────────────

export interface AppliedBlastRadiusLimits {
  readonly maxDepth: number;
  readonly maxServices: number;
  readonly maxPathsPerService: number;
  readonly maxTotalPaths: number;
  readonly maxTraversalStates: number;
  readonly maxDependentsPerNode: number;
  readonly maxWarnings: number;
}

// ─── Warnings ────────────────────────────────────────────────────

export interface AnalysisWarning {
  readonly code: AnalysisWarningCode;
  readonly message: string;
  readonly nodeId?: NodeId;
  readonly pathNodeIds?: readonly NodeId[];
}

// ─── Evidence funnel ─────────────────────────────────────────────

export interface EvidenceFunnelStage {
  readonly id: EvidenceFunnelStageId;
  readonly label: string;
  readonly description: string;
  readonly pathCount: number;
  readonly serviceCount: number;
  readonly pathPercentage: number;
  readonly servicePercentage: number;
}

export interface EvidenceLookup {
  readonly referencedEvidenceCount: number;
  readonly requestedEvidenceCount: number;
  readonly resolvedEvidenceCount: number;
  readonly missingEvidenceCount: number;
  readonly missingEvidenceIds: readonly NodeId[];
  readonly omittedEvidenceCount: number;
  readonly complete: boolean;
}

export interface EvidenceSourceSummary {
  readonly sourceType: EvidenceSourceType;
  readonly evidenceCount: number;
  readonly averageConfidence: number;
}

export interface EvidenceFunnel {
  readonly affectedVersionCount: number;
  readonly candidatePathCount: number;
  readonly candidateServiceCount: number;
  readonly highConfidenceThreshold: number;
  readonly stages: readonly EvidenceFunnelStage[];
  readonly evidenceLookup: EvidenceLookup;
  readonly sources: readonly EvidenceSourceSummary[];
  readonly completeForReturnedCandidates: boolean;
  readonly completeForIncident: boolean;
  readonly limitations: readonly string[];
}

// ─── Evidence catalog ────────────────────────────────────────────

export interface EvidenceCatalogEntry {
  readonly id: NodeId;
  readonly sourceType: EvidenceSourceType;
  readonly confidence: number;
  readonly observedAt: UnixEpochMilliseconds;
  readonly synthetic: boolean;
  readonly incidentLinked: boolean;
}

// ─── Telemetry ───────────────────────────────────────────────────

export interface HydraReadTelemetry {
  readonly readEpoch: string;
  readonly readEpochMs: UnixEpochMilliseconds;
  readonly queryCount: number;
  readonly rowsRead: number;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly latencyMs: number;
  readonly consistencyModel: 'bounded-multi-statement-read';
  readonly engine: 'HydraDB';
}

// ─── Incident summary ────────────────────────────────────────────

export interface IncidentSummary {
  readonly id: NodeId;
  readonly title: string;
  readonly status: IncidentStatus;
  readonly intervalStart: UnixEpochMilliseconds;
  readonly intervalEnd: UnixEpochMilliseconds | null;
  readonly synthetic: boolean;
}

// ─── Affected version summary ────────────────────────────────────

export interface AffectedVersionSummary {
  readonly id: NodeId;
  readonly packageName: string;
  readonly version: string;
  readonly publishedAt?: UnixEpochMilliseconds;
  readonly synthetic: boolean;
}

// ─── Affected version lookup ─────────────────────────────────────

export interface AffectedVersionLookup {
  readonly limit: number;
  readonly returnedCount: number;
  readonly truncated: boolean;
}

// ─── Top-level response ──────────────────────────────────────────

export interface LiveBlastRadiusResponse {
  readonly incidentId: NodeId;
  readonly incident: IncidentSummary;
  readonly affectedVersions: readonly AffectedVersionSummary[];
  readonly evidenceCatalog: readonly EvidenceCatalogEntry[];
  readonly affectedVersionLookup: AffectedVersionLookup;
  readonly affectedVersionIds: readonly NodeId[];
  readonly services: readonly ServiceCandidate[];
  readonly totalPathCount: number;
  readonly truncated: boolean;
  readonly limits: AppliedBlastRadiusLimits;
  readonly warnings: readonly AnalysisWarning[];
  readonly evidenceFunnel: EvidenceFunnel;
  readonly hydraRead: HydraReadTelemetry;
}
