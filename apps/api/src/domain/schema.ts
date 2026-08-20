import type { TransformationKind } from "../typosquatting/types.js";

export type NodeId = number;
export type EdgeId = number;
export type UnixEpochMilliseconds = number;

export type NodeKind =
  | "Package"
  | "PackageVersion"
  | "Repository"
  | "Service"
  | "Build"
  | "Artifact"
  | "Deployment"
  | "Maintainer"
  | "Credential"
  | "CIWorkflow"
  | "Organization"
  | "Incident"
  | "Evidence"
  | "Control"
  | "Finding";

export type DependencyType =
  | "production"
  | "development"
  | "optional"
  | "peer";

export type ServiceCriticality =
  | "low"
  | "medium"
  | "high"
  | "critical";

export type EvidenceSourceType =
  | "npm-registry"
  | "package-manifest"
  | "package-lock"
  | "git-commit"
  | "cyclonedx"
  | "spdx"
  | "slsa"
  | "sigstore"
  | "runtime-telemetry"
  | "security-advisory"
  | "typosquat-detector"
  | "analyst-review"
  | "synthetic-fixture"
  | "other";

export interface BaseNode<K extends NodeKind = NodeKind> {
  /**
   * Deterministic, nonnegative, 53-bit-safe HydraDB identifier.
   */
  readonly id: NodeId;

  /**
   * Canonical identity from which id was generated.
   */
  readonly logicalId: string;

  readonly kind: K;

  /**
   * Evidence nodes supporting the facts stored on this node.
   * EvidenceNode itself must use an empty array.
   */
  readonly evidenceIds: readonly NodeId[];

  /**
   * True when the node represents fabricated demonstration data.
   */
  readonly synthetic: boolean;

  /**
   * Milliseconds since the Unix epoch.
   */
  readonly observedAt: UnixEpochMilliseconds;
}

export interface PackageNode extends BaseNode<"Package"> {
  readonly ecosystem: "npm";
  readonly name: string;
}

export interface PackageVersionNode extends BaseNode<"PackageVersion"> {
  readonly ecosystem: "npm";
  readonly packageName: string;
  readonly version: string;
  readonly publishedAt?: UnixEpochMilliseconds;
}

/**
 * Do not add `compromised` here.
 * Compromise is incident-specific and is represented by AFFECTS.
 */
export interface RepositoryNode extends BaseNode<"Repository"> {
  readonly provider: "github" | "gitlab" | "other";
  readonly url: string;
  readonly defaultBranch?: string;
}

export interface ServiceNode extends BaseNode<"Service"> {
  readonly name: string;
  readonly criticality: ServiceCriticality;
  readonly internetExposed?: boolean;
  readonly dataSensitivity?: ServiceCriticality;
}

export interface BuildNode extends BaseNode<"Build"> {
  readonly provider: string;
  readonly buildNumber: string;
  readonly commitSha: string;
  readonly startedAt: UnixEpochMilliseconds;
  readonly completedAt?: UnixEpochMilliseconds;
}

export interface ArtifactNode extends BaseNode<"Artifact"> {
  readonly digest: string;
  readonly mediaType: string;
}

export interface DeploymentNode extends BaseNode<"Deployment"> {
  readonly environment: string;
  readonly deployedAt: UnixEpochMilliseconds;
  readonly removedAt?: UnixEpochMilliseconds;
}

export interface MaintainerNode extends BaseNode<"Maintainer"> {
  readonly handle: string;

  /**
   * Optional because registry records do not always expose an email.
   */
  readonly email?: string;
}

export type CredentialStatus =
  | "active"
  | "expired"
  | "revoked"
  | "unknown";

export interface CredentialNode extends BaseNode<"Credential"> {
  readonly credentialType:
    | "npm-token"
    | "github-token"
    | "oidc"
    | "signing-key"
    | "other";

  /**
   * Permission names only. Never store an actual token or secret.
   */
  readonly scopes: readonly string[];
  readonly status: CredentialStatus;
  readonly expiresAt?: UnixEpochMilliseconds;
}

export interface CIWorkflowNode extends BaseNode<"CIWorkflow"> {
  readonly provider: "github-actions" | "gitlab-ci" | "other";
  readonly path: string;
}

export interface OrganizationNode extends BaseNode<"Organization"> {
  readonly name: string;
  readonly provider?: string;
}

export interface IncidentNode extends BaseNode<"Incident"> {
  readonly title: string;
  readonly status: "draft" | "active" | "contained" | "closed";
  readonly intervalStart: UnixEpochMilliseconds;

  /**
   * Null means that the compromise interval is still open.
   */
  readonly intervalEnd: UnixEpochMilliseconds | null;
}

export interface EvidenceNode extends BaseNode<"Evidence"> {
  /**
   * Evidence records are direct provenance records, so they do not
   * recursively reference other Evidence nodes.
   */
  readonly evidenceIds: readonly [];

  readonly sourceType: EvidenceSourceType;
  readonly sourceUri: string;
  readonly collectorVersion: string;

  /**
   * Runtime validation must ensure this is between 0 and 1.
   */
  readonly confidence: number;
  readonly detail: string;
  readonly incidentId?: NodeId;
}

export type TyposquatFindingStatus =
  | "candidate"
  | "suspicious"
  | "high-confidence"
  | "confirmed"
  | "dismissed";

export interface TyposquatFindingNode extends BaseNode<"Finding"> {
  readonly findingType: "typosquatting";
  readonly status: TyposquatFindingStatus;

  /** Ranking evidence on a 0..100 scale; this is not a probability. */
  readonly score: number;

  readonly detectorVersion: string;
  readonly policyVersion: string;
  readonly corpusId: string;
  readonly comparisonVersion: string;
  readonly indexVersion: string;
  readonly candidatePackageName: string;
  readonly targetPackageName: string;
  readonly summary: string;
  readonly transformations: readonly TransformationKind[];
  readonly reasonCodes: readonly string[];
  readonly detectedAt: UnixEpochMilliseconds;
  readonly decidedAt?: UnixEpochMilliseconds;
  readonly decisionReason?: string;
}

export type ControlAction =
  | "block-package-version"
  | "pin-dependency"
  | "apply-override"
  | "revoke-credential"
  | "remove-publishing-access"
  | "disable-workflow"
  | "rotate-secret"
  | "rollback-artifact"
  | "isolate-service"
  | "restrict-network";

export interface ControlNode extends BaseNode<"Control"> {
  readonly action: ControlAction;
  readonly status: "proposed" | "simulated" | "approved" | "applied";
  readonly estimatedCost?: number;
  readonly estimatedMinutes?: number;
  readonly reversible: boolean;
}

export type GraphNode =
  | PackageNode
  | PackageVersionNode
  | RepositoryNode
  | ServiceNode
  | BuildNode
  | ArtifactNode
  | DeploymentNode
  | MaintainerNode
  | CredentialNode
  | CIWorkflowNode
  | OrganizationNode
  | IncidentNode
  | EvidenceNode
  | ControlNode
  | TyposquatFindingNode;

export type CanonicalRelKind =
  | "HAS_VERSION"
  | "DECLARES_DEPENDENCY"
  | "DEPENDS_ON"
  | "CONTAINS"
  | "TRIGGERS"
  | "PRODUCES"
  | "DEPLOYED_AS"
  | "RUNS"
  | "MAINTAINS"
  | "MEMBER_OF"
  | "OWNS"
  | "CAN_PUBLISH"
  | "CAN_ACCESS"
  | "CONTROLS"
  | "AFFECTS"
  | "SUPPORTS"
  | "TARGETS"
  | "LOOKALIKE_OF"
  | "IMITATES";

export type GraphRelKind = CanonicalRelKind | "USED_BY";

export interface BaseEdge<K extends GraphRelKind = GraphRelKind> {
  readonly id: EdgeId;
  readonly logicalId: string;
  readonly sourceId: NodeId;
  readonly targetId: NodeId;
  readonly kind: K;
  readonly observedAt: UnixEpochMilliseconds;
}

export interface CanonicalEdgeBase<
  K extends CanonicalRelKind = CanonicalRelKind,
> extends BaseEdge<K> {
  readonly derived: false;

  /**
   * Allows multiple legitimate edges of the same kind between the
   * same endpoints, such as separate workspace dependency entries.
   */
  readonly identityDiscriminator: string;

  readonly evidenceIds: readonly NodeId[];
}

/**
 * A declared dependency range, such as ^1.2.0.
 *
 * It targets Package because no exact version has been resolved yet.
 */
export interface DependencyDeclarationEdge
  extends CanonicalEdgeBase<"DECLARES_DEPENDENCY"> {
  readonly declaredRange: string;
  readonly dependencyType: DependencyType;
  readonly workspacePath?: string;
}

/**
 * A concrete dependency resolution.
 *
 * Its target must be an exact PackageVersion. Registry range metadata
 * alone is not enough to create this relationship.
 */
export interface DependencyEdge
  extends CanonicalEdgeBase<"DEPENDS_ON"> {
  readonly dependencyType: DependencyType;
  readonly declaredRange?: string;
  readonly lockfilePath?: string;
  readonly integrity?: string;
}

export interface LookalikeEdge
  extends CanonicalEdgeBase<"LOOKALIKE_OF"> {
  readonly algorithm: string;
  readonly comparisonVersion: string;
  readonly normalizedDistance: number;
  readonly transformations: readonly TransformationKind[];
}

export interface StandardCanonicalEdge
  extends CanonicalEdgeBase<
    Exclude<
      CanonicalRelKind,
      "DECLARES_DEPENDENCY" | "DEPENDS_ON" | "LOOKALIKE_OF"
    >
  > {}

export type CanonicalEdge =
  | DependencyDeclarationEdge
  | DependencyEdge
  | LookalikeEdge
  | StandardCanonicalEdge;

export interface DerivedEdge extends BaseEdge<"USED_BY"> {
  readonly derived: true;

  /**
   * ID and logical identity of the canonical DEPENDS_ON edge.
   */
  readonly derivedFrom: EdgeId;
  readonly derivedFromLogicalId: string;

  readonly generatedAt: UnixEpochMilliseconds;
  readonly generatorVersion: string;

  /**
   * Derived indexes must not carry independent security evidence.
   */
  readonly evidenceIds?: never;
}

export type GraphEdge = CanonicalEdge | DerivedEdge;
