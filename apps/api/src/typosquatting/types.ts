export const COMPARISON_VERSION = "npm-name-nfc-v2";
export const INDEX_VERSION = "trusted-target-signatures-v1";

export type PackageNameValidationCode =
  | "empty"
  | "too-long"
  | "control-character"
  | "invalid-scope"
  | "invalid-basename"
  | "invalid-character";

export interface ComparablePackageName {
  readonly original: string;
  readonly normalized: string;
  readonly scope?: string;
  readonly basename: string;
  readonly compact: string;
  readonly tokens: readonly string[];
  readonly comparisonVersion: typeof COMPARISON_VERSION;
}

export type DistanceOperationKind =
  | "match"
  | "insertion"
  | "deletion"
  | "substitution"
  | "adjacent-transposition";

export interface DistanceOperation {
  readonly kind: DistanceOperationKind;
  readonly sourceIndex: number;
  readonly targetIndex: number;
  readonly source: string;
  readonly target: string;
  readonly cost: number;
}

export interface DistanceResult {
  readonly cost: number;
  readonly normalizedCost: number;
  readonly operations: readonly DistanceOperation[];
}

export type TransformationKind =
  | "adjacent-transposition"
  | "insertion"
  | "deletion"
  | "substitution"
  | "separator-variation"
  | "repeated-character"
  | "scope-impersonation"
  | "unicode-confusable"
  | "prefix-suffix";

export type TargetSource =
  | "public-popular"
  | "org-owned"
  | "internal-resolved"
  | "active-incident"
  | "watchlist";

export interface TrustedTarget {
  readonly packageId: number;
  readonly packageName: string;
  readonly sources: readonly TargetSource[];
  readonly rank?: number;
  readonly popularity?: number;
  readonly internalUsageCount?: number;
  readonly maintainers?: readonly string[];
  readonly sourceEvidenceIds: readonly number[];
}

export interface TyposquattingCorpusInput {
  readonly corpusId: string;
  readonly generatedAt: number;
  readonly comparisonVersion: typeof COMPARISON_VERSION;
  readonly indexVersion: typeof INDEX_VERSION;
  readonly sourceEvidenceIds: readonly number[];
  readonly targetCount: number;
  readonly targets: readonly TrustedTarget[];
  readonly allowlist: readonly string[];
  readonly blocklist: readonly string[];
  readonly watchlist: readonly string[];
}

export interface IndexedTrustedTarget extends TrustedTarget {
  readonly comparableName: ComparablePackageName;
}

export type TargetSelectionReason =
  | "compact-signature"
  | "basename-signature"
  | "confusable-signature"
  | "deletion-signature"
  | "same-scope-signature"
  | "watchlist-priority"
  | "prominence-priority";

export interface CandidateIndexTarget {
  readonly packageId: number;
  readonly comparisonName: string;
}

export interface CandidateIndex {
  readonly maxDeletionDepth: number;
  readonly signatureToTargets: ReadonlyMap<string, readonly CandidateIndexTarget[]>;
  readonly targetById: ReadonlyMap<number, IndexedTrustedTarget>;
}

export interface NormalizedPolicyLists {
  readonly allowlist: ReadonlySet<string>;
  readonly blocklist: ReadonlySet<string>;
  readonly watchlist: ReadonlySet<string>;
}

export interface TyposquattingCorpus extends Omit<TyposquattingCorpusInput, "targets"> {
  readonly targets: readonly IndexedTrustedTarget[];
  readonly index: CandidateIndex;
  readonly normalizedPolicy: NormalizedPolicyLists;
}

export type ObservedPackageSource = "registry" | "lockfile";

export type ContextualEvidenceCategory =
  | "publication"
  | "downloads"
  | "maintainer"
  | "lifecycle-scripts"
  | "repository"
  | "dependency-graph"
  | "build"
  | "deployment"
  | "runtime"
  | "active-incident";

export interface ContextualEvidence {
  readonly category: ContextualEvidenceCategory;
  readonly evidenceIds: readonly number[];
  readonly detail?: string;
}

export interface ObservedPackage {
  readonly packageId: number;
  readonly name: string;
  readonly version?: string;
  readonly source: ObservedPackageSource;
  readonly sourceEvidenceIds: readonly number[];
  readonly publication?: number;
  readonly maintainers?: readonly string[];
  readonly downloads?: number;
  readonly lifecycleScripts?: readonly string[];
  readonly repository?: string;
  readonly contextualEvidence?: readonly ContextualEvidence[];
}

export interface CandidateSelection {
  readonly targetId: number;
  readonly comparisonName: string;
  readonly reasons: readonly TargetSelectionReason[];
}

export interface CandidateGenerationResult {
  readonly candidates: readonly CandidateSelection[];
  readonly visited: number;
  readonly truncated: boolean;
}

export type ReasonGroup =
  | "lexical"
  | "target"
  | "metadata"
  | "publisher"
  | "exposure"
  | "policy";

export type ReasonCode =
  | "LEXICAL_DISTANCE_VERY_CLOSE"
  | "LEXICAL_DISTANCE_CLOSE"
  | "LEXICAL_COMPACT_MATCH"
  | "LEXICAL_CONFUSABLE"
  | "LEXICAL_SPECIAL_TRANSFORMATION"
  | "TARGET_WATCHLIST_PRIORITY"
  | "TARGET_PROMINENCE"
  | "METADATA_RECENT_PUBLICATION"
  | "METADATA_DOWNLOAD_IMBALANCE"
  | "METADATA_LIFECYCLE_SCRIPTS"
  | "METADATA_CONTEXT_CONCERN"
  | "PUBLISHER_MAINTAINER_DIVERGENCE"
  | "PUBLISHER_CONTEXT_CONCERN"
  | "EXPOSURE_LOCKFILE"
  | "EXPOSURE_CONTEXT_CONCERN"
  | "POLICY_BLOCKLIST"
  | "POLICY_WATCHLIST";

export interface ScoreReason {
  readonly code: ReasonCode;
  readonly group: ReasonGroup;
  readonly points: number;
  readonly detail: string;
  readonly evidenceIds: readonly number[];
}

export type TyposquattingClassification = "candidate" | "suspicious" | "high-confidence";

export interface TyposquattingFinding {
  readonly targetPackageId: number;
  readonly targetName: string;
  readonly observedPackageId: number;
  readonly candidateName: string;
  readonly candidateVersion?: string;
  readonly candidateSource: ObservedPackageSource;
  readonly classification: TyposquattingClassification;
  readonly score: number;
  readonly strongLexicalMatch: boolean;
  readonly transformations: readonly TransformationKind[];
  readonly targetSelectionReasons: readonly TargetSelectionReason[];
  readonly reasons: readonly ScoreReason[];
  readonly nonLexicalEvidenceCategories: readonly string[];
  readonly distance: DistanceResult;
  readonly sourceEvidenceIds: readonly number[];
}

export interface DetectorOptions {
  readonly maxPackages: number;
  readonly maxCandidatesPerPackage: number;
  readonly maxComparisons: number;
  readonly maxNormalizedDistance?: number;
}

export type PackageScanStatus = "scanned" | "allowlisted" | "invalid" | "budget-exhausted";

export interface PackageScanDiagnostics {
  readonly status: PackageScanStatus;
  readonly candidatesVisited: number;
  readonly comparisonsPerformed: number;
  readonly truncated: boolean;
  readonly messages: readonly string[];
}

export interface ObservedPackageScanResult {
  readonly packageId: number;
  readonly name: string;
  readonly version?: string;
  readonly source: ObservedPackageSource;
  readonly comparableName?: ComparablePackageName;
  readonly findings: readonly TyposquattingFinding[];
  readonly diagnostics: PackageScanDiagnostics;
}

export type BudgetDiagnosticCode =
  | "MAX_PACKAGES_REACHED"
  | "MAX_CANDIDATES_PER_PACKAGE_REACHED"
  | "MAX_COMPARISONS_REACHED"
  | "INVALID_OBSERVED_PACKAGE"
  | "ALLOWLISTED_OBSERVED_PACKAGE";

export interface DetectionDiagnostics {
  readonly inputPackages: number;
  readonly packagesScanned: number;
  readonly invalidPackages: number;
  readonly candidatesVisited: number;
  readonly comparisonsPerformed: number;
  readonly truncated: boolean;
  readonly budgetCodes: readonly BudgetDiagnosticCode[];
  readonly limits: Readonly<DetectorOptions>;
}

export interface DetectionResult {
  readonly corpus: {
    readonly corpusId: string;
    readonly generatedAt: number;
    readonly comparisonVersion: typeof COMPARISON_VERSION;
    readonly indexVersion: typeof INDEX_VERSION;
    readonly targetCount: number;
    readonly sourceEvidenceIds: readonly number[];
  };
  readonly packages: readonly ObservedPackageScanResult[];
  readonly findings: readonly TyposquattingFinding[];
  readonly diagnostics: DetectionDiagnostics;
}
