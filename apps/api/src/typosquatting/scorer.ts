import { confusableSkeleton } from "./confusables.js";
import type {
  ComparablePackageName,
  ContextualEvidenceCategory,
  DistanceResult,
  IndexedTrustedTarget,
  ObservedPackage,
  ReasonGroup,
  ScoreReason,
  TargetSelectionReason,
  TransformationKind,
  TyposquattingClassification,
} from "./types.js";

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1_000;

export interface ScoreResult {
  readonly score: number;
  readonly classification: TyposquattingClassification;
  readonly reasons: readonly ScoreReason[];
  readonly nonLexicalEvidenceCategories: readonly string[];
}

function uniqueEvidence(values: readonly number[]): readonly number[] {
  return [...new Set(values)].sort((left, right) => left - right);
}

function reason(
  code: ScoreReason["code"],
  group: ScoreReason["group"],
  points: number,
  detail: string,
  evidenceIds: readonly number[] = [],
): ScoreReason {
  return { code, group, points, detail, evidenceIds: uniqueEvidence(evidenceIds) };
}

function contextualGroup(category: ContextualEvidenceCategory): Exclude<ReasonGroup, "lexical" | "target" | "policy"> {
  if (category === "maintainer") {
    return "publisher";
  }
  if (["dependency-graph", "build", "deployment", "runtime", "active-incident"].includes(category)) {
    return "exposure";
  }
  return "metadata";
}

function addCategory(
  categories: Map<string, Set<number>>,
  category: string,
  evidenceIds: readonly number[],
): void {
  const evidence = categories.get(category) ?? new Set<number>();
  for (const evidenceId of evidenceIds) {
    evidence.add(evidenceId);
  }
  categories.set(category, evidence);
}

function independentCategoryCount(categories: ReadonlyMap<string, ReadonlySet<number>>): number {
  const evidenceToCategory = new Map<number, string>();
  function assign(category: string, seen: Set<number>): boolean {
    for (const evidenceId of categories.get(category) ?? []) {
      if (seen.has(evidenceId)) {
        continue;
      }
      seen.add(evidenceId);
      const previous = evidenceToCategory.get(evidenceId);
      if (previous === undefined || assign(previous, seen)) {
        evidenceToCategory.set(evidenceId, category);
        return true;
      }
    }
    return false;
  }
  let count = 0;
  for (const category of [...categories.keys()].sort()) {
    if (assign(category, new Set())) {
      count += 1;
    }
  }
  return count;
}

export function scoreCandidate(
  generatedAt: number,
  target: IndexedTrustedTarget,
  observed: ObservedPackage,
  targetName: ComparablePackageName,
  candidateName: ComparablePackageName,
  distance: DistanceResult,
  transformations: readonly TransformationKind[],
  targetSelectionReasons: readonly TargetSelectionReason[],
  strongLexicalMatch: boolean,
  blocklisted: boolean,
  watchlisted: boolean,
): ScoreResult {
  const reasons: ScoreReason[] = [];
  const categories = new Map<string, Set<number>>();

  if (distance.normalizedCost <= 0.1) {
    reasons.push(reason("LEXICAL_DISTANCE_VERY_CLOSE", "lexical", 38, `normalized edit cost ${distance.normalizedCost.toFixed(4)}`));
  } else {
    reasons.push(reason("LEXICAL_DISTANCE_CLOSE", "lexical", strongLexicalMatch ? 30 : 22, `normalized edit cost ${distance.normalizedCost.toFixed(4)}`));
  }
  if (targetName.compact === candidateName.compact) {
    reasons.push(reason("LEXICAL_COMPACT_MATCH", "lexical", 24, "compact basenames match after separator removal"));
  }
  if (confusableSkeleton(targetName.normalized) === confusableSkeleton(candidateName.normalized)) {
    reasons.push(reason("LEXICAL_CONFUSABLE", "lexical", 32, "controlled confusable skeletons match"));
  }
  const special = transformations.filter((value) =>
    ["adjacent-transposition", "separator-variation", "repeated-character", "scope-impersonation", "unicode-confusable", "prefix-suffix"].includes(value)
  );
  if (special.length > 0) {
    reasons.push(reason("LEXICAL_SPECIAL_TRANSFORMATION", "lexical", 16, `special transformations: ${special.join(", ")}`));
  }

  if (targetSelectionReasons.includes("watchlist-priority")) {
    reasons.push(reason("TARGET_WATCHLIST_PRIORITY", "target", 0, "trusted target is watchlist-prioritized"));
  }
  if (targetSelectionReasons.includes("prominence-priority")) {
    reasons.push(reason("TARGET_PROMINENCE", "target", 0, "trusted target has prominence or internal-use priority"));
  }

  if (
    observed.publication !== undefined &&
    observed.publication <= generatedAt &&
    generatedAt - observed.publication <= THIRTY_DAYS_MS
  ) {
    addCategory(categories, "publication", observed.sourceEvidenceIds);
    reasons.push(reason("METADATA_RECENT_PUBLICATION", "metadata", 9, "publication is within 30 days of corpus generation", observed.sourceEvidenceIds));
  }
  if (
    target.popularity !== undefined && observed.downloads !== undefined &&
    target.popularity >= 1_000 && target.popularity >= Math.max(observed.downloads * 100, 1_000)
  ) {
    addCategory(categories, "downloads", observed.sourceEvidenceIds);
    reasons.push(reason("METADATA_DOWNLOAD_IMBALANCE", "metadata", 9, "trusted target popularity is at least 100x observed downloads", observed.sourceEvidenceIds));
  }
  if ((observed.lifecycleScripts ?? []).length > 0) {
    addCategory(categories, "lifecycle-scripts", observed.sourceEvidenceIds);
    reasons.push(reason("METADATA_LIFECYCLE_SCRIPTS", "metadata", 10, "observed package declares lifecycle scripts", observed.sourceEvidenceIds));
  }
  if (
    target.maintainers !== undefined && observed.maintainers !== undefined &&
    !observed.maintainers.some((maintainer) => target.maintainers!.includes(maintainer))
  ) {
    addCategory(categories, "maintainer", observed.sourceEvidenceIds);
    reasons.push(reason("PUBLISHER_MAINTAINER_DIVERGENCE", "publisher", 9, "no observed maintainer matches the trusted target", observed.sourceEvidenceIds));
  }

  for (const context of observed.contextualEvidence ?? []) {
    addCategory(categories, context.category, context.evidenceIds);
    const group = contextualGroup(context.category);
    const code = group === "publisher"
      ? "PUBLISHER_CONTEXT_CONCERN"
      : group === "exposure"
        ? "EXPOSURE_CONTEXT_CONCERN"
        : "METADATA_CONTEXT_CONCERN";
    reasons.push(reason(code, group, 10, context.detail ?? `${context.category} contextual concern`, context.evidenceIds));
  }

  if (observed.source === "lockfile") {
    reasons.push(reason("EXPOSURE_LOCKFILE", "exposure", 12, "package was actually observed in a lockfile", observed.sourceEvidenceIds));
  }
  if (blocklisted) {
    addCategory(categories, "policy:blocklist", observed.sourceEvidenceIds);
    reasons.push(reason("POLICY_BLOCKLIST", "policy", 24, "observed normalized name is blocklisted", observed.sourceEvidenceIds));
  }
  if (watchlisted) {
    reasons.push(reason("POLICY_WATCHLIST", "policy", 0, "observed or target normalized name is watchlisted"));
  }

  const nonLexicalEvidenceCategories = [...categories.keys()].sort();
  const highConfidenceGate = strongLexicalMatch &&
    observed.source === "lockfile" &&
    independentCategoryCount(categories) >= 2;
  const classification: TyposquattingClassification = highConfidenceGate
    ? "high-confidence"
    : categories.size > 0
      ? "suspicious"
      : "candidate";
  const score = Math.min(100, reasons.reduce((sum, value) => sum + value.points, 0));
  return { score, classification, reasons, nonLexicalEvidenceCategories };
}
