import { generateCandidates } from "./candidate-generator.js";
import { compareStableStrings } from "./candidate-index.js";
import { confusableSkeleton } from "./confusables.js";
import { weightedDamerauLevenshtein } from "./distance.js";
import { explainTransformations } from "./explanations.js";
import { normalizePackageName, PackageNameValidationError } from "./normalize.js";
import { scoreCandidate } from "./scorer.js";
import type {
  BudgetDiagnosticCode,
  ComparablePackageName,
  DetectionResult,
  DetectorOptions,
  DistanceResult,
  ObservedPackage,
  ObservedPackageScanResult,
  TransformationKind,
  TyposquattingClassification,
  TyposquattingCorpus,
  TyposquattingFinding,
} from "./types.js";

const DEFAULT_MAX_NORMALIZED_DISTANCE = 0.25;
const CLASSIFICATION_RANK: Readonly<Record<TyposquattingClassification, number>> = {
  "high-confidence": 3,
  suspicious: 2,
  candidate: 1,
};

function validateOptions(options: DetectorOptions): void {
  for (const [name, value] of [
    ["maxPackages", options.maxPackages],
    ["maxCandidatesPerPackage", options.maxCandidatesPerPackage],
    ["maxComparisons", options.maxComparisons],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${name} must be a non-negative safe integer`);
    }
  }
  if (
    options.maxNormalizedDistance !== undefined &&
    (!Number.isFinite(options.maxNormalizedDistance) || options.maxNormalizedDistance < 0 || options.maxNormalizedDistance > 1)
  ) {
    throw new Error("maxNormalizedDistance must be between 0 and 1");
  }
}

function validateObserved(observed: ObservedPackage): void {
  if (!Number.isSafeInteger(observed.packageId) || observed.packageId < 0) {
    throw new Error("packageId must be a non-negative safe integer");
  }
  if (observed.source !== "registry" && observed.source !== "lockfile") {
    throw new Error("source must be registry or lockfile");
  }
  for (const evidenceId of observed.sourceEvidenceIds) {
    if (!Number.isSafeInteger(evidenceId) || evidenceId < 0) {
      throw new Error("sourceEvidenceIds must contain non-negative safe integers");
    }
  }
  if (observed.publication !== undefined && (!Number.isSafeInteger(observed.publication) || observed.publication < 0)) {
    throw new Error("publication must be an epoch-ms non-negative safe integer");
  }
  if (observed.downloads !== undefined && (!Number.isSafeInteger(observed.downloads) || observed.downloads < 0)) {
    throw new Error("downloads must be a non-negative safe integer");
  }
  for (const context of observed.contextualEvidence ?? []) {
    for (const evidenceId of context.evidenceIds) {
      if (!Number.isSafeInteger(evidenceId) || evidenceId < 0) {
        throw new Error("contextual evidence IDs must be non-negative safe integers");
      }
    }
  }
}

function lexicalGate(
  target: ComparablePackageName,
  candidate: ComparablePackageName,
  distance: DistanceResult,
  transformations: readonly TransformationKind[],
  maximumDistance: number,
): { readonly accepted: boolean; readonly strong: boolean } {
  const length = Math.min(Array.from(target.compact).length, Array.from(candidate.compact).length);
  const skeletonMatch = confusableSkeleton(target.normalized) === confusableSkeleton(candidate.normalized);
  const compactMatch = target.compact === candidate.compact;
  const nonMatches = distance.operations.filter((operation) => operation.kind !== "match");
  const transposition = nonMatches.length === 1 && nonMatches[0]!.kind === "adjacent-transposition";
  const repeated = transformations.includes("repeated-character");
  const affix = transformations.includes("prefix-suffix") && Math.abs(target.compact.length - candidate.compact.length) <= 2;
  const special = compactMatch || skeletonMatch || transposition || repeated || affix;

  let accepted: boolean;
  if (length <= 3) {
    accepted = compactMatch || skeletonMatch;
  } else if (length === 4) {
    accepted = compactMatch || skeletonMatch || transposition || repeated;
  } else if (length <= 7) {
    accepted = distance.cost <= 100 || special;
  } else {
    accepted = (distance.cost <= 200 && distance.normalizedCost <= maximumDistance) || special;
  }
  accepted = accepted && (distance.normalizedCost <= maximumDistance || special);
  const strong = accepted && (
    compactMatch || skeletonMatch ||
    (length >= 4 && (transposition || repeated)) ||
    (length >= 5 && distance.cost <= 100 && distance.normalizedCost <= 0.2)
  );
  return { accepted, strong };
}

function compareFindings(left: TyposquattingFinding, right: TyposquattingFinding): number {
  return CLASSIFICATION_RANK[right.classification] - CLASSIFICATION_RANK[left.classification] ||
    right.score - left.score ||
    compareStableStrings(left.targetName, right.targetName) ||
    compareStableStrings(left.candidateName, right.candidateName) ||
    left.targetPackageId - right.targetPackageId ||
    left.observedPackageId - right.observedPackageId;
}

function evidenceIds(corpus: TyposquattingCorpus, targetIds: readonly number[], observed: ObservedPackage): readonly number[] {
  return [...new Set([
    ...corpus.sourceEvidenceIds,
    ...targetIds,
    ...observed.sourceEvidenceIds,
    ...(observed.contextualEvidence ?? []).flatMap((context) => context.evidenceIds),
  ])].sort((left, right) => left - right);
}

function invalidResult(observed: ObservedPackage, message: string): ObservedPackageScanResult {
  return {
    packageId: observed.packageId,
    name: observed.name,
    ...(observed.version === undefined ? {} : { version: observed.version }),
    source: observed.source,
    findings: [],
    diagnostics: {
      status: "invalid",
      candidatesVisited: 0,
      comparisonsPerformed: 0,
      truncated: false,
      messages: [message],
    },
  };
}

export function detectTyposquatting(
  observedPackages: readonly ObservedPackage[],
  corpus: TyposquattingCorpus,
  options: DetectorOptions,
): DetectionResult {
  validateOptions(options);
  const maximumDistance = options.maxNormalizedDistance ?? DEFAULT_MAX_NORMALIZED_DISTANCE;
  const packages: ObservedPackageScanResult[] = [];
  const allFindings: TyposquattingFinding[] = [];
  const budgetCodes = new Set<BudgetDiagnosticCode>();
  let comparisonsPerformed = 0;
  let candidatesVisited = 0;
  let invalidPackages = 0;

  const boundedPackages = observedPackages.slice(0, options.maxPackages);
  if (boundedPackages.length < observedPackages.length) {
    budgetCodes.add("MAX_PACKAGES_REACHED");
  }

  for (const observed of boundedPackages) {
    let candidateName: ComparablePackageName;
    try {
      validateObserved(observed);
      candidateName = normalizePackageName(observed.name);
    } catch (error) {
      invalidPackages += 1;
      budgetCodes.add("INVALID_OBSERVED_PACKAGE");
      const message = error instanceof PackageNameValidationError
        ? `${error.code}: ${error.message}`
        : error instanceof Error ? error.message : "invalid observed package";
      packages.push(invalidResult(observed, message));
      continue;
    }

    if (corpus.normalizedPolicy.allowlist.has(candidateName.normalized)) {
      budgetCodes.add("ALLOWLISTED_OBSERVED_PACKAGE");
      packages.push({
        packageId: observed.packageId,
        name: observed.name,
        ...(observed.version === undefined ? {} : { version: observed.version }),
        source: observed.source,
        comparableName: candidateName,
        findings: [],
        diagnostics: {
          status: "allowlisted",
          candidatesVisited: 0,
          comparisonsPerformed: 0,
          truncated: false,
          messages: ["normalized observed name is allowlisted"],
        },
      });
      continue;
    }

    const generated = generateCandidates(
      candidateName,
      corpus.index,
      options.maxCandidatesPerPackage,
      corpus.normalizedPolicy.watchlist,
    );
    candidatesVisited += generated.visited;
    if (generated.truncated) {
      budgetCodes.add("MAX_CANDIDATES_PER_PACKAGE_REACHED");
    }
    const findings: TyposquattingFinding[] = [];
    const packageStartComparisons = comparisonsPerformed;
    let comparisonTruncated = false;

    for (const selection of generated.candidates) {
      if (comparisonsPerformed >= options.maxComparisons) {
        comparisonTruncated = true;
        budgetCodes.add("MAX_COMPARISONS_REACHED");
        break;
      }
      const target = corpus.index.targetById.get(selection.targetId);
      if (target === undefined) {
        throw new Error(`candidate index references missing target: ${selection.targetId}`);
      }
      if (target.comparableName.normalized === candidateName.normalized) {
        continue;
      }
      comparisonsPerformed += 1;
      const distance = weightedDamerauLevenshtein(target.comparableName.compact, candidateName.compact);
      const transformations = explainTransformations(target.comparableName, candidateName, distance);
      const gate = lexicalGate(target.comparableName, candidateName, distance, transformations, maximumDistance);
      if (!gate.accepted) {
        continue;
      }
      const blocklisted = corpus.normalizedPolicy.blocklist.has(candidateName.normalized);
      const watchlisted = corpus.normalizedPolicy.watchlist.has(candidateName.normalized) ||
        corpus.normalizedPolicy.watchlist.has(target.comparableName.normalized) ||
        target.sources.includes("watchlist");
      const scored = scoreCandidate(
        corpus.generatedAt,
        target,
        observed,
        target.comparableName,
        candidateName,
        distance,
        transformations,
        selection.reasons,
        gate.strong,
        blocklisted,
        watchlisted,
      );
      findings.push({
        targetPackageId: target.packageId,
        targetName: target.packageName,
        observedPackageId: observed.packageId,
        candidateName: observed.name,
        ...(observed.version === undefined ? {} : { candidateVersion: observed.version }),
        candidateSource: observed.source,
        classification: scored.classification,
        score: scored.score,
        strongLexicalMatch: gate.strong,
        transformations,
        targetSelectionReasons: selection.reasons,
        reasons: scored.reasons,
        nonLexicalEvidenceCategories: scored.nonLexicalEvidenceCategories,
        distance,
        sourceEvidenceIds: evidenceIds(corpus, target.sourceEvidenceIds, observed),
      });
    }

    findings.sort(compareFindings);
    allFindings.push(...findings);
    const packageComparisons = comparisonsPerformed - packageStartComparisons;
    const budgetExhausted = comparisonTruncated ||
      (options.maxComparisons === comparisonsPerformed && generated.candidates.length > packageComparisons);
    packages.push({
      packageId: observed.packageId,
      name: observed.name,
      ...(observed.version === undefined ? {} : { version: observed.version }),
      source: observed.source,
      comparableName: candidateName,
      findings,
      diagnostics: {
        status: budgetExhausted ? "budget-exhausted" : "scanned",
        candidatesVisited: generated.visited,
        comparisonsPerformed: packageComparisons,
        truncated: generated.truncated || budgetExhausted,
        messages: [
          ...(generated.truncated ? ["candidate budget reached"] : []),
          ...(budgetExhausted ? ["total comparison budget reached"] : []),
        ],
      },
    });
  }

  allFindings.sort(compareFindings);
  const orderedBudgetCodes: readonly BudgetDiagnosticCode[] = [
    "MAX_PACKAGES_REACHED",
    "MAX_CANDIDATES_PER_PACKAGE_REACHED",
    "MAX_COMPARISONS_REACHED",
    "INVALID_OBSERVED_PACKAGE",
    "ALLOWLISTED_OBSERVED_PACKAGE",
  ];
  return {
    corpus: {
      corpusId: corpus.corpusId,
      generatedAt: corpus.generatedAt,
      comparisonVersion: corpus.comparisonVersion,
      indexVersion: corpus.indexVersion,
      targetCount: corpus.targetCount,
      sourceEvidenceIds: corpus.sourceEvidenceIds,
    },
    packages,
    findings: allFindings,
    diagnostics: {
      inputPackages: observedPackages.length,
      packagesScanned: packages.length,
      invalidPackages,
      candidatesVisited,
      comparisonsPerformed,
      truncated: budgetCodes.has("MAX_PACKAGES_REACHED") ||
        budgetCodes.has("MAX_CANDIDATES_PER_PACKAGE_REACHED") ||
        budgetCodes.has("MAX_COMPARISONS_REACHED"),
      budgetCodes: orderedBudgetCodes.filter((code) => budgetCodes.has(code)),
      limits: { ...options },
    },
  };
}
