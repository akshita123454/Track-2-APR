import type {
  NodeId,
  PackageNode,
} from "../../domain/schema.js";

export type TyposquatSignalCode =
  | "separator-variation"
  | "scope-variation"
  | "adjacent-transposition"
  | "single-character-insertion"
  | "single-character-deletion"
  | "single-character-substitution"
  | "bounded-edit-distance";

export interface TyposquatSignal {
  readonly code: TyposquatSignalCode;
  readonly scoreContribution: number;
  readonly detail: string;
}

export interface TyposquatCandidate {
  readonly candidatePackageId: NodeId;
  readonly candidatePackageName: string;
  readonly targetPackageId: NodeId;
  readonly targetPackageName: string;

  /**
   * Deterministic name-similarity score between 0 and 1.
   *
   * This is not confidence, severity, or proof of malicious intent.
   */
  readonly similarityScore: number;

  readonly signals: readonly TyposquatSignal[];

  /**
   * Canonical Evidence node IDs attached to the compared Package nodes.
   */
  readonly evidenceIds: readonly NodeId[];

  readonly uncertainties: readonly string[];
}

export interface TyposquatAnalysisOptions {
  /**
   * Minimum similarity score required for a result.
   */
  readonly minimumScore?: number;

  /**
   * Maximum Levenshtein distance considered by the general edit signal.
   */
  readonly maxEditDistance?: number;

  /**
   * Safety limit on candidate-to-target comparisons.
   */
  readonly maxComparisons?: number;

  /**
   * Maximum number of sorted candidates returned.
   */
  readonly maxResults?: number;
}

export interface AppliedTyposquatAnalysisOptions {
  readonly minimumScore: number;
  readonly maxEditDistance: number;
  readonly maxComparisons: number;
  readonly maxResults: number;
}

export type TyposquatPackageRole =
  | "candidate"
  | "protected-target";

export type TyposquatWarningCode =
  | "invalid-package-name"
  | "comparison-limit-reached"
  | "result-limit-reached";

export interface TyposquatAnalysisWarning {
  readonly code: TyposquatWarningCode;
  readonly message: string;
  readonly packageId?: NodeId;
  readonly packageName?: string;
  readonly role?: TyposquatPackageRole;
}

export interface TyposquatAnalysisResult {
  readonly candidates: readonly TyposquatCandidate[];
  readonly comparisonCount: number;
  readonly truncated: boolean;
  readonly options: AppliedTyposquatAnalysisOptions;
  readonly warnings: readonly TyposquatAnalysisWarning[];
}

interface NormalizedPackageName {
  readonly fullName: string;
  readonly scope: string | null;
  readonly leafName: string;
  readonly compactLeafName: string;
}

interface PreparedPackage {
  readonly node: PackageNode;
  readonly normalizedName: NormalizedPackageName;
}

interface NameComparison {
  readonly similarityScore: number;
  readonly signals: readonly TyposquatSignal[];
}

const DEFAULT_OPTIONS: AppliedTyposquatAnalysisOptions = {
  minimumScore: 0.75,
  maxEditDistance: 2,
  maxComparisons: 10_000,
  maxResults: 100,
};

const CANDIDATE_UNCERTAINTIES: readonly string[] = [
  "Package-name similarity alone does not prove malicious intent.",
  "Registry ownership, publication history, download behavior, and incident linkage were not evaluated.",
];

function compareText(left: string, right: string): number {
  return left.localeCompare(right);
}

function compareNodeIds(left: NodeId, right: NodeId): number {
  return left - right;
}

function roundScore(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}

function readProbability(
  value: number | undefined,
  fallback: number,
  optionName: string,
): number {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new RangeError(
      `${optionName} must be a finite number between 0 and 1`,
    );
  }

  return value;
}

function readPositiveSafeInteger(
  value: number | undefined,
  fallback: number,
  optionName: string,
): number {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(
      `${optionName} must be a positive safe integer`,
    );
  }

  return value;
}

function readNonnegativeSafeInteger(
  value: number | undefined,
  fallback: number,
  optionName: string,
): number {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(
      `${optionName} must be a nonnegative safe integer`,
    );
  }

  return value;
}

function normalizeOptions(
  options: TyposquatAnalysisOptions,
): AppliedTyposquatAnalysisOptions {
  return {
    minimumScore: readProbability(
      options.minimumScore,
      DEFAULT_OPTIONS.minimumScore,
      "minimumScore",
    ),
    maxEditDistance: readNonnegativeSafeInteger(
      options.maxEditDistance,
      DEFAULT_OPTIONS.maxEditDistance,
      "maxEditDistance",
    ),
    maxComparisons: readPositiveSafeInteger(
      options.maxComparisons,
      DEFAULT_OPTIONS.maxComparisons,
      "maxComparisons",
    ),
    maxResults: readPositiveSafeInteger(
      options.maxResults,
      DEFAULT_OPTIONS.maxResults,
      "maxResults",
    ),
  };
}

function normalizePackageName(
  packageName: string,
): NormalizedPackageName | null {
  const fullName = packageName.trim().toLowerCase();

  if (fullName.length === 0 || /\s/.test(fullName)) {
    return null;
  }

  let scope: string | null = null;
  let leafName = fullName;

  if (fullName.startsWith("@")) {
    const slashIndex = fullName.indexOf("/");

    if (
      slashIndex <= 1 ||
      slashIndex === fullName.length - 1 ||
      fullName.indexOf("/", slashIndex + 1) !== -1
    ) {
      return null;
    }

    scope = fullName.slice(1, slashIndex);
    leafName = fullName.slice(slashIndex + 1);
  } else if (fullName.includes("/")) {
    return null;
  }

  const compactLeafName = leafName.replace(/[-_.]/g, "");

  if (compactLeafName.length === 0) {
    return null;
  }

  return {
    fullName,
    scope,
    leafName,
    compactLeafName,
  };
}

function uniqueSortedEvidenceIds(
  evidenceGroups: readonly (readonly NodeId[])[],
): readonly NodeId[] {
  return [...new Set(evidenceGroups.flat())].sort(compareNodeIds);
}

function levenshteinDistance(
  left: string,
  right: string,
): number {
  let previousRow = Array.from(
    { length: right.length + 1 },
    (_, index) => index,
  );

  for (
    let leftIndex = 1;
    leftIndex <= left.length;
    leftIndex += 1
  ) {
    const currentRow: number[] = [leftIndex];

    for (
      let rightIndex = 1;
      rightIndex <= right.length;
      rightIndex += 1
    ) {
      const deletion =
        (previousRow[rightIndex] ?? 0) + 1;
      const insertion =
        (currentRow[rightIndex - 1] ?? 0) + 1;
      const substitution =
        (previousRow[rightIndex - 1] ?? 0) +
        (
          left[leftIndex - 1] === right[rightIndex - 1]
            ? 0
            : 1
        );

      currentRow.push(
        Math.min(deletion, insertion, substitution),
      );
    }

    previousRow = currentRow;
  }

  return previousRow[right.length] ?? left.length;
}

function isAdjacentTransposition(
  left: string,
  right: string,
): boolean {
  if (left.length !== right.length || left.length < 2) {
    return false;
  }

  const differentIndexes: number[] = [];

  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      differentIndexes.push(index);
    }
  }

  if (differentIndexes.length !== 2) {
    return false;
  }

  const firstIndex = differentIndexes[0];
  const secondIndex = differentIndexes[1];

  if (
    firstIndex === undefined ||
    secondIndex === undefined ||
    secondIndex !== firstIndex + 1
  ) {
    return false;
  }

  return (
    left[firstIndex] === right[secondIndex] &&
    left[secondIndex] === right[firstIndex]
  );
}

function isSingleCharacterInsertion(
  longer: string,
  shorter: string,
): boolean {
  if (longer.length !== shorter.length + 1) {
    return false;
  }

  let longerIndex = 0;
  let shorterIndex = 0;
  let skippedCharacters = 0;

  while (
    longerIndex < longer.length &&
    shorterIndex < shorter.length
  ) {
    if (longer[longerIndex] === shorter[shorterIndex]) {
      longerIndex += 1;
      shorterIndex += 1;
      continue;
    }

    skippedCharacters += 1;
    longerIndex += 1;

    if (skippedCharacters > 1) {
      return false;
    }
  }

  return true;
}

function isSingleCharacterSubstitution(
  left: string,
  right: string,
): boolean {
  if (left.length !== right.length) {
    return false;
  }

  let differenceCount = 0;

  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      differenceCount += 1;
    }

    if (differenceCount > 1) {
      return false;
    }
  }

  return differenceCount === 1;
}

function compareNames(
  candidate: NormalizedPackageName,
  target: NormalizedPackageName,
  maxEditDistance: number,
): NameComparison {
  const signals: TyposquatSignal[] = [];

  const addSignal = (
    code: TyposquatSignalCode,
    scoreContribution: number,
    detail: string,
  ): void => {
    signals.push({
      code,
      scoreContribution: roundScore(scoreContribution),
      detail,
    });
  };

  if (
    candidate.scope === target.scope &&
    candidate.leafName !== target.leafName &&
    candidate.compactLeafName === target.compactLeafName
  ) {
    addSignal(
      "separator-variation",
      0.98,
      "Names differ only by hyphen, underscore, or period separators.",
    );
  }

  if (
    candidate.scope !== target.scope &&
    candidate.compactLeafName === target.compactLeafName
  ) {
    addSignal(
      "scope-variation",
      0.82,
      "The package leaf name matches but its npm scope differs.",
    );
  }

  const candidateLeaf = candidate.compactLeafName;
  const targetLeaf = target.compactLeafName;

  if (isAdjacentTransposition(candidateLeaf, targetLeaf)) {
    addSignal(
      "adjacent-transposition",
      0.95,
      "Two adjacent characters are transposed.",
    );
  }

  if (
    isSingleCharacterInsertion(candidateLeaf, targetLeaf)
  ) {
    addSignal(
      "single-character-insertion",
      0.9,
      "The candidate contains one additional character.",
    );
  }

  if (
    isSingleCharacterInsertion(targetLeaf, candidateLeaf)
  ) {
    addSignal(
      "single-character-deletion",
      0.92,
      "The candidate omits one character from the protected name.",
    );
  }

  if (
    isSingleCharacterSubstitution(candidateLeaf, targetLeaf)
  ) {
    addSignal(
      "single-character-substitution",
      0.88,
      "One character differs from the protected name.",
    );
  }

  const editDistance = levenshteinDistance(
    candidateLeaf,
    targetLeaf,
  );
  const maximumLength = Math.max(
    candidateLeaf.length,
    targetLeaf.length,
  );

  if (
    editDistance > 0 &&
    editDistance <= maxEditDistance &&
    maximumLength > 0
  ) {
    const normalizedSimilarity =
      1 - editDistance / maximumLength;
    const contribution = Math.min(
      0.87,
      0.55 + normalizedSimilarity * 0.35,
    );

    addSignal(
      "bounded-edit-distance",
      contribution,
      `Normalized edit distance is ${String(editDistance)}.`,
    );
  }

  signals.sort(
    (left, right) =>
      right.scoreContribution - left.scoreContribution ||
      compareText(left.code, right.code),
  );

  return {
    similarityScore: signals[0]?.scoreContribution ?? 0,
    signals,
  };
}

function warningKey(
  warning: TyposquatAnalysisWarning,
): string {
  return JSON.stringify([
    warning.code,
    warning.message,
    warning.packageId ?? null,
    warning.packageName ?? null,
    warning.role ?? null,
  ]);
}

function compareWarnings(
  left: TyposquatAnalysisWarning,
  right: TyposquatAnalysisWarning,
): number {
  return (
    compareText(left.code, right.code) ||
    compareText(left.role ?? "", right.role ?? "") ||
    compareNodeIds(
      left.packageId ?? -1,
      right.packageId ?? -1,
    ) ||
    compareText(left.message, right.message)
  );
}

function preparePackages(
  packages: readonly PackageNode[],
  role: TyposquatPackageRole,
  addWarning: (
    warning: TyposquatAnalysisWarning,
  ) => void,
): readonly PreparedPackage[] {
  const sortedPackages = [...packages].sort(
    (left, right) =>
      compareNodeIds(left.id, right.id) ||
      compareText(left.name, right.name),
  );

  const seenPackageIds = new Set<NodeId>();
  const preparedPackages: PreparedPackage[] = [];

  for (const packageNode of sortedPackages) {
    if (seenPackageIds.has(packageNode.id)) {
      continue;
    }

    seenPackageIds.add(packageNode.id);

    const normalizedName = normalizePackageName(
      packageNode.name,
    );

    if (normalizedName === null) {
      addWarning({
        code: "invalid-package-name",
        message:
          `Package ${String(packageNode.id)} has an invalid npm name`,
        packageId: packageNode.id,
        packageName: packageNode.name,
        role,
      });
      continue;
    }

    preparedPackages.push({
      node: packageNode,
      normalizedName,
    });
  }

  return preparedPackages;
}

function compareCandidates(
  left: TyposquatCandidate,
  right: TyposquatCandidate,
): number {
  return (
    right.similarityScore - left.similarityScore ||
    compareText(
      left.candidatePackageName,
      right.candidatePackageName,
    ) ||
    compareText(
      left.targetPackageName,
      right.targetPackageName,
    ) ||
    compareNodeIds(
      left.candidatePackageId,
      right.candidatePackageId,
    ) ||
    compareNodeIds(
      left.targetPackageId,
      right.targetPackageId,
    )
  );
}

/**
 * Compares candidate npm Package nodes with explicitly supplied protected
 * Package nodes.
 *
 * This function is deterministic and network-free. It does not query npm,
 * mutate graph nodes, assign severity, or claim that a package is malicious.
 * Returned entries are similarity candidates requiring additional evidence
 * and human review.
 */
export function analyzeTyposquatCandidates(
  candidatePackages: readonly PackageNode[],
  protectedPackages: readonly PackageNode[],
  options: TyposquatAnalysisOptions = {},
): TyposquatAnalysisResult {
  const appliedOptions = normalizeOptions(options);
  const warnings: TyposquatAnalysisWarning[] = [];
  const recordedWarningKeys = new Set<string>();

  let comparisonCount = 0;
  let truncated = false;

  const addWarning = (
    warning: TyposquatAnalysisWarning,
  ): void => {
    const key = warningKey(warning);

    if (recordedWarningKeys.has(key)) {
      return;
    }

    recordedWarningKeys.add(key);
    warnings.push(warning);
  };

  const preparedCandidates = preparePackages(
    candidatePackages,
    "candidate",
    addWarning,
  );
  const preparedTargets = preparePackages(
    protectedPackages,
    "protected-target",
    addWarning,
  );

  const matches: TyposquatCandidate[] = [];

  comparisonLoop:
  for (const candidate of preparedCandidates) {
    for (const target of preparedTargets) {
      if (candidate.node.id === target.node.id) {
        continue;
      }

      if (
        candidate.normalizedName.fullName ===
        target.normalizedName.fullName
      ) {
        continue;
      }

      if (
        comparisonCount >= appliedOptions.maxComparisons
      ) {
        truncated = true;
        addWarning({
          code: "comparison-limit-reached",
          message:
            `Comparison limit of ` +
            `${String(appliedOptions.maxComparisons)} was reached`,
        });
        break comparisonLoop;
      }

      comparisonCount += 1;

      const comparison = compareNames(
        candidate.normalizedName,
        target.normalizedName,
        appliedOptions.maxEditDistance,
      );

      if (
        comparison.similarityScore <
        appliedOptions.minimumScore
      ) {
        continue;
      }

      matches.push({
        candidatePackageId: candidate.node.id,
        candidatePackageName: candidate.node.name,
        targetPackageId: target.node.id,
        targetPackageName: target.node.name,
        similarityScore: comparison.similarityScore,
        signals: comparison.signals,
        evidenceIds: uniqueSortedEvidenceIds([
          candidate.node.evidenceIds,
          target.node.evidenceIds,
        ]),
        uncertainties: [...CANDIDATE_UNCERTAINTIES],
      });
    }
  }

  matches.sort(compareCandidates);

  if (matches.length > appliedOptions.maxResults) {
    truncated = true;
    addWarning({
      code: "result-limit-reached",
      message:
        `Result limit of ` +
        `${String(appliedOptions.maxResults)} was reached`,
    });
  }

  return {
    candidates: matches.slice(0, appliedOptions.maxResults),
    comparisonCount,
    truncated,
    options: appliedOptions,
    warnings: [...warnings].sort(compareWarnings),
  };
}
