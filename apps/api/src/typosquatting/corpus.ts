import { buildCandidateIndex, compareStableStrings } from "./candidate-index.js";
import { normalizePackageName } from "./normalize.js";
import { COMPARISON_VERSION, INDEX_VERSION } from "./types.js";
import type {
  IndexedTrustedTarget,
  TargetSource,
  TrustedTarget,
  TyposquattingCorpus,
  TyposquattingCorpusInput,
} from "./types.js";

const TARGET_SOURCE_ORDER: readonly TargetSource[] = [
  "public-popular",
  "org-owned",
  "internal-resolved",
  "active-incident",
  "watchlist",
];

function requireNonEmpty(value: string, field: string): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${field} must not be empty`);
  }
}

function requireSafeNonNegative(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
}

function validateEvidenceIds(values: readonly number[], field: string): void {
  for (const value of values) {
    requireSafeNonNegative(value, field);
  }
}

function uniqueNumbers(values: readonly number[]): readonly number[] {
  return [...new Set(values)].sort((left, right) => left - right);
}

function uniqueStrings(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(compareStableStrings);
}

function validateTarget(target: TrustedTarget, index: number): void {
  const prefix = `targets[${index}]`;
  requireSafeNonNegative(target.packageId, `${prefix}.packageId`);
  requireNonEmpty(target.packageName, `${prefix}.packageName`);
  if (target.sources.length === 0) {
    throw new Error(`${prefix}.sources must not be empty`);
  }
  for (const source of target.sources) {
    if (!TARGET_SOURCE_ORDER.includes(source)) {
      throw new Error(`${prefix}.sources contains an unsupported source`);
    }
  }
  validateEvidenceIds(target.sourceEvidenceIds, `${prefix}.sourceEvidenceIds`);
  if (target.rank !== undefined && (!Number.isSafeInteger(target.rank) || target.rank <= 0)) {
    throw new Error(`${prefix}.rank must be a positive safe integer`);
  }
  for (const [field, value] of [
    ["popularity", target.popularity],
    ["internalUsageCount", target.internalUsageCount],
  ] as const) {
    if (value !== undefined) {
      requireSafeNonNegative(value, `${prefix}.${field}`);
    }
  }
  for (const maintainer of target.maintainers ?? []) {
    requireNonEmpty(maintainer, `${prefix}.maintainers`);
  }
}

function mergeTargets(values: readonly IndexedTrustedTarget[]): IndexedTrustedTarget {
  const ordered = [...values].sort((left, right) =>
    left.packageId - right.packageId ||
    compareStableStrings(left.packageName, right.packageName)
  );
  const canonical = ordered[0]!;
  const ranks = ordered.flatMap((value) => value.rank === undefined ? [] : [value.rank]);
  const popularity = ordered.reduce((maximum, value) => Math.max(maximum, value.popularity ?? 0), 0);
  const internalUsageCount = ordered.reduce((maximum, value) => Math.max(maximum, value.internalUsageCount ?? 0), 0);
  const maintainers = uniqueStrings(ordered.flatMap((value) => value.maintainers ?? []));
  const sources = TARGET_SOURCE_ORDER.filter((source) => ordered.some((value) => value.sources.includes(source)));
  return {
    packageId: canonical.packageId,
    packageName: canonical.packageName,
    sources,
    ...(ranks.length === 0 ? {} : { rank: Math.min(...ranks) }),
    ...(ordered.every((value) => value.popularity === undefined) ? {} : { popularity }),
    ...(ordered.every((value) => value.internalUsageCount === undefined) ? {} : { internalUsageCount }),
    ...(maintainers.length === 0 ? {} : { maintainers }),
    sourceEvidenceIds: uniqueNumbers(ordered.flatMap((value) => value.sourceEvidenceIds)),
    comparableName: canonical.comparableName,
  };
}

function normalizePolicy(values: readonly string[], field: string): ReadonlySet<string> {
  const normalized = new Set<string>();
  for (const value of values) {
    requireNonEmpty(value, field);
    normalized.add(normalizePackageName(value).normalized);
  }
  return normalized;
}

export function createTyposquattingCorpus(input: TyposquattingCorpusInput): TyposquattingCorpus {
  requireNonEmpty(input.corpusId, "corpusId");
  requireSafeNonNegative(input.generatedAt, "generatedAt");
  requireSafeNonNegative(input.targetCount, "targetCount");
  if (input.comparisonVersion !== COMPARISON_VERSION) {
    throw new Error(`unsupported comparisonVersion: ${input.comparisonVersion}`);
  }
  if (input.indexVersion !== INDEX_VERSION) {
    throw new Error(`unsupported indexVersion: ${input.indexVersion}`);
  }
  validateEvidenceIds(input.sourceEvidenceIds, "sourceEvidenceIds");

  const byNormalizedName = new Map<string, IndexedTrustedTarget[]>();
  const packageIdToName = new Map<number, string>();
  input.targets.forEach((target, index) => {
    validateTarget(target, index);
    const comparableName = normalizePackageName(target.packageName);
    const previousName = packageIdToName.get(target.packageId);
    if (previousName !== undefined && previousName !== comparableName.normalized) {
      throw new Error(`target packageId maps to multiple normalized names: ${target.packageId}`);
    }
    packageIdToName.set(target.packageId, comparableName.normalized);
    const values = byNormalizedName.get(comparableName.normalized) ?? [];
    values.push({ ...target, comparableName });
    byNormalizedName.set(comparableName.normalized, values);
  });

  const targets = [...byNormalizedName.values()]
    .map(mergeTargets)
    .sort((left, right) =>
      compareStableStrings(left.comparableName.normalized, right.comparableName.normalized) ||
      left.packageId - right.packageId
    );
  if (input.targetCount !== targets.length) {
    throw new Error(`targetCount ${input.targetCount} does not match ${targets.length} unique normalized targets`);
  }

  const normalizedPolicy = {
    allowlist: normalizePolicy(input.allowlist, "allowlist"),
    blocklist: normalizePolicy(input.blocklist, "blocklist"),
    watchlist: normalizePolicy(input.watchlist, "watchlist"),
  };
  return {
    ...input,
    sourceEvidenceIds: uniqueNumbers(input.sourceEvidenceIds),
    targets,
    normalizedPolicy,
    index: buildCandidateIndex(targets),
  };
}

export { COMPARISON_VERSION, INDEX_VERSION };
