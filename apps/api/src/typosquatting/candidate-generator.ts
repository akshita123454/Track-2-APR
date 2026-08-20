import {
  compareStableStrings,
  createDeletionVariants,
  signatureKey,
} from "./candidate-index.js";
import { confusableSkeleton } from "./confusables.js";
import type {
  CandidateGenerationResult,
  CandidateIndex,
  CandidateSelection,
  ComparablePackageName,
  IndexedTrustedTarget,
  TargetSelectionReason,
} from "./types.js";

const REASON_ORDER: readonly TargetSelectionReason[] = [
  "compact-signature",
  "basename-signature",
  "confusable-signature",
  "deletion-signature",
  "same-scope-signature",
  "watchlist-priority",
  "prominence-priority",
];

interface SignatureQuery {
  readonly lookupReason: TargetSelectionReason;
  readonly reportedReason: TargetSelectionReason;
  readonly value: string;
  readonly exactObservedVariant: boolean;
}

interface SelectionState {
  readonly reasons: Set<TargetSelectionReason>;
  matchCount: number;
  exactVariantMatches: number;
}

function lexicalPriority(reasons: ReadonlySet<TargetSelectionReason>): number {
  if (reasons.has("compact-signature") || reasons.has("confusable-signature")) {
    return 4;
  }
  if (reasons.has("basename-signature")) {
    return 3;
  }
  if (reasons.has("deletion-signature")) {
    return 2;
  }
  return 1;
}

function isProminent(target: IndexedTrustedTarget): boolean {
  return target.sources.includes("public-popular") ||
    target.sources.includes("internal-resolved") ||
    target.rank !== undefined || target.popularity !== undefined || target.internalUsageCount !== undefined;
}

export function generateCandidates(
  observed: ComparablePackageName,
  index: CandidateIndex,
  maxCandidates: number,
  watchlist: ReadonlySet<string>,
): CandidateGenerationResult {
  if (!Number.isSafeInteger(maxCandidates) || maxCandidates < 0) {
    throw new Error("maxCandidates must be a non-negative safe integer");
  }

  const deletions = createDeletionVariants(observed.compact, index.maxDeletionDepth);
  const queries: readonly SignatureQuery[] = [
    { lookupReason: "compact-signature", reportedReason: "compact-signature", value: observed.compact, exactObservedVariant: false },
    { lookupReason: "basename-signature", reportedReason: "basename-signature", value: observed.basename, exactObservedVariant: false },
    { lookupReason: "confusable-signature", reportedReason: "confusable-signature", value: confusableSkeleton(observed.normalized), exactObservedVariant: false },
    ...deletions
      .filter((deletion) => deletion !== observed.compact)
      .map((deletion) => ({
        lookupReason: "compact-signature" as const,
        reportedReason: "deletion-signature" as const,
        value: deletion,
        exactObservedVariant: true,
      })),
    ...deletions.map((deletion) => ({
      lookupReason: "deletion-signature" as const,
      reportedReason: "deletion-signature" as const,
      value: deletion,
      exactObservedVariant: false,
    })),
    ...(observed.scope === undefined
      ? []
      : [{ lookupReason: "same-scope-signature" as const, reportedReason: "same-scope-signature" as const, value: observed.scope, exactObservedVariant: false }]),
  ];
  const selected = new Map<number, SelectionState>();

  for (const query of queries) {
    for (const entry of index.signatureToTargets.get(signatureKey(query.lookupReason, query.value)) ?? []) {
      if (entry.comparisonName === observed.normalized) {
        continue;
      }
      const state = selected.get(entry.packageId) ?? {
        reasons: new Set<TargetSelectionReason>(),
        matchCount: 0,
        exactVariantMatches: 0,
      };
      state.reasons.add(query.reportedReason);
      state.matchCount += 1;
      if (query.exactObservedVariant) {
        state.exactVariantMatches += 1;
      }
      selected.set(entry.packageId, state);
    }
  }

  const ranked = [...selected.entries()].sort(([leftId, left], [rightId, right]) => {
    const leftTarget = index.targetById.get(leftId)!;
    const rightTarget = index.targetById.get(rightId)!;
    const leftWatch = watchlist.has(leftTarget.comparableName.normalized) || leftTarget.sources.includes("watchlist") ? 1 : 0;
    const rightWatch = watchlist.has(rightTarget.comparableName.normalized) || rightTarget.sources.includes("watchlist") ? 1 : 0;
    return lexicalPriority(right.reasons) - lexicalPriority(left.reasons) ||
      right.exactVariantMatches - left.exactVariantMatches ||
      right.matchCount - left.matchCount ||
      Math.abs(leftTarget.comparableName.compact.length - observed.compact.length) -
        Math.abs(rightTarget.comparableName.compact.length - observed.compact.length) ||
      rightWatch - leftWatch ||
      Number(isProminent(rightTarget)) - Number(isProminent(leftTarget)) ||
      compareStableStrings(leftTarget.comparableName.normalized, rightTarget.comparableName.normalized) ||
      leftId - rightId;
  });

  const candidates: CandidateSelection[] = ranked.slice(0, maxCandidates).map(([targetId, state]) => {
    const target = index.targetById.get(targetId)!;
    if (watchlist.has(target.comparableName.normalized) || target.sources.includes("watchlist")) {
      state.reasons.add("watchlist-priority");
    }
    if (isProminent(target)) {
      state.reasons.add("prominence-priority");
    }
    return {
      targetId,
      comparisonName: target.comparableName.normalized,
      reasons: REASON_ORDER.filter((reason) => state.reasons.has(reason)),
    };
  });
  return {
    candidates,
    visited: candidates.length,
    truncated: ranked.length > maxCandidates,
  };
}
