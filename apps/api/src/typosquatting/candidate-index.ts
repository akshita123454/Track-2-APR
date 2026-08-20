import { confusableSkeleton } from "./confusables.js";
import type {
  CandidateIndex,
  CandidateIndexTarget,
  IndexedTrustedTarget,
  TargetSelectionReason,
} from "./types.js";

export function compareStableStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function createDeletionVariants(value: string, maximumDepth: number): readonly string[] {
  const seen = new Set<string>([value]);
  let frontier = [value];
  for (let depth = 0; depth < maximumDepth; depth += 1) {
    const next = new Set<string>();
    for (const entry of frontier) {
      const characters = Array.from(entry);
      for (let index = 0; index < characters.length; index += 1) {
        const deletion = characters.slice(0, index).concat(characters.slice(index + 1)).join("");
        if (!seen.has(deletion)) {
          seen.add(deletion);
          next.add(deletion);
        }
      }
    }
    frontier = [...next].sort(compareStableStrings);
  }
  return [...seen].sort(compareStableStrings);
}

export function signatureKey(reason: TargetSelectionReason, value: string): string {
  return `${reason}:${value}`;
}

function targetPriority(left: IndexedTrustedTarget, right: IndexedTrustedTarget): number {
  const leftWatch = left.sources.includes("watchlist") ? 1 : 0;
  const rightWatch = right.sources.includes("watchlist") ? 1 : 0;
  const leftProminent = left.sources.includes("public-popular") || left.sources.includes("internal-resolved") ? 1 : 0;
  const rightProminent = right.sources.includes("public-popular") || right.sources.includes("internal-resolved") ? 1 : 0;
  return rightWatch - leftWatch ||
    rightProminent - leftProminent ||
    (left.rank ?? Number.MAX_SAFE_INTEGER) - (right.rank ?? Number.MAX_SAFE_INTEGER) ||
    (right.popularity ?? 0) - (left.popularity ?? 0) ||
    (right.internalUsageCount ?? 0) - (left.internalUsageCount ?? 0) ||
    compareStableStrings(left.comparableName.normalized, right.comparableName.normalized) ||
    left.packageId - right.packageId;
}

function add(index: Map<string, Set<number>>, key: string, packageId: number): void {
  const values = index.get(key) ?? new Set<number>();
  values.add(packageId);
  index.set(key, values);
}

export function buildCandidateIndex(
  targets: readonly IndexedTrustedTarget[],
  maxDeletionDepth = 2,
): CandidateIndex {
  if (!Number.isSafeInteger(maxDeletionDepth) || maxDeletionDepth < 0 || maxDeletionDepth > 3) {
    throw new Error("maxDeletionDepth must be an integer between 0 and 3");
  }
  const targetById = new Map(targets.map((target) => [target.packageId, target] as const));
  const signatures = new Map<string, Set<number>>();

  for (const target of [...targets].sort(targetPriority)) {
    const name = target.comparableName;
    add(signatures, signatureKey("compact-signature", name.compact), target.packageId);
    add(signatures, signatureKey("basename-signature", name.basename), target.packageId);
    add(signatures, signatureKey("confusable-signature", confusableSkeleton(name.normalized)), target.packageId);
    add(signatures, signatureKey("same-scope-signature", name.scope ?? ""), target.packageId);
    for (const deletion of createDeletionVariants(name.compact, maxDeletionDepth)) {
      add(signatures, signatureKey("deletion-signature", deletion), target.packageId);
    }
  }

  const orderedTargets = [...targets].sort(targetPriority);
  const priority = new Map(orderedTargets.map((target, index) => [target.packageId, index] as const));
  const signatureToTargets = new Map<string, readonly CandidateIndexTarget[]>(
    [...signatures.entries()]
      .sort(([left], [right]) => compareStableStrings(left, right))
      .map(([key, packageIds]) => [
        key,
        [...packageIds]
          .sort((left, right) => (priority.get(left)! - priority.get(right)!))
          .map((packageId) => ({
            packageId,
            comparisonName: targetById.get(packageId)!.comparableName.normalized,
          })),
      ] as const),
  );

  return { maxDeletionDepth, signatureToTargets, targetById };
}
