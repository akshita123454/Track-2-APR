import { hasConfusableDifference } from "./confusables.js";
import type {
  ComparablePackageName,
  DistanceResult,
  TransformationKind,
} from "./types.js";

const ORDER: readonly TransformationKind[] = [
  "adjacent-transposition",
  "insertion",
  "deletion",
  "substitution",
  "separator-variation",
  "repeated-character",
  "scope-impersonation",
  "unicode-confusable",
  "prefix-suffix",
];

function hasRepeatedCharacter(value: string): boolean {
  return /(.)\1/u.test(value);
}

export function explainTransformations(
  target: ComparablePackageName,
  candidate: ComparablePackageName,
  distance: DistanceResult,
): readonly TransformationKind[] {
  const found = new Set<TransformationKind>();
  for (const operation of distance.operations) {
    if (operation.kind !== "match") {
      found.add(operation.kind);
    }
  }
  if (
    target.scope === candidate.scope &&
    target.basename !== candidate.basename &&
    target.compact === candidate.compact
  ) {
    found.add("separator-variation");
  }
  if (
    target.scope !== candidate.scope &&
    (target.basename === candidate.basename || target.compact === candidate.compact)
  ) {
    found.add("scope-impersonation");
  }
  if (hasConfusableDifference(target.normalized, candidate.normalized)) {
    found.add("unicode-confusable");
  }
  if (
    target.compact !== candidate.compact &&
    (candidate.compact.startsWith(target.compact) ||
      candidate.compact.endsWith(target.compact) ||
      target.compact.startsWith(candidate.compact) ||
      target.compact.endsWith(candidate.compact))
  ) {
    found.add("prefix-suffix");
  }
  if (
    hasRepeatedCharacter(candidate.compact) &&
    candidate.compact.replace(/(.)\1+/gu, "$1") === target.compact.replace(/(.)\1+/gu, "$1")
  ) {
    found.add("repeated-character");
  }
  return ORDER.filter((kind) => found.has(kind));
}
