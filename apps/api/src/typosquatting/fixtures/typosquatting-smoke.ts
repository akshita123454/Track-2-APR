import assert from "node:assert/strict";

import { compareStableStrings } from "../candidate-index.js";
import { createTyposquattingCorpus, COMPARISON_VERSION, INDEX_VERSION } from "../corpus.js";
import { detectTyposquatting } from "../detector.js";
import { weightedDamerauLevenshtein } from "../distance.js";
import { normalizePackageName, PackageNameValidationError } from "../normalize.js";
import type {
  ContextualEvidence,
  DetectorOptions,
  ObservedPackage,
  TrustedTarget,
  TyposquattingClassification,
  TyposquattingCorpus,
} from "../types.js";

const GENERATED_AT = 1_800_000_000_000;
const OPTIONS: DetectorOptions = {
  maxPackages: 100,
  maxCandidatesPerPackage: 50,
  maxComparisons: 500,
};

function target(
  packageId: number,
  packageName: string,
  sourceEvidenceId: number,
  overrides: Partial<TrustedTarget> = {},
): TrustedTarget {
  return {
    packageId,
    packageName,
    sources: ["public-popular"],
    popularity: 2_000_000,
    maintainers: ["trusted-maintainer"],
    sourceEvidenceIds: [sourceEvidenceId],
    ...overrides,
  };
}

function observed(
  packageId: number,
  name: string,
  sourceEvidenceId: number,
  overrides: Partial<ObservedPackage> = {},
): ObservedPackage {
  return {
    packageId,
    name,
    source: "registry",
    sourceEvidenceIds: [sourceEvidenceId],
    ...overrides,
  };
}

function context(category: ContextualEvidence["category"], evidenceId: number): ContextualEvidence {
  return { category, evidenceIds: [evidenceId] };
}

function createCorpus(): TyposquattingCorpus {
  return createTyposquattingCorpus({
    corpusId: "trusted-npm-2027-01",
    generatedAt: GENERATED_AT,
    comparisonVersion: COMPARISON_VERSION,
    indexVersion: INDEX_VERSION,
    sourceEvidenceIds: [3, 2, 3],
    targetCount: 5,
    targets: [
      target(10, "React", 112, { sources: ["public-popular", "org-owned"] }),
      target(10, "react", 112, { sources: ["internal-resolved"], sourceEvidenceIds: [110, 111] }),
      target(20, "express", 114, { sources: ["public-popular", "watchlist"], rank: 5 }),
      target(30, "@angular/core", 114, { sources: ["org-owned"] }),
      target(40, "is", 109, { popularity: 50 }),
      target(50, "Café", 111, { sources: ["org-owned"] }),
    ],
    allowlist: ["React-Safe"],
    blocklist: ["reakt"],
    watchlist: ["RAECT", "express"],
  });
}

function assertValidationCode(name: string, code: PackageNameValidationError["code"]): void {
  assert.throws(
    () => normalizePackageName(name),
    (error: unknown) => error instanceof PackageNameValidationError && error.code === code,
  );
}

function runNormalizationAndCorpusChecks(): void {
  const normalized = normalizePackageName("@Scope/Cafe\u0301-Tools");
  assert.equal(normalized.original, "@Scope/Cafe\u0301-Tools");
  assert.equal(normalized.normalized, "@scope/café-tools");
  assert.equal(normalized.scope, "scope");
  assert.equal(normalized.basename, "café-tools");
  assert.equal(normalized.compact, "cafétools");
  assert.deepEqual(normalized.tokens, ["scope", "café", "tools"]);
  assert.equal(normalized.comparisonVersion, COMPARISON_VERSION);

  assertValidationCode("bad name", "invalid-character");
  assertValidationCode("@scope", "invalid-scope");
  assertValidationCode("bad\u0000name", "control-character");
  assertValidationCode("a".repeat(215), "too-long");

  const corpus = createCorpus();
  assert.equal(corpus.targetCount, 5);
  assert.equal(corpus.targets.length, 5, "normalized duplicate trusted targets must be deduplicated");
  assert.deepEqual(corpus.sourceEvidenceIds, [2, 3]);
  const react = corpus.targets.find((value) => value.comparableName.normalized === "react");
  assert.ok(react?.sources.includes("internal-resolved"), "duplicate target provenance must be merged");
  assert.equal(react?.packageId, 10);
  assert.deepEqual(react?.sourceEvidenceIds, [110, 111, 112]);
  assert.ok(corpus.index.signatureToTargets.size > 0, "trusted corpus must be indexed once");
  const numericIdCorpus = createTyposquattingCorpus({
    corpusId: "numeric-id-ordering",
    generatedAt: GENERATED_AT,
    comparisonVersion: COMPARISON_VERSION,
    indexVersion: INDEX_VERSION,
    sourceEvidenceIds: [],
    targetCount: 1,
    targets: [target(10, "react", 103), target(2, "react", 103)],
    allowlist: [],
    blocklist: [],
    watchlist: [],
  });
  assert.equal(numericIdCorpus.targets[0]?.packageId, 2, "numeric package IDs must determine canonical ordering");
  assert.throws(
    () => createTyposquattingCorpus({
      corpusId: "bad-count",
      generatedAt: GENERATED_AT,
      comparisonVersion: COMPARISON_VERSION,
      indexVersion: INDEX_VERSION,
      sourceEvidenceIds: [],
      targetCount: 2,
      targets: [target(60, "react", 103)],
      allowlist: [],
      blocklist: [],
      watchlist: [],
    }),
    /targetCount/,
  );
  assert.throws(
    () => createTyposquattingCorpus({
      corpusId: "invalid-target-id",
      generatedAt: GENERATED_AT,
      comparisonVersion: COMPARISON_VERSION,
      indexVersion: INDEX_VERSION,
      sourceEvidenceIds: [],
      targetCount: 1,
      targets: [target(-1, "react", 103)],
      allowlist: [],
      blocklist: [],
      watchlist: [],
    }),
    /packageId must be a non-negative safe integer/,
  );
}

function runDistanceChecks(): void {
  const first = weightedDamerauLevenshtein("react", "raect");
  assert.deepEqual(first, weightedDamerauLevenshtein("react", "raect"));
  assert.equal(first.operations.some((value) => value.kind === "adjacent-transposition"), true);
}

function mainObservedPackages(): readonly ObservedPackage[] {
  return [
    observed(101, "raect", 1_013),
    observed(102, "exprees", 1_011, {
      downloads: 5,
      maintainers: ["other-maintainer"],
    }),
    observed(103, "reactt", 1_020, {
      contextualEvidence: [context("build", 201), context("deployment", 202)],
    }),
    observed(104, "reacct", 1_016, {
      source: "lockfile",
      contextualEvidence: [context("build", 301), context("dependency-graph", 302)],
    }),
    observed(105, "@evil/react", 1_009),
    observed(106, "@angular/croe", 1_011),
    observed(107, "reaсt", 1_014),
    observed(108, "reakt", 1_011),
    observed(109, "react-safe", 1_009),
    observed(110, "REACT", 1_009),
    observed(111, "CAFE\u0301", 1_007),
    observed(112, "ix", 1_009),
    observed(113, "lodash", 1_012),
    observed(114, "bad name", 1_013),
  ];
}

function runDetectionChecks(): void {
  const corpus = createCorpus();
  const first = detectTyposquatting(mainObservedPackages(), corpus, OPTIONS);
  const second = detectTyposquatting(mainObservedPackages(), corpus, OPTIONS);
  assert.deepEqual(first, second, "pure detector output must be deterministic");
  assert.deepEqual(first.corpus, {
    corpusId: corpus.corpusId,
    generatedAt: GENERATED_AT,
    comparisonVersion: COMPARISON_VERSION,
    indexVersion: INDEX_VERSION,
    targetCount: 5,
    sourceEvidenceIds: [2, 3],
  });

  const transpose = first.findings.find((value) => value.candidateName === "raect");
  assert.equal(transpose?.targetName, "React", "multi-target lookup must select the correct trusted target");
  assert.equal(transpose?.classification, "candidate", "lexical and watchlist signals alone remain candidate");
  assert.ok(transpose?.targetSelectionReasons.includes("deletion-signature"));
  assert.ok(transpose?.reasons.some((value) => value.group === "target" || value.group === "policy"));
  assert.equal(transpose?.reasons.some((value) => value.code === "POLICY_WATCHLIST"), true);

  const express = first.findings.find((value) => value.candidateName === "exprees");
  assert.equal(express?.targetName, "express");
  assert.equal(express?.classification, "suspicious");
  assert.ok(express?.reasons.some((value) => value.group === "metadata"));
  assert.ok(express?.reasons.some((value) => value.group === "publisher"));

  const registryOnly = first.findings.find((value) => value.candidateName === "reactt");
  assert.equal(registryOnly?.classification, "suspicious", "registry-only observations cannot become high-confidence");
  const lockfile = first.findings.find((value) => value.candidateName === "reacct");
  assert.equal(lockfile?.classification, "high-confidence", "strong lexical plus lockfile and two categories can be high-confidence");
  assert.equal(lockfile?.strongLexicalMatch, true);
  assert.deepEqual(lockfile?.nonLexicalEvidenceCategories, ["build", "dependency-graph"]);

  assert.ok(first.findings.find((value) => value.candidateName === "@evil/react")?.transformations.includes("scope-impersonation"));
  assert.equal(first.findings.find((value) => value.candidateName === "@angular/croe")?.targetName, "@angular/core");
  assert.ok(first.findings.find((value) => value.candidateName === "reaсt")?.transformations.includes("unicode-confusable"));
  assert.equal(first.findings.find((value) => value.candidateName === "reakt")?.classification, "suspicious");
  assert.ok(first.findings.find((value) => value.candidateName === "reakt")?.reasons.some((value) => value.code === "POLICY_BLOCKLIST"));

  assert.equal(first.findings.some((value) => value.candidateName === "REACT"), false, "exact normalized trusted targets are excluded");
  assert.equal(first.findings.some((value) => value.candidateName === "CAFE\u0301"), false, "NFC-equivalent targets are excluded");
  assert.equal(first.findings.some((value) => value.candidateName === "ix"), false, "generic edits on short names are gated");
  assert.equal(first.findings.some((value) => value.candidateName === "lodash"), false);
  assert.equal(first.packages.find((value) => value.name === "react-safe")?.diagnostics.status, "allowlisted");
  assert.equal(first.packages.find((value) => value.name === "bad name")?.diagnostics.status, "invalid");
  const invalidId = detectTyposquatting(
    [observed(Number.MAX_SAFE_INTEGER + 1, "reactt", 1_012)],
    corpus,
    OPTIONS,
  );
  assert.equal(invalidId.packages[0]?.diagnostics.status, "invalid");
  assert.match(invalidId.packages[0]?.diagnostics.messages[0] ?? "", /packageId must be a non-negative safe integer/);
  assert.equal(first.diagnostics.invalidPackages, 1);
  assert.equal(first.findings.every((value) => !(value.classification as string).includes("confirmed")), true);

  const rank: Readonly<Record<TyposquattingClassification, number>> = {
    "high-confidence": 3,
    suspicious: 2,
    candidate: 1,
  };
  assert.deepEqual(
    first.findings,
    [...first.findings].sort((left, right) =>
      rank[right.classification] - rank[left.classification] ||
      right.score - left.score ||
      compareStableStrings(left.targetName, right.targetName) ||
      compareStableStrings(left.candidateName, right.candidateName) ||
      left.targetPackageId - right.targetPackageId ||
      left.observedPackageId - right.observedPackageId
    ),
    "findings must have stable classification/score/target/candidate ordering",
  );
}

function runBudgetChecks(): void {
  const corpus = createCorpus();
  const two = [observed(201, "raect", 1_003), observed(202, "exprees", 1_003)];
  const packageLimited = detectTyposquatting(two, corpus, {
    maxPackages: 1,
    maxCandidatesPerPackage: 50,
    maxComparisons: 50,
  });
  assert.equal(packageLimited.packages.length, 1);
  assert.ok(packageLimited.diagnostics.budgetCodes.includes("MAX_PACKAGES_REACHED"));

  const candidateLimited = detectTyposquatting(two, corpus, {
    maxPackages: 2,
    maxCandidatesPerPackage: 0,
    maxComparisons: 50,
  });
  assert.equal(candidateLimited.findings.length, 0);
  assert.ok(candidateLimited.diagnostics.budgetCodes.includes("MAX_CANDIDATES_PER_PACKAGE_REACHED"));

  const rankingCorpus = createTyposquattingCorpus({
    corpusId: "candidate-ranking",
    generatedAt: GENERATED_AT,
    comparisonVersion: COMPARISON_VERSION,
    indexVersion: INDEX_VERSION,
    sourceEvidenceIds: [],
    targetCount: 2,
    targets: [target(70, "aaaaa", 103), target(80, "aabaa", 105)],
    allowlist: [],
    blocklist: [],
    watchlist: [],
  });
  const closestLimited = detectTyposquatting(
    [observed(203, "aabbaa", 1_006)],
    rankingCorpus,
    { maxPackages: 1, maxCandidatesPerPackage: 1, maxComparisons: 1 },
  );
  assert.equal(closestLimited.findings[0]?.targetName, "aabaa", "candidate caps must retain the strongest signature match");

  const comparisonLimited = detectTyposquatting(two, corpus, {
    maxPackages: 2,
    maxCandidatesPerPackage: 50,
    maxComparisons: 0,
  });
  assert.equal(comparisonLimited.diagnostics.comparisonsPerformed, 0);
  assert.ok(comparisonLimited.diagnostics.budgetCodes.includes("MAX_COMPARISONS_REACHED"));
  assert.equal(comparisonLimited.diagnostics.truncated, true);

  const sharedEvidence = detectTyposquatting(
    [observed(204, "reactt", 1_015, {
      source: "lockfile",
      contextualEvidence: [context("build", 900), context("deployment", 900)],
    })],
    corpus,
    OPTIONS,
  );
  assert.equal(
    sharedEvidence.findings[0]?.classification,
    "suspicious",
    "one evidence record carrying two labels is not two independent categories",
  );
}

runNormalizationAndCorpusChecks();
runDistanceChecks();
runDetectionChecks();
runBudgetChecks();

console.log("typosquatting smoke passed");
