import {
  deepEqual,
  equal,
  ok,
} from "node:assert/strict";
import type {
  NodeId,
  PackageNode,
} from "../../domain/schema.js";
import {
  analyzeTyposquatCandidates,
} from "../typosquat/typosquat-analysis.js";
import type {
  TyposquatSignalCode,
} from "../typosquat/typosquat-analysis.js";

const OBSERVED_AT = 1_700_000_000_000;

function createPackage(
  id: NodeId,
  name: string,
  evidenceIds: readonly NodeId[],
): PackageNode {
  return {
    id,
    logicalId: `npm:${name}`,
    kind: "Package",
    evidenceIds,
    synthetic: true,
    observedAt: OBSERVED_AT,
    ecosystem: "npm",
    name,
  };
}

function signalCodes(
  signals: readonly {
    readonly code: TyposquatSignalCode;
  }[],
): readonly TyposquatSignalCode[] {
  return signals.map((signal) => signal.code);
}

function runSmoke(): void {
  const protectedPackages: readonly PackageNode[] = [
    createPackage(100, "lodash", [900]),
    createPackage(200, "@hydra/security-core", [901]),
  ];

  const candidatePackages: readonly PackageNode[] = [
    createPackage(300, "lodahs", [902]),
    createPackage(400, "lodash-extra", [903]),
    createPackage(500, "@other/security_core", [904]),
    createPackage(600, "totally-different", [905]),
    createPackage(700, "lodash", [906]),
  ];

  const inputSnapshot = JSON.stringify({
    protectedPackages,
    candidatePackages,
  });

  const result = analyzeTyposquatCandidates(
    candidatePackages,
    protectedPackages,
  );

  equal(result.truncated, false);
  equal(result.comparisonCount, 9);
  equal(result.candidates.length, 2);

  const transpositionCandidate = result.candidates.find(
    (candidate) =>
      candidate.candidatePackageName === "lodahs" &&
      candidate.targetPackageName === "lodash",
  );

  ok(transpositionCandidate);
  equal(transpositionCandidate.similarityScore, 0.95);
  ok(
    signalCodes(transpositionCandidate.signals).includes(
      "adjacent-transposition",
    ),
  );
  deepEqual(
    transpositionCandidate.evidenceIds,
    [900, 902],
  );
  ok(
    transpositionCandidate.uncertainties.some(
      (uncertainty) =>
        uncertainty.includes(
          "does not prove malicious intent",
        ),
    ),
  );

  const scopeCandidate = result.candidates.find(
    (candidate) =>
      candidate.candidatePackageName ===
        "@other/security_core" &&
      candidate.targetPackageName ===
        "@hydra/security-core",
  );

  ok(scopeCandidate);
  equal(scopeCandidate.similarityScore, 0.82);
  ok(
    signalCodes(scopeCandidate.signals).includes(
      "scope-variation",
    ),
  );
  deepEqual(scopeCandidate.evidenceIds, [901, 904]);

  ok(
    result.candidates.every(
      (candidate) =>
        candidate.candidatePackageName !==
        "totally-different",
    ),
  );

  ok(
    result.candidates.every(
      (candidate) =>
        candidate.candidatePackageId !== 700,
    ),
    "An exact normalized package match must not be reported",
  );

  const limitedResult = analyzeTyposquatCandidates(
    candidatePackages,
    protectedPackages,
    {
      maxComparisons: 1,
      maxResults: 1,
    },
  );

  equal(limitedResult.truncated, true);
  equal(limitedResult.comparisonCount, 1);
  ok(
    limitedResult.warnings.some(
      (warning) =>
        warning.code === "comparison-limit-reached",
    ),
  );

  equal(
    JSON.stringify({
      protectedPackages,
      candidatePackages,
    }),
    inputSnapshot,
    "Typosquat analysis must not mutate its inputs",
  );

  console.log(
    "typosquat smoke passed: " +
    `${String(result.comparisonCount)} comparisons, ` +
    `${String(result.candidates.length)} candidates`,
  );
}

runSmoke();
