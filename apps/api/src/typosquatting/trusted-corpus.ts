import {
  createEntityIdentity,
} from "../domain/identity.js";

import type {
  EvidenceNode,
  PackageNode,
} from "../domain/schema.js";

import {
  createTyposquattingCorpus,
} from "./corpus.js";

import {
  COMPARISON_VERSION,
  INDEX_VERSION,
} from "./types.js";

import type {
  TrustedTarget,
} from "./types.js";

export const TRUSTED_CORPUS_ID =
  "npm-curated-watchlist-2026-08-15-v1";

export const TRUSTED_CORPUS_GENERATED_AT =
  1_755_216_000_000;

export const TYPOSQUATTING_DETECTOR_VERSION =
  "hydraguard-typosquat-detector-v1";

export const TYPOSQUATTING_POLICY_VERSION =
  "evidence-first-policy-v1";

const corpusEvidenceIdentity =
  createEntityIdentity(
    `evidence:typosquatting-corpus:${TRUSTED_CORPUS_ID}`,
  );

export const TRUSTED_CORPUS_EVIDENCE:
  EvidenceNode = Object.freeze({
    ...corpusEvidenceIdentity,
    kind: "Evidence",
    evidenceIds: [] as const,
    synthetic: false,
    observedAt:
      TRUSTED_CORPUS_GENERATED_AT,
    sourceType: "other",
    sourceUri:
      `urn:hydraguard:trusted-corpus:${TRUSTED_CORPUS_ID}`,
    collectorVersion:
      "trusted-corpus-artifact-v1",
    confidence: 1,
    detail:
      "Checked-in npm reference-name watchlist. It establishes comparison targets only; it does not assert that similar packages are malicious or that popularity is current.",
  });

const TARGET_NAMES = [
  "axios",
  "express",
  "lodash",
  "react",
  "typescript",
] as const;

function targetPackage(
  name: string,
): PackageNode {
  const identity =
    createEntityIdentity(
      `pkg:npm:${name}`,
    );

  return Object.freeze({
    ...identity,
    kind: "Package",
    evidenceIds: [
      TRUSTED_CORPUS_EVIDENCE.id,
    ],
    synthetic: false,

    /*
     * Static corpus package observations deliberately use epoch zero. The
     * guarded writer can create a missing target, but cannot replace newer
     * registry or lockfile provenance for an existing Package node.
     */
    observedAt: 0,
    ecosystem: "npm",
    name,
  });
}

export const TRUSTED_CORPUS_PACKAGES:
  readonly PackageNode[] = Object.freeze(
    TARGET_NAMES.map(targetPackage),
  );

const targets: readonly TrustedTarget[] =
  Object.freeze(
    TRUSTED_CORPUS_PACKAGES.map(
      (packageNode) =>
        Object.freeze({
          packageId: packageNode.id,
          packageName:
            packageNode.name,
          sources: [
            "watchlist" as const,
          ],
          sourceEvidenceIds: [
            TRUSTED_CORPUS_EVIDENCE.id,
          ],
        }),
    ),
  );

export const TRUSTED_TYPOSQUATTING_CORPUS =
  createTyposquattingCorpus({
    corpusId: TRUSTED_CORPUS_ID,
    generatedAt:
      TRUSTED_CORPUS_GENERATED_AT,
    comparisonVersion:
      COMPARISON_VERSION,
    indexVersion: INDEX_VERSION,
    sourceEvidenceIds: [
      TRUSTED_CORPUS_EVIDENCE.id,
    ],
    targetCount: targets.length,
    targets,
    allowlist: [...TARGET_NAMES],
    blocklist: [],
    watchlist: [...TARGET_NAMES],
  });

export const TRUSTED_CORPUS_PACKAGE_BY_ID:
  ReadonlyMap<number, PackageNode> =
    new Map(
      TRUSTED_CORPUS_PACKAGES.map(
        (packageNode) => [
          packageNode.id,
          packageNode,
        ] as const,
      ),
    );
