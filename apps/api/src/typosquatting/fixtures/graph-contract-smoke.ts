import assert from "node:assert/strict";

import { generateFixture } from "../../domain/fixture.js";
import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../../domain/identity.js";
import { validateGraph } from "../../domain/validator.js";
import {
  deserializeHydraEdge,
  deserializeHydraNode,
} from "../../db/hydra-deserializer.js";
import {
  hashHydraScalarRecord,
  serializeHydraEdge,
  serializeHydraNode,
} from "../../db/hydra-serializer.js";

import type {
  CanonicalEdge,
  EvidenceNode,
  GraphEdge,
  GraphNode,
  LookalikeEdge,
  PackageNode,
  StandardCanonicalEdge,
  TyposquatFindingNode,
} from "../../domain/schema.js";
import type {
  HydraScalar,
} from "../../db/hydra-serializer.js";

const observedAt = 1_735_689_600_000;

function standardEdge(
  kind: "TARGETS" | "IMITATES" | "SUPPORTS",
  source: GraphNode,
  target: GraphNode,
  evidenceId: number,
): StandardCanonicalEdge {
  const identityDiscriminator = "typosquatting-contract-v1";

  return {
    ...createEdgeIdentity({
      kind,
      sourceLogicalId: source.logicalId,
      targetLogicalId: target.logicalId,
      discriminator: identityDiscriminator,
    }),
    kind,
    sourceId: source.id,
    targetId: target.id,
    observedAt,
    derived: false,
    identityDiscriminator,
    evidenceIds: [evidenceId],
  };
}

const evidence: EvidenceNode = {
  ...createEntityIdentity("evidence:typosquatting:graph-contract-v1"),
  kind: "Evidence",
  evidenceIds: [],
  synthetic: true,
  observedAt,
  sourceType: "typosquat-detector",
  sourceUri: "detector://typosquatting/graph-contract-v1",
  collectorVersion: "detector-v1",
  confidence: 0.98,
  detail: "Deterministic graph contract evidence",
  incidentId: undefined,
};

const candidatePackage: PackageNode = {
  ...createEntityIdentity("pkg:npm:lodahs"),
  kind: "Package",
  evidenceIds: [evidence.id],
  synthetic: true,
  observedAt,
  ecosystem: "npm",
  name: "lodahs",
};

const targetPackage: PackageNode = {
  ...createEntityIdentity("pkg:npm:lodash"),
  kind: "Package",
  evidenceIds: [evidence.id],
  synthetic: true,
  observedAt,
  ecosystem: "npm",
  name: "lodash",
};

const finding: TyposquatFindingNode = {
  ...createEntityIdentity("finding:typosquatting:lodahs:lodash:v1"),
  kind: "Finding",
  evidenceIds: [evidence.id],
  synthetic: true,
  observedAt,
  findingType: "typosquatting",
  status: "confirmed",
  score: 97,
  detectorVersion: "detector-v1",
  policyVersion: "policy-v1",
  corpusId: "corpus-v1",
  comparisonVersion: "npm-name-nfc-v2",
  indexVersion: "trusted-target-signatures-v1",
  candidatePackageName: "lodahs",
  targetPackageName: "lodash",
  summary: "Candidate name closely imitates a trusted package",
  transformations: ["adjacent-transposition", "substitution"],
  reasonCodes: ["distance-threshold", "popular-target"],
  detectedAt: observedAt,
  decidedAt: observedAt + 1_000,
  decisionReason: "Confirmed by deterministic analyst review fixture",
};

const lookalikeIdentity = createEdgeIdentity({
  kind: "LOOKALIKE_OF",
  sourceLogicalId: candidatePackage.logicalId,
  targetLogicalId: targetPackage.logicalId,
  discriminator: "npm-name-nfc-v2:detector-v1",
});

const lookalike: LookalikeEdge = {
  ...lookalikeIdentity,
  kind: "LOOKALIKE_OF",
  sourceId: candidatePackage.id,
  targetId: targetPackage.id,
  observedAt,
  derived: false,
  identityDiscriminator: "npm-name-nfc-v2:detector-v1",
  evidenceIds: [evidence.id],
  algorithm: "weighted-damerau-levenshtein",
  comparisonVersion: "npm-name-nfc-v2",
  normalizedDistance: 0.2,
  transformations: ["adjacent-transposition", "substitution"],
};

const targets = standardEdge(
  "TARGETS",
  finding,
  candidatePackage,
  evidence.id,
);
const imitates = standardEdge(
  "IMITATES",
  finding,
  targetPackage,
  evidence.id,
);
const supports = standardEdge(
  "SUPPORTS",
  evidence,
  finding,
  evidence.id,
);

const nodes: readonly GraphNode[] = [
  evidence,
  candidatePackage,
  targetPackage,
  finding,
];
const edges: readonly GraphEdge[] = [
  lookalike,
  targets,
  imitates,
  supports,
];

function expectInvalidGraph(
  candidateNodes: readonly GraphNode[],
  candidateEdges: readonly GraphEdge[],
  description: string,
): void {
  const result = validateGraph(candidateNodes, candidateEdges);
  assert.equal(result.valid, false, `${description} must fail closed`);
  assert.ok(result.errors.length > 0, `${description} must explain the failure`);
}

function nodeProperties(node: GraphNode): Record<string, HydraScalar> {
  const { vertex: _vertex, ...properties } = serializeHydraNode(node);
  return properties;
}

function edgeProperties(edge: GraphEdge): Record<string, HydraScalar> {
  const {
    relationship_vertex: _relationshipVertex,
    source_vertex: _sourceVertex,
    destination_vertex: _destinationVertex,
    ...properties
  } = serializeHydraEdge(edge);
  return properties;
}

function rehash(
  properties: Readonly<Record<string, HydraScalar>>,
  changes: Readonly<Record<string, HydraScalar>>,
): Record<string, HydraScalar> {
  const changed: Record<string, HydraScalar> = {
    ...properties,
    ...changes,
    payload_hash: "",
  };
  changed.payload_hash = hashHydraScalarRecord(changed, ["payload_hash"]);
  return changed;
}

const validation = validateGraph(nodes, edges);
assert.deepEqual(validation, { valid: true, errors: [] });

const nodeById = new Map(nodes.map((node) => [node.id, node]));

for (const node of nodes) {
  const properties = nodeProperties(node);
  const roundTrip = deserializeHydraNode({
    vertex: node.id,
    properties,
    expectedKind: node.kind,
  });
  assert.deepEqual(roundTrip, node);
}

for (const edge of edges) {
  const source = nodeById.get(edge.sourceId);
  const target = nodeById.get(edge.targetId);
  assert.ok(source !== undefined && target !== undefined);

  const roundTrip = deserializeHydraEdge({
    relationshipVertex: edge.id,
    sourceVertex: edge.sourceId,
    destinationVertex: edge.targetId,
    sourceLogicalId: source.logicalId,
    destinationLogicalId: target.logicalId,
    properties: edgeProperties(edge),
    expectedKind: edge.kind,
  });
  assert.deepEqual(roundTrip, edge);
}

const findingRow = nodeProperties(finding);
const lookalikeRow = edgeProperties(lookalike);
assert.equal(
  findingRow.transformations_json,
  '["adjacent-transposition","substitution"]',
);
assert.equal(
  findingRow.reason_codes_json,
  '["distance-threshold","popular-target"]',
);
assert.equal(
  lookalikeRow.transformations_json,
  '["adjacent-transposition","substitution"]',
);

const invalidEndpoint = standardEdge(
  "IMITATES",
  candidatePackage,
  targetPackage,
  evidence.id,
);
expectInvalidGraph(nodes, [lookalike, targets, invalidEndpoint, supports], "invalid endpoints");

const samePackageIdentity = createEdgeIdentity({
  kind: "LOOKALIKE_OF",
  sourceLogicalId: candidatePackage.logicalId,
  targetLogicalId: candidatePackage.logicalId,
  discriminator: lookalike.identityDiscriminator,
});
const samePackageLookalike: LookalikeEdge = {
  ...lookalike,
  ...samePackageIdentity,
  targetId: candidatePackage.id,
};
expectInvalidGraph(nodes, [samePackageLookalike, targets, imitates, supports], "same-package LOOKALIKE_OF");

const noEvidenceFinding: TyposquatFindingNode = {
  ...finding,
  evidenceIds: [],
};
expectInvalidGraph(
  [evidence, candidatePackage, targetPackage, noEvidenceFinding],
  edges,
  "finding without evidence",
);

const malformedDecisionFinding: TyposquatFindingNode = {
  ...finding,
  status: "candidate",
};
expectInvalidGraph(
  [evidence, candidatePackage, targetPackage, malformedDecisionFinding],
  edges,
  "nonterminal finding with decision fields",
);

const invalidScoreFinding: TyposquatFindingNode = {
  ...finding,
  score: 101,
};
expectInvalidGraph(
  [evidence, candidatePackage, targetPackage, invalidScoreFinding],
  edges,
  "out-of-range finding score",
);

const invalidDistanceLookalike: LookalikeEdge = {
  ...lookalike,
  normalizedDistance: 1.01,
};
expectInvalidGraph(
  nodes,
  [invalidDistanceLookalike, targets, imitates, supports],
  "out-of-range lookalike distance",
);

assert.throws(() => serializeHydraNode(invalidScoreFinding));
assert.throws(() => serializeHydraEdge(invalidDistanceLookalike));
assert.throws(() => serializeHydraEdge(samePackageLookalike));

const nodeInput = (properties: Record<string, HydraScalar>) => ({
  vertex: finding.id,
  properties,
  expectedKind: "Finding" as const,
});
assert.throws(() => deserializeHydraNode(nodeInput(rehash(findingRow, { status: "unknown" }))));
assert.throws(() => deserializeHydraNode(nodeInput(rehash(findingRow, { score: -1 }))));
assert.throws(() => deserializeHydraNode(nodeInput(rehash(findingRow, { transformations_json: "not-json" }))));
assert.throws(() => deserializeHydraNode(nodeInput(rehash(findingRow, {
  transformations_json: '["substitution","adjacent-transposition"]',
}))));
assert.throws(() => deserializeHydraNode(nodeInput(rehash(findingRow, {
  has_decided_at: false,
  decided_at: finding.decidedAt ?? 0,
}))));

const lookalikeInput = (properties: Record<string, HydraScalar>) => ({
  relationshipVertex: lookalike.id,
  sourceVertex: lookalike.sourceId,
  destinationVertex: lookalike.targetId,
  sourceLogicalId: candidatePackage.logicalId,
  destinationLogicalId: targetPackage.logicalId,
  properties,
  expectedKind: "LOOKALIKE_OF" as const,
});
assert.throws(() => deserializeHydraEdge(lookalikeInput(rehash(lookalikeRow, {
  normalized_distance: 1.01,
}))));
assert.throws(() => deserializeHydraEdge(lookalikeInput(rehash(lookalikeRow, {
  transformations_json: '["unsupported"]',
}))));

const parityFixture = generateFixture();
assert.equal(parityFixture.validation.valid, true);
assert.equal(
  parityFixture.edges.filter((edge) => edge.kind === "DEPENDS_ON").length,
  parityFixture.edges.filter((edge) => edge.kind === "USED_BY").length,
);
assert.equal(validateGraph(parityFixture.nodes, parityFixture.edges).valid, true);

console.log("Typosquatting graph contract smoke passed");
console.log("- new graph ontology validates and round-trips exactly");
console.log("- malformed endpoints, evidence, decisions, ranges, JSON, order, and sentinels fail closed");
console.log("- existing DEPENDS_ON/USED_BY parity remains unchanged");
