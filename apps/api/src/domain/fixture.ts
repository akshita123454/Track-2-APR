import { pathToFileURL } from "node:url";

import {
  createEntityIdentity,
} from "./identity.js";

import { validateGraph } from "./validator.js";
import { createDependencyPair } from "./factories.js";

import type {
  EvidenceNode,
  GraphEdge,
  GraphNode,
  PackageVersionNode,
  ServiceNode,
} from "./schema.js";

export interface FixtureResult {
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];
  readonly validation: ReturnType<typeof validateGraph>;
}

export function generateFixture(): FixtureResult {
  /*
   * Use one timestamp for the complete fixture so its provenance is
   * internally consistent. Timestamps do not affect deterministic IDs.
   */
  const observedAt = Date.now();

  /*
   * 1. Create provenance evidence.
   *
   * Evidence nodes must not recursively reference other Evidence nodes.
   */
  const evidenceIdentity = createEntityIdentity(
    "evidence:synthetic:strict-parity-fixture-v1",
  );

  const evidence: EvidenceNode = {
    ...evidenceIdentity,
    kind: "Evidence",
    evidenceIds: [],
    synthetic: true,
    observedAt,
    sourceType: "synthetic-fixture",
    sourceUri: "fixture://strict-parity-fixture-v1",
    collectorVersion: "1.0.0",
    confidence: 1,
    detail:
      "Synthetic evidence supporting the three-node dependency parity fixture",
  };

  /*
   * 2. Create the three subject nodes:
   *
   * payment-api -> auth-lib@2.0.0 -> bad-lib@1.2.4
   */
  const serviceIdentity = createEntityIdentity(
    "service:demo-org:payment-api",
  );

  const paymentService: ServiceNode = {
    ...serviceIdentity,
    kind: "Service",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt,
    name: "payment-api",
    criticality: "critical",
    internetExposed: true,
    dataSensitivity: "high",
  };

  const authIdentity = createEntityIdentity(
    "pkgver:npm:auth-lib@2.0.0",
  );

  const authVersion: PackageVersionNode = {
    ...authIdentity,
    kind: "PackageVersion",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt,
    ecosystem: "npm",
    packageName: "auth-lib",
    version: "2.0.0",
  };

  const badIdentity = createEntityIdentity(
    "pkgver:npm:bad-lib@1.2.4",
  );

  const badVersion: PackageVersionNode = {
    ...badIdentity,
    kind: "PackageVersion",
    evidenceIds: [evidence.id],
    synthetic: true,
    observedAt,
    ecosystem: "npm",
    packageName: "bad-lib",
    version: "1.2.4",
  };

  /*
   * 3 & 4. Use the factory to safely create both the canonical 
   * DEPENDS_ON edge and the matching derived USED_BY index.
   */
  const serviceToAuthPair = createDependencyPair({
    source: paymentService,
    target: authVersion,
    discriminator: "package-lock:root>node_modules/auth-lib",
    dependencyType: "production",
    evidenceIds: [evidence.id],
    observedAt,
    generatorVersion: "1.0.0",
    declaredRange: "2.0.0",
    lockfilePath: "node_modules/auth-lib",
  });

  const authToBadPair = createDependencyPair({
    source: authVersion,
    target: badVersion,
    discriminator: "package-lock:node_modules/auth-lib>node_modules/bad-lib",
    dependencyType: "production",
    evidenceIds: [evidence.id],
    observedAt,
    generatorVersion: "1.0.0",
    declaredRange: "^1.2.0",
    lockfilePath: "node_modules/auth-lib/node_modules/bad-lib",
  });

  const nodes: GraphNode[] = [
    evidence,
    paymentService,
    authVersion,
    badVersion,
  ];

  const edges: GraphEdge[] = [
    // We seamlessly spread both sides of the factory pair into our edges array
    serviceToAuthPair.canonical,
    authToBadPair.canonical,
    serviceToAuthPair.reverseIndex,
    authToBadPair.reverseIndex,
  ];

  /*
   * validateGraph includes:
   *
   * - deterministic ID validation
   * - duplicate ID detection
   * - endpoint-kind validation
   * - evidence validation
   * - synthetic evidence validation
   * - exact one-to-one USED_BY parity validation
   */
  const validation = validateGraph(nodes, edges);

  return {
    nodes,
    edges,
    validation,
  };
}

function runFixture(): void {
  console.log("Generating strict parity fixture...");

  const fixture = generateFixture();

  if (!fixture.validation.valid) {
    console.error("❌ Graph validation failed:");

    for (const error of fixture.validation.errors) {
      console.error(`   - ${error}`);
    }

    process.exitCode = 1;
    return;
  }

  console.log("✅ Graph validation passed");
  console.log("✅ Created 3 subject nodes plus 1 Evidence node");
  console.log("✅ Created 2 canonical DEPENDS_ON edges");
  console.log("✅ Created exactly 2 derived USED_BY edges");
  console.log("✅ Deterministic identity and parity checks passed");
}

/*
 * Convert process.argv[1] into a file URL rather than constructing
 * `file://${process.argv[1]}` manually, which is unreliable on Windows.
 */
const isExecutedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isExecutedDirectly) {
  runFixture();
}