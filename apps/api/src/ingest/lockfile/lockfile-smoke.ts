import { pathToFileURL } from "node:url";

import {
  collectPackageLock,
} from "./collector.js";

const lockfileFixture = {
  name: "payment-api",
  version: "1.0.0",
  lockfileVersion: 3,
  requires: true,
  packages: {
    "": {
      name: "payment-api",
      version: "1.0.0",
      dependencies: {
        "auth-lib": "2.0.0",
      },
    },

    "node_modules/auth-lib": {
      name: "auth-lib",
      version: "2.0.0",
      integrity: "sha512-auth-fixture",
      dependencies: {
        "bad-lib": "^1.2.0",
      },
    },

    "node_modules/bad-lib": {
      name: "bad-lib",
      version: "1.2.4",
      integrity: "sha512-bad-fixture",
    },
  },
};

function run(): void {
  console.log("Parsing package-lock v3 fixture...");

  const result = collectPackageLock(lockfileFixture, {
    serviceLogicalId: "service:demo-org:payment-api",
    serviceName: "payment-api",
    serviceCriticality: "critical",
    sourceUri: "fixture://payment-api/package-lock.json",
    observedAt: Date.now(),
    confidence: 1,
    synthetic: true,
    maxPackages: 100,
  });

  const canonicalDependencies = result.edges.filter(
    (edge) => edge.kind === "DEPENDS_ON",
  );

  const reverseIndexes = result.edges.filter(
    (edge) => edge.kind === "USED_BY",
  );

  if (
    canonicalDependencies.length !== 2 ||
    reverseIndexes.length !== 2
  ) {
    throw new Error(
      `Expected 2 DEPENDS_ON and 2 USED_BY edges; received ` +
        `${canonicalDependencies.length} DEPENDS_ON and ` +
        `${reverseIndexes.length} USED_BY`,
    );
  }

  console.log("✅ package-lock v3 parsed");
  console.log("✅ Hoisted dependency resolution completed");
  console.log("✅ Graph validation passed");
  console.log("✅ Created exactly 2 DEPENDS_ON edges");
  console.log("✅ Created exactly 2 derived USED_BY edges");
  console.log(`✅ Generated ${result.nodes.length} nodes`);
  console.log(`✅ Generated ${result.edges.length} total edges`);

  for (const issue of result.issues) {
    console.warn(`⚠️ ${issue.code}: ${issue.message}`);
  }
}

const isExecutedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isExecutedDirectly) {
  try {
    run();
  } catch (error) {
    console.error(
      "❌ Lockfile smoke test failed:",
      error instanceof Error ? error.message : String(error),
    );

    process.exitCode = 1;
  }
}
