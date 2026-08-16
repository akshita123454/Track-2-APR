import { performance } from "node:perf_hooks";
import { createHydraDriver } from "./hydra-client.js";

async function main(): Promise<void> {
  const driver = await createHydraDriver();
  console.log("✅ Connected to HydraDB");

  try {
    const session = driver.session({ database: "default" });

    try {
      await session.run("MATCH (n:Service) DETACH DELETE n");
      await session.run("MATCH (n:PackageVersion) DETACH DELETE n");
      console.log("✅ Graph cleared");

      // Create Nodes (Must use CREATE instead of MERGE in HydraDB v0.1.1)
      await session.run(`
        CREATE (:Service {id: 1, name: "payment-api"})
      `);
      await session.run(`
        CREATE (:PackageVersion {
          id: 2,
          name: "auth-lib",
          version: "2.0.0",
          key: "npm:auth-lib@2.0.0"
        })
      `);
      await session.run(`
        CREATE (:PackageVersion {
          id: 3,
          name: "bad-lib",
          version: "1.2.4",
          key: "npm:bad-lib@1.2.4",
          compromised: true
        })
      `);

      // Create Edges (Requires CREATE and ONLY integer IDs without labels)
      await session.run(`
        CREATE ({id: 1})-[:DEPENDS_ON]->({id: 2})
      `);
      await session.run(`
        CREATE ({id: 2})-[:DEPENDS_ON]->({id: 3})
      `);
      
      console.log("✅ Created 3 nodes and 2 edges");

      const queryStartedAt = performance.now();
      
      // The Reverse Traversal (Finding the Blast Radius)
      const result = await session.run(`
        MATCH p = (compromised:PackageVersion {
          key: "npm:bad-lib@1.2.4"
        })<-[:DEPENDS_ON*1..10]-(affected)
        RETURN affected.name AS name, labels(affected) AS type, length(p) AS depth
        ORDER BY depth ASC
      `);
      
      const queryDurationMs = performance.now() - queryStartedAt;

      console.log("✅ Reverse traversal from bad-lib@1.2.4:");
      for (const record of result.records) {
        const name = record.get("name") as string;
        const labels = record.get("type") as string[];
        console.log(`   → ${name} (${labels.join(", ")})`);
      }
      console.log(`✅ Query time: ${queryDurationMs.toFixed(2)}ms`);
      
    } finally {
      await session.close();
    }
  } finally {
    await driver.close();
    console.log("✅ Connection closed");
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`❌ Seed test failed: ${message}`);
  process.exitCode = 1;
});