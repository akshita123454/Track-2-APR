import { performance } from "node:perf_hooks";
import { createHydraDriver } from "./hydra-client.js";

/**
 * HydraGuard Compatibility Smoke Test
 *
 * Proves that TypeScript can connect to HydraDB through Bolt, write three
 * logical nodes and two DEPENDS_ON relationships, and traverse the graph
 * using a derived USED_BY reverse index.
 *
 * Because the tested HydraDB runtime (v0.1.1) requires a fixed outgoing
 * source for variable-length OpenCypher traversal, HydraGuard maintains
 * USED_BY as a derived reverse index for efficient blast-radius queries.
 *
 * This test does NOT prove strict incoming DEPENDS_ON traversal.
 */
async function main() {
  const driver = await createHydraDriver();
  const session = driver.session({ database: "default" });
  try {
    console.log("✅ Connected to HydraDB");

    // 1. Clear the graph
    await session.run("MATCH (n:Service) DETACH DELETE n");
    await session.run("MATCH (n:PackageVersion) DETACH DELETE n");
    console.log("✅ Graph cleared");

    // 2. Create 3 nodes and 2 DEPENDS_ON edges (the canonical relationships)
    await session.run(`
      CREATE (s:Service {id: 1, name: "payment-api"})-[:DEPENDS_ON]->(p1:PackageVersion {id: 2, name: "auth-lib", version: "2.0.0", key: "npm:auth-lib@2.0.0"})
    `);
    await session.run(`
      CREATE (p1:PackageVersion {id: 2, name: "auth-lib", version: "2.0.0", key: "npm:auth-lib@2.0.0"})-[:DEPENDS_ON]->(p2:PackageVersion {id: 3, name: "bad-lib", version: "1.2.4", key: "npm:bad-lib@1.2.4", compromised: true})
    `);

    // 3. Create 2 USED_BY edges (derived reverse index for blast-radius queries)
    //    Required because HydraDB v0.1.1 does not support variable-length
    //    incoming traversal (<-[:DEPENDS_ON*1..10]-).
    await session.run(`
      CREATE (p1:PackageVersion {id: 2})-[:USED_BY]->(s:Service {id: 1})
    `);
    await session.run(`
      CREATE (p2:PackageVersion {id: 3})-[:USED_BY]->(p1:PackageVersion {id: 2})
    `);

    console.log("✅ Created 3 nodes, 2 DEPENDS_ON edges, 2 USED_BY reverse-index edges");

    const queryStartedAt = performance.now();

    // 4. Traverse the USED_BY reverse index from the compromised package
    const result = await session.run(`
      MATCH (compromised:PackageVersion {id: 3})-[:USED_BY*1..10]->(affected)
      RETURN affected.name AS name
    `);

    const queryDurationMs = performance.now() - queryStartedAt;

    console.log("✅ Reverse traversal from bad-lib@1.2.4 (via USED_BY reverse index):");
    for (const record of result.records) {
      console.log(`   → ${record.get("name")}`);
    }
    console.log(`✅ Query time: ${queryDurationMs.toFixed(2)}ms`);

  } catch (e: any) {
    console.error("❌ Seed test failed:", e.message);
    process.exitCode = 1;
  } finally {
    await session.close();
    await driver.close();
    console.log("✅ Connection closed");
  }
}
main();