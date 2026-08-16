import { performance } from "node:perf_hooks";
import { createHydraDriver } from "./src/hydra-client.js";

async function main() {
  const driver = await createHydraDriver();
  const session = driver.session({ database: "default" });
  try {
    await session.run("MATCH (n:Service) DETACH DELETE n");
    await session.run("MATCH (n:PackageVersion) DETACH DELETE n");
    
    // Create nodes and DEPENDS_ON edges
    await session.run(`
      CREATE (s:Service {id: 1, name: "payment-api"})-[:DEPENDS_ON]->(p1:PackageVersion {id: 2, name: "auth-lib", version: "2.0.0", key: "npm:auth-lib@2.0.0"})
    `);
    await session.run(`
      CREATE (p1:PackageVersion {id: 2, name: "auth-lib", version: "2.0.0", key: "npm:auth-lib@2.0.0"})-[:DEPENDS_ON]->(p2:PackageVersion {id: 3, name: "bad-lib", version: "1.2.4", key: "npm:bad-lib@1.2.4", compromised: true})
    `);

    // Create USED_BY edges (reverse of DEPENDS_ON) for fast reverse traversal
    await session.run(`
      CREATE (p1:PackageVersion {id: 2})-[:USED_BY]->(s:Service {id: 1})
    `);
    await session.run(`
      CREATE (p2:PackageVersion {id: 3})-[:USED_BY]->(p1:PackageVersion {id: 2})
    `);

    console.log("✅ Created 3 nodes, 2 DEPENDS_ON edges, 2 USED_BY edges");
    
    const queryStartedAt = performance.now();

    // Query using the USED_BY edge, which is outbound from the compromised package
    const result = await session.run(`
      MATCH (compromised:PackageVersion {id: 3})-[:USED_BY*1..10]->(affected)
      RETURN affected.name AS name
    `);

    const queryDurationMs = performance.now() - queryStartedAt;

    console.log("✅ Reverse traversal from bad-lib@1.2.4:");
    for (const record of result.records) {
      console.log(`   → ${record.get("name")}`);
    }
    console.log(`✅ Query time: ${queryDurationMs.toFixed(2)}ms`);

  } catch (e: any) {
    console.log("❌ Seed test failed:", e.message);
  } finally {
    await session.close();
    await driver.close();
  }
}
main();
