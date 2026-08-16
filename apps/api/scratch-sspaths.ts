import { performance } from "node:perf_hooks";
import { createHydraDriver } from "./src/hydra-client.js";

async function main() {
  const driver = await createHydraDriver();
  const session = driver.session({ database: "default" });
  try {
    console.log("✅ Connected to HydraDB");

    // 1. Clear the graph
    await session.run("MATCH (n:Service) DETACH DELETE n");
    await session.run("MATCH (n:PackageVersion) DETACH DELETE n");
    console.log("✅ Graph cleared");

    // 2. Create the strictly canonical graph (NO USED_BY edges)
    await session.run(`
      CREATE (s:Service {id: 1, name: "payment-api"})-[:DEPENDS_ON]->(p1:PackageVersion {id: 2, name: "auth-lib", version: "2.0.0", key: "npm:auth-lib@2.0.0"})
    `);
    await session.run(`
      CREATE (p1:PackageVersion {id: 2, name: "auth-lib", version: "2.0.0", key: "npm:auth-lib@2.0.0"})-[:DEPENDS_ON]->(p2:PackageVersion {id: 3, name: "bad-lib", version: "1.2.4", key: "npm:bad-lib@1.2.4", compromised: true})
    `);
    console.log("✅ Created 3 nodes, 2 strictly canonical DEPENDS_ON edges");

    const queryStartedAt = performance.now();

    // 3. Test algo.SSpaths with relDirection: 'incoming'
    console.log("Testing native algo.SSpaths...");
    const result = await session.run(`
      CALL algo.SSpaths({
        sourceNode: 3,
        relTypes: ['DEPENDS_ON'],
        relDirection: 'incoming',
        maxLen: 10,
        pathCount: 100,
        resultLimit: 1000
      })
      YIELD path
      RETURN path
    `);

    const queryDurationMs = performance.now() - queryStartedAt;

    console.log("✅ Reverse traversal using native algo.SSpaths succeeded!");
    for (const record of result.records) {
      console.log(`   → ${JSON.stringify(record.get("path"))}`);
    }
    console.log(`✅ Query time: ${queryDurationMs.toFixed(2)}ms`);

  } catch (e: any) {
    console.error("❌ algo.SSpaths capability test failed:", e.message);
    process.exitCode = 1;
  } finally {
    await session.close();
    await driver.close();
    console.log("✅ Connection closed");
  }
}
main();
