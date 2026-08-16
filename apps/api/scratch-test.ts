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

    // Let's try the original reverse traversal query again to be absolutely sure.
    // If it fails, we know for sure we must use USED_BY.
    let usedBy = false;
    let result;
    const queryStartedAt = performance.now();
    try {
        result = await session.run(`
          MATCH (compromised:PackageVersion {id: 3})<-[:DEPENDS_ON*1..10]-(affected)
          RETURN affected
        `);
    } catch (err: any) {
        console.log("Original reverse traversal failed:", err.message);
        console.log("Falling back to USED_BY workaround.");
        usedBy = true;
    }

    if (usedBy) {
        await session.run(`
          CREATE (p1:PackageVersion {id: 2})-[:USED_BY]->(s:Service {id: 1})
        `);
        await session.run(`
          CREATE (p2:PackageVersion {id: 3})-[:USED_BY]->(p1:PackageVersion {id: 2})
        `);
        
        result = await session.run(`
          MATCH (compromised:PackageVersion {id: 3})-[:USED_BY*1..10]->(affected)
          RETURN affected
        `);
    }

    const queryDurationMs = performance.now() - queryStartedAt;

    console.log("✅ Reverse traversal from bad-lib@1.2.4:");
    for (const record of result!.records) {
      const node = record.get("affected");
      // Check if it's a Node object with labels and properties
      let name = "unknown";
      let labelStr = "";
      if (node && typeof node === 'object' && node.properties) {
          name = node.properties.name || "unknown";
          if (node.labels && node.labels.length > 0) {
              labelStr = ` (${node.labels.join(", ")})`;
          }
      } else {
          // If it just returned a string or something
          name = node;
      }
      console.log(`   → ${name}${labelStr}`);
    }
    console.log(`✅ Query time: ${queryDurationMs.toFixed(2)}ms`);

  } catch (e: any) {
    console.log("❌ Seed test failed:", e.message);
    process.exitCode = 1;
  } finally {
    await session.close();
    await driver.close();
  }
}
main();
