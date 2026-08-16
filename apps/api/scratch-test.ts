import { createHydraDriver } from "../src/hydra-client.js";

async function main() {
  const driver = await createHydraDriver();
  const session = driver.session({ database: "default" });
  try {
    console.log("Trying to create a single node...");
    await session.run(`CREATE (:Service {id: 1})`);
    console.log("Node created successfully!");
  } catch (e: any) {
    console.log("Error creating node:", e.message);
  } finally {
    await session.close();
    await driver.close();
  }
}
main();
