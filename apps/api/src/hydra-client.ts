import neo4j, { type Driver } from "neo4j-driver";

const HYDRADB_URI = "bolt://localhost:7687";
const HYDRADB_USER = "neo4j";
const HYDRADB_TOKEN = "local-development-token-32-bytes";

export async function createHydraDriver(): Promise<Driver> {
  const driver = neo4j.driver(
    HYDRADB_URI,
    neo4j.auth.basic(HYDRADB_USER, HYDRADB_TOKEN),
  );

  try {
    await driver.verifyConnectivity();
    return driver;
  } catch (error) {
    await driver.close();
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Could not connect to HydraDB at ${HYDRADB_URI}. Confirm Docker and the HydraDB container are running. ${reason}`,
    );
  }
}
