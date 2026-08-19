import neo4j, {
  type Driver,
} from "neo4j-driver";

export async function createHydraDriver(): Promise<Driver> {
  const uri =
    process.env.HYDRADB_URI ??
    "bolt://127.0.0.1:27687";

  const user =
    process.env.HYDRADB_USER ??
    "neo4j";

  const token =
    process.env.HYDRADB_TOKEN ??
    "local-development-token-32-bytes";

  return neo4j.driver(
    uri,
    neo4j.auth.basic(
      user,
      token,
    ),
  );
}
