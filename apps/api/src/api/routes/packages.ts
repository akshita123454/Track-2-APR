import type {
  Driver,
} from "neo4j-driver";
import type {
  FastifyInstance,
} from "fastify";

import {
  HydraPackageOverviewStore,
  PackageOverviewStoreError,
} from "../../packages/package-overview-store.js";

import {
  ApiError,
} from "../errors.js";

import {
  GET_PACKAGE_OVERVIEW_ROUTE_SCHEMA,
  PACKAGE_OVERVIEW_LIMITS,
} from "../schemas/packages.js";

import type {
  PackageOverviewParams,
  PackageOverviewQuerystring,
} from "../schemas/packages.js";

export interface PackageOverviewReader {
  investigate(
    packageName: string,
    limit: number,
  ): ReturnType<HydraPackageOverviewStore["investigate"]>;
}

export interface PackageRoutesOptions {
  readonly packageOverviewReader?: PackageOverviewReader;
  readonly driver: Driver;
}

/**
 * Registers GET /packages/:packageName?limit=12.
 *
 * The response intentionally separates registry declarations from exact
 * lockfile-backed reverse dependencies. It is a read-only HydraDB projection
 * designed for the Evidence Console's package investigation flow.
 */
export async function registerPackageRoutes(
  app: FastifyInstance,
  options: PackageRoutesOptions,
): Promise<void> {
  const reader = options.packageOverviewReader ??
    new HydraPackageOverviewStore(options.driver);

  app.get<{
    Params: PackageOverviewParams;
    Querystring: PackageOverviewQuerystring;
  }>(
    "/packages/:packageName",
    { schema: GET_PACKAGE_OVERVIEW_ROUTE_SCHEMA },
    async (request, reply) => {
      try {
        const result = await reader.investigate(
          request.params.packageName,
          request.query.limit ?? PACKAGE_OVERVIEW_LIMITS.defaultResults,
        );

        return reply.code(200).send(result);
      } catch (error: unknown) {
        if (error instanceof RangeError) {
          throw new ApiError(
            "INVALID_PACKAGE_OVERVIEW_REQUEST",
            400,
            "The package investigation request is invalid.",
          );
        }

        if (error instanceof PackageOverviewStoreError) {
          request.log.error(
            { err: error, packageName: request.params.packageName },
            "HydraDB package investigation failed",
          );
          throw new ApiError(
            "PACKAGE_OVERVIEW_UNAVAILABLE",
            503,
            "HydraDB could not complete the package investigation.",
          );
        }

        throw error;
      }
    },
  );
}
