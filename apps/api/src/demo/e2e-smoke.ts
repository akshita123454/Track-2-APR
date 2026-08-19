import assert from "node:assert/strict";

import {
  bootstrapDemo,
} from "./preload.js";

import {
  createHydraDriver,
} from "../hydra-client.js";

import {
  buildServer,
} from "../api/server.js";

async function main(): Promise<void> {
  const demo =
    await bootstrapDemo();

  const driver =
    await createHydraDriver();

  try {
    const runtime =
      await buildServer({
        driver,
      });

    try {
      const response =
        await runtime.app.inject({
          method: "GET",
          url:
            `/incidents/` +
            `${demo.incident.incidentId}` +
            `/blast-radius`,
        });

      assert.equal(
        response.statusCode,
        200,
        response.body,
      );

      const body =
        response.json() as {
          incident: {
            id: number;
          };

          affectedVersions:
            Array<{
              packageName: string;
              version: string;
            }>;

          services:
            readonly unknown[];
        };

      assert.equal(
        body.incident.id,
        demo.incident.incidentId,
      );

      assert.ok(
        body.affectedVersions.some(
          (version) =>
            version.packageName ===
              "bad-lib" &&
            version.version ===
              "1.2.4",
        ),
      );

      console.log(
        "HydraGuard Phase 10 E2E passed",
      );

      console.log(
        `Incident ID: ${demo.incident.incidentId}`,
      );

      console.log(
        `Dashboard: ${demo.dashboardUrl}`,
      );
    } finally {
      await runtime.app.close();
    }
  } finally {
    await driver.close();
  }
}

await main();
