import {
  buildServer,
} from "./server.js";

import {
  loadApiConfig,
} from "./config.js";

async function main(): Promise<void> {
  const config =
    loadApiConfig();

  const runtime =
    await buildServer({
      config,
    });

  let shutdown:
    Promise<void> | undefined;

  const stop = (
    signal: NodeJS.Signals,
  ): Promise<void> => {
    if (
      shutdown !== undefined
    ) {
      return shutdown;
    }

    runtime.app.log.info(
      {
        signal,
      },
      "Shutting down HydraGuard API",
    );

    shutdown =
      runtime.app.close();

    return shutdown;
  };

  process.once(
    "SIGINT",
    () => {
      void stop("SIGINT");
    },
  );

  process.once(
    "SIGTERM",
    () => {
      void stop("SIGTERM");
    },
  );

  await runtime.app.listen({
    host: config.host,
    port: config.port,
  });
}

try {
  await main();
} catch (error: unknown) {
  console.error(
    "HydraGuard API startup failed",
    error,
  );

  process.exitCode = 1;
}
