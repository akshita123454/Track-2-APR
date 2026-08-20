export interface ApiConfig {
  readonly environment:
    | "development"
    | "test"
    | "production";

  readonly host: string;
  readonly port: number;
  readonly bodyLimitBytes: number;
  readonly corsOrigins: readonly string[];
  readonly logging: boolean;

  readonly typosquattingReview: {
    readonly bearerToken: string;
    readonly reviewer: string;
  };

  readonly hydra: {
    readonly uri: string;
    readonly user: string;
    readonly token: string;
  };

  readonly jobs: {
    readonly maxJobs: number;
    readonly maxRunningJobs: number;
    readonly terminalRetentionMs: number;
    readonly activeJobTimeoutMs: number;
    readonly sweepIntervalMs: number;
  };

  readonly workers: {
    readonly maxConcurrentJobs: number;
  };

  readonly npmRegistry: {
    readonly registryUrl: string;
    readonly timeoutMs: number;
    readonly retries: number;
    readonly maxResponseBytes: number;
    readonly concurrency: number;
  };

  readonly persistence: {
    readonly chunkSize: number;
    readonly maxAttempts: number;
    readonly retryDelayMs: number;
    readonly statementTimeoutMs: number;
    readonly maxPartialReplays: number;
    readonly partialReplayDelayMs: number;
  };

  readonly incidents: {
    readonly maxVersionsScannedPerPackage: number;
    readonly affectedEdgeChunkSize: number;
    readonly statementTimeoutMs: number;
  };
}

function readText(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback?: string,
): string {
  const value =
    env[name] ?? fallback;

  if (
    value === undefined ||
    value.trim().length === 0
  ) {
    throw new Error(
      `Missing required environment variable ${name}`,
    );
  }

  return value.trim();
}

function readInteger(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw =
    env[name] ?? String(fallback);

  const value = Number(raw);

  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error(
      `${name} must be an integer between ${minimum} and ${maximum}`,
    );
  }

  return value;
}

function readBoolean(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: boolean,
): boolean {
  const raw =
    env[name]?.trim().toLowerCase();

  if (raw === undefined) {
    return fallback;
  }

  if (
    raw === "true" ||
    raw === "1"
  ) {
    return true;
  }

  if (
    raw === "false" ||
    raw === "0"
  ) {
    return false;
  }

  throw new Error(
    `${name} must be true, false, 1, or 0`,
  );
}

function readEnvironment(
  env: NodeJS.ProcessEnv,
): ApiConfig["environment"] {
  const value =
    env.NODE_ENV ??
    "development";

  if (
    value !== "development" &&
    value !== "test" &&
    value !== "production"
  ) {
    throw new Error(
      "NODE_ENV must be development, test, or production",
    );
  }

  return value;
}

function readAnalystBearerToken(
  env: NodeJS.ProcessEnv,
  environment: ApiConfig["environment"],
): string {
  const token = readText(
    env,
    "TYPOSQUATTING_ANALYST_BEARER_TOKEN",
    environment === "production"
      ? undefined
      : "local-development-analyst-token",
  );

  if (
    token.length < 16 ||
    token.length > 512 ||
    /\s/.test(token)
  ) {
    throw new Error(
      "TYPOSQUATTING_ANALYST_BEARER_TOKEN must contain 16 to 512 non-whitespace characters",
    );
  }

  return token;
}

function readAnalystPrincipal(
  env: NodeJS.ProcessEnv,
): string {
  const reviewer = readText(
    env,
    "TYPOSQUATTING_ANALYST_PRINCIPAL",
    "local-dashboard-analyst",
  );

  if (reviewer.length > 200) {
    throw new Error(
      "TYPOSQUATTING_ANALYST_PRINCIPAL must contain at most 200 characters",
    );
  }

  return reviewer;
}

function readUrl(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: string,
  protocols: readonly string[],
): string {
  const value =
    readText(env, name, fallback);

  let parsed: URL;

  try {
    parsed = new URL(value);
  } catch {
    throw new Error(
      `${name} must be a valid URL`,
    );
  }

  if (
    !protocols.includes(
      parsed.protocol,
    )
  ) {
    throw new Error(
      `${name} must use one of: ${protocols.join(", ")}`,
    );
  }

  return parsed.toString();
}

function readCorsOrigins(
  env: NodeJS.ProcessEnv,
): readonly string[] {
  const raw =
    env.API_CORS_ORIGINS ??
    "http://localhost:5173,http://localhost:8080";

  const origins = [
    ...new Set(
      raw
        .split(",")
        .map((origin) =>
          origin.trim(),
        )
        .filter(Boolean),
    ),
  ];

  if (origins.length === 0) {
    throw new Error(
      "API_CORS_ORIGINS must contain at least one origin",
    );
  }

  for (const origin of origins) {
    if (origin === "*") {
      continue;
    }

    try {
      const parsed =
        new URL(origin);

      if (
        parsed.protocol !== "http:" &&
        parsed.protocol !== "https:"
      ) {
        throw new Error();
      }
    } catch {
      throw new Error(
        `Invalid CORS origin: ${origin}`,
      );
    }
  }

  return Object.freeze(origins);
}

export function loadApiConfig(
  env: NodeJS.ProcessEnv =
    process.env,
): ApiConfig {
  const environment =
    readEnvironment(env);
  const maxJobs =
    readInteger(
      env,
      "API_MAX_JOBS",
      1_000,
      1,
      10_000,
    );

  const maxRunningJobs =
    readInteger(
      env,
      "API_MAX_RUNNING_JOBS",
      4,
      1,
      1_000,
    );

  const maxConcurrentJobs =
    readInteger(
      env,
      "API_WORKER_CONCURRENCY",
      Math.min(
        4,
        maxRunningJobs,
      ),
      1,
      maxRunningJobs,
    );

  if (
    maxRunningJobs >
    maxJobs
  ) {
    throw new Error(
      "API_MAX_RUNNING_JOBS cannot exceed API_MAX_JOBS",
    );
  }

  return Object.freeze({
    environment,

    host:
      readText(
        env,
        "API_HOST",
        "127.0.0.1",
      ),

    port:
      readInteger(
        env,
        "API_PORT",
        3000,
        1,
        65_535,
      ),

    bodyLimitBytes:
      readInteger(
        env,
        "API_BODY_LIMIT_BYTES",
        12 * 1024 * 1024,
        1_024,
        50 * 1024 * 1024,
      ),

    corsOrigins:
      readCorsOrigins(env),

    logging:
      readBoolean(
        env,
        "API_LOGGING",
        true,
      ),

    typosquattingReview:
      Object.freeze({
        bearerToken:
          readAnalystBearerToken(
            env,
            environment,
          ),
        reviewer:
          readAnalystPrincipal(env),
      }),

    hydra: Object.freeze({
      uri:
        readUrl(
          env,
          "HYDRADB_URI",
          "bolt://127.0.0.1:27687",
          [
            "bolt:",
            "neo4j:",
            "neo4j+s:",
            "neo4j+ssc:",
          ],
        ),

      user:
        readText(
          env,
          "HYDRADB_USER",
          "neo4j",
        ),

      token:
        readText(
          env,
          "HYDRADB_TOKEN",
          "local-development-token-32-bytes",
        ),
    }),

    jobs: Object.freeze({
      maxJobs,
      maxRunningJobs,

      terminalRetentionMs:
        readInteger(
          env,
          "API_JOB_RETENTION_MS",
          60 * 60_000,
          1_000,
          7 * 24 * 60 * 60_000,
        ),

      activeJobTimeoutMs:
        readInteger(
          env,
          "API_JOB_TIMEOUT_MS",
          15 * 60_000,
          1_000,
          24 * 60 * 60_000,
        ),

      sweepIntervalMs:
        readInteger(
          env,
          "API_JOB_SWEEP_INTERVAL_MS",
          30_000,
          0,
          60 * 60_000,
        ),
    }),

    workers: Object.freeze({
      maxConcurrentJobs,
    }),

    npmRegistry: Object.freeze({
      registryUrl:
        readUrl(
          env,
          "NPM_REGISTRY_URL",
          "https://registry.npmjs.org",
          ["https:"],
        ),

      timeoutMs:
        readInteger(
          env,
          "NPM_REGISTRY_TIMEOUT_MS",
          10_000,
          100,
          120_000,
        ),

      retries:
        readInteger(
          env,
          "NPM_REGISTRY_RETRIES",
          2,
          0,
          10,
        ),

      maxResponseBytes:
        readInteger(
          env,
          "NPM_REGISTRY_MAX_RESPONSE_BYTES",
          10 * 1024 * 1024,
          1_024,
          50 * 1024 * 1024,
        ),

      concurrency:
        readInteger(
          env,
          "NPM_REGISTRY_CONCURRENCY",
          4,
          1,
          20,
        ),
    }),

    persistence: Object.freeze({
      chunkSize:
        readInteger(
          env,
          "HYDRA_WRITE_CHUNK_SIZE",
          250,
          1,
          10_000,
        ),

      maxAttempts:
        readInteger(
          env,
          "HYDRA_WRITE_MAX_ATTEMPTS",
          3,
          1,
          10,
        ),

      retryDelayMs:
        readInteger(
          env,
          "HYDRA_WRITE_RETRY_DELAY_MS",
          100,
          0,
          60_000,
        ),

      statementTimeoutMs:
        readInteger(
          env,
          "HYDRA_STATEMENT_TIMEOUT_MS",
          20_000,
          100,
          600_000,
        ),

      maxPartialReplays:
        readInteger(
          env,
          "HYDRA_MAX_PARTIAL_REPLAYS",
          2,
          0,
          10,
        ),

      partialReplayDelayMs:
        readInteger(
          env,
          "HYDRA_PARTIAL_REPLAY_DELAY_MS",
          100,
          0,
          60_000,
        ),
    }),

    incidents: Object.freeze({
      maxVersionsScannedPerPackage:
        readInteger(
          env,
          "INCIDENT_MAX_VERSIONS_SCANNED",
          10_000,
          1,
          50_000,
        ),

      affectedEdgeChunkSize:
        readInteger(
          env,
          "INCIDENT_EDGE_CHUNK_SIZE",
          250,
          1,
          5_000,
        ),

      statementTimeoutMs:
        readInteger(
          env,
          "INCIDENT_STATEMENT_TIMEOUT_MS",
          20_000,
          100,
          600_000,
        ),
    }),
  });
}
