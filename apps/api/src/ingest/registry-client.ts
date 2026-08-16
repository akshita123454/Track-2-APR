import { createHash } from "node:crypto";

import {
  parseNpmRegistryPackage,
} from "./registry-types.js";

import type {
  NpmRegistryFetchResult,
} from "./registry-types.js";

const DEFAULT_REGISTRY_URL = "https://registry.npmjs.org";
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_RETRIES = 2;
const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

export interface RegistryFetchOptions {
  readonly registryUrl?: string;
  readonly timeoutMs?: number;
  readonly retries?: number;
  readonly maxResponseBytes?: number;
}

export class NpmRegistryError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly retryable: boolean = false,
  ) {
    super(message);
    this.name = "NpmRegistryError";
  }
}

function validatePackageName(packageName: string): void {
  if (
    packageName.length === 0 ||
    packageName.length > 214 ||
    packageName.trim() !== packageName ||
    /[\s\\?#]/.test(packageName)
  ) {
    throw new Error(`Invalid npm package name: "${packageName}"`);
  }

  const parts = packageName.split("/");

  if (
    parts.length > 2 ||
    (parts.length === 2 && !parts[0].startsWith("@"))
  ) {
    throw new Error(`Invalid npm package name: "${packageName}"`);
  }
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function retryDelay(
  response: Response,
  attempt: number,
): number {
  const retryAfter = response.headers.get("retry-after");

  if (retryAfter !== null) {
    const seconds = Number(retryAfter);

    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds * 1_000, 30_000);
    }

    const date = Date.parse(retryAfter);

    if (Number.isFinite(date)) {
      return Math.min(Math.max(date - Date.now(), 0), 30_000);
    }
  }

  return Math.min(500 * 2 ** attempt, 5_000);
}

export async function fetchPackageMetadata(
  packageName: string,
  options: RegistryFetchOptions = {},
): Promise<NpmRegistryFetchResult> {
  validatePackageName(packageName);

  const registryUrl =
    options.registryUrl ?? DEFAULT_REGISTRY_URL;

  const timeoutMs =
    options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const retries =
    options.retries ?? DEFAULT_RETRIES;

  const maxResponseBytes =
    options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;

  if (timeoutMs <= 0 || retries < 0 || maxResponseBytes <= 0) {
    throw new Error("Invalid npm registry client options");
  }

  const url = new URL(
    encodeURIComponent(packageName),
    `${registryUrl.replace(/\/+$/, "")}/`,
  );

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const response = await fetch(url, {
        headers: {
          Accept: "application/vnd.npm.install-v1+json",
          "User-Agent": "HydraGuard/0.1.0",
        },
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!response.ok) {
        const retryable =
          response.status === 429 || response.status >= 500;

        if (retryable && attempt < retries) {
          const delay = retryDelay(response, attempt);
          await response.body?.cancel();
          await sleep(delay);
          continue;
        }

        if (response.status === 404) {
          throw new NpmRegistryError(
            `Package not found on npm: ${packageName}`,
            404,
            false,
          );
        }

        throw new NpmRegistryError(
          `npm registry error for ${packageName}: ` +
            `${response.status} ${response.statusText}`,
          response.status,
          retryable,
        );
      }

      const contentLength = Number(
        response.headers.get("content-length"),
      );

      if (
        Number.isFinite(contentLength) &&
        contentLength > maxResponseBytes
      ) {
        await response.body?.cancel();

        throw new NpmRegistryError(
          `npm metadata for ${packageName} exceeds ` +
            `${maxResponseBytes} bytes`,
          response.status,
          false,
        );
      }

      const body = await response.text();
      const actualBytes = Buffer.byteLength(body, "utf8");

      if (actualBytes > maxResponseBytes) {
        throw new NpmRegistryError(
          `npm metadata for ${packageName} exceeds ` +
            `${maxResponseBytes} bytes`,
          response.status,
          false,
        );
      }

      let rawValue: unknown;

      try {
        rawValue = JSON.parse(body) as unknown;
      } catch {
        throw new NpmRegistryError(
          `npm returned invalid JSON for ${packageName}`,
          response.status,
          false,
        );
      }

      let metadata;

      try {
        metadata = parseNpmRegistryPackage(rawValue);
      } catch (error) {
        const message =
          error instanceof Error ? error.message : String(error);

        throw new NpmRegistryError(
          `Invalid npm metadata for ${packageName}: ${message}`,
          response.status,
          false,
        );
      }

      return {
        metadata,
        sourceUri: url.toString(),
        observedAt: Date.now(),
        contentSha256: createHash("sha256")
          .update(body, "utf8")
          .digest("hex"),
        ...(response.headers.get("etag") === null
          ? {}
          : { etag: response.headers.get("etag")! }),
        ...(response.headers.get("last-modified") === null
          ? {}
          : {
              lastModified:
                response.headers.get("last-modified")!,
            }),
      };
    } catch (error) {
      const retryable =
        !(error instanceof NpmRegistryError) ||
        error.retryable;

      if (!retryable || attempt >= retries) {
        throw error;
      }

      await sleep(Math.min(500 * 2 ** attempt, 5_000));
    }
  }

  throw new Error(
    `npm registry request ended unexpectedly for ${packageName}`,
  );
}
