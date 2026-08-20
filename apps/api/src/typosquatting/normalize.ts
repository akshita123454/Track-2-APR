import { tokenizePackageName } from "./tokenize.js";
import { COMPARISON_VERSION } from "./types.js";
import type {
  ComparablePackageName,
  PackageNameValidationCode,
} from "./types.js";

const MAX_NPM_NAME_BYTES = 214;
const COMPONENT_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N}._-]*$/u;
const CONTROL_PATTERN = /[\p{Cc}\p{Cf}]/u;

export class PackageNameValidationError extends Error {
  public constructor(
    public readonly code: PackageNameValidationCode,
    message: string,
  ) {
    super(message);
    this.name = "PackageNameValidationError";
  }
}

function validateComponent(value: string, kind: "scope" | "basename"): void {
  const code = kind === "scope" ? "invalid-scope" : "invalid-basename";
  if (value.length === 0 || value === "." || value === "..") {
    throw new PackageNameValidationError(code, `npm ${kind} must not be empty`);
  }
  if (!COMPONENT_PATTERN.test(value)) {
    throw new PackageNameValidationError(
      "invalid-character",
      `npm ${kind} contains an invalid character`,
    );
  }
}

export function normalizePackageName(original: string): ComparablePackageName {
  if (original.length === 0) {
    throw new PackageNameValidationError("empty", "npm package name must not be empty");
  }
  if (CONTROL_PATTERN.test(original)) {
    throw new PackageNameValidationError(
      "control-character",
      "npm package name must not contain control or format characters",
    );
  }
  if (Buffer.byteLength(original, "utf8") > MAX_NPM_NAME_BYTES) {
    throw new PackageNameValidationError(
      "too-long",
      `npm package name must not exceed ${MAX_NPM_NAME_BYTES} UTF-8 bytes`,
    );
  }

  const normalized = original.normalize("NFC").toLocaleLowerCase("en-US");
  let scope: string | undefined;
  let basename = normalized;

  if (normalized.startsWith("@")) {
    const slash = normalized.indexOf("/");
    if (slash <= 1 || normalized.indexOf("/", slash + 1) !== -1) {
      throw new PackageNameValidationError(
        "invalid-scope",
        "scoped npm name must have exactly one non-empty scope and basename",
      );
    }
    scope = normalized.slice(1, slash);
    basename = normalized.slice(slash + 1);
    validateComponent(scope, "scope");
  } else if (normalized.includes("/") || normalized.startsWith(".")) {
    throw new PackageNameValidationError(
      "invalid-basename",
      "unscoped npm name must be a single non-hidden component",
    );
  }

  validateComponent(basename, "basename");
  const tokens = tokenizePackageName(scope, basename);
  const compact = tokenizePackageName(undefined, basename).join("");
  if (compact.length === 0) {
    throw new PackageNameValidationError(
      "invalid-basename",
      "npm package name must contain a letter or number",
    );
  }

  return {
    original,
    normalized,
    ...(scope === undefined ? {} : { scope }),
    basename,
    compact,
    tokens,
    comparisonVersion: COMPARISON_VERSION,
  };
}
