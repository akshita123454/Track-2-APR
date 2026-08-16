import { createHash } from "node:crypto";
import type { GraphRelKind } from "./schema.js";

const MAX_SAFE_ID = (1n << 53n) - 1n;

export interface EntityIdentity {
  readonly id: number;
  readonly logicalId: string;
}

export interface EdgeIdentityInput {
  readonly kind: GraphRelKind;
  readonly sourceLogicalId: string;
  readonly targetLogicalId: string;

  /**
   * Distinguishes multiple edges of the same kind between the same
   * endpoints, for example separate workspace lockfile paths.
   */
  readonly discriminator?: string;
}

export class IdentityCollisionError extends Error {
  constructor(
    readonly id: number,
    readonly existingLogicalId: string,
    readonly incomingLogicalId: string,
  ) {
    super(
      `Identity collision for ID ${id}: ` +
        `"${existingLogicalId}" conflicts with "${incomingLogicalId}"`,
    );

    this.name = "IdentityCollisionError";
  }
}

export function normalizeLogicalId(logicalId: string): string {
  const normalized = logicalId.normalize("NFC");

  if (normalized.length === 0) {
    throw new Error("Logical ID must not be empty");
  }

  if (normalized.trim() !== normalized) {
    throw new Error(
      `Logical ID must not contain leading or trailing whitespace: "${logicalId}"`,
    );
  }

  if (!/^[a-z][a-z0-9-]*:/.test(normalized)) {
    throw new Error(
      `Logical ID must begin with a lowercase namespace, such as ` +
        `"pkg:", "service:", or "rel:": "${logicalId}"`,
    );
  }

  return normalized;
}

/**
 * Deterministically maps a canonical string into the complete
 * nonnegative 53-bit safe-integer range.
 *
 * Truncating a hash can produce collisions, so callers must also use
 * IdentityRegistry and verify existing HydraDB logicalId properties.
 */
export function generateDeterministicId(logicalId: string): number {
  const normalized = normalizeLogicalId(logicalId);

  const digest = createHash("sha256")
    .update(normalized, "utf8")
    .digest();

  /*
   * Read 64 hash bits and retain 53 bits.
   *
   * Result range:
   * 0 through Number.MAX_SAFE_INTEGER (2^53 - 1)
   */
  const truncated = digest.readBigUInt64BE(0) & MAX_SAFE_ID;
  const id = Number(truncated);

  if (!Number.isSafeInteger(id) || id < 0) {
    throw new Error(`Generated unsafe ID for logical identity "${normalized}"`);
  }

  return id;
}

export function createEntityIdentity(logicalId: string): EntityIdentity {
  const normalized = normalizeLogicalId(logicalId);

  return {
    id: generateDeterministicId(normalized),
    logicalId: normalized,
  };
}

/**
 * Uses JSON tuple encoding so separators inside package names or
 * logical IDs cannot make two different edge identities ambiguous.
 */
export function createEdgeIdentity(
  input: EdgeIdentityInput,
): EntityIdentity {
  const sourceLogicalId = normalizeLogicalId(input.sourceLogicalId);
  const targetLogicalId = normalizeLogicalId(input.targetLogicalId);
  const discriminator = input.discriminator ?? "default";

  const tuple = JSON.stringify([
    "edge",
    input.kind,
    sourceLogicalId,
    targetLogicalId,
    discriminator,
  ]);

  const logicalId = `rel:${tuple}`;

  return {
    logicalId,
    id: generateDeterministicId(logicalId),
  };
}

/**
 * A derived edge identity is tied to the canonical edge identity,
 * rather than independently representing security evidence.
 */
export function createDerivedEdgeIdentity(
  canonicalEdgeLogicalId: string,
): EntityIdentity {
  const canonical = normalizeLogicalId(canonicalEdgeLogicalId);
  const tuple = JSON.stringify(["derived-edge", "USED_BY", canonical]);
  const logicalId = `rel-derived:${tuple}`;

  return {
    logicalId,
    id: generateDeterministicId(logicalId),
  };
}

/**
 * Tracks collisions within one ingestion process.
 *
 * During database ingestion, call registerKnown() for identities read
 * from HydraDB before attempting an upsert. This catches collisions
 * across separate ingestion runs as well.
 */
export class IdentityRegistry {
  private readonly logicalIdById = new Map<number, string>();
  private readonly idByLogicalId = new Map<string, number>();

  register(logicalId: string): EntityIdentity {
    const identity = createEntityIdentity(logicalId);
    this.registerKnown(identity.id, identity.logicalId);
    return identity;
  }

  registerKnown(id: number, logicalId: string): void {
    const normalized = normalizeLogicalId(logicalId);

    if (!Number.isSafeInteger(id) || id < 0) {
      throw new Error(`ID must be a nonnegative safe integer: ${id}`);
    }

    const expectedId = generateDeterministicId(normalized);

    if (id !== expectedId) {
      throw new Error(
        `ID ${id} does not match deterministic ID ${expectedId} ` +
          `for "${normalized}"`,
      );
    }

    const existingLogicalId = this.logicalIdById.get(id);

    if (
      existingLogicalId !== undefined &&
      existingLogicalId !== normalized
    ) {
      throw new IdentityCollisionError(
        id,
        existingLogicalId,
        normalized,
      );
    }

    const existingId = this.idByLogicalId.get(normalized);

    if (existingId !== undefined && existingId !== id) {
      throw new Error(
        `Logical identity "${normalized}" was registered with both ` +
          `${existingId} and ${id}`,
      );
    }

    this.logicalIdById.set(id, normalized);
    this.idByLogicalId.set(normalized, id);
  }

  get size(): number {
    return this.logicalIdById.size;
  }
}
