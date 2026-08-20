import type {
  ReleaseFirewallOptions,
  ReleaseFirewallResult,
} from "./release-influence-types.js";
import {
  evaluateReleaseFirewall,
} from "./release-influence-firewall.js";
import type {
  PersistedReleaseInfluenceSnapshot,
} from "./hydra-release-influence-store.js";

export interface ReleaseInfluenceSnapshotReader {
  readSnapshot(
    snapshotId: string,
  ): Promise<PersistedReleaseInfluenceSnapshot>;
}

export interface PersistedReleaseFirewallResult {
  readonly snapshotId: string;
  readonly persistedAt: number;
  readonly firewall: ReleaseFirewallResult;
  readonly consistencyModel: "verified-release-influence-snapshot";
  readonly engine: "HydraDB";
}

export async function runPersistedReleaseFirewall(
  reader: ReleaseInfluenceSnapshotReader,
  snapshotId: string,
  options: ReleaseFirewallOptions = {},
): Promise<PersistedReleaseFirewallResult> {
  const snapshot = await reader.readSnapshot(snapshotId);

  if (snapshot.snapshotId !== snapshotId) {
    throw new Error(
      "Release influence reader returned a mismatched snapshot identity",
    );
  }

  return Object.freeze({
    snapshotId,
    persistedAt: snapshot.persistedAt,
    firewall: evaluateReleaseFirewall(
      snapshot.input,
      options,
    ),
    consistencyModel:
      "verified-release-influence-snapshot" as const,
    engine: "HydraDB" as const,
  });
}
