export const HYDRA_PERSISTENCE_PHASES = [
  "validate-serialize",
  "preflight-identities",
  "upsert-nodes",
  "upsert-canonical-edges",
  "upsert-derived-edges",
  "verify",
] as const;

export type HydraPersistencePhase =
  (typeof HYDRA_PERSISTENCE_PHASES)[number];

export type PersistencePhaseStatus =
  | "succeeded"
  | "failed"
  | "skipped";

export type PersistenceStatus =
  | "succeeded"
  | "failed"
  | "partial";

export interface PersistenceFailure {
  readonly phase: HydraPersistencePhase;
  readonly code: string;

  /**
   * Intentionally excludes query parameters and serialized graph rows.
   */
  readonly message: string;

  readonly retryable: boolean;
  readonly queryShapeId?: string;
  readonly chunkIndex?: number;
  readonly attempts?: number;
  readonly causeName?: string;
  readonly causeCode?: string;
}

export interface PersistencePhaseResult {
  readonly phase: HydraPersistencePhase;
  readonly status: PersistencePhaseStatus;
  readonly rowsPlanned: number;
  readonly rowsProcessed: number;
  readonly statementsAttempted: number;
  readonly statementsSucceeded: number;
  readonly retries: number;
  readonly durationMs: number;
  readonly queryShapeIds: readonly string[];
  readonly failure?: PersistenceFailure;
}

export interface PersistenceMetadata {
  readonly correlationId: string;
  readonly idempotencyBaseKey?: string;
  readonly batchHash?: string;
  readonly schemaVersion?: number;

  /**
   * Always false because HydraDB Bolt does not expose explicit
   * multi-statement transactions.
   */
  readonly atomic: false;

  readonly guardedUpserts: boolean;
  readonly verificationRequested: boolean;
}

export interface PersistenceTotals {
  readonly nodesPlanned: number;
  readonly canonicalEdgesPlanned: number;
  readonly derivedEdgesPlanned: number;
  readonly rowsPlanned: number;
  readonly rowsSubmitted: number;
  readonly mutationStatementsSucceeded: number;
}

export interface PersistenceResult {
  readonly ok: boolean;
  readonly status: PersistenceStatus;

  /**
   * True when one or more durable mutation statements may have
   * completed before a later phase failed.
   */
  readonly partialWrites: boolean;

  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;

  readonly metadata: PersistenceMetadata;
  readonly totals: PersistenceTotals;
  readonly phases: readonly PersistencePhaseResult[];
  readonly failure?: PersistenceFailure;
}
