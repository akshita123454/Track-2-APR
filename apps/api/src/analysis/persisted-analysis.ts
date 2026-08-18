import type {
  PersistedGraphBatch,
} from "../db/persistence-service.js";
import type {
  NodeId,
} from "../domain/schema.js";
import {
  analyzeBlastRadius,
} from "./core/blast-radius.js";
import type {
  BlastRadiusOptions,
  BlastRadiusResult,
} from "./core/analysis-types.js";
import {
  GraphBatchReader,
} from "./readers/graph-batch-reader.js";

/**
 * Blast-radius output linked to the verified persistence operation that
 * authorized analysis.
 */
export interface PersistedBlastRadiusResult
  extends BlastRadiusResult {
  readonly batchHash: string;
  readonly correlationId: string;
}

/**
 * Production blast-radius entry point.
 *
 * The branded PersistedGraphBatch capability can only be constructed by
 * HydraPersistenceService after the immutable GraphBatch has been persisted
 * and verification has succeeded.
 *
 * Pure analyzeBlastRadius remains available only through its internal core
 * module for deterministic fixtures and focused testing.
 */
export async function runBlastRadius(
  persisted: PersistedGraphBatch,
  affectedVersionIds: readonly NodeId[],
  options: BlastRadiusOptions = {},
): Promise<PersistedBlastRadiusResult> {
  /*
   * The caller cannot inject a reader for another graph. Analysis is
   * constructed from the exact immutable batch that persistence verified.
   */
  const reader =
    new GraphBatchReader(persisted.batch);

  const result = await analyzeBlastRadius(
    reader,
    affectedVersionIds,
    options,
  );

  return {
    ...result,
    batchHash: persisted.batchHash,
    correlationId: persisted.correlationId,
  };
}
