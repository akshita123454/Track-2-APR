import type {
  Driver,
  Session,
} from "neo4j-driver";

import {
  toHydraParameters,
} from "../db/hydra-parameters.js";

const DEFAULT_STATEMENT_TIMEOUT_MS = 10_000;
const MAX_STATEMENT_TIMEOUT_MS = 120_000;
const MAX_CONFIGURED_LIMIT = 500;

/**
 * Upper bound on AFFECTS targets counted per incident.
 *
 * The count is a ranking hint for the index, so a bounded read is preferable
 * to an unbounded one; the blast-radius endpoint remains authoritative.
 */
const MAX_AFFECTS_COUNTED = 5_000;

/**
 * Incident lifecycle states that may appear on a persisted Incident node.
 *
 * This intentionally includes "contained" and "closed", which the creation
 * contract does not return but which are valid later lifecycle states.
 */
const INCIDENT_STATUS_SET = new Set<string>([
  "draft",
  "active",
  "contained",
  "closed",
]);

export type IncidentListStatus =
  | "draft"
  | "active"
  | "contained"
  | "closed";

export interface IncidentListCursor {
  readonly observedAt: number;
  readonly id: number;
}

export interface IncidentListEntry {
  readonly id: number;
  readonly logicalId: string;
  readonly title: string;
  readonly status: IncidentListStatus;
  readonly intervalStart: number;

  /**
   * Null means the compromise interval is still open.
   */
  readonly intervalEnd: number | null;

  /**
   * Count of canonical AFFECTS targets, so the dashboard can rank incidents
   * without running a blast-radius traversal per row.
   */
  readonly affectedVersionCount: number;

  readonly synthetic: boolean;
  readonly observedAt: number;
}

export interface IncidentListPage {
  readonly incidents: readonly IncidentListEntry[];

  /**
   * True when more incidents exist beyond the requested limit.
   */
  readonly truncated: boolean;

  readonly nextCursor: IncidentListCursor | null;
}

export interface ListIncidentsOptions {
  readonly limit: number;
  readonly cursor?: IncidentListCursor;
}

/**
 * Read boundary consumed by GET /incidents.
 *
 * Declared as an interface so routes and smoke tests can inject a
 * deterministic reader without opening a second HydraDB driver.
 */
export interface IncidentListReader {
  listIncidents(
    options: ListIncidentsOptions,
  ): Promise<IncidentListPage>;
}

export type IncidentListStoreErrorCode =
  | "DATABASE_QUERY_FAILED"
  | "DATABASE_RESULT_INVALID"
  | "INCIDENT_LIST_CORRUPT";

export class IncidentListStoreError extends Error {
  public constructor(
    readonly code: IncidentListStoreErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(
      message,
      cause === undefined
        ? undefined
        : { cause },
    );

    this.name = "IncidentListStoreError";
  }
}

interface RecordLike {
  get(key: string): unknown;
}

interface ResultLike {
  readonly records: readonly RecordLike[];
}

/*
 * Cursor paging uses (observed_at, id) descending so the newest incident is
 * first and the ordering is total even when two incidents share a timestamp.
 *
 * $has_cursor gates the comparison instead of relying on NULL ordering
 * semantics, which differ between Cypher implementations.
 */
function buildListIncidentsQuery(
  fetchLimit: number,
): string {
  return [
    "MATCH (incident:Incident)",
    "WHERE $has_cursor = false",
    "   OR incident.observed_at < $cursor_observed_at",
    "   OR (incident.observed_at = $cursor_observed_at",
    "       AND incident.id < $cursor_id)",
    "RETURN incident.id AS incident_vertex,",
    "       incident.logical_id AS incident_logical_id,",
    "       incident.title AS incident_title,",
    "       incident.status AS incident_status,",
    "       incident.interval_start AS incident_interval_start,",
    "       incident.interval_end AS incident_interval_end,",
    "       incident.has_interval_end AS incident_has_interval_end,",
    "       incident.synthetic AS incident_synthetic,",
    "       incident.observed_at AS incident_observed_at",
    "ORDER BY incident_observed_at DESC, incident_vertex DESC",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

/*
 * AFFECTS fan-out is counted from returned pairs rather than a WITH/count
 * aggregation, because HydraDB requires WITH to pass through every in-scope
 * binding and so cannot express the grouped count.
 */
function buildCountAffectsQuery(
  fetchLimit: number,
): string {
  return [
    "MATCH (incident:Incident {id: $incident_id})" +
      "-[affects:AFFECTS]->(version:PackageVersion)",
    "RETURN version.id AS version_vertex",
    "ORDER BY version_vertex",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function assertPositiveInteger(
  value: number,
  field: string,
  maximum: number,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximum
  ) {
    throw new RangeError(
      `${field} must be a positive safe integer ` +
        `not greater than ${maximum}`,
    );
  }
}

function asResultLike(
  value: unknown,
): ResultLike {
  if (
    typeof value !== "object" ||
    value === null ||
    !("records" in value) ||
    !Array.isArray(value.records)
  ) {
    throw new IncidentListStoreError(
      "DATABASE_RESULT_INVALID",
      "HydraDB returned a result without a records array",
    );
  }

  for (const record of value.records) {
    if (
      typeof record !== "object" ||
      record === null ||
      !("get" in record) ||
      typeof record.get !== "function"
    ) {
      throw new IncidentListStoreError(
        "DATABASE_RESULT_INVALID",
        "HydraDB returned an invalid record",
      );
    }
  }

  return value as ResultLike;
}

function asSafeInteger(
  value: unknown,
  field: string,
): number {
  let numberValue: number;

  if (typeof value === "number") {
    numberValue = value;
  } else if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    numberValue =
      (value.toNumber as () => number)();
  } else {
    throw new IncidentListStoreError(
      "INCIDENT_LIST_CORRUPT",
      `Stored ${field} is not an integer`,
    );
  }

  if (
    !Number.isSafeInteger(numberValue) ||
    numberValue < 0
  ) {
    throw new IncidentListStoreError(
      "INCIDENT_LIST_CORRUPT",
      `Stored ${field} is outside the safe nonnegative range`,
    );
  }

  return numberValue;
}

function asNonEmptyString(
  value: unknown,
  field: string,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0
  ) {
    throw new IncidentListStoreError(
      "INCIDENT_LIST_CORRUPT",
      `Stored ${field} is not a nonempty string`,
    );
  }

  return value;
}

function asBoolean(
  value: unknown,
  field: string,
): boolean {
  if (typeof value !== "boolean") {
    throw new IncidentListStoreError(
      "INCIDENT_LIST_CORRUPT",
      `Stored ${field} is not a boolean`,
    );
  }

  return value;
}

function asStatus(
  value: unknown,
): IncidentListStatus {
  const status = asNonEmptyString(
    value,
    "incident.status",
  );

  if (!INCIDENT_STATUS_SET.has(status)) {
    throw new IncidentListStoreError(
      "INCIDENT_LIST_CORRUPT",
      `Stored incident.status has unsupported value ${status}`,
    );
  }

  return status as IncidentListStatus;
}

function readIncident(
  record: RecordLike,
  affectedVersionCount: number,
): IncidentListEntry {
  const hasIntervalEnd = asBoolean(
    record.get("incident_has_interval_end"),
    "incident.has_interval_end",
  );

  const intervalStart = asSafeInteger(
    record.get("incident_interval_start"),
    "incident.interval_start",
  );

  const intervalEnd = hasIntervalEnd
    ? asSafeInteger(
        record.get("incident_interval_end"),
        "incident.interval_end",
      )
    : null;

  if (
    intervalEnd !== null &&
    intervalEnd < intervalStart
  ) {
    throw new IncidentListStoreError(
      "INCIDENT_LIST_CORRUPT",
      "Stored incident interval ends before it starts",
    );
  }

  const logicalId = asNonEmptyString(
    record.get("incident_logical_id"),
    "incident.logical_id",
  );

  if (!logicalId.startsWith("incident:")) {
    throw new IncidentListStoreError(
      "INCIDENT_LIST_CORRUPT",
      "Stored incident.logical_id is not an incident identity",
    );
  }

  return Object.freeze({
    id: asSafeInteger(
      record.get("incident_vertex"),
      "incident.id",
    ),

    logicalId,

    title: asNonEmptyString(
      record.get("incident_title"),
      "incident.title",
    ),

    status: asStatus(
      record.get("incident_status"),
    ),

    intervalStart,
    intervalEnd,

    affectedVersionCount,

    synthetic: asBoolean(
      record.get("incident_synthetic"),
      "incident.synthetic",
    ),

    observedAt: asSafeInteger(
      record.get("incident_observed_at"),
      "incident.observed_at",
    ),
  });
}

export interface HydraIncidentListStoreOptions {
  readonly statementTimeoutMs?: number;
  readonly sessionFactory?: () => Session;
}

/**
 * Bounded HydraDB-backed incident index.
 *
 * This exists so the dashboard can present a real incident list instead of
 * requiring an analyst to already know a numeric incident ID. It performs a
 * single ordered read with LIMIT + 1 and never interpolates caller input.
 */
export class HydraIncidentListStore
  implements IncidentListReader {
  private readonly statementTimeoutMs: number;
  private readonly sessionFactory: () => Session;

  public constructor(
    driver: Driver,
    options:
      HydraIncidentListStoreOptions = {},
  ) {
    this.statementTimeoutMs =
      options.statementTimeoutMs ??
      DEFAULT_STATEMENT_TIMEOUT_MS;

    assertPositiveInteger(
      this.statementTimeoutMs,
      "statementTimeoutMs",
      MAX_STATEMENT_TIMEOUT_MS,
    );

    this.sessionFactory =
      options.sessionFactory ??
      (() => driver.session());
  }

  public async listIncidents(
    options: ListIncidentsOptions,
  ): Promise<IncidentListPage> {
    assertPositiveInteger(
      options.limit,
      "limit",
      MAX_CONFIGURED_LIMIT,
    );

    const cursor = options.cursor;

    if (cursor !== undefined) {
      if (
        !Number.isSafeInteger(
          cursor.observedAt,
        ) ||
        cursor.observedAt < 0 ||
        !Number.isSafeInteger(cursor.id) ||
        cursor.id < 0
      ) {
        throw new RangeError(
          "cursor must contain nonnegative safe integers",
        );
      }
    }

    /*
     * Reading limit + 1 rows detects further pages without a second count
     * query and without ever returning more than the caller asked for.
     */
    const records = await this.runQuery(
      buildListIncidentsQuery(
        options.limit + 1,
      ),
      {
        has_cursor: cursor !== undefined,

        cursor_observed_at:
          cursor?.observedAt ?? 0,

        cursor_id: cursor?.id ?? 0,
      },
      "list-incidents",
    );

    const truncated =
      records.length > options.limit;

    const pageRecords = truncated
      ? records.slice(0, options.limit)
      : records;

    const page: IncidentListEntry[] = [];

    for (const record of pageRecords) {
      const incidentId = asSafeInteger(
        record.get("incident_vertex"),
        "incident.id",
      );

      const affectsRecords =
        await this.runQuery(
          buildCountAffectsQuery(
            MAX_AFFECTS_COUNTED,
          ),
          { incident_id: incidentId },
          "count-incident-affects",
        );

      page.push(
        readIncident(
          record,
          affectsRecords.length,
        ),
      );
    }

    const last =
      page.length === 0
        ? undefined
        : page[page.length - 1];

    return Object.freeze({
      incidents: Object.freeze(page),
      truncated,

      nextCursor:
        truncated && last !== undefined
          ? Object.freeze({
              observedAt: last.observedAt,
              id: last.id,
            })
          : null,
    });
  }

  private async runQuery(
    query: string,
    parameters: Readonly<
      Record<string, unknown>
    >,
    operation: string,
  ): Promise<readonly RecordLike[]> {
    let session: Session;

    try {
      session = this.sessionFactory();
    } catch (error) {
      throw new IncidentListStoreError(
        "DATABASE_QUERY_FAILED",
        `Could not open a HydraDB session for ${operation}`,
        error,
      );
    }

    let result: unknown;

    try {
      result = await session.run(
        query,
        toHydraParameters(parameters),
        {
          timeout: this.statementTimeoutMs,

          metadata: {
            "hydradb.caller.step": operation,
          },
        },
      );
    } catch (error) {
      try {
        await session.close();
      } catch {
        // Preserve the original query failure.
      }

      throw new IncidentListStoreError(
        "DATABASE_QUERY_FAILED",
        `HydraDB operation ${operation} failed`,
        error,
      );
    }

    try {
      await session.close();
    } catch (error) {
      throw new IncidentListStoreError(
        "DATABASE_QUERY_FAILED",
        `HydraDB session close failed after ${operation}`,
        error,
      );
    }

    return asResultLike(result).records;
  }
}
