import type {
  NodeId,
  UnixEpochMilliseconds,
} from "../../domain/schema.js";

/**
 * Whether a dependency resolution was in force while a compromise interval
 * was open.
 *
 * "unknown-window" is a first-class outcome. A resolution with no recorded
 * validity cannot be shown to be outside the window, so it must never be
 * folded into "outside" and presented as safe.
 */
export type WindowOverlap =
  | "resolved-during-window"
  | "resolved-outside-window"
  | "unknown-window";

export interface ResolutionWindow {
  /**
   * Absent means the resolution window was never recorded.
   */
  readonly validFrom?: UnixEpochMilliseconds;

  /**
   * Absent means the resolution is still current.
   */
  readonly validUntil?: UnixEpochMilliseconds;
}

export interface IncidentWindow {
  readonly intervalStart: UnixEpochMilliseconds;

  /**
   * Null means the compromise interval is still open.
   */
  readonly intervalEnd:
    UnixEpochMilliseconds | null;
}

export interface WindowClassification {
  readonly overlap: WindowOverlap;

  /**
   * Analyst-facing justification. Always populated.
   */
  readonly reason: string;

  /**
   * Evidence supporting the resolution window itself.
   *
   * Empty for "unknown-window", because no evidence established a window.
   */
  readonly evidenceIds: readonly NodeId[];
}

export type TemporalWindowErrorCode =
  | "INVALID_INCIDENT_WINDOW"
  | "INVALID_RESOLUTION_WINDOW";

export class TemporalWindowError extends Error {
  public constructor(
    readonly code: TemporalWindowErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "TemporalWindowError";
  }
}

function isValidEpoch(
  value: number,
): boolean {
  return (
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function assertIncidentWindow(
  incident: IncidentWindow,
): void {
  if (!isValidEpoch(incident.intervalStart)) {
    throw new TemporalWindowError(
      "INVALID_INCIDENT_WINDOW",
      "intervalStart must be a nonnegative safe integer epoch",
    );
  }

  if (incident.intervalEnd !== null) {
    if (!isValidEpoch(incident.intervalEnd)) {
      throw new TemporalWindowError(
        "INVALID_INCIDENT_WINDOW",
        "intervalEnd must be null or a nonnegative safe integer epoch",
      );
    }

    if (
      incident.intervalEnd <
      incident.intervalStart
    ) {
      throw new TemporalWindowError(
        "INVALID_INCIDENT_WINDOW",
        "intervalEnd must not precede intervalStart",
      );
    }
  }
}

function assertResolutionWindow(
  resolution: ResolutionWindow,
): void {
  if (
    resolution.validFrom !== undefined &&
    !isValidEpoch(resolution.validFrom)
  ) {
    throw new TemporalWindowError(
      "INVALID_RESOLUTION_WINDOW",
      "validFrom must be a nonnegative safe integer epoch",
    );
  }

  if (resolution.validUntil !== undefined) {
    if (!isValidEpoch(resolution.validUntil)) {
      throw new TemporalWindowError(
        "INVALID_RESOLUTION_WINDOW",
        "validUntil must be a nonnegative safe integer epoch",
      );
    }

    /*
     * A closing timestamp with no opening timestamp cannot be positioned on
     * the time axis, and silently treating it as unknown would look
     * temporally precise while being meaningless.
     */
    if (resolution.validFrom === undefined) {
      throw new TemporalWindowError(
        "INVALID_RESOLUTION_WINDOW",
        "validUntil requires validFrom",
      );
    }

    if (
      resolution.validUntil <
      resolution.validFrom
    ) {
      throw new TemporalWindowError(
        "INVALID_RESOLUTION_WINDOW",
        "validUntil must not precede validFrom",
      );
    }
  }
}

function describeInstant(
  value: number,
): string {
  return new Date(value).toISOString();
}

function describeInterval(
  start: number,
  end: number | null,
): string {
  return end === null
    ? `${describeInstant(start)} onward`
    : `${describeInstant(start)} to ${describeInstant(end)}`;
}

/**
 * Classifies one resolution against one compromise interval.
 *
 * Both intervals are treated as inclusive of their endpoints. A resolution
 * that was in force at the exact instant the compromise opened or closed is
 * therefore reported as overlapping: when the boundary is ambiguous the
 * defender-safe answer is to surface the exposure, not hide it.
 */
export function classifyWindowOverlap(
  resolution: ResolutionWindow,
  incident: IncidentWindow,
  evidenceIds: readonly NodeId[] = [],
): WindowClassification {
  assertIncidentWindow(incident);
  assertResolutionWindow(resolution);

  if (resolution.validFrom === undefined) {
    return Object.freeze({
      overlap: "unknown-window" as const,

      reason:
        "No lockfile snapshot validity was recorded for this resolution, " +
        "so it cannot be placed inside or outside the compromise interval.",

      evidenceIds: Object.freeze([]),
    });
  }

  const resolutionStart = resolution.validFrom;

  const resolutionEnd =
    resolution.validUntil ??
    Number.POSITIVE_INFINITY;

  const incidentStart = incident.intervalStart;

  const incidentEnd =
    incident.intervalEnd ??
    Number.POSITIVE_INFINITY;

  const latestStart = Math.max(
    resolutionStart,
    incidentStart,
  );

  const earliestEnd = Math.min(
    resolutionEnd,
    incidentEnd,
  );

  const uniqueEvidenceIds = Object.freeze(
    [...new Set(evidenceIds)].sort(
      (left, right) => left - right,
    ),
  );

  if (latestStart <= earliestEnd) {
    return Object.freeze({
      overlap:
        "resolved-during-window" as const,

      reason:
        `The resolution was in force ` +
        `${describeInterval(
          resolutionStart,
          resolution.validUntil ?? null,
        )}, which overlaps the compromise interval ` +
        `${describeInterval(
          incidentStart,
          incident.intervalEnd,
        )}.`,

      evidenceIds: uniqueEvidenceIds,
    });
  }

  return Object.freeze({
    overlap:
      "resolved-outside-window" as const,

    reason:
      `The resolution was in force ` +
      `${describeInterval(
        resolutionStart,
        resolution.validUntil ?? null,
      )}, which does not overlap the compromise interval ` +
      `${describeInterval(
        incidentStart,
        incident.intervalEnd,
      )}.`,

    evidenceIds: uniqueEvidenceIds,
  });
}

export interface WindowPartitionEntry<T> {
  readonly subject: T;
  readonly classification: WindowClassification;
}

export interface WindowPartition<T> {
  readonly resolvedDuringWindow:
    readonly WindowPartitionEntry<T>[];

  readonly resolvedOutsideWindow:
    readonly WindowPartitionEntry<T>[];

  readonly unknownWindow:
    readonly WindowPartitionEntry<T>[];

  /**
   * True when at least one subject could not be placed on the time axis.
   *
   * Callers must surface this rather than reporting a clean partition.
   */
  readonly hasUnknown: boolean;
}

/**
 * Partitions many subjects into the three temporal outcomes.
 *
 * Ordering within each bucket follows input order so results stay
 * deterministic for a deterministic caller.
 */
export function partitionByWindow<T>(
  subjects: readonly T[],
  incident: IncidentWindow,
  describe: (subject: T) => {
    readonly resolution: ResolutionWindow;
    readonly evidenceIds?: readonly NodeId[];
  },
): WindowPartition<T> {
  assertIncidentWindow(incident);

  const resolvedDuringWindow:
    WindowPartitionEntry<T>[] = [];
  const resolvedOutsideWindow:
    WindowPartitionEntry<T>[] = [];
  const unknownWindow:
    WindowPartitionEntry<T>[] = [];

  for (const subject of subjects) {
    const described = describe(subject);

    const classification =
      classifyWindowOverlap(
        described.resolution,
        incident,
        described.evidenceIds ?? [],
      );

    const entry = Object.freeze({
      subject,
      classification,
    });

    if (
      classification.overlap ===
      "resolved-during-window"
    ) {
      resolvedDuringWindow.push(entry);
    } else if (
      classification.overlap ===
      "resolved-outside-window"
    ) {
      resolvedOutsideWindow.push(entry);
    } else {
      unknownWindow.push(entry);
    }
  }

  return Object.freeze({
    resolvedDuringWindow: Object.freeze(
      resolvedDuringWindow,
    ),
    resolvedOutsideWindow: Object.freeze(
      resolvedOutsideWindow,
    ),
    unknownWindow: Object.freeze(
      unknownWindow,
    ),
    hasUnknown: unknownWindow.length > 0,
  });
}
