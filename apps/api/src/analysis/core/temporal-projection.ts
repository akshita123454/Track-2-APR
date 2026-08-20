import {
  partitionByWindow,
} from "./temporal-window.js";

import type {
  IncidentWindow,
  WindowOverlap,
} from "./temporal-window.js";

import type {
  BlastRadiusResult,
  BlastRadiusServiceCandidate,
} from "./analysis-types.js";

import type {
  NodeId,
  UnixEpochMilliseconds,
} from "../../domain/schema.js";

/**
 * Temporal standing of one service against the compromise interval.
 */
export interface ServiceWindowAssessment {
  readonly serviceId: NodeId;
  readonly serviceName: string;
  readonly overlap: WindowOverlap;
  readonly reason: string;

  /**
   * Evidence supporting the resolution windows that produced this verdict.
   */
  readonly evidenceIds: readonly NodeId[];

  /**
   * Earliest recorded opening instant across the service's paths, when any
   * path recorded one.
   */
  readonly earliestValidFrom?: UnixEpochMilliseconds;

  /**
   * Latest recorded closing instant, absent when at least one contributing
   * resolution is still current.
   */
  readonly latestValidUntil?: UnixEpochMilliseconds;
}

export interface TemporalWindowResult {
  /**
   * Instant the traversal was restricted to, when the caller supplied one.
   */
  readonly asOf: UnixEpochMilliseconds | null;

  readonly incidentInterval: {
    readonly intervalStart: UnixEpochMilliseconds;
    readonly intervalEnd:
      UnixEpochMilliseconds | null;
  };

  readonly resolvedDuringWindow:
    readonly ServiceWindowAssessment[];

  readonly resolvedOutsideWindow:
    readonly ServiceWindowAssessment[];

  readonly unknownWindow:
    readonly ServiceWindowAssessment[];

  /**
   * True when at least one service could not be placed on the time axis.
   *
   * Consumers must present this rather than implying a clean partition.
   */
  readonly hasUnknown: boolean;

  /**
   * True when lockfile history is complete enough to answer the question for
   * every returned service.
   */
  readonly complete: boolean;

  readonly limitations: readonly string[];
}

interface ServiceWindowInput {
  readonly candidate: BlastRadiusServiceCandidate;
  readonly validFrom?: UnixEpochMilliseconds;
  readonly validUntil?: UnixEpochMilliseconds;
  readonly evidenceIds: readonly NodeId[];
  readonly pathsWithoutValidity: number;
  readonly pathCount: number;
}

/*
 * A service is placed on the time axis using the widest interval its paths
 * recorded: the earliest opening instant and, only if every contributing
 * resolution is closed, the latest closing instant.
 *
 * Widening is deliberate. A service exposed by any path during the window is
 * exposed, so narrowing would understate reach.
 */
function summarizeCandidate(
  candidate: BlastRadiusServiceCandidate,
): ServiceWindowInput {
  let earliestValidFrom:
    | UnixEpochMilliseconds
    | undefined;

  let latestValidUntil:
    | UnixEpochMilliseconds
    | undefined;

  let anyStillOpen = false;
  let pathsWithoutValidity = 0;

  const evidenceIds = new Set<NodeId>();

  for (const path of candidate.paths) {
    let pathValidFrom:
      | UnixEpochMilliseconds
      | undefined;

    let pathValidUntil:
      | UnixEpochMilliseconds
      | undefined;

    let pathClosed = false;
    let pathHasValidity = false;

    for (const edge of path.canonicalEdges) {
      if (edge.validFrom === undefined) {
        continue;
      }

      pathHasValidity = true;

      /*
       * Along a single path every hop must have been in force together, so
       * the path opens at the latest opening instant and closes at the
       * earliest closing instant.
       */
      pathValidFrom =
        pathValidFrom === undefined
          ? edge.validFrom
          : Math.max(
              pathValidFrom,
              edge.validFrom,
            );

      if (edge.validUntil !== undefined) {
        pathClosed = true;

        pathValidUntil =
          pathValidUntil === undefined
            ? edge.validUntil
            : Math.min(
                pathValidUntil,
                edge.validUntil,
              );
      }

      for (const evidenceId of edge.evidenceIds) {
        evidenceIds.add(evidenceId);
      }
    }

    if (!pathHasValidity || pathValidFrom === undefined) {
      pathsWithoutValidity += 1;
      continue;
    }

    earliestValidFrom =
      earliestValidFrom === undefined
        ? pathValidFrom
        : Math.min(
            earliestValidFrom,
            pathValidFrom,
          );

    if (pathClosed && pathValidUntil !== undefined) {
      latestValidUntil =
        latestValidUntil === undefined
          ? pathValidUntil
          : Math.max(
              latestValidUntil,
              pathValidUntil,
            );
    } else {
      anyStillOpen = true;
    }
  }

  return {
    candidate,

    ...(earliestValidFrom === undefined
      ? {}
      : { validFrom: earliestValidFrom }),

    ...(anyStillOpen ||
    latestValidUntil === undefined
      ? {}
      : { validUntil: latestValidUntil }),

    evidenceIds: [...evidenceIds].sort(
      (left, right) => left - right,
    ),

    pathsWithoutValidity,
    pathCount: candidate.paths.length,
  };
}

/**
 * Partitions blast-radius services by whether their dependency resolutions
 * were in force while the compromise interval was open.
 *
 * This is the Q3 answer: "which applications resolved the compromised version
 * while it was live". Services whose lockfile history was never recorded are
 * reported as unknown, never as safe.
 */
export function buildTemporalWindow(
  blastRadius: BlastRadiusResult,
  incident: IncidentWindow,
  options: {
    readonly asOf?: UnixEpochMilliseconds;
  } = {},
): TemporalWindowResult {
  const inputs = blastRadius.services.map(
    summarizeCandidate,
  );

  const partition = partitionByWindow(
    inputs,
    incident,
    (input) => ({
      resolution: {
        ...(input.validFrom === undefined
          ? {}
          : { validFrom: input.validFrom }),

        ...(input.validUntil === undefined
          ? {}
          : { validUntil: input.validUntil }),
      },
      evidenceIds: input.evidenceIds,
    }),
  );

  const describe = (entry: {
    readonly subject: ServiceWindowInput;
    readonly classification: {
      readonly overlap: WindowOverlap;
      readonly reason: string;
      readonly evidenceIds: readonly NodeId[];
    };
  }): ServiceWindowAssessment => {
    const partialHistory =
      entry.subject.pathsWithoutValidity > 0 &&
      entry.subject.pathsWithoutValidity <
        entry.subject.pathCount;

    return Object.freeze({
      serviceId:
        entry.subject.candidate.service.id,

      serviceName:
        entry.subject.candidate.service.name,

      overlap: entry.classification.overlap,

      reason: partialHistory
        ? `${entry.classification.reason} ` +
          `${entry.subject.pathsWithoutValidity} of ` +
          `${entry.subject.pathCount} paths have no recorded ` +
          `lockfile validity and did not contribute.`
        : entry.classification.reason,

      evidenceIds:
        entry.classification.evidenceIds,

      ...(entry.subject.validFrom === undefined
        ? {}
        : {
            earliestValidFrom:
              entry.subject.validFrom,
          }),

      ...(entry.subject.validUntil === undefined
        ? {}
        : {
            latestValidUntil:
              entry.subject.validUntil,
          }),
    });
  };

  const limitations: string[] = [];

  if (partition.hasUnknown) {
    limitations.push(
      `${partition.unknownWindow.length} services have no recorded lockfile ` +
        `history, so whether they resolved the affected version during the ` +
        `compromise interval is unknown. Unknown is not safe.`,
    );
  }

  const partialHistoryCount = inputs.filter(
    (input) =>
      input.pathsWithoutValidity > 0 &&
      input.pathsWithoutValidity <
        input.pathCount,
  ).length;

  if (partialHistoryCount > 0) {
    limitations.push(
      `${partialHistoryCount} services have partial lockfile history, so ` +
        `their temporal verdict rests on a subset of their paths.`,
    );
  }

  if (blastRadius.truncated) {
    limitations.push(
      "Blast-radius traversal was truncated, so additional services may " +
        "fall inside the compromise interval.",
    );
  }

  return Object.freeze({
    asOf: options.asOf ?? null,

    incidentInterval: Object.freeze({
      intervalStart: incident.intervalStart,
      intervalEnd: incident.intervalEnd,
    }),

    resolvedDuringWindow: Object.freeze(
      partition.resolvedDuringWindow.map(
        describe,
      ),
    ),

    resolvedOutsideWindow: Object.freeze(
      partition.resolvedOutsideWindow.map(
        describe,
      ),
    ),

    unknownWindow: Object.freeze(
      partition.unknownWindow.map(describe),
    ),

    hasUnknown: partition.hasUnknown,

    complete:
      !partition.hasUnknown &&
      partialHistoryCount === 0 &&
      !blastRadius.truncated,

    limitations: Object.freeze(limitations),
  });
}
