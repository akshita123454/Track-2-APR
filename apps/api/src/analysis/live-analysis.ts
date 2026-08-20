import type {
  Driver,
} from "neo4j-driver";

import type {
  EvidenceNode,
  IncidentNode,
  NodeId,
  PackageVersionNode,
} from "../domain/schema.js";
import {
  buildTemporalWindow,
} from "./core/temporal-projection.js";

import type {
  TemporalWindowResult,
} from "./core/temporal-projection.js";

import type {
  BlastRadiusOptions,
  BlastRadiusResult,
  ReadonlyGraphReader,
} from "./core/analysis-types.js";


import {
  analyzeBlastRadius,
} from "./core/blast-radius.js";

import {
  buildEvidenceFunnel,
} from "./core/evidence-funnel.js";

import {
  buildServiceImpactExplanations,
} from "./core/service-impact-explanation.js";

import type {
  ServiceImpactExplanation,
} from "./core/service-impact-explanation.js";

import {
  HydraGraphReader,
} from "./readers/hydra-graph-reader.js";



import type {
  EvidenceFunnelOptions,
  EvidenceFunnelResult,
} from "./core/evidence-funnel.js";

import type {
  HydraGraphReaderOptions,
  HydraReadDiagnostics,
} from "./readers/hydra-graph-reader.js";

const DEFAULT_MAX_AFFECTED_VERSIONS = 1_000;
const MAX_AFFECTED_VERSIONS = 5_000;
const MAX_DATE_EPOCH_MS =
  8_640_000_000_000_000;
const DEFAULT_EVIDENCE_CATALOG_LIMIT = 2_000;
const DEFAULT_EVIDENCE_CATALOG_CHUNK_SIZE = 250;


export interface LiveAnalysisOptions {
  /**
   * Maximum number of canonical Incident -[:AFFECTS]->
   * PackageVersion targets admitted as traversal roots.
   */
  readonly maxAffectedVersions?: number;

  readonly blastRadius?: BlastRadiusOptions;
  readonly evidenceFunnel?: EvidenceFunnelOptions;

  /**
   * Reader settings such as statement timeout and smoke-test session
   * factory. The live analysis owns the client read epoch.
   */
  readonly reader?: Omit<
    HydraGraphReaderOptions,
    "clock"
  >;

  /**
   * Injectable wall clock for deterministic validation.
   */
  readonly clock?: () => number;
}

export interface AffectedVersionLookupSummary {
  readonly limit: number;
  readonly returnedCount: number;
  readonly truncated: boolean;
}

export interface HydraLiveReadTelemetry
  extends HydraReadDiagnostics {
  readonly startedAt: string;
  readonly completedAt: string;

  /**
   * End-to-end API analysis latency, including affected-root lookup,
   * blast-radius traversal, and evidence funnel reads.
   */
  readonly latencyMs: number;

  /**
   * Makes the consistency boundary explicit to API consumers.
   *
   * HydraDB is queried through multiple bounded read statements. The
   * readEpoch is a client correlation epoch, not a database snapshot ID.
   */
  readonly consistencyModel:
    "bounded-multi-statement-read";

  readonly engine: "HydraDB";
}
export interface LiveIncidentSummary {
  readonly id: NodeId;
  readonly title: string;

  readonly status:
    | "draft"
    | "active"
    | "contained"
    | "closed";

  readonly intervalStart: number;
  readonly intervalEnd: number | null;
  readonly synthetic: boolean;
}

export interface LiveAffectedVersionSummary {
  readonly id: NodeId;
  readonly packageName: string;
  readonly version: string;
  readonly publishedAt?: number;
  readonly synthetic: boolean;
}

export interface LiveEvidenceCatalogEntry {
  readonly id: NodeId;
  readonly sourceType:
    EvidenceNode["sourceType"];

  readonly confidence: number;
  readonly observedAt: number;
  readonly synthetic: boolean;

  /**
   * True only when Evidence.incidentId exactly equals the analyzed Incident.
   *
   * False does not make evidence invalid. For example, package-lock evidence
   * can support a dependency edge without being incident-specific.
   */
  readonly incidentLinked: boolean;
}

export interface LiveBlastRadiusResult
  extends BlastRadiusResult {
  readonly incidentId: NodeId;

  readonly incident:
    LiveIncidentSummary;

  readonly affectedVersions:
    readonly LiveAffectedVersionSummary[];

  /**
   * Safe evidence metadata only.
   *
   * sourceUri, detail and collectorVersion intentionally remain internal.
   */
  readonly evidenceCatalog:
    readonly LiveEvidenceCatalogEntry[];

  /**
   * Canonical backend decisions for each returned Service candidate.
   * Dashboard consumers must render these decisions rather than infer a
   * security state from graph shape or evidence confidence locally.
   */
  readonly serviceImpacts:
    readonly ServiceImpactExplanation[];

  readonly affectedVersionLookup:
    AffectedVersionLookupSummary;

  readonly evidenceFunnel:
    EvidenceFunnelResult;

  /**
   * Whether each returned service resolved an affected version while the
   * compromise interval was open.
   */
  readonly temporalWindow:
    TemporalWindowResult;

  readonly hydraRead:
    HydraLiveReadTelemetry;
}


export type LiveAnalysisErrorCode =
  | "INVALID_OPTIONS"
  | "INVALID_CLOCK";

export class LiveAnalysisError extends Error {
  constructor(
    readonly code: LiveAnalysisErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(
      message,
      cause === undefined
        ? undefined
        : { cause },
    );

    this.name = "LiveAnalysisError";
  }
}

function readMaxAffectedVersions(
  value: number | undefined,
): number {
  const normalized =
    value ??
    DEFAULT_MAX_AFFECTED_VERSIONS;

  if (
    !Number.isSafeInteger(normalized) ||
    normalized < 1 ||
    normalized > MAX_AFFECTED_VERSIONS
  ) {
    throw new LiveAnalysisError(
      "INVALID_OPTIONS",
      `maxAffectedVersions must be a positive safe integer not greater than ${MAX_AFFECTED_VERSIONS}`,
    );
  }

  return normalized;
}

function readClock(
  clock: () => number,
  field: string,
): number {
  let value: number;

  try {
    value = clock();
  } catch (error) {
    throw new LiveAnalysisError(
      "INVALID_CLOCK",
      `${field} clock read failed`,
      error,
    );
  }

  if (
    !Number.isFinite(value) ||
    value < 0 ||
    value > MAX_DATE_EPOCH_MS
  ) {
    throw new LiveAnalysisError(
      "INVALID_CLOCK",
      `${field} must be a valid nonnegative Unix epoch in milliseconds`,
    );
  }

  return value;
}

/**
 * Runs blast-radius analysis directly against persisted HydraDB state.
 *
 * Flow:
 *
 * 1. Verify the requested node is an Incident.
 * 2. Resolve bounded canonical AFFECTS targets.
 * 3. Traverse reverse dependencies through validated USED_BY indexes.
 * 4. Retain canonical DEPENDS_ON edges as the actual evidence path.
 * 5. Resolve bounded Evidence nodes and construct the evidence funnel.
 * 6. Return HydraDB read diagnostics and end-to-end latency.
 */
interface EvidenceCatalogBuildResult {
  readonly entries:
    readonly LiveEvidenceCatalogEntry[];

  readonly complete: boolean;
  readonly limitation?: string;
}

function summarizeIncident(
  incident: IncidentNode,
): LiveIncidentSummary {
  return Object.freeze({
    id: incident.id,
    title: incident.title,
    status: incident.status,
    intervalStart:
      incident.intervalStart,
    intervalEnd:
      incident.intervalEnd,
    synthetic:
      incident.synthetic,
  });
}

function summarizeAffectedVersion(
  version: PackageVersionNode,
): LiveAffectedVersionSummary {
  return Object.freeze({
    id: version.id,
    packageName:
      version.packageName,
    version:
      version.version,

    ...(version.publishedAt ===
    undefined
      ? {}
      : {
          publishedAt:
            version.publishedAt,
        }),

    synthetic:
      version.synthetic,
  });
}

function collectRelevantEvidenceIds(
  incident: IncidentNode,
  affectedVersions:
    readonly PackageVersionNode[],
  affectsEvidenceIds:
    readonly NodeId[],
  blastRadius: BlastRadiusResult,
): readonly NodeId[] {
  const evidenceIds =
    new Set<NodeId>();

  const addIds = (
    ids: readonly NodeId[],
  ): void => {
    for (const id of ids) {
      evidenceIds.add(id);
    }
  };

  addIds(incident.evidenceIds);
  addIds(affectsEvidenceIds);

  for (
    const version
    of affectedVersions
  ) {
    addIds(
      version.evidenceIds,
    );
  }

  for (
    const candidate
    of blastRadius.services
  ) {
    addIds(
      candidate.service
        .evidenceIds,
    );

    for (
      const path
      of candidate.paths
    ) {
      for (
        const node
        of path.nodes
      ) {
        addIds(
          node.evidenceIds,
        );
      }

      for (
        const edge
        of path.canonicalEdges
      ) {
        addIds(
          edge.evidenceIds,
        );
      }
    }
  }

  return Object.freeze(
    [...evidenceIds].sort(
      (left, right) =>
        left - right,
    ),
  );
}

async function buildRedactedEvidenceCatalog(
  reader: ReadonlyGraphReader,
  incidentId: NodeId,
  evidenceIds: readonly NodeId[],
  options: EvidenceFunnelOptions,
): Promise<EvidenceCatalogBuildResult> {
  const maximum =
    options.maxEvidenceIds ??
    DEFAULT_EVIDENCE_CATALOG_LIMIT;

  const requestedIds =
    evidenceIds.slice(
      0,
      maximum,
    );

  const omittedCount =
    evidenceIds.length -
    requestedIds.length;

  const chunkSize =
    Math.min(
      options.evidenceReadChunkSize ??
        DEFAULT_EVIDENCE_CATALOG_CHUNK_SIZE,
      maximum,
    );

  const evidenceById =
    new Map<NodeId, EvidenceNode>();

  for (
    let offset = 0;
    offset <
      requestedIds.length;
    offset += chunkSize
  ) {
    const chunk =
      requestedIds.slice(
        offset,
        offset + chunkSize,
      );

    const evidence =
      await reader.getEvidence(
        chunk,
      );

    for (const item of evidence) {
      evidenceById.set(
        item.id,
        item,
      );
    }
  }

  const missingCount =
    requestedIds.filter(
      (id) =>
        !evidenceById.has(id),
    ).length;

  const entries =
    [...evidenceById.values()]
      .sort(
        (left, right) =>
          left.id - right.id,
      )
      .map(
        (
          evidence,
        ): LiveEvidenceCatalogEntry =>
          Object.freeze({
            id:
              evidence.id,

            sourceType:
              evidence.sourceType,

            confidence:
              evidence.confidence,

            observedAt:
              evidence.observedAt,

            synthetic:
              evidence.synthetic,

            incidentLinked:
              evidence.incidentId ===
              incidentId,
          }),
      );

  const complete =
    omittedCount === 0 &&
    missingCount === 0;

  let limitation:
    string | undefined;

  if (!complete) {
    limitation =
      `${omittedCount} relevant Evidence IDs were omitted by the catalog budget and ` +
      `${missingCount} requested Evidence IDs did not resolve.`;
  }

  return Object.freeze({
    entries:
      Object.freeze(entries),

    complete,

    ...(limitation === undefined
      ? {}
      : {
          limitation,
        }),
  });
}

export async function runLiveBlastRadius(
  driver: Driver,
  incidentId: NodeId,
  options: LiveAnalysisOptions = {},
): Promise<LiveBlastRadiusResult> {
  if (
    !Number.isSafeInteger(incidentId) ||
    incidentId < 0
  ) {
    throw new LiveAnalysisError(
      "INVALID_OPTIONS",
      "incidentId must be a nonnegative safe integer",
    );
  }

  const maxAffectedVersions =
    readMaxAffectedVersions(
      options.maxAffectedVersions,
    );

  const clock =
    options.clock ?? Date.now;

  const startedAtMs =
    readClock(clock, "start");

  /*
   * The same client epoch is assigned to every bounded statement made by
   * this reader. It is intentionally not described as a transactional
   * snapshot because the live analysis uses multiple HydraDB statements.
   */
  const reader =
    new HydraGraphReader(
      driver,
      {
        ...options.reader,
        clock: () => startedAtMs,
      },
    );

  const affectedVersionPage =
    await reader.findAffectedVersions(
      incidentId,
      {
        limit: maxAffectedVersions,
      },
    );

  const affectedVersionIds =
  affectedVersionPage
    .affectedVersions
    .map(
      (version) =>
        version.id,
    );

const rawBlastRadius =
  await analyzeBlastRadius(
    reader,
    affectedVersionIds,
    options.blastRadius,
  );


  /*
   * Truncation during root resolution is part of overall analysis
   * truncation even when traversal itself stayed inside its limits.
   */
  const blastRadius: BlastRadiusResult = {
    ...rawBlastRadius,
    truncated:
      rawBlastRadius.truncated ||
      affectedVersionPage.truncated,
  };

  const requestedFunnelOptions =
  options.evidenceFunnel ?? {};

const rawEvidenceFunnel =
  await buildEvidenceFunnel(
    reader,
    blastRadius,
    requestedFunnelOptions,
  );

const relevantEvidenceIds =
  collectRelevantEvidenceIds(
    affectedVersionPage.incident,
    affectedVersionPage
      .affectedVersions,
    affectedVersionPage
      .affectsEvidenceIds,
    blastRadius,
  );

const catalog =
  await buildRedactedEvidenceCatalog(
    reader,
    incidentId,
    relevantEvidenceIds,
    requestedFunnelOptions,
  );

const evidenceFunnel:
  EvidenceFunnelResult =
    catalog.complete
      ? rawEvidenceFunnel
      : Object.freeze({
          ...rawEvidenceFunnel,

          completeForIncident:
            false,

          limitations:
            Object.freeze([
              ...rawEvidenceFunnel
                .limitations,

              catalog.limitation ??
                "The redacted evidence catalog is incomplete.",
            ]),
        });

const temporalWindow =
  buildTemporalWindow(
    blastRadius,
    {
      intervalStart:
        affectedVersionPage.incident
          .intervalStart,
      intervalEnd:
        affectedVersionPage.incident
          .intervalEnd,
    },
    options.blastRadius?.asOf === undefined
      ? {}
      : {
          asOf:
            options.blastRadius.asOf,
        },
  );

const serviceImpacts =
  buildServiceImpactExplanations(
    blastRadius,
    affectedVersionPage
      .affectedVersions,
    catalog.entries,
    {
      asOf: startedAtMs,
      highConfidenceThreshold:
        evidenceFunnel
          .highConfidenceThreshold,
      evidenceComplete:
        evidenceFunnel
          .completeForIncident,
    },
  );


  const completedAtMs =
    readClock(clock, "completion");

  if (completedAtMs < startedAtMs) {
    throw new LiveAnalysisError(
      "INVALID_CLOCK",
      "completion clock value must not precede the start value",
    );
  }

  const diagnostics =
    reader.getDiagnostics();

  const hydraRead: HydraLiveReadTelemetry =
    Object.freeze({
      ...diagnostics,
      startedAt:
        new Date(
          startedAtMs,
        ).toISOString(),
      completedAt:
        new Date(
          completedAtMs,
        ).toISOString(),
      latencyMs:
        completedAtMs - startedAtMs,
      consistencyModel:
        "bounded-multi-statement-read",
      engine: "HydraDB",
    });

  return Object.freeze({
    ...blastRadius,

    incidentId,
    incident:
  summarizeIncident(
    affectedVersionPage.incident,
  ),

affectedVersions:
  Object.freeze(
    affectedVersionPage
      .affectedVersions
      .map(
        summarizeAffectedVersion,
      ),
  ),

evidenceCatalog:
  catalog.entries,

serviceImpacts,

    affectedVersionLookup:
      Object.freeze({
        limit:
          maxAffectedVersions,
        returnedCount:
          affectedVersionPage
            .affectedVersions
            .length,
        truncated:
          affectedVersionPage
            .truncated,
      }),

    evidenceFunnel,
    temporalWindow,
    hydraRead,
  });
}
