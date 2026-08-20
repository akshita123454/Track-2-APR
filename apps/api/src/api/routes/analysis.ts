import type {
  Driver,
} from "neo4j-driver";

import type {
  FastifyInstance,
} from "fastify";

import {
  EvidenceFunnelError,
} from "../../analysis/core/evidence-funnel.js";

import {
  LiveAnalysisError,
  runLiveBlastRadius,
} from "../../analysis/live-analysis.js";

import {
  HydraGraphReaderError,
} from "../../analysis/readers/hydra-graph-reader.js";

import {
  ApiError,
} from "../errors.js";

import {
  GET_LIVE_BLAST_RADIUS_ROUTE_SCHEMA,
  registerAnalysisSchemas,
} from "../schemas/analysis.js";

import type {
  LiveAnalysisOptions,
  LiveBlastRadiusResult,
} from "../../analysis/live-analysis.js";

import type {
  IncidentAnalysisParams,
  IncidentAnalysisQuerystring,
} from "../schemas/analysis.js";

export type LiveBlastRadiusRunner = (
  driver: Driver,
  incidentId: number,
  options?: LiveAnalysisOptions,
) => Promise<LiveBlastRadiusResult>;

export interface AnalysisRoutesOptions {
  /**
   * Use the same application-owned Driver used by persistence, health
   * checks and incident creation. This route must not open a second driver.
   */
  readonly driver: Driver;

  /**
   * Optional reader configuration, normally statement timeout limits.
   *
   * Do not expose sessionFactory or clock through the HTTP request.
   */
  readonly readerOptions?: LiveAnalysisOptions["reader"];

  /**
   * Test boundary. Production defaults to runLiveBlastRadius.
   */
  readonly runAnalysis?: LiveBlastRadiusRunner;
}

function blastRadiusOptions(
  query: IncidentAnalysisQuerystring,
): NonNullable<
  LiveAnalysisOptions["blastRadius"]
> {
  return {
    ...(query.maxDepth === undefined
      ? {}
      : {
          maxDepth:
            query.maxDepth,
        }),

    ...(query.maxServices === undefined
      ? {}
      : {
          maxServices:
            query.maxServices,
        }),

    ...(query.maxPathsPerService === undefined
      ? {}
      : {
          maxPathsPerService:
            query.maxPathsPerService,
        }),

    ...(query.maxTotalPaths === undefined
      ? {}
      : {
          maxTotalPaths:
            query.maxTotalPaths,
        }),

    ...(query.maxTraversalStates === undefined
      ? {}
      : {
          maxTraversalStates:
            query.maxTraversalStates,
        }),

    ...(query.maxDependentsPerNode === undefined
      ? {}
      : {
          maxDependentsPerNode:
            query.maxDependentsPerNode,
        }),

    ...(query.maxWarnings === undefined
      ? {}
      : {
          maxWarnings:
            query.maxWarnings,
        }),
  };
}

function evidenceFunnelOptions(
  query: IncidentAnalysisQuerystring,
): NonNullable<
  LiveAnalysisOptions["evidenceFunnel"]
> {
  return {
    ...(query.highConfidenceThreshold ===
    undefined
      ? {}
      : {
          highConfidenceThreshold:
            query.highConfidenceThreshold,
        }),

    ...(query.maxEvidenceIds === undefined
      ? {}
      : {
          maxEvidenceIds:
            query.maxEvidenceIds,
        }),

    ...(query.evidenceReadChunkSize ===
    undefined
      ? {}
      : {
          evidenceReadChunkSize:
            query.evidenceReadChunkSize,
        }),
  };
}

function liveAnalysisOptions(
  query: IncidentAnalysisQuerystring,
  reader:
    LiveAnalysisOptions["reader"],
): LiveAnalysisOptions {
  return {
    ...(query.maxAffectedVersions ===
    undefined
      ? {}
      : {
          maxAffectedVersions:
            query.maxAffectedVersions,
        }),

    blastRadius:
      blastRadiusOptions(query),

    evidenceFunnel:
      evidenceFunnelOptions(query),

    ...(reader === undefined
      ? {}
      : {
          reader,
        }),
  };
}

function assertAnalysisResponse(
  incidentId: number,
  result: LiveBlastRadiusResult,
): void {


    if (
    result.incidentId !== incidentId ||
    result.incident.id !== incidentId ||
    result.hydraRead.engine !== "HydraDB" ||
    result.hydraRead.consistencyModel !==
      "bounded-multi-statement-read"
  ) {
    throw new Error(
      "Live analysis returned an invalid response identity",
    );
  }
  if (
result.affectedVersions.length !==
result.affectedVersionLookup.returnedCount
) {
throw new Error(
"Live analysis returned inconsistent affected-version summaries",
);
}
const affectedSummaryIds =
new Set(
result.affectedVersions.map(
(version) =>
version.id,
),
);
if (
result.affectedVersionIds.some(
(id) =>
!affectedSummaryIds.has(id),
)
) {
throw new Error(
"Live analysis returned an affected root without a public version summary",
);
}

  const serviceIds = new Set(
    result.services.map(
      (candidate) => candidate.service.id,
    ),
  );

  const impactServiceIds = new Set(
    result.serviceImpacts.map(
      (impact) => impact.serviceId,
    ),
  );

  if (
    serviceIds.size !==
      impactServiceIds.size ||
    [...serviceIds].some(
      (serviceId) =>
        !impactServiceIds.has(serviceId),
    )
  ) {
    throw new Error(
      "Live analysis returned inconsistent service-impact decisions",
    );
  }

  for (const impact of result.serviceImpacts) {
    const candidate = result.services.find(
      (item) =>
        item.service.id === impact.serviceId,
    );

    const candidatePathKeys = new Set(
      candidate?.paths.map(
        (path) => path.pathKey,
      ) ?? [],
    );

    if (
      impact.paths.length !==
        candidatePathKeys.size ||
      impact.paths.some(
        (path) =>
          !candidatePathKeys.has(path.pathKey),
      )
    ) {
      throw new Error(
        "Live analysis returned inconsistent path-impact decisions",
      );
    }
  }

  const stages =
    result.evidenceFunnel.stages;

  if (stages.length !== 3) {
    throw new Error(
      "Live analysis returned an invalid evidence funnel",
    );
  }

  for (
    let index = 1;
    index < stages.length;
    index += 1
  ) {
    const previous =
      stages[index - 1];

    const current =
      stages[index];

    if (
      previous === undefined ||
      current === undefined ||
      current.pathCount >
        previous.pathCount ||
      current.serviceCount >
        previous.serviceCount
    ) {
      throw new Error(
        "Evidence funnel is not monotonic",
      );
    }
  }
}

function mapKnownAnalysisError(
  error: unknown,
): ApiError | null {
  if (
    error instanceof
      HydraGraphReaderError
  ) {
    switch (error.code) {
      case "INCIDENT_NOT_FOUND":
      case "NODE_KIND_MISMATCH":
        return new ApiError(
          "INCIDENT_NOT_FOUND",
          404,
          "The requested incident was not found.",
        );

      case "DATABASE_QUERY_FAILED":
        return new ApiError(
          "ANALYSIS_DATABASE_UNAVAILABLE",
          503,
          "HydraDB is temporarily unavailable for live analysis.",
        );

      case "DATABASE_RESULT_INVALID":
      case "GRAPH_CORRUPTION":
        return new ApiError(
          "ANALYSIS_DATA_UNAVAILABLE",
          503,
          "Live analysis could not verify the integrity of the stored graph.",
        );
    }
  }

  if (
    error instanceof
      LiveAnalysisError
  ) {
    if (
      error.code ===
        "INVALID_OPTIONS"
    ) {
      return new ApiError(
        "INVALID_ANALYSIS_REQUEST",
        400,
        "The live-analysis options are invalid.",
      );
    }

    return null;
  }

  if (
    error instanceof
      EvidenceFunnelError
  ) {
    if (
      error.code ===
        "INVALID_OPTIONS"
    ) {
      return new ApiError(
        "INVALID_ANALYSIS_REQUEST",
        400,
        "The evidence-funnel options are invalid.",
      );
    }

    return new ApiError(
      "ANALYSIS_EVIDENCE_UNAVAILABLE",
      503,
      "Live analysis could not verify the referenced evidence.",
    );
  }

  return null;
}

/**
 * Registers:
 *
 * GET /incidents/:incidentId/blast-radius
 *
 * The endpoint reads live persisted HydraDB state. It does not analyze an
 * ingestion worker's in-memory GraphBatch.
 */
export async function registerAnalysisRoutes(
  app: FastifyInstance,
  options: AnalysisRoutesOptions,
): Promise<void> {
  if (
    options.driver === undefined ||
    options.driver === null
  ) {
    throw new Error(
      "Analysis routes require the application HydraDB driver",
    );
  }

  /*
   * This remains safe when buildServer already registered the schema.
   * It also makes isolated route tests self-contained.
   */
  registerAnalysisSchemas(app);

  const execute =
    options.runAnalysis ??
    runLiveBlastRadius;

  app.get<{
    Params:
      IncidentAnalysisParams;

    Querystring:
      IncidentAnalysisQuerystring;
  }>(
    "/incidents/:incidentId/blast-radius",
    {
      schema:
        GET_LIVE_BLAST_RADIUS_ROUTE_SCHEMA,
    },
    async (request, reply) => {
      const incidentId =
        request.params.incidentId;

      try {
        const result =
          await execute(
            options.driver,
            incidentId,
            liveAnalysisOptions(
              request.query,
              options.readerOptions,
            ),
          );

        assertAnalysisResponse(
          incidentId,
          result,
        );

        return reply
          .code(200)
          .send(result);
      } catch (error: unknown) {
        const publicError =
          mapKnownAnalysisError(error);

        if (publicError !== null) {
          /*
           * Preserve the raw cause only in private structured logs. The
           * centralized ApiError handler sends the redacted public message.
           */
          request.log.error(
            {
              err: error,
              incidentId,
            },
            "Live HydraDB analysis failed",
          );

          throw publicError;
        }

        throw error;
      }
    },
  );
}
