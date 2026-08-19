import {
  createHash,
  randomUUID,
} from "node:crypto";

import {
  satisfies,
  valid,
  validRange,
} from "semver";

import type {
  Driver,
  Session,
} from "neo4j-driver";

import {
  createEdgeIdentity,
  createEntityIdentity,
} from "../domain/identity.js";

import {
  mergeGraphFragments,
} from "../ingest/graph-batch.js";

import {
  EDGE_PROPERTY_KEYS,
  serializeHydraEdge,
} from "../db/hydra-serializer.js";

import {
  PersistenceServiceError,
} from "../db/persistence-service.js";

import type {
  HydraPersistenceService,
  PersistenceServiceOptions,
} from "../db/persistence-service.js";

import type {
  EvidenceNode,
  IncidentNode,
  StandardCanonicalEdge,
} from "../domain/schema.js";

import {
  toHydraParameters,
} from "../db/hydra-parameters.js";

import type {
  HydraEdgeRow,
} from "../db/hydra-serializer.js";

import type {
  IncidentCreateCommand,
  IncidentCreator,
} from "../api/routes/incidents.js";

import type {
  IncidentCreatedResponse,
} from "../api/schemas/incidents.js";

export type IncidentServiceErrorCode =
  | "INVALID_AFFECTED_VERSION"
  | "INVALID_AFFECTED_RANGE"
  | "AFFECTED_VERSION_NOT_FOUND"
  | "INCIDENT_IDEMPOTENCY_CONFLICT"
  | "INCIDENT_IDENTITY_CONFLICT"
  | "INCIDENT_PERSISTENCE_FAILED"
  | "INCIDENT_VERIFICATION_FAILED"
  | "INCIDENT_DATABASE_UNAVAILABLE";

export class IncidentServiceError
  extends Error {
  constructor(
    readonly code:
      IncidentServiceErrorCode,
    readonly httpStatusCode: number,
    message: string,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name =
      "IncidentServiceError";
  }
}

export interface IncidentServiceOptions {
  readonly maxVersionsScannedPerPackage?: number;
  readonly affectedEdgeChunkSize?: number;
  readonly statementTimeoutMs?: number;

  readonly persistenceOptions?: Omit<
    PersistenceServiceOptions,
    | "idempotencyKey"
    | "correlationId"
  >;
}

interface PackageVersionReference {
  readonly id: number;
  readonly logicalId: string;
  readonly packageName: string;
  readonly version: string;
}

interface PersistedRequestDetail {
  readonly requestFingerprint: string;
}

const DEFAULT_MAX_VERSIONS_SCANNED =
  10_000;

const DEFAULT_EDGE_CHUNK_SIZE =
  250;

const DEFAULT_STATEMENT_TIMEOUT_MS =
  20_000;

function sha256(
  value: string,
): string {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

function asString(
  value: unknown,
  description: string,
): string {
  if (typeof value !== "string") {
    throw new IncidentServiceError(
      "INCIDENT_DATABASE_UNAVAILABLE",
      503,
      `HydraDB returned an invalid ${description}`,
    );
  }

  return value;
}

function asSafeInteger(
  value: unknown,
  description: string,
): number {
  let converted = value;

  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber ===
      "function"
  ) {
    converted = value.toNumber();
  }

  if (
    typeof converted !== "number" ||
    !Number.isSafeInteger(
      converted,
    ) ||
    converted < 0
  ) {
    throw new IncidentServiceError(
      "INCIDENT_DATABASE_UNAVAILABLE",
      503,
      `HydraDB returned an invalid ${description}`,
    );
  }

  return converted;
}

function chunks<T>(
  values: readonly T[],
  chunkSize: number,
): readonly T[][] {
  const output: T[][] = [];

  for (
    let offset = 0;
    offset < values.length;
    offset += chunkSize
  ) {
    output.push(
      values.slice(
        offset,
        offset + chunkSize,
      ),
    );
  }

  return output;
}

function readRequestDetail(
  value: string,
): PersistedRequestDetail {
  try {
    const parsed =
      JSON.parse(value) as unknown;

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !(
        "requestFingerprint" in
        parsed
      ) ||
      typeof parsed
        .requestFingerprint !==
        "string"
    ) {
      throw new Error();
    }

    return {
      requestFingerprint:
        parsed.requestFingerprint,
    };
  } catch {
    throw new IncidentServiceError(
      "INCIDENT_IDENTITY_CONFLICT",
      409,
      "Existing incident evidence has an invalid request identity",
    );
  }
}

export class HydraIncidentService
  implements IncidentCreator {
  private readonly maxVersionsScannedPerPackage:
    number;

  private readonly affectedEdgeChunkSize:
    number;

  private readonly statementTimeoutMs:
    number;

  private readonly persistenceOptions:
    Omit<
      PersistenceServiceOptions,
      | "idempotencyKey"
      | "correlationId"
    >;

  /**
   * Serializes the entire incident operation, including replay checks.
   *
   * HydraPersistenceService serializes graph batches, but the incident replay
   * check and AFFECTS phase must be in the same process-local lane.
   */
  private operationTail:
    Promise<void> =
      Promise.resolve();

  constructor(
    private readonly driver:
      Driver,

    private readonly persistence:
      Pick<
        HydraPersistenceService,
        "persist"
      >,

    options:
      IncidentServiceOptions = {},
  ) {
    this.maxVersionsScannedPerPackage =
      options
        .maxVersionsScannedPerPackage ??
      DEFAULT_MAX_VERSIONS_SCANNED;

    this.affectedEdgeChunkSize =
      options
        .affectedEdgeChunkSize ??
      DEFAULT_EDGE_CHUNK_SIZE;

    this.statementTimeoutMs =
      options.statementTimeoutMs ??
      DEFAULT_STATEMENT_TIMEOUT_MS;

    this.persistenceOptions =
      options.persistenceOptions ??
      {};
  }

  createIncident(
    command: IncidentCreateCommand,
  ): Promise<IncidentCreatedResponse> {
    const operation =
      this.operationTail.then(
        () =>
          this.createIncidentExclusive(
            command,
          ),
        () =>
          this.createIncidentExclusive(
            command,
          ),
      );

    this.operationTail =
      operation.then(
        () => undefined,
        () => undefined,
      );

    return operation;
  }

  private async createIncidentExclusive(
    command: IncidentCreateCommand,
  ): Promise<IncidentCreatedResponse> {
    const identityToken =
      command.idempotencyKey ===
      undefined
        ? randomUUID()
        : sha256(
            `incident-idempotency:${command.idempotencyKey}`,
          ).slice(0, 40);

    const incidentIdentity =
      createEntityIdentity(
        `incident:${identityToken}`,
      );

    const evidenceIdentity =
      createEntityIdentity(
        `evidence:incident:${identityToken}`,
      );

    await this.assertReplayCompatible(
      evidenceIdentity.id,
      evidenceIdentity.logicalId,
      command.requestFingerprint,
    );

    /*
     * Resolve every package version before writing Incident state. An invalid
     * range or missing exact version therefore leaves no partial incident.
     */
    const affectedVersions =
      await this.resolveAffectedVersions(
        command,
      );

    const evidence:
      EvidenceNode = {
        ...evidenceIdentity,
        kind: "Evidence",
        evidenceIds: [],
        synthetic:
          command.request
            .provenance.synthetic,
        observedAt:
          command
            .provenanceObservedAt,
        sourceType:
          command.request
            .provenance.sourceType,
        sourceUri:
          command.request
            .provenance.sourceUri,
        collectorVersion:
          command.request
            .provenance
            .collectorVersion,
        confidence:
          command.request
            .provenance.confidence,
        incidentId:
          incidentIdentity.id,
        detail: JSON.stringify({
          requestFingerprint:
            command.requestFingerprint,
        }),
      };

    const incident:
      IncidentNode = {
        ...incidentIdentity,
        kind: "Incident",
        evidenceIds: [
          evidence.id,
        ],
        synthetic:
          command.request
            .provenance.synthetic,
        observedAt:
          command
            .provenanceObservedAt,
        title:
          command.request.title,
        status: "active",
        intervalStart:
          command.intervalStart,
        intervalEnd:
          command.intervalEnd,
      };

    const supportIdentity =
      createEdgeIdentity({
        kind: "SUPPORTS",
        sourceLogicalId:
          evidence.logicalId,
        targetLogicalId:
          incident.logicalId,
        discriminator:
          "incident-provenance",
      });

    const support:
      StandardCanonicalEdge = {
        ...supportIdentity,
        sourceId: evidence.id,
        targetId: incident.id,
        kind: "SUPPORTS",
        observedAt:
          command
            .provenanceObservedAt,
        derived: false,
        identityDiscriminator:
          "incident-provenance",
        evidenceIds: [
          evidence.id,
        ],
      };

    const batch =
      mergeGraphFragments([
        {
          source:
            `incident:${command.requestFingerprint}`,
          nodes: [
            evidence,
            incident,
          ],
          edges: [
            support,
          ],
        },
      ]);

    const persistenceKey =
      `hg-incident-${sha256(identityToken).slice(0, 40)}`;

    const correlationId =
      `hg-incident-${sha256(incident.logicalId).slice(0, 32)}`;

    try {
      await this.persistence.persist(
        batch,
        {
          ...this
            .persistenceOptions,
          idempotencyKey:
            persistenceKey,
          correlationId,
        },
      );
    } catch (error: unknown) {
      if (
        error instanceof
        PersistenceServiceError
      ) {
        throw new IncidentServiceError(
          "INCIDENT_PERSISTENCE_FAILED",
          503,
          "The incident graph could not be persisted and verified",
          error,
        );
      }

      throw error;
    }

    const affectedEdges =
      affectedVersions.map(
        (
          version,
        ): StandardCanonicalEdge => {
          const identity =
            createEdgeIdentity({
              kind: "AFFECTS",
              sourceLogicalId:
                incident.logicalId,
              targetLogicalId:
                version.logicalId,
              discriminator:
                "default",
            });

          return {
            ...identity,
            sourceId:
              incident.id,
            targetId:
              version.id,
            kind: "AFFECTS",
            observedAt:
              command
                .provenanceObservedAt,
            derived: false,
            identityDiscriminator:
              "default",
            evidenceIds: [
              evidence.id,
            ],
          };
        },
      );

    await this.persistAffectedEdges(
      incident.id,
      affectedEdges.map(
        serializeHydraEdge,
      ),
      persistenceKey,
      correlationId,
    );

    await this.verifyAffectedEdges(
      affectedEdges.map(
        serializeHydraEdge,
      ),
    );

    return Object.freeze({
      incidentId:
        incident.id,
      logicalId:
        incident.logicalId,
        /*
        * This service always creates a newly reported incident in active state.
        * "contained" and "closed" are valid later lifecycle transitions, but are
        * not valid creation responses under the current OpenAPI contract.
        */
      status: "active" as const,
    });
}

  private async assertReplayCompatible(
    evidenceId: number,
    evidenceLogicalId: string,
    requestFingerprint: string,
  ): Promise<void> {
    const session =
      this.driver.session();

    try {
      const result =
        await session.run(
          [
            "MATCH (e:Evidence {id: $id})",
            "RETURN e.logical_id AS logical_id,",
            "       e.detail AS detail",
          ].join("\n"),
          toHydraParameters({ id: evidenceId }),
          {
            timeout:
              this.statementTimeoutMs,
          },
        );

      if (
        result.records.length === 0
      ) {
        return;
      }

      if (
        result.records.length !== 1
      ) {
        throw new IncidentServiceError(
          "INCIDENT_IDENTITY_CONFLICT",
          409,
          "Multiple evidence nodes use the incident identity",
        );
      }

      const record =
        result.records[0];

      if (
        asString(
          record.get(
            "logical_id",
          ),
          "evidence logical identity",
        ) !== evidenceLogicalId
      ) {
        throw new IncidentServiceError(
          "INCIDENT_IDENTITY_CONFLICT",
          409,
          "The deterministic incident evidence ID is already in use",
        );
      }

      const detail =
        readRequestDetail(
          asString(
            record.get("detail"),
            "incident request detail",
          ),
        );

      if (
        detail.requestFingerprint !==
        requestFingerprint
      ) {
        throw new IncidentServiceError(
          "INCIDENT_IDEMPOTENCY_CONFLICT",
          409,
          "The Idempotency-Key is already associated with a different incident request",
        );
      }
    } catch (error: unknown) {
      if (
        error instanceof
        IncidentServiceError
      ) {
        throw error;
      }

      throw new IncidentServiceError(
        "INCIDENT_DATABASE_UNAVAILABLE",
        503,
        "HydraDB could not verify the incident identity",
        error,
      );
    } finally {
      await session.close();
    }
  }

  private async resolveAffectedVersions(
    command: IncidentCreateCommand,
  ): Promise<readonly PackageVersionReference[]> {
    const output =
      new Map<
        number,
        PackageVersionReference
      >();

    const session =
      this.driver.session();

    try {
      for (
        const release
        of command.request
          .affectedReleases
      ) {
        const result =
          await session.run(
            [
              "MATCH (v:PackageVersion)",
              "WHERE v.package_name = $package_name",
              "RETURN v.id AS id,",
              "       v.logical_id AS logical_id,",
              "       v.version AS version",
            ].join("\n"),
            toHydraParameters({
              package_name:
                release.packageName,
            }),
            {
              timeout:
                this.statementTimeoutMs,
            },
          );

        if (
          result.records.length >
          this
            .maxVersionsScannedPerPackage
        ) {
          throw new IncidentServiceError(
            "INVALID_AFFECTED_RANGE",
            400,
            `Package ${release.packageName} has too many versions to resolve safely`,
          );
        }

        const available =
          result.records.map(
            (
              record,
            ): PackageVersionReference => ({
              id:
                asSafeInteger(
                  record.get("id"),
                  "package-version ID",
                ),

              logicalId:
                asString(
                  record.get(
                    "logical_id",
                  ),
                  "package-version logical identity",
                ),

              packageName:
                release.packageName,

              version:
                asString(
                  record.get(
                    "version",
                  ),
                  "package version",
                ),
            }),
          );

        const exactVersions =
          new Set<string>();

        for (
          const requestedVersion
          of release.exactVersions ??
            []
        ) {
          const normalized =
            valid(
              requestedVersion,
            );

          if (
            normalized === null
          ) {
            throw new IncidentServiceError(
              "INVALID_AFFECTED_VERSION",
              400,
              `Invalid npm version ${requestedVersion} for ${release.packageName}`,
            );
          }

          exactVersions.add(
            normalized,
          );
        }

        let normalizedRange:
          string | null = null;

        if (
          release.affectedRange !==
          undefined
        ) {
          normalizedRange =
            validRange(
              release.affectedRange,
            );

          if (
            normalizedRange === null
          ) {
            throw new IncidentServiceError(
              "INVALID_AFFECTED_RANGE",
              400,
              `Invalid npm range for ${release.packageName}`,
            );
          }
        }

        const foundExactVersions =
          new Set<string>();

        let rangeMatches = 0;

        for (const candidate of available) {
          const normalized =
            valid(
              candidate.version,
            );

          if (
            normalized === null
          ) {
            continue;
          }

          const exactMatch =
            exactVersions.has(
              normalized,
            );

          const rangeMatch =
            normalizedRange !== null &&
            satisfies(
              normalized,
              normalizedRange,
            );

          if (
            !exactMatch &&
            !rangeMatch
          ) {
            continue;
          }

          if (exactMatch) {
            foundExactVersions.add(
              normalized,
            );
          }

          if (rangeMatch) {
            rangeMatches += 1;
          }

          output.set(
            candidate.id,
            candidate,
          );
        }

        for (
          const exactVersion
          of exactVersions
        ) {
          if (
            !foundExactVersions.has(
              exactVersion,
            )
          ) {
            throw new IncidentServiceError(
              "AFFECTED_VERSION_NOT_FOUND",
              400,
              `${release.packageName}@${exactVersion} is not present in the evidence graph`,
            );
          }
        }

        if (
          normalizedRange !== null &&
          exactVersions.size === 0 &&
          rangeMatches === 0
        ) {
          throw new IncidentServiceError(
            "AFFECTED_VERSION_NOT_FOUND",
            400,
            `No persisted versions of ${release.packageName} match the affected range`,
          );
        }
      }
    } catch (error: unknown) {
      if (
        error instanceof
        IncidentServiceError
      ) {
        throw error;
      }

      throw new IncidentServiceError(
        "INCIDENT_DATABASE_UNAVAILABLE",
        503,
        "HydraDB could not resolve affected package versions",
        error,
      );
    } finally {
      await session.close();
    }

    return Object.freeze(
      [...output.values()].sort(
        (left, right) =>
          left.id - right.id,
      ),
    );
  }

  private async persistAffectedEdges(
    incidentId: number,
    rows: readonly HydraEdgeRow[],
    persistenceKey: string,
    correlationId: string,
  ): Promise<void> {
    const assignments =
      EDGE_PROPERTY_KEYS.AFFECTS
        .map(
          (property) =>
            `r.${property} = row.${property}`,
        )
        .join(", ");

    const query = [
      "UNWIND $rows AS row",
      "MATCH (i:Incident {id: row.source_vertex}),",
      "      (v:PackageVersion {id: row.destination_vertex})",
      "MERGE (i)-[r:AFFECTS {id: row.relationship_vertex}]->(v)",
      `SET ${assignments}`,
    ].join("\n");

    const rowChunks =
      chunks(
        rows,
        this
          .affectedEdgeChunkSize,
      );

    for (
      let index = 0;
      index < rowChunks.length;
      index += 1
    ) {
      const session =
        this.driver.session();

      try {
        await session.run(
          query,
          toHydraParameters({
            rows:
              rowChunks[index].map(
                (row) => ({
                  ...row,
                }),
              ),
          }),
          {
            timeout:
              this.statementTimeoutMs,

            metadata: {
              "hydradb.correlation_id":
                correlationId,

              "hydradb.caller.step":
                `incident.affects.${index}`,

              "hydradb.idempotency_key":
                `${persistenceKey}.affects.${index}`,
            },
          },
        );
      } catch (error: unknown) {
        throw new IncidentServiceError(
          "INCIDENT_PERSISTENCE_FAILED",
          503,
          `Incident ${incidentId} AFFECTS relationships could not be persisted`,
          error,
        );
      } finally {
        await session.close();
      }
    }
  }

  private async verifyAffectedEdges(
    rows: readonly HydraEdgeRow[],
  ): Promise<void> {
    const session =
      this.driver.session();

    try {
      for (const row of rows) {
        const result =
          await session.run(
            [
              "MATCH (i:Incident {id: $source_vertex})",
              "-[:AFFECTS {",
              "  id: $relationship_vertex,",
              "  logical_id: $logical_id,",
              "  kind: $kind",
              "}]->",
              "(v:PackageVersion {id: $destination_vertex})",
              "RETURN i.id AS source_vertex,",
              "       v.id AS destination_vertex",
            ].join("\n"),
            toHydraParameters({
              source_vertex:
                row.source_vertex,

              destination_vertex:
                row.destination_vertex,

              relationship_vertex:
                row.relationship_vertex,

              logical_id:
                row.logical_id,

              kind:
                row.kind,
            }),
            {
              timeout:
                this.statementTimeoutMs,
            },
          );

        if (result.records.length !== 1) {
          throw new IncidentServiceError(
            "INCIDENT_VERIFICATION_FAILED",
            503,
            "An incident AFFECTS relationship could not be uniquely verified",
          );
        }
      }
    } finally {
      await session.close();
    }
  }
}
