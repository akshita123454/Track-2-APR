import type {
  Driver,
  Session,
} from "neo4j-driver";

import {
  toHydraParameters,
} from "../db/hydra-parameters.js";

const DEFAULT_STATEMENT_TIMEOUT_MS = 10_000;
const MAX_STATEMENT_TIMEOUT_MS = 120_000;
const MAX_PAGE_SIZE = 50;

interface RecordLike {
  get(key: string): unknown;
}

interface ResultLike {
  readonly records: readonly RecordLike[];
}

export interface PackageOverviewVersion {
  readonly id: number;
  readonly version: string;
  readonly publishedAt: number | null;
  readonly observedAt: number;
}

/** Registry declarations are possibilities, not proof of an installed version. */
export interface PackageOverviewDeclaration {
  readonly sourceVersionId: number;
  readonly sourceVersion: string;
  readonly packageName: string;
  readonly declaredRange: string;
  readonly dependencyType: string;
}

/** An exact lockfile-backed dependency edge into a package version. */
export interface PackageOverviewDependent {
  readonly rootVersionId: number;
  readonly nodeId: number;
  readonly nodeKind: string;
  readonly logicalId: string;
  readonly displayName: string;
  readonly criticality: string | null;
  readonly lockfilePath: string | null;
  readonly validFrom: number | null;
  readonly validUntil: number | null;
}

export interface PackageOverviewMaintainer {
  readonly handle: string;
  readonly email: string | null;
}

/** Other packages reachable through a shared publishing authority. */
export interface PackageOverviewAuthorityPackage {
  readonly maintainerHandle: string;
  readonly packageName: string;
}

export interface PackageOverviewIncident {
  readonly id: number;
  readonly title: string;
  readonly status: string;
  readonly intervalStart: number;
  readonly intervalEnd: number | null;
}

export interface PackageOverviewRead {
  readonly engine: "HydraDB";
  readonly readEpoch: string;
  readonly queryCount: number;
  readonly rowsRead: number;
  readonly latencyMs: number;
  readonly consistencyModel: "bounded-multi-statement-read";
}

export interface PackageOverview {
  readonly packageName: string;
  readonly found: boolean;
  readonly versions: readonly PackageOverviewVersion[];
  readonly declarations: readonly PackageOverviewDeclaration[];
  readonly dependents: readonly PackageOverviewDependent[];
  readonly maintainers: readonly PackageOverviewMaintainer[];
  readonly authorityPackages: readonly PackageOverviewAuthorityPackage[];
  readonly incidents: readonly PackageOverviewIncident[];
  readonly truncated: boolean;
  readonly hydraRead: PackageOverviewRead;
}

export type PackageOverviewStoreErrorCode =
  | "DATABASE_QUERY_FAILED"
  | "DATABASE_RESULT_INVALID"
  | "PACKAGE_OVERVIEW_CORRUPT";

export class PackageOverviewStoreError extends Error {
  public constructor(
    readonly code: PackageOverviewStoreErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PackageOverviewStoreError";
  }
}

export interface PackageOverviewStoreOptions {
  readonly statementTimeoutMs?: number;
  readonly sessionFactory?: () => Session;
  readonly clock?: () => number;
}

function asResultLike(value: unknown): ResultLike {
  if (
    typeof value !== "object" ||
    value === null ||
    !("records" in value) ||
    !Array.isArray(value.records)
  ) {
    throw new PackageOverviewStoreError(
      "DATABASE_RESULT_INVALID",
      "HydraDB returned a result without a records array.",
    );
  }

  for (const record of value.records) {
    if (
      typeof record !== "object" ||
      record === null ||
      !("get" in record) ||
      typeof record.get !== "function"
    ) {
      throw new PackageOverviewStoreError(
        "DATABASE_RESULT_INVALID",
        "HydraDB returned an invalid graph record.",
      );
    }
  }

  return value as ResultLike;
}

function asSafeInteger(value: unknown, field: string): number {
  const converted =
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
      ? value.toNumber()
      : value;

  if (
    typeof converted !== "number" ||
    !Number.isSafeInteger(converted) ||
    converted < 0
  ) {
    throw new PackageOverviewStoreError(
      "PACKAGE_OVERVIEW_CORRUPT",
      `Stored ${field} is not a nonnegative safe integer.`,
    );
  }

  return converted;
}

function asOptionalSafeInteger(
  value: unknown,
  field: string,
): number | null {
  if (value === null || value === undefined) {
    return null;
  }

  return asSafeInteger(value, field);
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new PackageOverviewStoreError(
      "PACKAGE_OVERVIEW_CORRUPT",
      `Stored ${field} is not a nonempty string.`,
    );
  }

  return value;
}

function assertPackageName(value: string): void {
  if (
    value.length < 1 ||
    value.length > 214 ||
    /\s|\\|\?|#/.test(value)
  ) {
    throw new RangeError("packageName is not a valid npm package name.");
  }
}

function assertLimit(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_PAGE_SIZE) {
    throw new RangeError(
      `limit must be a positive safe integer not greater than ${MAX_PAGE_SIZE}.`,
    );
  }
}

function buildVersionsQuery(fetchLimit: number): string {
  return [
    "MATCH (version:PackageVersion {package_name: $package_name})",
    "RETURN version.id AS version_id,",
    "       version.version AS version,",
    "       version.published_at AS published_at,",
    "       version.has_published_at AS has_published_at,",
    "       version.observed_at AS observed_at",
    "ORDER BY version.observed_at DESC, version_id DESC",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildDeclarationsQuery(fetchLimit: number): string {
  return [
    "MATCH (source:PackageVersion {id: $version_id})",
    "-[dependency:DECLARES_DEPENDENCY]->",
    "(target:Package)",
    "RETURN source.id AS source_version_id,",
    "       source.version AS source_version,",
    "       target.name AS target_package_name,",
    "       dependency.declared_range AS declared_range,",
    "       dependency.dependency_type AS dependency_type",
    "ORDER BY target_package_name, dependency_type",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildDependentsQuery(fetchLimit: number): string {
  return [
    "MATCH (root:PackageVersion {id: $version_id})",
    "-[reverse:USED_BY]->(dependent)",
    "OPTIONAL MATCH (dependent)-[canonical:DEPENDS_ON]->(root)",
    "WHERE canonical.id = reverse.derived_from",
    "RETURN root.id AS root_version_id,",
    "       dependent.id AS dependent_id,",
    "       dependent.kind AS dependent_kind,",
    "       dependent.logical_id AS dependent_logical_id,",
    "       dependent.name AS dependent_name,",
    "       dependent.package_name AS dependent_package_name,",
    "       dependent.version AS dependent_version,",
    "       dependent.criticality AS dependent_criticality,",
    "       canonical.lockfile_path AS lockfile_path,",
    "       canonical.valid_from AS valid_from,",
    "       canonical.has_valid_from AS has_valid_from,",
    "       canonical.valid_until AS valid_until,",
    "       canonical.has_valid_until AS has_valid_until",
    "ORDER BY dependent_kind, dependent_logical_id",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildMaintainersQuery(fetchLimit: number): string {
  return [
    "MATCH (maintainer:Maintainer)-[:MAINTAINS]->",
    "(pkg:Package {name: $package_name})",
    "RETURN maintainer.handle AS handle,",
    "       maintainer.email AS email,",
    "       maintainer.has_email AS has_email",
    "ORDER BY handle",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildAuthorityPackagesQuery(fetchLimit: number): string {
  return [
    "MATCH (maintainer:Maintainer)-[:MAINTAINS]->",
    "(pkg:Package {name: $package_name})",
    "MATCH (maintainer)-[:MAINTAINS]->(related:Package)",
    "WHERE related.name <> $package_name",
    "RETURN maintainer.handle AS maintainer_handle,",
    "       related.name AS related_package_name",
    "ORDER BY maintainer_handle, related_package_name",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

function buildIncidentsQuery(fetchLimit: number): string {
  return [
    "MATCH (incident:Incident)-[:AFFECTS]->",
    "(version:PackageVersion {id: $version_id})",
    "RETURN incident.id AS incident_id,",
    "       incident.title AS incident_title,",
    "       incident.status AS incident_status,",
    "       incident.interval_start AS interval_start,",
    "       incident.interval_end AS interval_end,",
    "       incident.has_interval_end AS has_interval_end",
    "ORDER BY interval_start DESC, incident_id DESC",
    `LIMIT ${fetchLimit}`,
  ].join("\n");
}

/**
 * Bounded, read-only package investigation projection.
 *
 * It deliberately keeps registry declarations and lockfile-backed exact
 * dependencies separate: a declaration says what a release may request;
 * a DEPENDS_ON edge says what an internal service or version actually
 * resolved. All query inputs are parameters and every fan-out has a limit.
 */
export class HydraPackageOverviewStore {
  private readonly statementTimeoutMs: number;
  private readonly sessionFactory: () => Session;
  private readonly clock: () => number;
  private queryCount = 0;
  private rowsRead = 0;

  public constructor(
    driver: Driver,
    options: PackageOverviewStoreOptions = {},
  ) {
    this.statementTimeoutMs = options.statementTimeoutMs ?? DEFAULT_STATEMENT_TIMEOUT_MS;
    if (
      !Number.isSafeInteger(this.statementTimeoutMs) ||
      this.statementTimeoutMs < 100 ||
      this.statementTimeoutMs > MAX_STATEMENT_TIMEOUT_MS
    ) {
      throw new RangeError("statementTimeoutMs is outside its permitted range.");
    }

    this.sessionFactory = options.sessionFactory ?? (() => driver.session());
    this.clock = options.clock ?? Date.now;
  }

  public async investigate(
    packageName: string,
    limit: number,
  ): Promise<PackageOverview> {
    assertPackageName(packageName);
    assertLimit(limit);

    const startedAt = this.clock();
    const readEpoch = new Date(startedAt).toISOString();
    this.queryCount = 0;
    this.rowsRead = 0;

    const versionRows = await this.runQuery(
      buildVersionsQuery(limit + 1),
      { package_name: packageName },
      "package-overview.versions",
      readEpoch,
    );

    const presentVersions = versionRows.filter(
      (record) => record.get("version_id") !== null && record.get("version_id") !== undefined,
    );
    const truncated = presentVersions.length > limit;
    const versions = presentVersions.slice(0, limit).map((record) => {
      const hasPublishedAt = record.get("has_published_at") === true;
      return Object.freeze({
        id: asSafeInteger(record.get("version_id"), "version.id"),
        version: asString(record.get("version"), "version.version"),
        publishedAt: hasPublishedAt
          ? asSafeInteger(record.get("published_at"), "version.published_at")
          : null,
        observedAt: asSafeInteger(record.get("observed_at"), "version.observed_at"),
      });
    });

    if (versions.length === 0) {
      return Object.freeze({
        packageName,
        found: false,
        versions: Object.freeze([]),
        declarations: Object.freeze([]),
        dependents: Object.freeze([]),
        maintainers: Object.freeze([]),
        authorityPackages: Object.freeze([]),
        incidents: Object.freeze([]),
        truncated: false,
        hydraRead: this.diagnostics(readEpoch, startedAt),
      });
    }

    const maintainerRows = await this.runQuery(
      buildMaintainersQuery(limit + 1),
      { package_name: packageName },
      "package-overview.maintainers",
      readEpoch,
    );
    const maintainers = maintainerRows
      .filter((record) => record.get("handle") !== null && record.get("handle") !== undefined)
      .slice(0, limit)
      .map((record) => Object.freeze({
        handle: asString(record.get("handle"), "maintainer.handle"),
        email: record.get("has_email") === true
          ? asString(record.get("email"), "maintainer.email")
          : null,
      }));

    const authorityRows = await this.runQuery(
      buildAuthorityPackagesQuery(limit + 1),
      { package_name: packageName },
      "package-overview.authority-packages",
      readEpoch,
    );
    const authorityPackages = authorityRows
      .filter((record) => record.get("related_package_name") !== null && record.get("related_package_name") !== undefined)
      .slice(0, limit)
      .map((record) => Object.freeze({
        maintainerHandle: asString(record.get("maintainer_handle"), "authority.maintainer_handle"),
        packageName: asString(record.get("related_package_name"), "authority.related_package_name"),
      }));

    const declarations: PackageOverviewDeclaration[] = [];
    const dependents: PackageOverviewDependent[] = [];
    const incidentsById = new Map<number, PackageOverviewIncident>();

    for (const version of versions) {
      const declarationRows = await this.runQuery(
        buildDeclarationsQuery(limit + 1),
        { version_id: version.id },
        "package-overview.declarations",
        readEpoch,
      );
      for (const record of declarationRows.slice(0, limit)) {
        if (record.get("source_version_id") === null || record.get("source_version_id") === undefined) continue;
        declarations.push(Object.freeze({
          sourceVersionId: asSafeInteger(record.get("source_version_id"), "declaration.source_version_id"),
          sourceVersion: asString(record.get("source_version"), "declaration.source_version"),
          packageName: asString(record.get("target_package_name"), "declaration.target_package_name"),
          declaredRange: asString(record.get("declared_range"), "declaration.declared_range"),
          dependencyType: asString(record.get("dependency_type"), "declaration.dependency_type"),
        }));
      }

      const dependentRows = await this.runQuery(
        buildDependentsQuery(limit + 1),
        { version_id: version.id },
        "package-overview.dependents",
        readEpoch,
      );
      for (const record of dependentRows.slice(0, limit)) {
        if (record.get("dependent_id") === null || record.get("dependent_id") === undefined) continue;
        const kind = asString(record.get("dependent_kind"), "dependent.kind");
        const packageNameValue = record.get("dependent_package_name");
        const versionValue = record.get("dependent_version");
        const nameValue = record.get("dependent_name");
        const displayName = kind === "PackageVersion" &&
          typeof packageNameValue === "string" && typeof versionValue === "string"
          ? `${packageNameValue}@${versionValue}`
          : asString(nameValue, "dependent.name");

        dependents.push(Object.freeze({
          rootVersionId: version.id,
          nodeId: asSafeInteger(record.get("dependent_id"), "dependent.id"),
          nodeKind: kind,
          logicalId: asString(record.get("dependent_logical_id"), "dependent.logical_id"),
          displayName,
          criticality: record.get("dependent_criticality") === null || record.get("dependent_criticality") === undefined
            ? null
            : asString(record.get("dependent_criticality"), "dependent.criticality"),
          lockfilePath: record.get("lockfile_path") === null || record.get("lockfile_path") === undefined
            ? null
            : asString(record.get("lockfile_path"), "dependent.lockfile_path"),
          validFrom: record.get("has_valid_from") === true
            ? asSafeInteger(record.get("valid_from"), "dependent.valid_from")
            : null,
          validUntil: record.get("has_valid_until") === true
            ? asSafeInteger(record.get("valid_until"), "dependent.valid_until")
            : null,
        }));
      }

      const incidentRows = await this.runQuery(
        buildIncidentsQuery(limit + 1),
        { version_id: version.id },
        "package-overview.incidents",
        readEpoch,
      );
      for (const record of incidentRows.slice(0, limit)) {
        if (record.get("incident_id") === null || record.get("incident_id") === undefined) continue;
        const id = asSafeInteger(record.get("incident_id"), "incident.id");
        incidentsById.set(id, Object.freeze({
          id,
          title: asString(record.get("incident_title"), "incident.title"),
          status: asString(record.get("incident_status"), "incident.status"),
          intervalStart: asSafeInteger(record.get("interval_start"), "incident.interval_start"),
          intervalEnd: record.get("has_interval_end") === true
            ? asSafeInteger(record.get("interval_end"), "incident.interval_end")
            : null,
        }));
      }
    }

    return Object.freeze({
      packageName,
      found: true,
      versions: Object.freeze(versions),
      declarations: Object.freeze(declarations.slice(0, limit)),
      dependents: Object.freeze(dependents.slice(0, limit)),
      maintainers: Object.freeze(maintainers),
      authorityPackages: Object.freeze(authorityPackages),
      incidents: Object.freeze([...incidentsById.values()].slice(0, limit)),
      truncated,
      hydraRead: this.diagnostics(readEpoch, startedAt),
    });
  }

  private diagnostics(readEpoch: string, startedAt: number): PackageOverviewRead {
    return Object.freeze({
      engine: "HydraDB",
      readEpoch,
      queryCount: this.queryCount,
      rowsRead: this.rowsRead,
      latencyMs: Math.max(0, this.clock() - startedAt),
      consistencyModel: "bounded-multi-statement-read",
    });
  }

  private async runQuery(
    query: string,
    parameters: Readonly<Record<string, unknown>>,
    operation: string,
    readEpoch: string,
  ): Promise<readonly RecordLike[]> {
    let session: Session;
    try {
      session = this.sessionFactory();
    } catch (error) {
      throw new PackageOverviewStoreError(
        "DATABASE_QUERY_FAILED",
        `Could not open a HydraDB session for ${operation}.`,
        error,
      );
    }

    try {
      const result = await session.run(
        query,
        toHydraParameters(parameters),
        {
          timeout: this.statementTimeoutMs,
          metadata: {
            "hydradb.caller.step": operation,
            "hydraguard.read_epoch": readEpoch,
          },
        },
      );
      const normalized = asResultLike(result);
      this.queryCount += 1;
      this.rowsRead += normalized.records.length;
      return normalized.records;
    } catch (error) {
      if (error instanceof PackageOverviewStoreError) throw error;
      throw new PackageOverviewStoreError(
        "DATABASE_QUERY_FAILED",
        `HydraDB read failed during ${operation}.`,
        error,
      );
    } finally {
      try {
        await session.close();
      } catch (error) {
        throw new PackageOverviewStoreError(
          "DATABASE_QUERY_FAILED",
          `HydraDB session close failed after ${operation}.`,
          error,
        );
      }
    }
  }
}
