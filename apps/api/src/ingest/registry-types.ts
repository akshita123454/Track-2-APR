export interface NpmMaintainer {
  readonly name: string;
  readonly email?: string;
}

export interface NpmDistribution {
  readonly shasum?: string;
  readonly tarball?: string;
  readonly integrity?: string;
}

export interface NpmRegistryVersion {
  readonly name: string;
  readonly version: string;
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
  readonly peerDependencies?: Readonly<Record<string, string>>;
  readonly optionalDependencies?: Readonly<Record<string, string>>;
  readonly deprecated?: string;
  readonly dist?: NpmDistribution;
}

export interface NpmRegistryPackage {
  readonly name: string;
  readonly versions: Readonly<Record<string, NpmRegistryVersion>>;
  readonly time?: Readonly<Record<string, string>>;
  readonly distTags?: Readonly<Record<string, string>>;
  readonly maintainers?: readonly NpmMaintainer[];
}

export interface NpmRegistryFetchResult {
  readonly metadata: NpmRegistryPackage;
  readonly sourceUri: string;
  readonly observedAt: number;
  readonly contentSha256: string;
  readonly etag?: string;
  readonly lastModified?: string;
}

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function readOptionalStringRecord(
  owner: string,
  value: unknown,
): Readonly<Record<string, string>> | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error(`${owner} must be an object`);
  }

  const result: Record<string, string> = {};

  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== "string") {
      throw new Error(`${owner}.${key} must be a string`);
    }

    result[key] = entry;
  }

  return result;
}

function readMaintainers(value: unknown): readonly NpmMaintainer[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value)) {
    throw new Error("npm maintainers must be an array");
  }

  return value.map((entry, index) => {
    if (!isRecord(entry) || typeof entry.name !== "string") {
      throw new Error(`npm maintainers[${index}].name must be a string`);
    }

    if (
      entry.email !== undefined &&
      typeof entry.email !== "string"
    ) {
      throw new Error(`npm maintainers[${index}].email must be a string`);
    }

    return {
      name: entry.name,
      ...(entry.email === undefined ? {} : { email: entry.email }),
    };
  });
}

function readDistribution(value: unknown): NpmDistribution | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error("npm version dist must be an object");
  }

  for (const key of ["shasum", "tarball", "integrity"] as const) {
    if (value[key] !== undefined && typeof value[key] !== "string") {
      throw new Error(`npm version dist.${key} must be a string`);
    }
  }

  return {
    ...(typeof value.shasum === "string"
      ? { shasum: value.shasum }
      : {}),
    ...(typeof value.tarball === "string"
      ? { tarball: value.tarball }
      : {}),
    ...(typeof value.integrity === "string"
      ? { integrity: value.integrity }
      : {}),
  };
}

export function parseNpmRegistryPackage(
  value: unknown,
): NpmRegistryPackage {
  if (!isRecord(value)) {
    throw new Error("npm registry response must be an object");
  }

  if (typeof value.name !== "string" || value.name.length === 0) {
    throw new Error("npm registry response is missing package name");
  }

  if (!isRecord(value.versions)) {
    throw new Error("npm registry response is missing versions");
  }

  const versions: Record<string, NpmRegistryVersion> = {};

  for (const [versionKey, rawVersion] of Object.entries(value.versions)) {
    if (!isRecord(rawVersion)) {
      throw new Error(`npm version ${versionKey} must be an object`);
    }

    const version =
      typeof rawVersion.version === "string"
        ? rawVersion.version
        : versionKey;

    if (version !== versionKey) {
      throw new Error(
        `npm version key ${versionKey} disagrees with payload version ${version}`,
      );
    }

    const name =
      typeof rawVersion.name === "string"
        ? rawVersion.name
        : value.name;

    versions[versionKey] = {
      name,
      version,
      dependencies: readOptionalStringRecord(
        `versions.${versionKey}.dependencies`,
        rawVersion.dependencies,
      ),
      devDependencies: readOptionalStringRecord(
        `versions.${versionKey}.devDependencies`,
        rawVersion.devDependencies,
      ),
      peerDependencies: readOptionalStringRecord(
        `versions.${versionKey}.peerDependencies`,
        rawVersion.peerDependencies,
      ),
      optionalDependencies: readOptionalStringRecord(
        `versions.${versionKey}.optionalDependencies`,
        rawVersion.optionalDependencies,
      ),
      ...(typeof rawVersion.deprecated === "string"
        ? { deprecated: rawVersion.deprecated }
        : {}),
      ...(rawVersion.dist === undefined
        ? {}
        : { dist: readDistribution(rawVersion.dist) }),
    };
  }

  return {
    name: value.name,
    versions,
    time: readOptionalStringRecord("time", value.time),
    distTags: readOptionalStringRecord("dist-tags", value["dist-tags"]),
    maintainers: readMaintainers(value.maintainers),
  };
}
