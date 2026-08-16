import type {
  DependencyType,
} from "../../domain/schema.js";

import type {
  LockfileIssue,
  PackageLockVersion,
  ParsePackageLockOptions,
  ParsedLockPackage,
  ParsedPackageLock,
  ResolvedLockDependency,
} from "./package-lock-types.js";

type UnknownRecord = Record<string, unknown>;
type StringMap = Readonly<Record<string, string>>;

interface InternalEntry {
  readonly installPath: string;
  readonly effectivePath: string;
  readonly linkTarget?: string;

  readonly name?: string;
  readonly version?: string;
  readonly resolved?: string;
  readonly integrity?: string;

  readonly link: boolean;
  readonly dev: boolean;
  readonly optional: boolean;

  readonly dependencies?: StringMap;
  readonly devDependencies?: StringMap;
  readonly optionalDependencies?: StringMap;
  readonly peerDependencies?: StringMap;
}

interface DependencyDeclaration {
  readonly name: string;
  readonly range: string;
  readonly dependencyType: DependencyType;
}

function isRecord(value: unknown): value is UnknownRecord {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function readOptionalString(
  owner: string,
  value: unknown,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== "string") {
    throw new Error(`${owner} must be a string`);
  }

  return value;
}

function readOptionalBoolean(
  owner: string,
  value: unknown,
): boolean {
  if (value === undefined) {
    return false;
  }

  if (typeof value !== "boolean") {
    throw new Error(`${owner} must be a boolean`);
  }

  return value;
}

function readOptionalStringMap(
  owner: string,
  value: unknown,
): StringMap | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error(`${owner} must be an object`);
  }

  const result: Record<string, string> = {};

  for (const [name, range] of Object.entries(value)) {
    if (typeof range !== "string" || range.length === 0) {
      throw new Error(`${owner}.${name} must be a nonempty string`);
    }

    result[name] = range;
  }

  return result;
}

function normalizeInstallPath(path: string): string {
  if (path === "") {
    return "";
  }

  if (
    path.includes("\\") ||
    path.startsWith("/") ||
    /^[A-Za-z]:/.test(path)
  ) {
    throw new Error(`Unsafe package-lock path: "${path}"`);
  }

  const segments = path.split("/");

  if (
    segments.some(
      (segment) =>
        segment.length === 0 ||
        segment === "." ||
        segment === "..",
    )
  ) {
    throw new Error(`Invalid package-lock path: "${path}"`);
  }

  return segments.join("/");
}

function derivePackageNameFromPath(
  installPath: string,
): string | undefined {
  const marker = "node_modules/";

  const markerIndex = installPath.lastIndexOf(marker);

  if (markerIndex < 0) {
    return undefined;
  }

  const remainder = installPath.slice(
    markerIndex + marker.length,
  );

  const segments = remainder.split("/");

  if (segments[0]?.startsWith("@")) {
    return segments.length >= 2
      ? `${segments[0]}/${segments[1]}`
      : undefined;
  }

  return segments[0];
}

function readEntry(
  installPath: string,
  value: unknown,
): InternalEntry {
  if (!isRecord(value)) {
    throw new Error(
      `package-lock packages["${installPath}"] must be an object`,
    );
  }

  const link = readOptionalBoolean(
    `packages["${installPath}"].link`,
    value.link,
  );

  const resolved = readOptionalString(
    `packages["${installPath}"].resolved`,
    value.resolved,
  );

  if (link && resolved === undefined) {
    throw new Error(
      `Linked package ${installPath} must have a resolved target`,
    );
  }

  return {
    installPath,
    effectivePath: installPath,
    name: readOptionalString(
      `packages["${installPath}"].name`,
      value.name,
    ),
    version: readOptionalString(
      `packages["${installPath}"].version`,
      value.version,
    ),
    resolved,
    integrity: readOptionalString(
      `packages["${installPath}"].integrity`,
      value.integrity,
    ),
    link,
    dev: readOptionalBoolean(
      `packages["${installPath}"].dev`,
      value.dev,
    ),
    optional: readOptionalBoolean(
      `packages["${installPath}"].optional`,
      value.optional,
    ),
    dependencies: readOptionalStringMap(
      `packages["${installPath}"].dependencies`,
      value.dependencies,
    ),
    devDependencies: readOptionalStringMap(
      `packages["${installPath}"].devDependencies`,
      value.devDependencies,
    ),
    optionalDependencies: readOptionalStringMap(
      `packages["${installPath}"].optionalDependencies`,
      value.optionalDependencies,
    ),
    peerDependencies: readOptionalStringMap(
      `packages["${installPath}"].peerDependencies`,
      value.peerDependencies,
    ),
  };
}

function mergeLinkedEntry(
  linkEntry: InternalEntry,
  targetEntry: InternalEntry,
  targetPath: string,
): InternalEntry {
  return {
    ...targetEntry,
    installPath: linkEntry.installPath,
    effectivePath: targetEntry.effectivePath,
    linkTarget: targetPath,
    link: true,

    /*
     * Placement flags belong to the link location when present.
     */
    dev: linkEntry.dev || targetEntry.dev,
    optional: linkEntry.optional || targetEntry.optional,
  };
}

function collectDeclarations(
  entry: InternalEntry,
): readonly DependencyDeclaration[] {
  const declarations = new Map<
    string,
    DependencyDeclaration
  >();

  const add = (
    dependencies: StringMap | undefined,
    dependencyType: DependencyType,
  ): void => {
    if (dependencies === undefined) {
      return;
    }

    for (const [name, range] of Object.entries(dependencies)) {
      declarations.set(name, {
        name,
        range,
        dependencyType,
      });
    }
  };

  /*
   * Root projects and workspace packages may have installed
   * development dependencies. Published node_modules packages do not
   * bring their own devDependencies into a consuming application.
   */
  const includeDevelopmentDependencies =
    entry.installPath === "" ||
    !entry.effectivePath.includes("node_modules/");

  if (includeDevelopmentDependencies) {
    add(entry.devDependencies, "development");
  }

  add(entry.peerDependencies, "peer");
  add(entry.dependencies, "production");

  /*
   * optionalDependencies override dependencies of the same name.
   */
  add(entry.optionalDependencies, "optional");

  return [...declarations.values()];
}

function dependencyCandidatePaths(
  sourcePath: string,
  dependencyName: string,
): readonly string[] {
  const candidates: string[] = [];
  let currentPath = sourcePath;

  while (true) {
    candidates.push(
      currentPath === ""
        ? `node_modules/${dependencyName}`
        : `${currentPath}/node_modules/${dependencyName}`,
    );

    if (currentPath === "") {
      break;
    }

    const finalSlash = currentPath.lastIndexOf("/");

    currentPath =
      finalSlash < 0
        ? ""
        : currentPath.slice(0, finalSlash);
  }

  return candidates;
}

function resolveDependencyPath(
  source: InternalEntry,
  dependencyName: string,
  entries: ReadonlyMap<string, InternalEntry>,
): string | undefined {
  const searchBases = [
    source.effectivePath,
    source.installPath,
  ];

  const visitedCandidates = new Set<string>();

  for (const basePath of searchBases) {
    for (
      const candidate of dependencyCandidatePaths(
        basePath,
        dependencyName,
      )
    ) {
      if (visitedCandidates.has(candidate)) {
        continue;
      }

      visitedCandidates.add(candidate);

      if (entries.has(candidate)) {
        return candidate;
      }
    }
  }

  return undefined;
}

export function parsePackageLock(
  value: unknown,
  options: ParsePackageLockOptions = {},
): ParsedPackageLock {
  if (!isRecord(value)) {
    throw new Error("package-lock content must be an object");
  }

  const lockfileVersionValue = value.lockfileVersion;

  if (
    lockfileVersionValue !== 2 &&
    lockfileVersionValue !== 3
  ) {
    throw new Error(
      `Only package-lock versions 2 and 3 are supported; received ` +
        `${String(lockfileVersionValue)}`,
    );
  }

  const lockfileVersion: PackageLockVersion =
    lockfileVersionValue;

  if (!isRecord(value.packages)) {
    throw new Error(
      "package-lock v2/v3 must contain a packages object",
    );
  }

  const maxPackages = options.maxPackages ?? 10_000;

  if (
    !Number.isInteger(maxPackages) ||
    maxPackages < 1 ||
    maxPackages > 100_000
  ) {
    throw new Error(
      "maxPackages must be an integer between 1 and 100000",
    );
  }

  const rawEntries = new Map<string, InternalEntry>();

  for (const [rawPath, rawEntry] of Object.entries(value.packages)) {
    const installPath = normalizeInstallPath(rawPath);

    if (rawEntries.has(installPath)) {
      throw new Error(
        `Duplicate normalized package-lock path: ${installPath}`,
      );
    }

    rawEntries.set(
      installPath,
      readEntry(installPath, rawEntry),
    );
  }

  const nonRootCount = [...rawEntries.keys()].filter(
    (path) => path !== "",
  ).length;

  if (nonRootCount > maxPackages) {
    throw new Error(
      `package-lock contains ${nonRootCount} package entries; ` +
        `maximum is ${maxPackages}`,
    );
  }

  const rootEntry = rawEntries.get("");

  if (rootEntry === undefined) {
    throw new Error(
      'package-lock packages must contain the root entry ""',
    );
  }

  const resolvedEntries = new Map<string, InternalEntry>();
  const resolving = new Set<string>();

  const resolveEntry = (path: string): InternalEntry => {
    const cached = resolvedEntries.get(path);

    if (cached !== undefined) {
      return cached;
    }

    const entry = rawEntries.get(path);

    if (entry === undefined) {
      throw new Error(`Unknown package-lock path: ${path}`);
    }

    if (!entry.link) {
      resolvedEntries.set(path, entry);
      return entry;
    }

    if (resolving.has(path)) {
      throw new Error(`Cyclic package-lock link at ${path}`);
    }

    resolving.add(path);

    const targetPath = normalizeInstallPath(entry.resolved!);
    const target = rawEntries.get(targetPath);

    if (target === undefined) {
      throw new Error(
        `Linked package ${path} targets missing path ${targetPath}`,
      );
    }

    const effectiveTarget = resolveEntry(targetPath);
    const merged = mergeLinkedEntry(
      entry,
      effectiveTarget,
      targetPath,
    );

    resolving.delete(path);
    resolvedEntries.set(path, merged);

    return merged;
  };

  for (const path of rawEntries.keys()) {
    resolveEntry(path);
  }

  const packages: ParsedLockPackage[] = [];
  const packageByPath = new Map<string, ParsedLockPackage>();
  const issues: LockfileIssue[] = [];

  for (const [installPath, entry] of resolvedEntries) {
    if (installPath === "") {
      continue;
    }

    const name =
      entry.name ?? derivePackageNameFromPath(installPath);

    if (name === undefined) {
      issues.push({
        severity: "error",
        code: "MISSING_PACKAGE_VERSION",
        message:
          `Unable to determine package name for ${installPath}`,
        sourcePath: installPath,
      });

      continue;
    }

    if (entry.version === undefined) {
      issues.push({
        severity: "error",
        code: "MISSING_PACKAGE_VERSION",
        message:
          `Package ${name} at ${installPath} has no version`,
        sourcePath: installPath,
      });

      continue;
    }

    const parsedPackage: ParsedLockPackage = {
      installPath,
      effectivePath: entry.effectivePath,
      ...(entry.linkTarget === undefined
        ? {}
        : { linkTarget: entry.linkTarget }),
      name,
      version: entry.version,
      ...(entry.resolved === undefined
        ? {}
        : { resolved: entry.resolved }),
      ...(entry.integrity === undefined
        ? {}
        : { integrity: entry.integrity }),
      dev: entry.dev,
      optional: entry.optional,
    };

    packages.push(parsedPackage);
    packageByPath.set(installPath, parsedPackage);
  }

  const resolutions: ResolvedLockDependency[] = [];

  for (const [sourcePath, sourceEntry] of resolvedEntries) {
    const declarations = collectDeclarations(sourceEntry);

    for (const declaration of declarations) {
      const targetPath = resolveDependencyPath(
        sourceEntry,
        declaration.name,
        resolvedEntries,
      );

      if (
        targetPath === undefined ||
        !packageByPath.has(targetPath)
      ) {
        const nonFatal =
          declaration.dependencyType === "optional" ||
          declaration.dependencyType === "peer";

        issues.push({
          severity: nonFatal ? "warning" : "error",
          code: "UNRESOLVED_DEPENDENCY",
          message:
            `Could not resolve ${declaration.name}@${declaration.range} ` +
            `from ${sourcePath || "<root>"}`,
          sourcePath,
          dependencyName: declaration.name,
        });

        continue;
      }

      resolutions.push({
        sourcePath,
        targetPath,
        dependencyName: declaration.name,
        declaredRange: declaration.range,
        dependencyType: declaration.dependencyType,
      });
    }
  }

  return {
    name:
      typeof value.name === "string"
        ? value.name
        : rootEntry.name,
    version:
      typeof value.version === "string"
        ? value.version
        : rootEntry.version,
    lockfileVersion,
    packages,
    resolutions,
    issues,
  };
}
