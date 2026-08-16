import type {
  DependencyType,
} from "../../domain/schema.js";

export type PackageLockVersion = 2 | 3;

export type LockfileIssueSeverity = "warning" | "error";

export interface LockfileIssue {
  readonly severity: LockfileIssueSeverity;
  readonly code:
    | "UNRESOLVED_DEPENDENCY"
    | "MISSING_PACKAGE_VERSION"
    | "INVALID_LINK_TARGET";
  readonly message: string;
  readonly sourcePath?: string;
  readonly dependencyName?: string;
}

export interface ParsedLockPackage {
  /**
   * Location inside the lockfile packages map.
   *
   * Examples:
   * node_modules/auth-lib
   * node_modules/auth-lib/node_modules/bad-lib
   */
  readonly installPath: string;

  /**
   * For workspace links, this points to the actual workspace path.
   */
  readonly effectivePath: string;
  readonly linkTarget?: string;

  readonly name: string;
  readonly version: string;
  readonly resolved?: string;
  readonly integrity?: string;

  readonly dev: boolean;
  readonly optional: boolean;
}

export interface ResolvedLockDependency {
  /**
   * Empty sourcePath means the root Service.
   */
  readonly sourcePath: string;
  readonly targetPath: string;
  readonly dependencyName: string;
  readonly declaredRange: string;
  readonly dependencyType: DependencyType;
}

export interface ParsedPackageLock {
  readonly name?: string;
  readonly version?: string;
  readonly lockfileVersion: PackageLockVersion;
  readonly packages: readonly ParsedLockPackage[];
  readonly resolutions: readonly ResolvedLockDependency[];
  readonly issues: readonly LockfileIssue[];
}

export interface ParsePackageLockOptions {
  readonly maxPackages?: number;
}
