export type LockfileFormat =
  | 'npm' // package-lock.json / npm-shrinkwrap.json
  | 'pnpm' // pnpm-lock.yaml
  | 'yarn-classic' // yarn.lock v1
  | 'yarn-berry' // yarn.lock v2+
  | 'bun'; // bun.lock (text)

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun';

/** One resolved package version found in a lockfile. */
export interface LockedPackage {
  name: string;
  version: string;
  /** True when the package is listed as a direct dependency of a workspace/root. Undefined when unknown. */
  direct?: boolean;
  /** True when only reachable through devDependencies. Undefined when the lockfile does not say. */
  dev?: boolean;
  optional?: boolean;
  /** The lockfile records that this package runs install scripts. Undefined when the lockfile does not say. */
  hasInstallScript?: boolean;
  /** Where the lockfile says the package came from, if not the default npm registry. */
  source?: 'registry' | 'git' | 'file' | 'url' | 'other-registry';
}

export interface ParsedLockfile {
  format: LockfileFormat;
  manager: PackageManager;
  lockfileVersion: string;
  packages: LockedPackage[];
  /** Entries that cannot be checked against the public registry (git, file, links, workspaces). */
  skipped: { name: string; spec: string; reason: string }[];
  warnings: string[];
}

export type Severity = 'critical' | 'high' | 'moderate' | 'low' | 'unknown';

export interface Advisory {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  malware: boolean;
  /** Lowest version that fixes the advisory for this package, when OSV knows it. */
  fixedIn?: string;
  url: string;
  published?: string;
}

export type LicenseKind = 'permissive' | 'weak-copyleft' | 'strong-copyleft' | 'unknown' | 'none';

export interface PackageMeta {
  /** ISO timestamp of when this exact version was published. */
  publishedAt?: string;
  deprecated?: string;
  licenses: string[];
  licenseKind: LicenseKind;
  provenance: boolean;
  /** The version could not be found on the public npm registry. */
  missing: boolean;
  /** The registry recorded that this version was unpublished. */
  unpublished?: boolean;
}

export type FindingKind =
  'malware' | 'vulnerability' | 'missing' | 'fresh' | 'install-script' | 'deprecated' | 'copyleft';

export interface PackageReport extends LockedPackage {
  key: string;
  advisories: Advisory[];
  meta?: PackageMeta;
  /** Age of this version in days at scan time. */
  ageDays?: number;
  flags: FindingKind[];
}

export interface ScanSummary {
  total: number;
  malware: number;
  vulnerable: number;
  vulnsBySeverity: Record<Severity, number>;
  missing: number;
  fresh: number;
  installScripts: number;
  deprecated: number;
  copyleft: number;
  provenance: number;
  licenses: Record<LicenseKind, number>;
}

export interface ScanReport {
  tool: { name: 'lockspect'; version: string };
  scannedAt: string;
  cooldownDays: number;
  lockfile: {
    format: LockfileFormat;
    manager: PackageManager;
    lockfileVersion: string;
    fileName?: string;
  };
  summary: ScanSummary;
  packages: PackageReport[];
  skipped: ParsedLockfile['skipped'];
  warnings: string[];
  /** Data sources that failed; results from them are incomplete. */
  errors: string[];
}

export interface ScanProgress {
  stage: 'parse' | 'advisories' | 'metadata' | 'done';
  done: number;
  total: number;
  message: string;
}
