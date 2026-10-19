import type {
  Advisory,
  FindingKind,
  PackageMeta,
  PackageReport,
  ParsedLockfile,
  ScanProgress,
  ScanReport,
  ScanSummary,
  Severity,
} from './types';
import {
  fetchOsvVulns,
  queryDepsDev,
  queryOsvIds,
  queryRegistry,
  toAdvisory,
  type FetchLike,
} from './sources';
import { VERSION } from './version';

export interface AnalyzeOptions {
  /** Versions younger than this many days are flagged as fresh. Default 7. */
  cooldownDays?: number;
  fetch?: FetchLike;
  now?: Date;
  fileName?: string;
  onProgress?: (progress: ScanProgress) => void;
  /** Max packages to look up on the npm registry when deps.dev has no record. Default 150. */
  registryFallbackLimit?: number;
}

export const DEFAULT_COOLDOWN_DAYS = 7;
const DAY_MS = 86_400_000;

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'moderate', 'low', 'unknown'];

export async function analyzeLockfile(
  lockfile: ParsedLockfile,
  options: AnalyzeOptions = {},
): Promise<ScanReport> {
  const fetchFn: FetchLike = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const cooldownDays = options.cooldownDays ?? DEFAULT_COOLDOWN_DAYS;
  const now = options.now ?? new Date();
  const progress = options.onProgress ?? (() => {});
  const packages = lockfile.packages;
  const total = packages.length;
  const errors: string[] = [];

  // 1. Advisories (vulnerabilities + malware) from OSV.
  progress({ stage: 'advisories', done: 0, total, message: 'Checking OSV for advisories' });
  const advisories = new Map<string, Advisory[]>();
  try {
    const ids = await queryOsvIds(packages, fetchFn, (done) =>
      progress({ stage: 'advisories', done, total, message: 'Checking OSV for advisories' }),
    );
    const unique = [...new Set([...ids.values()].flat())];
    const vulns = await fetchOsvVulns(unique, fetchFn, (done) =>
      progress({
        stage: 'advisories',
        done,
        total: unique.length,
        message: `Loading ${unique.length} advisories`,
      }),
    );
    for (const pkg of packages) {
      const key = `${pkg.name}@${pkg.version}`;
      const list: Advisory[] = [];
      for (const id of ids.get(key) ?? []) {
        const vuln = vulns.get(id);
        const advisory = vuln && toAdvisory(vuln, pkg);
        if (advisory) list.push(advisory);
      }
      list.sort(
        (a, b) =>
          Number(b.malware) - Number(a.malware) ||
          SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
      );
      advisories.set(key, list);
    }
  } catch (error) {
    errors.push(
      `Advisory lookup failed (${(error as Error).message}). Malware and vulnerability results are incomplete.`,
    );
  }

  // 2. Metadata (age, deprecation, licence, provenance) from deps.dev, then the npm registry.
  progress({ stage: 'metadata', done: 0, total, message: 'Fetching publish dates and licences' });
  let meta = new Map<string, PackageMeta>();
  try {
    meta = await queryDepsDev(packages, fetchFn, (done) =>
      progress({ stage: 'metadata', done, total, message: 'Fetching publish dates and licences' }),
    );
  } catch (error) {
    errors.push(
      `deps.dev lookup failed (${(error as Error).message}). Age, licence and deprecation results are incomplete.`,
    );
  }
  const unknown = packages.filter(
    (pkg) => !meta.has(`${pkg.name}@${pkg.version}`) && pkg.source !== 'other-registry',
  );
  const limit = options.registryFallbackLimit ?? 150;
  if (unknown.length && (errors.length === 0 || meta.size > 0)) {
    progress({
      stage: 'metadata',
      done: 0,
      total: Math.min(unknown.length, limit),
      message: 'Checking the npm registry for unindexed versions',
    });
    try {
      const fallback = await queryRegistry(unknown.slice(0, limit), fetchFn);
      for (const [key, value] of fallback) meta.set(key, value);
    } catch (error) {
      errors.push(`npm registry lookup failed (${(error as Error).message}).`);
    }
    if (unknown.length > limit) {
      errors.push(
        `${unknown.length - limit} packages were not found on deps.dev and were not checked against the npm registry.`,
      );
    }
  }

  // 3. Combine into findings.
  const reports: PackageReport[] = packages.map((pkg) => {
    const key = `${pkg.name}@${pkg.version}`;
    const pkgAdvisories = advisories.get(key) ?? [];
    const pkgMeta = meta.get(key);
    const ageDays = pkgMeta?.publishedAt
      ? Math.max(0, (now.getTime() - Date.parse(pkgMeta.publishedAt)) / DAY_MS)
      : undefined;
    const flags: FindingKind[] = [];
    if (pkgAdvisories.some((a) => a.malware)) flags.push('malware');
    if (pkgAdvisories.some((a) => !a.malware)) flags.push('vulnerability');
    if (pkgMeta?.missing) flags.push('missing');
    if (ageDays !== undefined && ageDays < cooldownDays) flags.push('fresh');
    if (pkg.hasInstallScript) flags.push('install-script');
    if (pkgMeta?.deprecated) flags.push('deprecated');
    if (pkgMeta?.licenseKind === 'strong-copyleft') flags.push('copyleft');
    return { ...pkg, key, advisories: pkgAdvisories, meta: pkgMeta, ageDays, flags };
  });

  progress({ stage: 'done', done: total, total, message: 'Done' });

  return {
    tool: { name: 'lockspect', version: VERSION },
    scannedAt: now.toISOString(),
    cooldownDays,
    lockfile: {
      format: lockfile.format,
      manager: lockfile.manager,
      lockfileVersion: lockfile.lockfileVersion,
      fileName: options.fileName,
    },
    summary: summarize(reports),
    packages: reports,
    skipped: lockfile.skipped,
    warnings: lockfile.warnings,
    errors,
  };
}

export function summarize(reports: readonly PackageReport[]): ScanSummary {
  const summary: ScanSummary = {
    total: reports.length,
    malware: 0,
    vulnerable: 0,
    vulnsBySeverity: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 },
    missing: 0,
    fresh: 0,
    installScripts: 0,
    deprecated: 0,
    copyleft: 0,
    provenance: 0,
    licenses: { permissive: 0, 'weak-copyleft': 0, 'strong-copyleft': 0, unknown: 0, none: 0 },
  };
  for (const r of reports) {
    if (r.flags.includes('malware')) summary.malware++;
    if (r.flags.includes('vulnerability')) summary.vulnerable++;
    for (const a of r.advisories) if (!a.malware) summary.vulnsBySeverity[a.severity]++;
    if (r.flags.includes('missing')) summary.missing++;
    if (r.flags.includes('fresh')) summary.fresh++;
    if (r.flags.includes('install-script')) summary.installScripts++;
    if (r.flags.includes('deprecated')) summary.deprecated++;
    if (r.flags.includes('copyleft')) summary.copyleft++;
    if (r.meta?.provenance) summary.provenance++;
    if (r.meta && !r.meta.missing) summary.licenses[r.meta.licenseKind]++;
  }
  return summary;
}

/** Highest severity among a package's non-malware advisories. */
export function worstSeverity(advisories: readonly Advisory[]): Severity | undefined {
  let best: Severity | undefined;
  for (const a of advisories) {
    if (a.malware) continue;
    if (!best || SEVERITY_ORDER.indexOf(a.severity) < SEVERITY_ORDER.indexOf(best))
      best = a.severity;
  }
  return best;
}
