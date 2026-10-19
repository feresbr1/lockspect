import type { Advisory, LockedPackage, PackageMeta, Severity } from './types';
import { classifyLicenses } from './licenses';
import { compareVersions } from './semver';
import { isRecord } from './parsers/util';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export const OSV_API = 'https://api.osv.dev/v1';
export const DEPS_DEV_API = 'https://api.deps.dev/v3alpha';
export const NPM_REGISTRY = 'https://registry.npmjs.org';

const OSV_BATCH = 1000;
const DEPS_DEV_BATCH = 500;

export class SourceError extends Error {
  constructor(
    readonly source: string,
    message: string,
  ) {
    super(`${source}: ${message}`);
    this.name = 'SourceError';
  }
}

async function fetchJson(
  fetchFn: FetchLike,
  source: string,
  url: string,
  init?: RequestInit,
  retries = 2,
): Promise<unknown> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetchFn(url, init);
      if (res.status === 404) return undefined;
      if (res.status === 429 || res.status >= 500) {
        lastError = new SourceError(source, `HTTP ${res.status}`);
        await delay(400 * 2 ** attempt);
        continue;
      }
      if (!res.ok) throw new SourceError(source, `HTTP ${res.status} for ${url}`);
      return await res.json();
    } catch (error) {
      if (error instanceof SourceError) throw error;
      lastError = error;
      await delay(400 * 2 ** attempt);
    }
  }
  const message = lastError instanceof Error ? lastError.message : String(lastError);
  throw new SourceError(source, message);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Run `task` over `items` with at most `limit` in flight. */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await task(items[index]!, index);
    }
  });
  await Promise.all(workers);
  return results;
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

// ---------------------------------------------------------------------------
// OSV: known vulnerabilities and malicious packages (MAL-*)
// ---------------------------------------------------------------------------

interface OsvBatchResult {
  vulns?: { id: string }[];
  next_page_token?: string;
}

/** Returns the OSV advisory ids that affect each package, keyed by "name@version". */
export async function queryOsvIds(
  packages: readonly LockedPackage[],
  fetchFn: FetchLike,
  onProgress?: (done: number) => void,
): Promise<Map<string, string[]>> {
  const ids = new Map<string, string[]>();
  let done = 0;
  for (const batch of chunk(packages, OSV_BATCH)) {
    let pending = batch.map((pkg) => ({ pkg, pageToken: undefined as string | undefined }));
    while (pending.length) {
      const body = {
        queries: pending.map(({ pkg, pageToken }) => ({
          package: { name: pkg.name, ecosystem: 'npm' },
          version: pkg.version,
          ...(pageToken ? { page_token: pageToken } : {}),
        })),
      };
      const data = await fetchJson(fetchFn, 'OSV', `${OSV_API}/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      const results: OsvBatchResult[] =
        isRecord(data) && Array.isArray(data.results) ? (data.results as OsvBatchResult[]) : [];
      const nextPending: typeof pending = [];
      pending.forEach(({ pkg }, i) => {
        const result = results[i] ?? {};
        const key = `${pkg.name}@${pkg.version}`;
        const list = ids.get(key) ?? [];
        for (const vuln of result.vulns ?? []) if (!list.includes(vuln.id)) list.push(vuln.id);
        ids.set(key, list);
        if (result.next_page_token) nextPending.push({ pkg, pageToken: result.next_page_token });
      });
      pending = nextPending;
    }
    done += batch.length;
    onProgress?.(done);
  }
  return ids;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  withdrawn?: string;
  database_specific?: { severity?: string };
  severity?: { type: string; score: string }[];
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { type?: string; events?: Record<string, string>[] }[];
    database_specific?: { severity?: string };
  }[];
}

export async function fetchOsvVulns(
  ids: readonly string[],
  fetchFn: FetchLike,
  onProgress?: (done: number) => void,
): Promise<Map<string, OsvVuln>> {
  const out = new Map<string, OsvVuln>();
  let done = 0;
  await mapLimit(ids, 8, async (id) => {
    const data = await fetchJson(fetchFn, 'OSV', `${OSV_API}/vulns/${encodeURIComponent(id)}`);
    if (isRecord(data)) out.set(id, data as unknown as OsvVuln);
    onProgress?.(++done);
  });
  return out;
}

export function toAdvisory(vuln: OsvVuln, pkg: LockedPackage): Advisory | undefined {
  if (vuln.withdrawn) return undefined;
  const malware = vuln.id.startsWith('MAL-');
  return {
    id: vuln.id,
    aliases: vuln.aliases ?? [],
    summary: vuln.summary || firstLine(vuln.details) || vuln.id,
    severity: malware ? 'critical' : severityOf(vuln),
    malware,
    fixedIn: malware ? undefined : fixedVersionFor(vuln, pkg),
    url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`,
    published: vuln.published,
  };
}

function firstLine(text: string | undefined): string {
  const line = text?.split('\n').find((l) => l.trim()) ?? '';
  return line.length > 160 ? `${line.slice(0, 157)}…` : line;
}

function severityOf(vuln: OsvVuln): Severity {
  const label = (
    vuln.database_specific?.severity ??
    vuln.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity ??
    ''
  ).toUpperCase();
  if (label === 'CRITICAL') return 'critical';
  if (label === 'HIGH') return 'high';
  if (label === 'MODERATE' || label === 'MEDIUM') return 'moderate';
  if (label === 'LOW') return 'low';
  return 'unknown';
}

/** The smallest "fixed" version above the installed version, across this package's ranges. */
function fixedVersionFor(vuln: OsvVuln, pkg: LockedPackage): string | undefined {
  const candidates: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== pkg.name) continue;
    for (const range of affected.ranges ?? []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      for (const event of range.events ?? []) {
        if (event.fixed && compareVersions(event.fixed, pkg.version) > 0) {
          candidates.push(event.fixed);
        }
      }
    }
  }
  return candidates.sort(compareVersions)[0];
}

// ---------------------------------------------------------------------------
// deps.dev: publish dates, deprecation, licenses and provenance
// ---------------------------------------------------------------------------

interface DepsDevVersion {
  versionKey: { name: string; version: string };
  publishedAt?: string;
  isDeprecated?: boolean;
  deprecatedReason?: string;
  licenses?: string[];
  slsaProvenances?: unknown[];
  attestations?: unknown[];
}

export async function queryDepsDev(
  packages: readonly LockedPackage[],
  fetchFn: FetchLike,
  onProgress?: (done: number) => void,
): Promise<Map<string, PackageMeta>> {
  const out = new Map<string, PackageMeta>();
  let done = 0;
  await mapLimit(chunk(packages, DEPS_DEV_BATCH), 3, async (batch) => {
    const requests = batch.map((pkg) => ({
      versionKey: { system: 'NPM', name: pkg.name, version: pkg.version },
    }));
    let pageToken = '';
    do {
      const data = await fetchJson(fetchFn, 'deps.dev', `${DEPS_DEV_API}/versionbatch`, {
        method: 'POST',
        // deps.dev rejects CORS preflights; a text/plain body keeps this a "simple" request.
        headers: { 'content-type': 'text/plain;charset=UTF-8' },
        body: JSON.stringify({ requests, ...(pageToken ? { pageToken } : {}) }),
      });
      if (!isRecord(data)) break;
      for (const response of Array.isArray(data.responses) ? data.responses : []) {
        if (!isRecord(response) || !isRecord(response.version)) continue;
        const v = response.version as unknown as DepsDevVersion;
        const licenses = (v.licenses ?? []).filter(Boolean);
        out.set(`${v.versionKey.name}@${v.versionKey.version}`, {
          publishedAt: v.publishedAt,
          deprecated: v.isDeprecated ? v.deprecatedReason || 'deprecated' : undefined,
          licenses,
          licenseKind: classifyLicenses(licenses),
          provenance: Boolean(v.slsaProvenances?.length || v.attestations?.length),
          missing: false,
        });
      }
      pageToken = typeof data.nextPageToken === 'string' ? data.nextPageToken : '';
    } while (pageToken);
    done += batch.length;
    onProgress?.(done);
  });
  return out;
}

// ---------------------------------------------------------------------------
// npm registry: fallback for versions deps.dev has not indexed (very new, or unpublished)
// ---------------------------------------------------------------------------

interface Packument {
  versions?: Record<
    string,
    { deprecated?: string; license?: unknown; dist?: { attestations?: unknown } }
  >;
  time?: Record<string, unknown> & { unpublished?: unknown };
}

export async function queryRegistry(
  packages: readonly LockedPackage[],
  fetchFn: FetchLike,
): Promise<Map<string, PackageMeta>> {
  const out = new Map<string, PackageMeta>();
  await mapLimit(packages, 6, async (pkg) => {
    const url = `${NPM_REGISTRY}/${pkg.name.replace('/', '%2f')}`;
    const data = (await fetchJson(fetchFn, 'npm registry', url, {
      headers: { accept: 'application/json' },
    })) as Packument | undefined;
    const key = `${pkg.name}@${pkg.version}`;
    const manifest = data?.versions?.[pkg.version];
    if (!data || !manifest) {
      out.set(key, {
        licenses: [],
        licenseKind: 'none',
        provenance: false,
        missing: true,
        unpublished: Boolean(data?.time?.unpublished) || Boolean(data && !manifest),
      });
      return;
    }
    const published = data.time?.[pkg.version];
    const license = typeof manifest.license === 'string' ? [manifest.license] : [];
    out.set(key, {
      publishedAt: typeof published === 'string' ? published : undefined,
      deprecated: manifest.deprecated || undefined,
      licenses: license,
      licenseKind: classifyLicenses(license),
      provenance: Boolean(manifest.dist?.attestations),
      missing: false,
    });
  });
  return out;
}
