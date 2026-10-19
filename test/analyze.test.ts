import { describe, expect, it } from 'vitest';
import { analyzeLockfile } from '../src/core/analyze';
import type { LockedPackage, ParsedLockfile } from '../src/core/types';
import { fakeFetch, type FakeWorld } from './helpers';

const NOW = new Date('2026-10-19T12:00:00Z');

function lockfile(packages: LockedPackage[]): ParsedLockfile {
  return {
    format: 'npm',
    manager: 'npm',
    lockfileVersion: '3',
    packages,
    skipped: [],
    warnings: [],
  };
}

const pkg = (name: string, version: string, extra: Partial<LockedPackage> = {}): LockedPackage => ({
  name,
  version,
  source: 'registry',
  ...extra,
});

const old = (extra: Record<string, unknown> = {}) => ({
  publishedAt: '2024-01-01T00:00:00Z',
  licenses: ['MIT'],
  ...extra,
});

const WORLD: FakeWorld = {
  osv: {
    'evil@1.0.0': [{ id: 'MAL-2026-1', summary: 'Malicious code in evil (npm)' }],
    'lodash@4.17.15': [
      {
        id: 'GHSA-aaaa',
        summary: 'Prototype pollution',
        aliases: ['CVE-2020-1'],
        database_specific: { severity: 'HIGH' },
        affected: [
          {
            package: { ecosystem: 'npm', name: 'lodash' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }],
          },
        ],
      },
      {
        id: 'GHSA-bbbb',
        summary: 'Command injection',
        database_specific: { severity: 'CRITICAL' },
        affected: [
          {
            package: { ecosystem: 'npm', name: 'lodash' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
          },
        ],
      },
      { id: 'GHSA-gone', summary: 'Withdrawn', withdrawn: '2026-01-01T00:00:00Z' },
    ],
  },
  depsDev: {
    'evil@1.0.0': old(),
    'lodash@4.17.15': old(),
    'fresh@2.0.0': old({ publishedAt: '2026-10-17T12:00:00Z', attestations: [{ verified: true }] }),
    'gpl@1.0.0': old({ licenses: ['GPL-3.0-only'] }),
    'dual@1.0.0': old({ licenses: ['MIT OR GPL-3.0'] }),
    'request@2.88.2': old({ isDeprecated: true, deprecatedReason: 'request has been deprecated' }),
    'scripty@1.0.0': old(),
  },
  registry: {
    // deps.dev has not indexed this one yet; the registry knows it was published an hour ago.
    brandnew: {
      versions: { '1.0.0': { license: 'ISC', dist: {} } },
      time: { '1.0.0': '2026-10-19T11:00:00Z' },
    },
    // The package exists but this version was removed.
    pulled: { versions: { '1.0.1': {} }, time: { '1.0.1': '2025-01-01T00:00:00Z' } },
  },
};

const PACKAGES = [
  pkg('evil', '1.0.0'),
  pkg('lodash', '4.17.15', { direct: true }),
  pkg('fresh', '2.0.0'),
  pkg('gpl', '1.0.0'),
  pkg('dual', '1.0.0'),
  pkg('request', '2.88.2'),
  pkg('scripty', '1.0.0', { hasInstallScript: true }),
  pkg('brandnew', '1.0.0'),
  pkg('pulled', '1.0.0'),
  pkg('private-thing', '1.0.0'),
  pkg('mirror-only', '1.0.0', { source: 'other-registry' }),
];

describe('analyzeLockfile', () => {
  it('combines OSV, deps.dev and npm registry data into findings', async () => {
    const fetch = fakeFetch(WORLD);
    const report = await analyzeLockfile(lockfile(PACKAGES), { fetch, now: NOW, cooldownDays: 7 });
    const byName = Object.fromEntries(report.packages.map((p) => [p.name, p]));

    expect(report.errors).toEqual([]);
    expect(byName.evil!.flags).toEqual(['malware']);
    expect(byName.evil!.advisories[0]).toMatchObject({ malware: true, severity: 'critical' });

    expect(byName.lodash!.flags).toEqual(['vulnerability']);
    expect(byName.lodash!.advisories.map((a) => a.id)).toEqual(['GHSA-bbbb', 'GHSA-aaaa']);
    expect(byName.lodash!.advisories[1]).toMatchObject({
      fixedIn: '4.17.19',
      aliases: ['CVE-2020-1'],
    });

    expect(byName.fresh!.flags).toEqual(['fresh']);
    expect(byName.fresh!.ageDays).toBeCloseTo(2, 5);
    expect(byName.fresh!.meta?.provenance).toBe(true);

    expect(byName.gpl!.flags).toEqual(['copyleft']);
    expect(byName.dual!.flags).toEqual([]);
    expect(byName.dual!.meta?.licenseKind).toBe('permissive');
    expect(byName.request!.flags).toEqual(['deprecated']);
    expect(byName.scripty!.flags).toEqual(['install-script']);

    expect(byName.brandnew!.flags).toEqual(['fresh']);
    expect(byName.brandnew!.meta?.licenses).toEqual(['ISC']);
    expect(byName.pulled!.flags).toEqual(['missing']);
    expect(byName.pulled!.meta?.unpublished).toBe(true);
    expect(byName['private-thing']!.flags).toEqual(['missing']);
    expect(byName['private-thing']!.meta?.unpublished).toBe(false);

    // Packages from another registry are never reported as missing from npm.
    expect(byName['mirror-only']!.flags).toEqual([]);
    expect(fetch.calls.some((c) => c.url.endsWith('/mirror-only'))).toBe(false);

    expect(report.summary).toMatchObject({
      total: 11,
      malware: 1,
      vulnerable: 1,
      missing: 2,
      fresh: 2,
      installScripts: 1,
      deprecated: 1,
      copyleft: 1,
      provenance: 1,
    });
    expect(report.summary.vulnsBySeverity).toMatchObject({ critical: 1, high: 1 });
  });

  it('only sends names and versions, and uses a CORS-simple request for deps.dev', async () => {
    const fetch = fakeFetch(WORLD);
    await analyzeLockfile(lockfile([pkg('lodash', '4.17.15')]), { fetch, now: NOW });
    const depsDev = fetch.calls.find((c) => c.url.includes('deps.dev'))!;
    expect(JSON.parse(depsDev.body!)).toEqual({
      requests: [{ versionKey: { system: 'NPM', name: 'lodash', version: '4.17.15' } }],
    });
    const osv = fetch.calls.find((c) => c.url.endsWith('querybatch'))!;
    expect(JSON.parse(osv.body!)).toEqual({
      queries: [{ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.15' }],
    });
  });

  it('respects the cooldown window', async () => {
    const fetch = fakeFetch(WORLD);
    const report = await analyzeLockfile(lockfile([pkg('fresh', '2.0.0')]), {
      fetch,
      now: NOW,
      cooldownDays: 1,
    });
    expect(report.packages[0]!.flags).toEqual([]);
  });

  it('reports an incomplete scan instead of a clean one when OSV is down', async () => {
    const fetch = fakeFetch({ ...WORLD, failOsv: true });
    const report = await analyzeLockfile(lockfile([pkg('evil', '1.0.0')]), { fetch, now: NOW });
    expect(report.errors).toHaveLength(1);
    expect(report.errors[0]).toMatch(/Advisory lookup failed/);
    expect(report.packages[0]!.meta?.publishedAt).toBeDefined();
  });

  it('does not flag every package as missing when deps.dev is down', async () => {
    const fetch = fakeFetch({ ...WORLD, failDepsDev: true });
    const report = await analyzeLockfile(lockfile([pkg('lodash', '4.17.15')]), { fetch, now: NOW });
    expect(report.errors[0]).toMatch(/deps.dev lookup failed/);
    expect(report.summary.missing).toBe(0);
    expect(report.summary.vulnerable).toBe(1);
  });

  it('reports progress through every stage', async () => {
    const stages: string[] = [];
    await analyzeLockfile(lockfile([pkg('lodash', '4.17.15')]), {
      fetch: fakeFetch(WORLD),
      now: NOW,
      onProgress: (p) => stages.push(p.stage),
    });
    expect(new Set(stages)).toEqual(new Set(['advisories', 'metadata', 'done']));
  });

  it('follows OSV pagination', async () => {
    let page = 0;
    const base = fakeFetch(WORLD);
    const fetch = (async (url: string, init?: RequestInit) => {
      if (url.endsWith('/querybatch')) {
        page++;
        const body = JSON.parse(String(init?.body)) as { queries: { page_token?: string }[] };
        if (page === 1) {
          return new Response(
            JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-aaaa' }], next_page_token: 't1' }] }),
          );
        }
        expect(body.queries[0]!.page_token).toBe('t1');
        return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-bbbb' }] }] }));
      }
      return base(url, init);
    }) as typeof base;
    const report = await analyzeLockfile(lockfile([pkg('lodash', '4.17.15')]), { fetch, now: NOW });
    expect(report.packages[0]!.advisories.map((a) => a.id).sort()).toEqual([
      'GHSA-aaaa',
      'GHSA-bbbb',
    ]);
  });
});
