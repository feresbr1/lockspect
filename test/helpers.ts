import type { FetchLike } from '../src/core/sources';

export interface FakeWorld {
  /** OSV advisories by "name@version". */
  osv?: Record<string, Record<string, unknown>[]>;
  /** deps.dev versions by "name@version". */
  depsDev?: Record<string, Record<string, unknown>>;
  /** npm packuments by package name. */
  registry?: Record<string, Record<string, unknown>>;
  failOsv?: boolean;
  failDepsDev?: boolean;
}

export interface FakeFetch extends FetchLike {
  calls: { url: string; method: string; body?: string }[];
}

/** A fetch stand-in that answers like OSV, deps.dev and the npm registry. */
export function fakeFetch(world: FakeWorld): FakeFetch {
  const calls: FakeFetch['calls'] = [];
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  const fn = (async (url: string, init?: RequestInit) => {
    const body = typeof init?.body === 'string' ? init.body : undefined;
    calls.push({ url, method: init?.method ?? 'GET', body });

    if (url === 'https://api.osv.dev/v1/querybatch') {
      if (world.failOsv) return json({ error: 'down' }, 503);
      const { queries } = JSON.parse(body!) as {
        queries: { package: { name: string }; version: string }[];
      };
      return json({
        results: queries.map((q) => {
          const vulns = world.osv?.[`${q.package.name}@${q.version}`] ?? [];
          return vulns.length ? { vulns: vulns.map((v) => ({ id: v.id })) } : {};
        }),
      });
    }
    const vulnMatch = /^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/.exec(url);
    if (vulnMatch) {
      const id = decodeURIComponent(vulnMatch[1]!);
      const vuln = Object.values(world.osv ?? {})
        .flat()
        .find((v) => v.id === id);
      return vuln ? json(vuln) : json({ code: 5 }, 404);
    }
    if (url === 'https://api.deps.dev/v3alpha/versionbatch') {
      if (world.failDepsDev) return json({ error: 'down' }, 500);
      const { requests } = JSON.parse(body!) as {
        requests: { versionKey: { name: string; version: string } }[];
      };
      return json({
        responses: requests.map((r) => {
          const v = world.depsDev?.[`${r.versionKey.name}@${r.versionKey.version}`];
          return v ? { request: r, version: { versionKey: r.versionKey, ...v } } : { request: r };
        }),
        nextPageToken: '',
      });
    }
    const regMatch = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    if (regMatch) {
      const name = decodeURIComponent(regMatch[1]!);
      const doc = world.registry?.[name];
      return doc ? json(doc) : json({ error: 'Not found' }, 404);
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as FakeFetch;
  fn.calls = calls;
  return fn;
}
