import { useMemo, useState } from 'preact/hooks';
import { worstSeverity } from '../../core/analyze';
import { FINDING_INFO, formatAge, highestFix, rankPackages } from '../../core/report';
import type { FindingKind, PackageReport } from '../../core/types';
import { FINDING_TONE, SEVERITY_TONE, toneStyle } from '../tones';
import { Caret } from './Icons';

export type Filter = 'flagged' | 'all' | FindingKind;
type Sort = 'risk' | 'name' | 'newest';

const PAGE = 100;

interface PackageListProps {
  packages: PackageReport[];
  filter: Filter;
  onFilterChange: (filter: Filter) => void;
  cooldownDays: number;
}

export function PackageList({ packages, filter, onFilterChange, cooldownDays }: PackageListProps) {
  const [query, setQuery] = useState('');
  const [directOnly, setDirectOnly] = useState(false);
  const [sort, setSort] = useState<Sort>('risk');
  const [limit, setLimit] = useState(PAGE);
  const [open, setOpen] = useState<Set<string>>(() => new Set());

  const hasDirectInfo = packages.some((p) => p.direct !== undefined);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    let list = packages.filter((p) => {
      if (filter === 'flagged' && !p.flags.some(isSerious)) return false;
      if (filter !== 'flagged' && filter !== 'all' && !p.flags.includes(filter)) return false;
      if (directOnly && !p.direct) return false;
      if (q && !`${p.name}@${p.version}`.toLowerCase().includes(q)) return false;
      return true;
    });
    if (sort === 'risk') list = rankPackages(list);
    else if (sort === 'name') list = [...list].sort((a, b) => a.name.localeCompare(b.name));
    else list = [...list].sort((a, b) => (a.ageDays ?? Infinity) - (b.ageDays ?? Infinity));
    return list;
  }, [packages, filter, query, directOnly, sort]);

  const toggle = (key: string) => {
    const next = new Set(open);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setOpen(next);
  };

  return (
    <section aria-labelledby="packages-title">
      <h2 id="packages-title" class="sr-only">
        Packages
      </h2>
      <div class="toolbar">
        <div class="toolbar-left">
          <label class="sr-only" for="pkg-search">
            Filter packages by name
          </label>
          <input
            id="pkg-search"
            class="search"
            type="search"
            placeholder="Filter by name…"
            value={query}
            onInput={(e) => {
              setQuery(e.currentTarget.value);
              setLimit(PAGE);
            }}
          />
          <label class="sr-only" for="pkg-filter">
            Show
          </label>
          <select
            id="pkg-filter"
            class="select"
            value={filter}
            onChange={(e) => {
              onFilterChange(e.currentTarget.value as Filter);
              setLimit(PAGE);
            }}
          >
            <option value="flagged">Needs attention</option>
            <option value="all">All packages</option>
            {(Object.keys(FINDING_INFO) as FindingKind[]).map((kind) => (
              <option key={kind} value={kind}>
                {FINDING_INFO[kind].title}
              </option>
            ))}
          </select>
          <label class="sr-only" for="pkg-sort">
            Sort by
          </label>
          <select
            id="pkg-sort"
            class="select"
            value={sort}
            onChange={(e) => setSort(e.currentTarget.value as Sort)}
          >
            <option value="risk">Sort: risk</option>
            <option value="newest">Sort: newest release</option>
            <option value="name">Sort: name</option>
          </select>
          {hasDirectInfo && (
            <label class="check-label">
              <input
                type="checkbox"
                checked={directOnly}
                onChange={(e) => setDirectOnly(e.currentTarget.checked)}
              />
              Direct only
            </label>
          )}
        </div>
        <span class="count-note" aria-live="polite">
          {visible.length.toLocaleString()} of {packages.length.toLocaleString()} packages
        </span>
      </div>

      {visible.length > 0 && (
        <div class="list-head" aria-hidden="true">
          <span>Package</span>
          <span class="h-find">Findings</span>
          <span>Age</span>
          <span class="h-lic">Licence</span>
          <span />
        </div>
      )}
      <ul class="pkg-list">
        {visible.length === 0 && (
          <li class="empty">
            {filter === 'flagged' && !query && !directOnly ? (
              <>
                Nothing needs attention: no malware, advisories, missing or too-fresh versions.{' '}
                <button type="button" class="linkish" onClick={() => onFilterChange('all')}>
                  Show all packages
                </button>
              </>
            ) : (
              'No packages match these filters.'
            )}
          </li>
        )}
        {visible.slice(0, limit).map((pkg) => (
          <PackageRow
            key={pkg.key}
            pkg={pkg}
            open={open.has(pkg.key)}
            onToggle={() => toggle(pkg.key)}
            cooldownDays={cooldownDays}
          />
        ))}
      </ul>
      {visible.length > limit && (
        <div class="more">
          <button type="button" class="btn btn-sm" onClick={() => setLimit(limit + PAGE * 5)}>
            Show more ({(visible.length - limit).toLocaleString()} left)
          </button>
        </div>
      )}
    </section>
  );
}

function isSerious(kind: FindingKind): boolean {
  return kind === 'malware' || kind === 'vulnerability' || kind === 'missing' || kind === 'fresh';
}

function chipLabel(kind: FindingKind, pkg: PackageReport): string {
  switch (kind) {
    case 'vulnerability': {
      const n = pkg.advisories.filter((a) => !a.malware).length;
      return `${n} ${worstSeverity(pkg.advisories) ?? ''} advisor${n === 1 ? 'y' : 'ies'}`.replace(
        '  ',
        ' ',
      );
    }
    case 'missing':
      return pkg.meta?.unpublished ? 'Unpublished' : 'Not on npm';
    case 'fresh':
      return `Fresh · ${formatAge(pkg.ageDays)}`;
    default:
      return FINDING_INFO[kind].title;
  }
}

function PackageRow({
  pkg,
  open,
  onToggle,
  cooldownDays,
}: {
  pkg: PackageReport;
  open: boolean;
  onToggle: () => void;
  cooldownDays: number;
}) {
  const detailId = `pkg-${pkg.key.replace(/[^a-z0-9]/gi, '-')}`;
  const fix = highestFix(pkg);
  const npmUrl = `https://www.npmjs.com/package/${pkg.name}/v/${pkg.version}`;
  const depsDevUrl = `https://deps.dev/npm/${encodeURIComponent(pkg.name)}/${encodeURIComponent(pkg.version)}`;
  const licences = pkg.meta?.licenses.join(', ') || (pkg.meta && !pkg.meta.missing ? 'none' : '?');

  return (
    <li class="pkg" data-open={open} data-testid="pkg">
      <button
        type="button"
        class="pkg-row"
        aria-expanded={open}
        aria-controls={detailId}
        onClick={onToggle}
      >
        <span class="pkg-name" title={`${pkg.name}@${pkg.version}`}>
          {pkg.name}
          <span class="ver">@{pkg.version}</span>
          {pkg.direct && <span class="tag">direct</span>}
          {pkg.dev && <span class="tag">dev</span>}
        </span>
        <span class="chips">
          {pkg.flags.length === 0 && <span class="muted">·</span>}
          {pkg.flags.map((kind) => (
            <span class="chip" key={kind} style={toneStyle(FINDING_TONE[kind])}>
              {chipLabel(kind, pkg)}
            </span>
          ))}
        </span>
        <span class="pkg-age" data-fresh={pkg.flags.includes('fresh')}>
          {formatAge(pkg.ageDays)}
        </span>
        <span class="pkg-lic" title={licences}>
          {licences}
        </span>
        <Caret />
      </button>
      {open && (
        <div class="pkg-detail" id={detailId}>
          <div class="facts">
            <span>
              Published{' '}
              <b>
                {pkg.meta?.publishedAt
                  ? new Date(pkg.meta.publishedAt).toLocaleString(undefined, {
                      dateStyle: 'medium',
                      timeStyle: 'short',
                    })
                  : 'unknown'}
              </b>
              {pkg.flags.includes('fresh') && ` (inside your ${cooldownDays}-day cooldown)`}
            </span>
            <span>
              Provenance <b>{pkg.meta?.provenance ? 'yes' : 'no'}</b>
            </span>
            <span>
              Install scripts{' '}
              <b>
                {pkg.hasInstallScript === undefined
                  ? 'not recorded'
                  : pkg.hasInstallScript
                    ? 'yes'
                    : 'no'}
              </b>
            </span>
            {pkg.dev !== undefined && (
              <span>
                Scope <b>{pkg.dev ? 'dev only' : 'production'}</b>
              </span>
            )}
            {fix && <span class="fix">fixes all known advisories: upgrade to {fix} or later</span>}
          </div>
          {pkg.meta?.missing && (
            <p class="notice is-error" style={{ margin: 0 }}>
              {pkg.meta.unpublished
                ? 'This version has been removed from the npm registry. Registry removals usually mean malware or a compromised release. Check how it got into your lockfile.'
                : 'This version was not found on the public npm registry. That is expected for private packages; otherwise treat it as suspicious.'}
            </p>
          )}
          {pkg.meta?.deprecated && (
            <p style={{ margin: 0 }}>
              <b>Deprecated:</b> {pkg.meta.deprecated}
            </p>
          )}
          {pkg.advisories.length > 0 && (
            <ul class="advisories">
              {pkg.advisories.map((a) => (
                <li
                  class="advisory"
                  key={a.id}
                  style={toneStyle(a.malware ? FINDING_TONE.malware : SEVERITY_TONE[a.severity])}
                >
                  <span class="sev">{a.malware ? 'malware' : a.severity}</span>
                  <div>
                    <a href={a.url} target="_blank" rel="noreferrer">
                      {a.id}
                    </a>
                    {a.aliases.length > 0 && (
                      <span class="muted mono" style={{ fontSize: '12.5px' }}>
                        {' '}
                        {a.aliases.slice(0, 2).join(' · ')}
                      </span>
                    )}
                    <p>{a.summary}</p>
                    {a.fixedIn && <span class="fix">fixed in {a.fixedIn}</span>}
                  </div>
                </li>
              ))}
            </ul>
          )}
          <div class="facts">
            <a href={npmUrl} target="_blank" rel="noreferrer">
              npm page
            </a>
            <a href={depsDevUrl} target="_blank" rel="noreferrer">
              deps.dev
            </a>
            <a
              href={`https://osv.dev/list?ecosystem=npm&q=${encodeURIComponent(pkg.name)}`}
              target="_blank"
              rel="noreferrer"
            >
              All OSV advisories for {pkg.name}
            </a>
          </div>
        </div>
      )}
    </li>
  );
}
