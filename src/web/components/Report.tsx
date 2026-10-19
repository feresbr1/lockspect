import { useState } from 'preact/hooks';
import { cooldownSnippets } from '../../core/cooldown';
import { FINDING_INFO, FINDING_ORDER, toMarkdown } from '../../core/report';
import type { FindingKind, LicenseKind, ScanReport, ScanSummary } from '../../core/types';
import { FINDING_TONE, toneStyle } from '../tones';
import { CopyButton } from './CopyButton';
import { PackageList, type Filter } from './PackageList';

interface ReportProps {
  report: ScanReport;
  onReset: () => void;
}

const MANAGER_LABEL = { npm: 'npm', pnpm: 'pnpm', yarn: 'Yarn', bun: 'Bun' } as const;

export function Report({ report, onReset }: ReportProps) {
  const [filter, setFilter] = useState<Filter>(() =>
    report.packages.some((p) => p.flags.length) ? 'flagged' : 'all',
  );
  const s = report.summary;
  const v = verdict(report);

  const download = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lockspect-report-${report.scannedAt.slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <main id="main" class="wrap">
      <header class="report-head">
        <div>
          <p class="report-file">
            {report.lockfile.fileName ?? 'pasted lockfile'} ·{' '}
            {MANAGER_LABEL[report.lockfile.manager]} lockfile v
            {report.lockfile.lockfileVersion || '?'} · {s.total.toLocaleString()} packages
          </p>
          <h1 class="verdict" data-tone={v.tone} data-testid="verdict">
            {v.title}
          </h1>
          <p class="verdict-sub">{v.detail}</p>
        </div>
        <div class="report-actions">
          <CopyButton text={() => toMarkdown(report)} label="Copy Markdown" />
          <button type="button" class="btn btn-sm" onClick={download}>
            Download JSON
          </button>
          <button type="button" class="btn btn-sm btn-primary" onClick={onReset}>
            Scan another
          </button>
        </div>
      </header>

      {report.errors.map((error) => (
        <p class="notice is-error" role="alert" key={error}>
          {error}
        </p>
      ))}

      <div class="tiles" role="group" aria-label="Findings by type. Select one to filter the list.">
        {FINDING_ORDER.map((kind) => {
          const count = countFor(kind, s);
          return (
            <button
              type="button"
              key={kind}
              class="tile"
              style={toneStyle(FINDING_TONE[kind])}
              data-zero={count === 0}
              aria-pressed={filter === kind}
              onClick={() => setFilter(filter === kind ? 'flagged' : kind)}
            >
              <span class="tile-count">{count.toLocaleString()}</span>
              <span class="tile-label">{FINDING_INFO[kind].title}</span>
              <span class="tile-hint">{tileHint(kind, report)}</span>
            </button>
          );
        })}
      </div>

      <PackageList
        packages={report.packages}
        filter={filter}
        onFilterChange={setFilter}
        cooldownDays={report.cooldownDays}
      />

      <div class="lower">
        <Hardening report={report} />
        <div>
          <Licences summary={s} />
          <h2 class="section-title" style={{ marginTop: '28px' }}>
            Provenance
          </h2>
          <p class="section-sub">
            <b>{s.provenance.toLocaleString()}</b> of {s.total.toLocaleString()} versions (
            {s.total ? Math.round((s.provenance / s.total) * 100) : 0}%) have a verified npm
            provenance attestation linking them to a public source commit and CI build.
          </p>
          {(report.warnings.length > 0 || report.skipped.length > 0) && (
            <div>
              <h2 class="section-title" style={{ marginTop: '28px' }}>
                Notes
              </h2>
              {report.warnings.map((w) => (
                <p class="section-sub" key={w}>
                  {w}
                </p>
              ))}
              {report.skipped.length > 0 && (
                <details class="skipped">
                  <summary>
                    {report.skipped.length} entr{report.skipped.length === 1 ? 'y' : 'ies'} not
                    checked (workspaces, git, local or URL dependencies)
                  </summary>
                  <ul>
                    {report.skipped.map((entry, i) => (
                      <li key={i}>
                        {entry.name}: {entry.reason}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
          )}
        </div>
      </div>
    </main>
  );
}

function countFor(kind: FindingKind, s: ScanSummary): number {
  switch (kind) {
    case 'malware':
      return s.malware;
    case 'vulnerability':
      return s.vulnerable;
    case 'missing':
      return s.missing;
    case 'fresh':
      return s.fresh;
    case 'install-script':
      return s.installScripts;
    case 'deprecated':
      return s.deprecated;
    case 'copyleft':
      return s.copyleft;
  }
}

function tileHint(kind: FindingKind, report: ScanReport): string {
  const s = report.summary;
  switch (kind) {
    case 'malware':
      return 'known malicious';
    case 'vulnerability': {
      const hi = s.vulnsBySeverity.critical + s.vulnsBySeverity.high;
      return hi ? `${hi} critical/high advisories` : 'with advisories';
    }
    case 'missing':
      return 'unpublished or private';
    case 'fresh':
      return `published < ${report.cooldownDays}d ago`;
    case 'install-script':
      return report.packages.some((p) => p.hasInstallScript !== undefined)
        ? 'run code on install'
        : 'not in this lockfile format';
    case 'deprecated':
      return 'by maintainers';
    case 'copyleft':
      return 'GPL / AGPL / SSPL';
  }
}

interface Verdict {
  tone: 'bad' | 'warn' | 'good';
  title: string;
  detail: string;
}

export function verdict(report: ScanReport): Verdict {
  const s = report.summary;
  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);
  if (s.malware) {
    return {
      tone: 'bad',
      title: `${s.malware} malicious ${plural(s.malware, 'package', 'packages')} found`,
      detail:
        'Treat every machine and CI runner that installed this lockfile as compromised: remove the packages, then rotate tokens, keys and passwords from a clean machine.',
    };
  }
  if (report.errors.length) {
    return {
      tone: 'warn',
      title: 'Scan incomplete',
      detail: 'Some data sources could not be reached, so results below may be missing findings.',
    };
  }
  if (s.missing) {
    return {
      tone: 'warn',
      title: `${s.missing} ${plural(s.missing, 'version is', 'versions are')} not on npm`,
      detail:
        'No known malware, but versions missing from the public registry were often pulled for a reason. Private packages are expected here.',
    };
  }
  const hi = s.vulnsBySeverity.critical + s.vulnsBySeverity.high;
  if (hi) {
    return {
      tone: 'warn',
      title: 'No known malware',
      detail: `${s.vulnerable} ${plural(s.vulnerable, 'package has', 'packages have')} published advisories, including ${hi} critical or high. Open a package to see the version that fixes it.`,
    };
  }
  if (s.fresh) {
    return {
      tone: 'warn',
      title: 'No known malware',
      detail: `${s.fresh} ${plural(s.fresh, 'version was', 'versions were')} published in the last ${report.cooldownDays} days, before many compromised releases are caught. Consider a release cooldown.`,
    };
  }
  return {
    tone: 'good',
    title: 'No known malware or serious advisories',
    detail:
      s.vulnerable > 0
        ? `${s.vulnerable} ${plural(s.vulnerable, 'package has', 'packages have')} moderate or low advisories.`
        : 'Nothing in this lockfile matches a known advisory, and nothing is younger than your cooldown window.',
  };
}

function Hardening({ report }: { report: ScanReport }) {
  const snippets = cooldownSnippets(report.cooldownDays);
  const [active, setActive] = useState<string>(report.lockfile.manager);
  const current = snippets.find((s) => s.manager === active) ?? snippets[0]!;
  return (
    <section aria-labelledby="harden-title">
      <h2 class="section-title" id="harden-title">
        Refuse fresh releases at install time
      </h2>
      <p class="section-sub">
        A {report.cooldownDays}-day release cooldown makes your package manager skip versions until
        they are {report.cooldownDays} days old. Hijacked releases are often spotted and unpublished
        within that time.
      </p>
      <div class="tabs" role="tablist" aria-label="Tool">
        {snippets.map((s) => (
          <button
            type="button"
            role="tab"
            key={s.manager}
            aria-selected={s.manager === current.manager}
            onClick={() => setActive(s.manager)}
          >
            {s.label}
          </button>
        ))}
      </div>
      <div class="snippet" role="tabpanel">
        <div class="snippet-head">
          <span>{current.file}</span>
          <CopyButton text={current.code} />
        </div>
        <pre>
          <code>{current.code}</code>
        </pre>
      </div>
      <p class="snippet-note">{current.note}</p>
    </section>
  );
}

const LICENCE_ROWS: { kind: LicenseKind; label: string; color: string }[] = [
  { kind: 'permissive', label: 'Permissive (MIT, ISC, BSD, Apache…)', color: 'var(--green)' },
  { kind: 'weak-copyleft', label: 'Weak copyleft (LGPL, MPL, EPL…)', color: 'var(--amber)' },
  { kind: 'strong-copyleft', label: 'Strong copyleft (GPL, AGPL, SSPL…)', color: 'var(--red)' },
  { kind: 'unknown', label: 'Non-standard or unrecognised', color: 'var(--violet)' },
  { kind: 'none', label: 'No licence declared', color: 'var(--slate)' },
];

function Licences({ summary }: { summary: ScanSummary }) {
  const total = LICENCE_ROWS.reduce((n, row) => n + summary.licenses[row.kind], 0);
  return (
    <section aria-labelledby="lic-title">
      <h2 class="section-title" id="lic-title">
        Licences
      </h2>
      {total === 0 ? (
        <p class="section-sub">No licence data available.</p>
      ) : (
        <>
          <div class="lic-bar" aria-hidden="true">
            {LICENCE_ROWS.map((row) =>
              summary.licenses[row.kind] ? (
                <span
                  key={row.kind}
                  style={{
                    width: `${(summary.licenses[row.kind] / total) * 100}%`,
                    background: row.color,
                  }}
                />
              ) : null,
            )}
          </div>
          <ul class="legend">
            {LICENCE_ROWS.map((row) => (
              <li key={row.kind}>
                <span class="dot" style={{ background: row.color, marginTop: 0 }} />
                {row.label}
                <span class="n">{summary.licenses[row.kind].toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
