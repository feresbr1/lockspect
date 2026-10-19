import type { FindingKind, PackageReport, ScanReport, Severity } from './types';
import { SEVERITY_ORDER, worstSeverity } from './analyze';
import { compareVersions } from './semver';

export const FINDING_INFO: Record<FindingKind, { title: string; blurb: string }> = {
  malware: {
    title: 'Malware',
    blurb: 'Versions OSV lists as malicious. Treat any machine that installed them as compromised.',
  },
  vulnerability: {
    title: 'Vulnerable',
    blurb: 'Versions with published security advisories (GHSA / CVE).',
  },
  missing: {
    title: 'Not on npm',
    blurb:
      'Versions the public registry does not have. Unpublished versions are often removed malware; private packages also land here.',
  },
  fresh: {
    title: 'Too fresh',
    blurb:
      'Published inside your cooldown window. Hijacked releases are often caught and pulled within days.',
  },
  'install-script': {
    title: 'Install scripts',
    blurb: 'Run code on your machine during install (preinstall / install / postinstall).',
  },
  deprecated: {
    title: 'Deprecated',
    blurb: 'Marked deprecated by their maintainers.',
  },
  copyleft: {
    title: 'Strong copyleft',
    blurb: 'GPL, AGPL, SSPL and similar licences that can impose obligations on your code.',
  },
};

export const FINDING_ORDER: FindingKind[] = [
  'malware',
  'vulnerability',
  'missing',
  'fresh',
  'install-script',
  'deprecated',
  'copyleft',
];

// ---------------------------------------------------------------------------
// --fail-on policy
// ---------------------------------------------------------------------------

export type FailRule =
  | { kind: 'malware' | 'missing' | 'fresh' | 'install-script' | 'deprecated' | 'copyleft' }
  | { kind: 'vulnerability'; minSeverity: Severity };

export const FAIL_ON_HELP =
  'malware, vuln (any), vuln:critical, vuln:high, vuln:moderate, vuln:low, missing, fresh, install-script, deprecated, copyleft, none';

export function parseFailOn(value: string): FailRule[] {
  const rules: FailRule[] = [];
  for (const raw of value
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)) {
    if (raw === 'none') continue;
    if (raw === 'vuln' || raw === 'vulnerability') {
      rules.push({ kind: 'vulnerability', minSeverity: 'unknown' });
      continue;
    }
    const vuln = /^(?:vuln|vulnerability):(critical|high|moderate|medium|low)$/.exec(raw);
    if (vuln?.[1]) {
      const sev = (vuln[1] === 'medium' ? 'moderate' : vuln[1]) as Severity;
      rules.push({ kind: 'vulnerability', minSeverity: sev });
      continue;
    }
    if (['malware', 'missing', 'fresh', 'install-script', 'deprecated', 'copyleft'].includes(raw)) {
      rules.push({ kind: raw as Exclude<FailRule['kind'], 'vulnerability'> });
      continue;
    }
    throw new Error(`Unknown --fail-on value "${raw}". Use: ${FAIL_ON_HELP}`);
  }
  return rules;
}

/** Packages that break at least one rule. */
export function violations(report: ScanReport, rules: readonly FailRule[]): PackageReport[] {
  return report.packages.filter((pkg) =>
    rules.some((rule) => {
      if (rule.kind !== 'vulnerability') return pkg.flags.includes(rule.kind);
      // "unknown" severity counts only for the catch-all rule
      return pkg.advisories.some(
        (a) =>
          !a.malware &&
          (rule.minSeverity === 'unknown' ||
            (a.severity !== 'unknown' &&
              SEVERITY_ORDER.indexOf(a.severity) <= SEVERITY_ORDER.indexOf(rule.minSeverity))),
      );
    }),
  );
}

// ---------------------------------------------------------------------------
// Markdown (PR comments, GitHub job summaries, issues)
// ---------------------------------------------------------------------------

export function formatAge(days: number | undefined): string {
  if (days === undefined) return '?';
  if (days < 1 / 24) return `${Math.max(1, Math.round(days * 1440))}m`;
  if (days < 1) return `${Math.round(days * 24)}h`;
  if (days < 60) return `${Math.floor(days)}d`;
  if (days < 730) return `${Math.floor(days / 30.44)}mo`;
  return `${Math.floor(days / 365.25)}y`;
}

function verdict(report: ScanReport): string {
  const s = report.summary;
  if (s.malware) return `🚨 **${s.malware} malicious package${s.malware > 1 ? 's' : ''} found.**`;
  if (report.errors.length) return '⚠️ **Scan incomplete.** Some data sources failed.';
  if (s.vulnsBySeverity.critical || s.vulnsBySeverity.high) {
    return `⚠️ **No known malware**, but ${s.vulnsBySeverity.critical + s.vulnsBySeverity.high} critical/high advisories.`;
  }
  return '✅ **No known malware or high-severity advisories.**';
}

export function toMarkdown(report: ScanReport, maxRows = 50): string {
  const s = report.summary;
  const lines: string[] = [];
  const name = report.lockfile.fileName ?? report.lockfile.format;
  lines.push(`## lockspect report: \`${name}\``, '');
  lines.push(verdict(report), '');
  lines.push('| Check | Packages |', '| --- | ---: |');
  lines.push(`| Malware | ${s.malware} |`);
  lines.push(
    `| Vulnerable | ${s.vulnerable} (${s.vulnsBySeverity.critical} critical, ${s.vulnsBySeverity.high} high, ${s.vulnsBySeverity.moderate} moderate, ${s.vulnsBySeverity.low} low) |`,
  );
  lines.push(`| Not on npm | ${s.missing} |`);
  lines.push(`| Published < ${report.cooldownDays}d ago | ${s.fresh} |`);
  lines.push(`| Install scripts | ${s.installScripts} |`);
  lines.push(`| Deprecated | ${s.deprecated} |`);
  lines.push(`| Strong copyleft | ${s.copyleft} |`);
  lines.push(`| With provenance | ${s.provenance} / ${s.total} |`, '');

  const flagged = report.packages.filter((p) =>
    p.flags.some(
      (f) => f === 'malware' || f === 'vulnerability' || f === 'missing' || f === 'fresh',
    ),
  );
  if (flagged.length) {
    lines.push('| Package | Findings | Age | Details |', '| --- | --- | ---: | --- |');
    for (const pkg of rankPackages(flagged).slice(0, maxRows)) {
      lines.push(
        `| \`${pkg.name}@${pkg.version}\`${pkg.direct ? ' (direct)' : ''} | ${describeFlags(pkg)} | ${formatAge(pkg.ageDays)} | ${describeDetails(pkg)} |`,
      );
    }
    if (flagged.length > maxRows) lines.push('', `…and ${flagged.length - maxRows} more.`);
    lines.push('');
  }
  for (const error of report.errors) lines.push(`> ⚠️ ${error}`);
  if (report.errors.length) lines.push('');
  lines.push(
    `<sub>Scanned ${s.total} packages from a ${report.lockfile.manager} lockfile with [lockspect](https://github.com/feresbr1/lockspect) ${report.tool.version} · data from OSV.dev and deps.dev</sub>`,
  );
  return lines.join('\n');
}

export function rankPackages(packages: readonly PackageReport[]): PackageReport[] {
  const score = (p: PackageReport) => {
    if (p.flags.includes('malware')) return 0;
    if (p.flags.includes('missing')) return 1;
    const sev = worstSeverity(p.advisories);
    if (sev) return 2 + SEVERITY_ORDER.indexOf(sev);
    if (p.flags.includes('fresh')) return 8;
    return 9;
  };
  return [...packages].sort((a, b) => score(a) - score(b) || a.name.localeCompare(b.name));
}

function describeFlags(pkg: PackageReport): string {
  const parts: string[] = [];
  if (pkg.flags.includes('malware')) parts.push('🚨 malware');
  const vulns = pkg.advisories.filter((a) => !a.malware);
  if (vulns.length)
    parts.push(
      `${vulns.length} advisor${vulns.length > 1 ? 'ies' : 'y'} (${worstSeverity(vulns)})`,
    );
  if (pkg.flags.includes('missing'))
    parts.push(pkg.meta?.unpublished ? 'unpublished' : 'not on npm');
  if (pkg.flags.includes('fresh')) parts.push('fresh');
  return parts.join(', ');
}

function describeDetails(pkg: PackageReport): string {
  const ids = pkg.advisories.slice(0, 3).map((a) => `[${a.id}](${a.url})`);
  if (pkg.advisories.length > 3) ids.push(`+${pkg.advisories.length - 3}`);
  const fix = highestFix(pkg);
  return [ids.join(' '), fix ? `fix: ≥ ${fix}` : ''].filter(Boolean).join(' · ');
}

/** The lowest version that fixes every advisory with a known fix (the highest "fixedIn"). */
export function highestFix(pkg: PackageReport): string | undefined {
  return pkg.advisories
    .map((a) => a.fixedIn)
    .filter((v): v is string => Boolean(v))
    .sort(compareVersions)
    .pop();
}
