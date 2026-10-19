import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { cooldownSnippets } from '../src/core/cooldown';
import { classifyLicense, classifyLicenses } from '../src/core/licenses';
import { formatAge, parseFailOn, toMarkdown, violations } from '../src/core/report';
import { compareVersions } from '../src/core/semver';
import type { PackageReport, ScanReport } from '../src/core/types';
import { summarize } from '../src/core/analyze';
import { VERSION } from '../src/core/version';

describe('compareVersions', () => {
  it.each([
    ['1.0.0', '1.0.1', -1],
    ['1.10.0', '1.9.9', 1],
    ['2.0.0', '2.0.0', 0],
    ['1.0.0-beta.1', '1.0.0', -1],
    ['1.0.0-beta.2', '1.0.0-beta.10', -1],
    ['1.0.0-alpha', '1.0.0-beta', -1],
    ['1.0.0-1', '1.0.0-alpha', -1],
    ['1.0.0+build.5', '1.0.0', 0],
  ])('%s vs %s', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
    expect(compareVersions(b, a)).toBe(-expected || 0);
  });
});

describe('licences', () => {
  it.each([
    ['MIT', 'permissive'],
    ['Apache-2.0', 'permissive'],
    ['BSD-3-Clause', 'permissive'],
    ['LGPL-2.1-or-later', 'weak-copyleft'],
    ['MPL-2.0', 'weak-copyleft'],
    ['GPL-3.0-only', 'strong-copyleft'],
    ['AGPL-3.0', 'strong-copyleft'],
    ['SSPL-1.0', 'strong-copyleft'],
    ['non-standard', 'unknown'],
    ['', 'none'],
  ])('%s is %s', (id, kind) => {
    expect(classifyLicense(id)).toBe(kind);
  });

  it('OR picks the most permissive option, AND the strictest', () => {
    expect(classifyLicenses(['(MIT OR GPL-3.0-or-later)'])).toBe('permissive');
    expect(classifyLicenses(['MIT AND GPL-2.0-only'])).toBe('strong-copyleft');
    expect(classifyLicenses(['GPL-2.0-only WITH Classpath-exception-2.0'])).toBe('strong-copyleft');
    expect(classifyLicenses(['MIT', 'MPL-2.0'])).toBe('weak-copyleft');
    expect(classifyLicenses([])).toBe('none');
  });
});

describe('--fail-on', () => {
  it('parses rule lists', () => {
    expect(parseFailOn('malware, vuln:HIGH,fresh')).toEqual([
      { kind: 'malware' },
      { kind: 'vulnerability', minSeverity: 'high' },
      { kind: 'fresh' },
    ]);
    expect(parseFailOn('vuln:medium')).toEqual([
      { kind: 'vulnerability', minSeverity: 'moderate' },
    ]);
    expect(parseFailOn('none')).toEqual([]);
    expect(() => parseFailOn('malware,nope')).toThrow(/Unknown --fail-on value "nope"/);
  });

  const pkg = (name: string, partial: Partial<PackageReport>): PackageReport => ({
    name,
    version: '1.0.0',
    key: `${name}@1.0.0`,
    advisories: [],
    flags: [],
    ...partial,
  });
  const adv = (severity: 'critical' | 'high' | 'moderate' | 'unknown') => ({
    id: `X-${severity}`,
    aliases: [],
    summary: '',
    severity,
    malware: false,
    url: '',
  });
  const packages = [
    pkg('crit', { advisories: [adv('critical')], flags: ['vulnerability'] }),
    pkg('mod', { advisories: [adv('moderate')], flags: ['vulnerability'] }),
    pkg('unk', { advisories: [adv('unknown')], flags: ['vulnerability'] }),
    pkg('young', { flags: ['fresh'] }),
  ];
  const report = { packages } as ScanReport;

  it('matches severities at or above the threshold', () => {
    const names = (rules: string) => violations(report, parseFailOn(rules)).map((p) => p.name);
    expect(names('vuln:high')).toEqual(['crit']);
    expect(names('vuln:moderate')).toEqual(['crit', 'mod']);
    expect(names('vuln')).toEqual(['crit', 'mod', 'unk']);
    expect(names('fresh')).toEqual(['young']);
    expect(names('malware')).toEqual([]);
  });

  it('renders a Markdown summary', () => {
    const full: ScanReport = {
      tool: { name: 'lockspect', version: VERSION },
      scannedAt: '2026-10-19T00:00:00Z',
      cooldownDays: 7,
      lockfile: {
        format: 'npm',
        manager: 'npm',
        lockfileVersion: '3',
        fileName: 'package-lock.json',
      },
      summary: summarize(packages),
      packages,
      skipped: [],
      warnings: [],
      errors: [],
    };
    const md = toMarkdown(full);
    expect(md).toContain('## lockspect report: `package-lock.json`');
    expect(md).toContain('| `crit@1.0.0` | 1 advisory (critical)');
    expect(md).toContain('No known malware');
  });
});

describe('formatAge', () => {
  it.each([
    [undefined, '?'],
    [0.0001, '1m'],
    [0.5, '12h'],
    [3.7, '3d'],
    [90, '2mo'],
    [1000, '2y'],
  ])('%s days → %s', (days, text) => {
    expect(formatAge(days)).toBe(text);
  });
});

describe('cooldown snippets', () => {
  it('converts days into each tool’s unit', () => {
    const byManager = Object.fromEntries(cooldownSnippets(7).map((s) => [s.manager, s.code]));
    expect(byManager.npm).toBe('min-release-age=7');
    expect(byManager.pnpm).toBe('minimumReleaseAge: 10080');
    expect(byManager.yarn).toBe('npmMinimalAgeGate: 10080');
    expect(byManager.bun).toContain('minimumReleaseAge = 604800');
    expect(byManager.renovate).toContain('"7 days"');
    expect(byManager.dependabot).toContain('default-days: 7');
  });
});

describe('version', () => {
  it('matches package.json', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    expect(VERSION).toBe(pkg.version);
  });
});
