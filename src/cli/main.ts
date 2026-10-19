import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { analyzeLockfile, DEFAULT_COOLDOWN_DAYS, worstSeverity } from '../core/analyze';
import { LockfileError, parseLockfile, SUPPORTED_LOCKFILES } from '../core/parsers';
import {
  FAIL_ON_HELP,
  formatAge,
  highestFix,
  parseFailOn,
  rankPackages,
  toMarkdown,
  violations,
} from '../core/report';
import type { PackageReport, ScanReport } from '../core/types';
import { VERSION } from '../core/version';

const HELP = `lockspect ${VERSION}
Inspect a lockfile for malware, vulnerabilities, too-fresh releases, unpublished
versions, install scripts and licence risk. Data from OSV.dev, deps.dev and npm.

Usage
  lockspect [lockfile] [options]

  With no lockfile, the first of ${SUPPORTED_LOCKFILES.join(', ')}
  found in the current directory is used.

Options
  -c, --cooldown <days>     Flag versions younger than this (default ${DEFAULT_COOLDOWN_DAYS})
  -f, --fail-on <rules>     Exit 1 when a package matches (default "malware")
                            ${FAIL_ON_HELP}
      --json                Print the full report as JSON
      --markdown            Print a Markdown summary (for PR comments)
      --markdown-file <p>   Also append the Markdown summary to a file
                            (e.g. "$GITHUB_STEP_SUMMARY")
  -a, --all                 List every package, not only flagged ones
      --allow-incomplete    Exit 0/1 even if a data source could not be reached
      --no-color            Disable colours (NO_COLOR is also respected)
  -v, --version             Print the version
  -h, --help                Show this help

Exit codes
  0  no package matched --fail-on
  1  at least one package matched --fail-on
  2  usage error, unreadable lockfile, or incomplete scan

Examples
  npx github:feresbr1/lockspect
  npx github:feresbr1/lockspect pnpm-lock.yaml --cooldown 3
  npx github:feresbr1/lockspect --fail-on malware,vuln:high,fresh
`;

export async function main(argv: string[]): Promise<number> {
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        cooldown: { type: 'string', short: 'c' },
        'fail-on': { type: 'string', short: 'f' },
        json: { type: 'boolean' },
        markdown: { type: 'boolean' },
        'markdown-file': { type: 'string' },
        all: { type: 'boolean', short: 'a' },
        'allow-incomplete': { type: 'boolean' },
        'no-color': { type: 'boolean' },
        version: { type: 'boolean', short: 'v' },
        help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (error) {
    process.stderr.write(
      `lockspect: ${(error as Error).message}\nRun lockspect --help for usage.\n`,
    );
    return 2;
  }
  const { values, positionals } = args;
  if (values.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  const color = !values['no-color'] && !process.env.NO_COLOR && Boolean(process.stdout.isTTY);
  const c = palette(color);
  const fail = (message: string) => {
    process.stderr.write(`${c.red('lockspect:')} ${message}\n`);
    return 2;
  };

  const cooldown = values.cooldown === undefined ? DEFAULT_COOLDOWN_DAYS : Number(values.cooldown);
  if (!Number.isFinite(cooldown) || cooldown < 0) {
    return fail(`--cooldown must be a number of days, got "${values.cooldown}".`);
  }
  let rules;
  try {
    rules = parseFailOn(values['fail-on'] ?? 'malware');
  } catch (error) {
    return fail((error as Error).message);
  }

  if (positionals.length > 1) return fail('Pass at most one lockfile.');
  const path = positionals[0] ? resolve(positionals[0]) : findLockfile(process.cwd());
  if (!path) {
    const hint = existsSync(join(process.cwd(), 'bun.lockb'))
      ? ' Found bun.lockb: run `bun install --save-text-lockfile` to create bun.lock.'
      : '';
    return fail(
      `No lockfile found in ${process.cwd()}.${hint} Pass a path, e.g. lockspect path/to/package-lock.json`,
    );
  }

  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    return fail(
      `Cannot read ${path}: ${(error as NodeJS.ErrnoException).code ?? (error as Error).message}`,
    );
  }

  let parsed;
  try {
    parsed = parseLockfile(text, basename(path));
  } catch (error) {
    if (error instanceof LockfileError) return fail(error.message);
    return fail(`Could not parse ${basename(path)}: ${(error as Error).message}`);
  }

  const quiet = values.json || values.markdown || !process.stderr.isTTY;
  if (!quiet)
    process.stderr.write(
      c.dim(`Scanning ${parsed.packages.length} packages from ${basename(path)}…\n`),
    );

  const report = await analyzeLockfile(parsed, {
    cooldownDays: cooldown,
    fileName: basename(path),
  });
  const failing = violations(report, rules);

  if (values['markdown-file']) {
    try {
      appendFileSync(values['markdown-file'], `${toMarkdown(report)}\n`);
    } catch (error) {
      return fail(`Cannot write ${values['markdown-file']}: ${(error as Error).message}`);
    }
  }

  if (values.json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else if (values.markdown) process.stdout.write(`${toMarkdown(report)}\n`);
  else
    process.stdout.write(
      renderText(report, failing, Boolean(values.all), c, values['fail-on'] ?? 'malware'),
    );

  if (report.errors.length && !values['allow-incomplete']) return 2;
  return failing.length ? 1 : 0;
}

export function findLockfile(dir: string): string | undefined {
  for (const name of SUPPORTED_LOCKFILES) {
    const candidate = join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

type Paint = (s: string) => string;
interface Palette {
  red: Paint;
  orange: Paint;
  yellow: Paint;
  green: Paint;
  violet: Paint;
  blue: Paint;
  dim: Paint;
  bold: Paint;
}

function palette(enabled: boolean): Palette {
  const wrap = (open: string, close = '\x1b[39m'): Paint =>
    enabled ? (s) => `${open}${s}${close}` : (s) => s;
  return {
    red: wrap('\x1b[31m'),
    orange: wrap('\x1b[38;5;208m'),
    yellow: wrap('\x1b[33m'),
    green: wrap('\x1b[32m'),
    violet: wrap('\x1b[35m'),
    blue: wrap('\x1b[34m'),
    dim: wrap('\x1b[2m', '\x1b[22m'),
    bold: wrap('\x1b[1m', '\x1b[22m'),
  };
}

function renderText(
  report: ScanReport,
  failing: PackageReport[],
  all: boolean,
  c: Palette,
  failOn: string,
): string {
  const s = report.summary;
  const out: string[] = [''];
  const title = `${report.lockfile.fileName ?? 'lockfile'} · ${report.lockfile.manager} lockfile v${report.lockfile.lockfileVersion} · ${s.total} packages`;
  out.push(c.dim(title));

  if (s.malware)
    out.push(c.bold(c.red(`✖ ${s.malware} malicious package${s.malware > 1 ? 's' : ''} found`)));
  else if (report.errors.length) out.push(c.bold(c.yellow('! Scan incomplete')));
  else out.push(c.bold(c.green('✔ No known malware')));
  out.push('');

  const sev = s.vulnsBySeverity;
  const n = (value: number, paint: Paint) => (value ? paint(String(value)) : c.dim('0'));
  const row = (label: string, value: string, extra = '') =>
    out.push(`  ${label.padEnd(17)}${value}${extra ? `  ${c.dim(extra)}` : ''}`);
  row('malware', n(s.malware, c.red));
  row(
    'vulnerable',
    n(s.vulnerable, c.orange),
    `(${sev.critical} critical, ${sev.high} high, ${sev.moderate} moderate, ${sev.low} low advisories)`,
  );
  row('not on npm', n(s.missing, c.violet));
  row(`fresh (<${report.cooldownDays}d)`, n(s.fresh, c.yellow));
  row('install scripts', n(s.installScripts, c.blue));
  row('deprecated', n(s.deprecated, c.dim));
  row('strong copyleft', n(s.copyleft, c.dim));
  row('provenance', `${s.provenance}/${s.total}`);
  out.push('');

  const shown = rankPackages(
    all
      ? report.packages
      : report.packages.filter((p) =>
          p.flags.some(
            (f) => f === 'malware' || f === 'vulnerability' || f === 'missing' || f === 'fresh',
          ),
        ),
  );
  for (const pkg of shown) {
    const id = `${pkg.name}@${pkg.version}`;
    const parts: string[] = [];
    if (pkg.flags.includes('malware')) parts.push(c.red('MALWARE'));
    const vulns = pkg.advisories.filter((a) => !a.malware);
    if (vulns.length) {
      const worst = worstSeverity(vulns) ?? 'unknown';
      const paint = worst === 'critical' ? c.red : worst === 'high' ? c.orange : c.yellow;
      parts.push(paint(`${vulns.length} ${worst}`));
    }
    if (pkg.flags.includes('missing'))
      parts.push(c.violet(pkg.meta?.unpublished ? 'unpublished' : 'not on npm'));
    if (pkg.flags.includes('fresh')) parts.push(c.yellow(`fresh ${formatAge(pkg.ageDays)}`));
    if (pkg.flags.includes('install-script')) parts.push(c.blue('install script'));
    if (pkg.flags.includes('deprecated')) parts.push(c.dim('deprecated'));
    const fix = highestFix(pkg);
    const marker = failing.includes(pkg) ? c.red('✖') : ' ';
    out.push(
      ` ${marker} ${id}${pkg.direct ? c.dim(' (direct)') : ''}  ${parts.join(c.dim(' · ')) || c.dim('ok')}${fix ? c.green(`  → ${fix}`) : ''}`,
    );
    for (const a of pkg.advisories.slice(0, 3)) {
      out.push(c.dim(`      ${a.id}  ${a.summary.slice(0, 90)}`));
    }
    if (pkg.advisories.length > 3) out.push(c.dim(`      …and ${pkg.advisories.length - 3} more`));
  }
  if (shown.length) out.push('');

  for (const error of report.errors) out.push(c.yellow(`! ${error}`));
  for (const warning of report.warnings) out.push(c.dim(`note: ${warning}`));
  if (failing.length) {
    out.push(
      c.red(
        `${failing.length} package${failing.length > 1 ? 's' : ''} matched --fail-on ${failOn}`,
      ),
    );
  } else {
    out.push(c.dim(`Nothing matched --fail-on ${failOn}.`));
  }
  out.push('');
  return out.join('\n');
}
