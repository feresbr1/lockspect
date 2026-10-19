import { mkdtempSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { main } from '../src/cli/main';
import { fakeFetch } from './helpers';

const FIXTURE = fileURLToPath(new URL('./fixtures/package-lock.v3.json', import.meta.url));

let out = '';
let err = '';

beforeEach(() => {
  out = '';
  err = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    out += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    err += String(chunk);
    return true;
  });
  vi.stubGlobal(
    'fetch',
    fakeFetch({
      osv: {
        'minimist@1.2.5': [
          {
            id: 'GHSA-crit',
            summary: 'Prototype pollution',
            database_specific: { severity: 'CRITICAL' },
          },
        ],
      },
      depsDev: {},
      registry: {},
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'lockspect-'));
}

describe('cli', () => {
  it('prints help and version', async () => {
    expect(await main(['--help'])).toBe(0);
    expect(out).toContain('Usage');
    out = '';
    expect(await main(['-v'])).toBe(0);
    expect(out.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('exits 0 when nothing matches --fail-on (default malware)', async () => {
    const code = await main([FIXTURE, '--allow-incomplete']);
    expect(code).toBe(0);
    expect(out).toContain('minimist@1.2.5');
    expect(out).toContain('Nothing matched --fail-on malware');
  });

  it('exits 1 when a package matches --fail-on', async () => {
    const dir = tempDir();
    copyFileSync(FIXTURE, join(dir, 'package-lock.json'));
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(dir);
    const code = await main(['--fail-on', 'vuln:critical']);
    cwd.mockRestore();
    expect(code).toBe(1);
    expect(out).toContain('1 package matched --fail-on vuln:critical');
  });

  it('writes JSON and appends Markdown to a file', async () => {
    const dir = tempDir();
    const lock = join(dir, 'package-lock.json');
    copyFileSync(FIXTURE, lock);
    const summary = join(dir, 'summary.md');
    writeFileSync(summary, '# Existing\n');
    const code = await main([lock, '--json', '--markdown-file', summary, '--fail-on', 'none']);
    expect(code).toBe(0);
    const report = JSON.parse(out);
    expect(report.summary.total).toBe(45);
    expect(report.summary.vulnerable).toBe(1);
    const md = readFileSync(summary, 'utf8');
    expect(md.startsWith('# Existing\n')).toBe(true);
    expect(md).toContain('lockspect report');
  });

  it('exits 2 with a clear message for usage errors', async () => {
    expect(await main(['--cooldown', 'soon'])).toBe(2);
    expect(err).toContain('--cooldown must be a number');
    expect(await main(['--fail-on', 'whatever'])).toBe(2);
    expect(await main(['a', 'b'])).toBe(2);
    expect(await main(['does-not-exist.json'])).toBe(2);
    expect(err).toContain('ENOENT');
    expect(await main(['--bogus'])).toBe(2);
  });

  it('explains when no lockfile is found, including bun.lockb', async () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'bun.lockb'), '\u0000');
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(dir);
    expect(await main([])).toBe(2);
    cwd.mockRestore();
    expect(err).toContain('No lockfile found');
    expect(err).toContain('save-text-lockfile');
  });

  it('exits 2 when a data source fails, unless --allow-incomplete', async () => {
    vi.stubGlobal('fetch', fakeFetch({ failDepsDev: true }));
    const path = FIXTURE;
    expect(await main([path])).toBe(2);
    expect(out).toContain('Scan incomplete');
    expect(await main([path, '--allow-incomplete'])).toBe(0);
  }, 20_000); // failed requests are retried with backoff
});
