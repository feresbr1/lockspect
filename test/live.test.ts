import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeLockfile, parseLockfile } from '../src/core';

// Hits the real OSV.dev, deps.dev and npm registry APIs. Run with LIVE=1 npm test.
describe.runIf(process.env.LIVE === '1')('live APIs', () => {
  it('flags the hijacked axios release and its payload as malware', async () => {
    const text = readFileSync(
      new URL('../examples/axios-compromise/package-lock.json', import.meta.url),
      'utf8',
    );
    const report = await analyzeLockfile(parseLockfile(text, 'package-lock.json'));
    expect(report.errors).toEqual([]);
    const malware = report.packages.filter((p) => p.flags.includes('malware')).map((p) => p.key);
    expect(malware.sort()).toEqual(['axios@1.14.1', 'plain-crypto-js@4.2.1']);
    const axios = report.packages.find((p) => p.key === 'axios@1.14.1')!;
    expect(axios.flags).toContain('missing');
    expect(axios.advisories.some((a) => a.id.startsWith('MAL-'))).toBe(true);
    expect(report.summary.provenance).toBeGreaterThan(0);
    const express = report.packages.find((p) => p.name === 'express')!;
    expect(express.meta?.publishedAt).toMatch(/^20\d\d-/);
  }, 120_000);
});
