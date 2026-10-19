import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';
import { parseLockfile } from '../src/core/parsers';
import { fakeFetch, type FakeWorld } from '../test/helpers';

const fixturePath = (name: string) =>
  fileURLToPath(new URL(`../test/fixtures/${name}`, import.meta.url));

const WORLD: FakeWorld = {
  osv: {
    'minimist@1.2.5': [
      {
        id: 'GHSA-xvch-5gv4-984h',
        summary: 'Prototype Pollution in minimist',
        database_specific: { severity: 'CRITICAL' },
        affected: [
          {
            package: { ecosystem: 'npm', name: 'minimist' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.6' }] }],
          },
        ],
      },
    ],
    'left-pad@1.3.0': [{ id: 'MAL-2099-0001', summary: 'Malicious code in left-pad (npm)' }],
  },
  depsDev: {
    // Every fixture package is old and MIT, except is-number which is two days old.
    ...Object.fromEntries(
      parseLockfile(
        readFileSync(fixturePath('package-lock.v3.json'), 'utf8'),
        'package-lock.json',
      ).packages.map((p) => [
        `${p.name}@${p.version}`,
        { publishedAt: '2020-01-01T00:00:00Z', licenses: ['MIT'] },
      ]),
    ),
    'is-number@7.0.0': {
      publishedAt: new Date(Date.now() - 2 * 86_400_000).toISOString(),
      licenses: ['MIT'],
    },
  },
  registry: {},
};

/** Serve OSV, deps.dev and npm registry calls from a fixed fake world. */
async function mockApis(page: Page, world: FakeWorld = WORLD) {
  const fetch = fakeFetch(world);
  const handler = async (route: Parameters<Parameters<Page['route']>[1]>[0]) => {
    const req = route.request();
    if (req.method() === 'OPTIONS') {
      return route.fulfill({ status: 204, headers: cors() });
    }
    const res = await fetch(req.url(), { method: req.method(), body: req.postData() ?? undefined });
    await route.fulfill({
      status: res.status,
      headers: { ...cors(), 'content-type': 'application/json' },
      body: await res.text(),
    });
  };
  await page.route('https://api.osv.dev/**', handler);
  await page.route('https://api.deps.dev/**', handler);
  await page.route('https://registry.npmjs.org/**', handler);
}

function cors() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  };
}

function collectErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  return errors;
}

test.describe('with mocked data sources', () => {
  test.beforeEach(async ({ page }) => {
    await mockApis(page);
  });

  test('scans an uploaded package-lock.json end to end', async ({ page }) => {
    const errors = collectErrors(page);
    await page.goto('./');
    await expect(page.getByRole('heading', { level: 1 })).toContainText('hiding something');

    await page.locator('input[type=file]').setInputFiles(fixturePath('package-lock.v3.json'));

    await expect(page.getByTestId('verdict')).toHaveText('1 malicious package found');
    await expect(
      page.getByText('package-lock.v3.json · npm lockfile v3 · 45 packages'),
    ).toBeVisible();

    // Flagged packages are listed, worst first.
    const rows = page.getByTestId('pkg');
    await expect(rows.first()).toContainText('left-pad@1.3.0');
    await expect(rows.nth(1)).toContainText('minimist@1.2.5');
    await expect(page.getByText('45 packages', { exact: false }).first()).toBeVisible();

    // Expanding a row shows the advisory and its fix.
    await rows.nth(1).getByRole('button').first().click();
    await expect(page.getByRole('link', { name: 'GHSA-xvch-5gv4-984h' })).toBeVisible();
    await expect(page.getByText('upgrade to 1.2.6 or later')).toBeVisible();

    // The "Too fresh" tile filters the list to is-number (published two days ago).
    await page.getByRole('button', { name: /Too fresh/ }).click();
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('is-number@7.0.0');

    // Search across all packages.
    await page.getByLabel('Show').selectOption('all');
    await page.getByPlaceholder('Filter by name…').fill('lodash');
    await expect(rows).toHaveCount(1);

    // JSON export.
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download JSON' }).click();
    const file = await (await download).path();
    const report = JSON.parse(readFileSync(file, 'utf8'));
    expect(report.summary.malware).toBe(1);

    // Hardening snippet follows the detected package manager.
    await expect(page.getByRole('tab', { name: 'npm', exact: true })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    await expect(page.locator('.snippet pre')).toHaveText('min-release-age=7');

    expect(errors).toEqual([]);
  });

  test('scans pasted pnpm-lock.yaml text and goes back with the browser', async ({ page }) => {
    await page.goto('./');
    await page.getByRole('button', { name: 'Paste text' }).click();
    await page
      .getByLabel('Lockfile contents')
      .fill(readFileSync(fixturePath('pnpm-lock.v9.yaml'), 'utf8'));
    await page.getByRole('button', { name: 'Scan pasted lockfile' }).click();
    await expect(page.getByTestId('verdict')).toBeVisible();
    await expect(
      page.getByText('pasted lockfile · pnpm lockfile v9.0 · 45 packages'),
    ).toBeVisible();
    await expect(page.getByRole('tab', { name: 'pnpm', exact: true })).toHaveAttribute(
      'aria-selected',
      'true',
    );

    await page.goBack();
    await expect(page.getByRole('heading', { level: 1 })).toContainText('hiding something');
  });

  test('cooldown choice changes what counts as fresh', async ({ page }) => {
    await page.goto('./');
    await page.getByRole('button', { name: '1d', exact: true }).click();
    await page.locator('input[type=file]').setInputFiles(fixturePath('bun.lock'));
    await expect(page.getByTestId('verdict')).toBeVisible();
    await expect(page.getByRole('button', { name: /Too fresh/ })).toContainText('0');
    await expect(page.locator('.snippet pre')).toContainText('minimumReleaseAge = 86400');
  });

  test('explains what to upload instead of a package.json', async ({ page }) => {
    await page.goto('./');
    await page.locator('input[type=file]').setInputFiles({
      name: 'package.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({ name: 'x', dependencies: { a: '^1.0.0' } })),
    });
    await expect(page.getByRole('alert')).toContainText('It lists version ranges');
  });

  test('says the scan is incomplete when OSV is unreachable', async ({ page }) => {
    await page.unrouteAll();
    await mockApis(page, { ...WORLD, failOsv: true });
    await page.goto('./');
    await page.locator('input[type=file]').setInputFiles(fixturePath('yarn-classic.lock'));
    await expect(page.getByTestId('verdict')).toHaveText('Scan incomplete', { timeout: 30_000 });
    await expect(page.getByRole('alert').first()).toContainText('Advisory lookup failed');
  });

  test('the main actions are reachable by keyboard', async ({ page }) => {
    await page.goto('./');
    const choose = page.getByRole('button', { name: 'Choose lockfile' });
    for (
      let i = 0;
      i < 10 && !(await choose.evaluate((el) => el === document.activeElement));
      i++
    ) {
      await page.keyboard.press('Tab');
    }
    await expect(choose).toBeFocused();
  });
});

// Real OSV.dev / deps.dev / npm requests. Run with LIVE=1, or against the deployed site.
test.describe('live', () => {
  test.skip(!process.env.LIVE && !process.env.E2E_BASE_URL, 'set LIVE=1 to hit the real APIs');

  test('the axios sample is flagged as malware', async ({ page }) => {
    const errors = collectErrors(page);
    await page.goto('./');
    await page.getByRole('button', { name: 'a lockfile hit by the axios compromise' }).click();
    await expect(page.getByTestId('verdict')).toHaveText('2 malicious packages found', {
      timeout: 45_000,
    });
    await expect(page.getByTestId('pkg').first()).toContainText('axios@1.14.1');
    expect(errors).toEqual([]);
  });
});
