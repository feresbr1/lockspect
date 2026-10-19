import type { PackageManager } from './types';

export interface CooldownSnippet {
  manager: PackageManager | 'renovate' | 'dependabot';
  label: string;
  file: string;
  code: string;
  note: string;
}

/**
 * Config that makes each tool refuse versions younger than `days`.
 * Units differ per tool: npm uses days, pnpm and Yarn minutes, Bun seconds.
 */
export function cooldownSnippets(days: number): CooldownSnippet[] {
  const d = Math.max(1, Math.round(days));
  return [
    {
      manager: 'npm',
      label: 'npm',
      file: '.npmrc',
      code: `min-release-age=${d}`,
      note: 'npm 11.10 or newer. Value in days.',
    },
    {
      manager: 'pnpm',
      label: 'pnpm',
      file: 'pnpm-workspace.yaml',
      code: `minimumReleaseAge: ${d * 1440}`,
      note: 'pnpm 10.16 or newer. Value in minutes (pnpm 11 defaults to 1440).',
    },
    {
      manager: 'yarn',
      label: 'Yarn',
      file: '.yarnrc.yml',
      code: `npmMinimalAgeGate: ${d * 1440}`,
      note: 'Yarn 4.10 or newer. Value in minutes ("7d" style strings work from 4.11).',
    },
    {
      manager: 'bun',
      label: 'Bun',
      file: 'bunfig.toml',
      code: `[install]\nminimumReleaseAge = ${d * 86400}`,
      note: 'Bun 1.3 or newer. Value in seconds.',
    },
    {
      manager: 'renovate',
      label: 'Renovate',
      file: 'renovate.json',
      code: `{\n  "minimumReleaseAge": "${d} days"\n}`,
      note: 'Renovate waits before opening update PRs.',
    },
    {
      manager: 'dependabot',
      label: 'Dependabot',
      file: '.github/dependabot.yml',
      code: `    cooldown:\n      default-days: ${d}`,
      note: 'Add under each npm entry in "updates".',
    },
  ];
}
