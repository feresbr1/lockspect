import type { FindingKind, Severity } from '../core/types';

export interface Tone {
  fg: string;
  bg: string;
}

export const FINDING_TONE: Record<FindingKind, Tone> = {
  malware: { fg: 'var(--red)', bg: 'var(--red-bg)' },
  vulnerability: { fg: 'var(--orange)', bg: 'var(--orange-bg)' },
  missing: { fg: 'var(--violet)', bg: 'var(--violet-bg)' },
  fresh: { fg: 'var(--amber)', bg: 'var(--amber-bg)' },
  'install-script': { fg: 'var(--blue)', bg: 'var(--blue-bg)' },
  deprecated: { fg: 'var(--slate)', bg: 'var(--slate-bg)' },
  copyleft: { fg: 'var(--slate)', bg: 'var(--slate-bg)' },
};

export const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: { fg: 'var(--red)', bg: 'var(--red-bg)' },
  high: { fg: 'var(--orange)', bg: 'var(--orange-bg)' },
  moderate: { fg: 'var(--amber)', bg: 'var(--amber-bg)' },
  low: { fg: 'var(--slate)', bg: 'var(--slate-bg)' },
  unknown: { fg: 'var(--slate)', bg: 'var(--slate-bg)' },
};

export function toneStyle(tone: Tone): Record<string, string> {
  return { '--tone': tone.fg, '--tone-bg': tone.bg };
}
