import type { LicenseKind } from './types';

const STRONG = [/^A?GPL-/, /^GPL/, /^AGPL/, /^SSPL/, /^OSL-/, /^EUPL-/, /^RPL-/, /^CPAL-/];
const WEAK = [/^LGPL/, /^MPL-/, /^EPL-/, /^CDDL-/, /^CPL-/, /^MS-RL$/, /^CC-BY-SA-/, /^ODbL/];
const PERMISSIVE = [
  /^MIT(-0)?$/,
  /^ISC$/,
  /^BSD-/,
  /^0BSD$/,
  /^Apache-/,
  /^Unlicense$/,
  /^CC0-/,
  /^CC-BY-\d/,
  /^BlueOak-/,
  /^Python-2\.0/,
  /^PSF-/,
  /^Zlib$/,
  /^WTFPL$/,
  /^Artistic-2\.0$/,
  /^BSL-1\.0$/,
  /^X11$/,
  /^Unicode-/,
  /^MIT-/,
];

const RANK: Record<LicenseKind, number> = {
  none: 0,
  permissive: 1,
  unknown: 2,
  'weak-copyleft': 3,
  'strong-copyleft': 4,
};

export function classifyLicense(id: string): LicenseKind {
  const clean = id.trim().replace(/^\(|\)$/g, '');
  if (!clean) return 'none';
  if (STRONG.some((re) => re.test(clean))) return 'strong-copyleft';
  if (WEAK.some((re) => re.test(clean))) return 'weak-copyleft';
  if (PERMISSIVE.some((re) => re.test(clean))) return 'permissive';
  return 'unknown';
}

/**
 * Classify the licences of one package. Each entry may be an SPDX expression:
 * "A OR B" lets you pick the most permissive option, "A AND B" binds you to the strictest.
 */
export function classifyLicenses(licenses: readonly string[]): LicenseKind {
  if (!licenses.length) return 'none';
  let worst: LicenseKind = 'none';
  for (const expression of licenses) {
    const kind = classifyExpression(expression);
    if (RANK[kind] > RANK[worst]) worst = kind;
  }
  return worst;
}

function classifyExpression(expression: string): LicenseKind {
  const orParts = expression.split(/\s+OR\s+/i);
  if (orParts.length > 1) {
    const kinds = orParts.map(classifyExpression).filter((k) => k !== 'none');
    // pick the option that binds you least; prefer known permissive over unknown
    return kinds.sort((a, b) => RANK[a] - RANK[b])[0] ?? 'none';
  }
  const andParts = expression.split(/\s+AND\s+/i);
  let worst: LicenseKind = 'none';
  for (const part of andParts) {
    const id = part.replace(/[()]/g, '').replace(/\s+WITH\s+.*$/i, '');
    const kind = classifyLicense(id);
    if (RANK[kind] > RANK[worst]) worst = kind;
  }
  return worst;
}
