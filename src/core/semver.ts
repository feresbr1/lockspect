/** Minimal semver comparison for exact versions ("1.2.3", "1.2.3-beta.1"). Build metadata is ignored. */
export function compareVersions(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const diff = (pa.core[i] ?? 0) - (pb.core[i] ?? 0);
    if (diff !== 0) return Math.sign(diff);
  }
  // A version without a prerelease is greater than one with it.
  if (!pa.pre.length && !pb.pre.length) return 0;
  if (!pa.pre.length) return 1;
  if (!pb.pre.length) return -1;
  const len = Math.max(pa.pre.length, pb.pre.length);
  for (let i = 0; i < len; i++) {
    const x = pa.pre[i];
    const y = pb.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const nx = /^\d+$/.test(x) ? Number(x) : NaN;
    const ny = /^\d+$/.test(y) ? Number(y) : NaN;
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) return Math.sign(nx - ny);
    if (!Number.isNaN(nx)) return -1;
    if (!Number.isNaN(ny)) return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

function parse(version: string): { core: number[]; pre: string[] } {
  const [main = '', ...rest] = version.split('+')[0]!.split('-');
  const pre = rest.join('-');
  return {
    core: main.split('.').map((n) => Number.parseInt(n, 10) || 0),
    pre: pre ? pre.split('.') : [],
  };
}
