export interface Sample {
  id: string;
  label: string;
  description: string;
  fileName: string;
  load: () => Promise<string>;
}

// Loaded on demand so the samples do not weigh down the first page load.
export const SAMPLES: Sample[] = [
  {
    id: 'axios',
    label: 'a lockfile hit by the axios compromise',
    description:
      'A demo package-lock.json for an Express app that resolved axios@1.14.1, the hijacked release published on 31 March 2026, and its payload dependency plain-crypto-js@4.2.1.',
    fileName: 'package-lock.json',
    load: () =>
      import('../../examples/axios-compromise/package-lock.json?raw').then((m) => m.default),
  },
  {
    id: 'self',
    label: "lockspect's own lockfile",
    description: 'The real package-lock.json this site was built from.',
    fileName: 'package-lock.json',
    load: () => import('../../package-lock.json?raw').then((m) => m.default),
  },
];
