// Bundle the CLI into one dependency-free file that runs on Node 18.17+.
import { build } from 'esbuild';

const banner = [
  '#!/usr/bin/env node',
  // Bundled CommonJS dependencies (yaml) need a real require() inside an ES module.
  "import { createRequire as __lockspectRequire } from 'node:module';",
  'const require = __lockspectRequire(import.meta.url);',
].join('\n');

await build({
  entryPoints: ['src/cli/index.ts'],
  outfile: 'dist/cli/lockspect.mjs',
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node18',
  banner: { js: banner },
  legalComments: 'inline',
  logLevel: 'info',
});
