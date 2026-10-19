import { defineConfig } from 'vitest/config';
import preact from '@preact/preset-vite';

// Served from https://feresbr1.github.io/lockspect/ (dev and preview use the same base path).
export default defineConfig({
  base: '/lockspect/',
  plugins: [preact()],
  build: {
    outDir: 'dist/web',
    emptyOutDir: true,
    target: 'es2022',
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
