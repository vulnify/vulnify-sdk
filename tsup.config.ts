import { defineConfig } from 'tsup';

const shared = {
  sourcemap: true,
  splitting: false,
  treeshake: true,
  target: 'es2022' as const,
  platform: 'node' as const,
  outDir: 'dist',
};

export default defineConfig([
  {
    ...shared,
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
  },
  {
    ...shared,
    entry: { cli: 'src/cli.ts' },
    format: ['cjs'],
    dts: false,
    clean: false,
    noExternal: ['ajv', 'yaml'],
    sourcemap: false,
    banner: { js: '#!/usr/bin/env node' },
  },
]);
