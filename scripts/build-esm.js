const esbuild = require('esbuild');
const path = require('path');

async function buildESM() {
  await esbuild.build({
    // Build the ESM bundle from the TS SOURCE, not the compiled CJS
    // (dist/index.js): esbuild cannot recover named exports from tsc's CJS
    // getter output, which left .mjs default-only and broke
    // `import { X } from 'llm-trust-guard'`. Source entry preserves `export {}`.
    entryPoints: [path.join(__dirname, '..', 'src', 'index.ts')],
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'es2020',
    outfile: path.join(__dirname, '..', 'dist', 'index.mjs'),
    external: ['crypto'],
    minify: true,
  });
  console.log('ESM build complete.');
}

buildESM().catch(console.error);
