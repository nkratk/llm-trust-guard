const esbuild = require('esbuild');
const path = require('path');

async function buildESM() {
  await esbuild.build({
    entryPoints: [path.join(__dirname, '..', 'dist', 'index.js')],
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
