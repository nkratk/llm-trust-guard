const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

const distDir = path.join(__dirname, '..', 'dist');

function getAllJsFiles(dir) {
  const files = [];
  const items = fs.readdirSync(dir);

  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      files.push(...getAllJsFiles(fullPath));
    } else if (item.endsWith('.js')) {
      files.push(fullPath);
    }
  }

  return files;
}

async function minify() {
  const jsFiles = getAllJsFiles(distDir);
  console.log(`Minifying ${jsFiles.length} files...`);

  for (const file of jsFiles) {
    const result = await esbuild.transform(fs.readFileSync(file, 'utf8'), {
      minify: true,
      target: 'es2020',
    });
    fs.writeFileSync(file, result.code);
  }

  console.log('Minification complete.');
}

minify().catch(console.error);
