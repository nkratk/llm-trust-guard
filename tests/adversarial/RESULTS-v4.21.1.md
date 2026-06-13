# Results — v4.21.1 (ESM named-export fix)

- **Date:** 2026-06-12
- **Library version:** 4.21.1 (npm)
- **Change:** `build-esm.js` now builds `dist/index.mjs` from the TS source
- **Guards/harnesses:** `tests/esm-build.test.ts` + `npm pack` → ESM/CJS consumer smoke

## TL;DR

`dist/index.mjs` was default-only, so `import { X } from "llm-trust-guard"` threw
`does not provide an export named …` for every export. Building the `.mjs` from the TS
source (instead of the compiled CJS) restores named exports. CommonJS was never affected.

## Results (measured on the publishable artifact)

| Check | Before (4.21.0) | After (4.21.1) |
|---|---|---|
| `export {` named-export blocks in `dist/index.mjs` | **0** | **1** |
| `export default` in `dist/index.mjs` | 1 | 0 |
| ESM `import { CodeExecutionGuard } from "llm-trust-guard"` | **throws** | **resolves** |
| CommonJS `require("llm-trust-guard")` | works | works |
| Runtime classes exported by name (InputSanitizer/CodeExecutionGuard/TrustGuard/EncodingDetector) | n/a | present |

Type-only exports (`CodeFinding`, `CodeAnalyzerBackend`) are intentionally absent from
the runtime `.mjs` and remain in `dist/index.d.ts` for type imports.

## Root cause (git-traced)

`build-esm.js` shipped in the initial commit (`ccec10a`, 2026-03-31) pointing esbuild at
the compiled CJS `dist/index.js`. esbuild cannot statically recover named exports from
tsc's `Object.defineProperty(exports, …)` getter output, so it emitted `export default`
only. `minify: true` is for size and is orthogonal — it does not affect named exports.

## Reproduce

```bash
npm run build
node -e "const n=require('fs').readFileSync('dist/index.mjs','utf8'); \
  console.log('named:', /export\\s*\\{/.test(n), 'defaultOnly:', !/export\\s*\\{/.test(n))"
npm pack --pack-destination /tmp
#  then in a clean dir: npm i /tmp/llm-trust-guard-4.21.1.tgz
#  node --input-type=module -e "import {InputSanitizer} from 'llm-trust-guard'; console.log(typeof InputSanitizer)"
npm run verify
```
