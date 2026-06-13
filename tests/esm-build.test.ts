import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

/**
 * Regression guard for the ESM build.
 *
 * `dist/index.mjs` must expose NAMED exports so `import { X } from 'llm-trust-guard'`
 * works. It was previously default-only (esbuild bundling the compiled CJS could not
 * recover named exports) — fixed by building the .mjs from the TS source. Runs after
 * the build in the verify pipeline (G1 builds before G3 tests); skips if not built.
 */
const MJS = path.join(process.cwd(), "dist/index.mjs");

describe("ESM build exposes named exports", () => {
  it("dist/index.mjs has named exports, not default-only", () => {
    if (!fs.existsSync(MJS)) {
      console.log("dist/index.mjs not built (run `npm run build`) — skipping");
      return;
    }
    const src = fs.readFileSync(MJS, "utf-8");
    // Must contain an esbuild named-export block, not just `export default`.
    expect(src, "no named `export {` block in dist/index.mjs").toMatch(/export\s*\{/);
    for (const name of ["InputSanitizer", "CodeExecutionGuard", "TrustGuard", "EncodingDetector"]) {
      expect(src.includes(name), `${name} not exported from dist/index.mjs`).toBe(true);
    }
  });
});
