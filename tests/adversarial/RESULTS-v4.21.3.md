# Results — v4.21.3 (runnable CodeAnalyzerBackend example + CI Node 24)

- **Date:** 2026-06-13
- **Library version:** 4.21.3 (npm)
- **Change:** docs + CI only — no code/behavior change

## Why

A fresh-registry consumer test of 4.21.2 surfaced two gaps:
1. The README's `CodeAnalyzerBackend` snippet called a placeholder `findGadgets(...)`
   and pointed at `examples/acorn-code-analyzer.ts`, which is **not shipped** in the npm
   package (`files` ships `dist` + docs). Consumers had no runnable backend for the
   headline new feature.
2. CI/release workflows used GitHub Actions on the deprecated Node 20 runtime
   (forced-migrated 2026-06-16).

## Fix

- **README**: complete, copy-pasteable acorn backend (AST walker flagging
  `constructor.constructor` and `Function` gadgets) + a GitHub permalink to the full
  reference. Verified the snippet blocks `this.constructor.constructor('return process')()`.
- **CI**: `checkout@v6`, `setup-node@v6`, `setup-python@v6`, `gh-release@v3`,
  `github-script@v8` across `ci.yml` / `release.yml` / `freshness.yml` in both repos.

## Verification

- `npm run verify` — all 11 gates green.
- Re-tested with a clean `npm i llm-trust-guard@4.21.3` consumer (ESM + the README
  backend snippet).
