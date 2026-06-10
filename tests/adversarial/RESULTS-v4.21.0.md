# Results — v4.21.0 (pluggable CodeAnalyzerBackend + acorn reference)

- **Date:** 2026-06-09
- **Library version:** 4.21.0 (npm)
- **Change:** `CodeExecutionGuard` gains an optional `analyzerBackend` (AST) seam
- **Harnesses:** `tests/code-analyzer-backend.test.ts`, `tests/code-analyzer-acorn.test.ts`

## TL;DR

Regex code analysis cannot reliably see JS sandbox-escape gadget chains. Rather than
bundle a parser (which would break the zero-dependency guarantee), the guard exposes a
**pluggable backend** — the user opts into acorn/oxc; default stays regex-only/zero-dep.

## Results (measured)

| Set | n | Regex only (no backend) | With acorn backend |
|---|---|---|---|
| JS escape gadgets (must block) | 3 | **0 blocked** | **3 blocked** |
| Benign JS (must allow) | 4 | allowed | **allowed** (no FP) |
| Wiring unit tests (zero-dep mock) | 6 | — | pass |
| acorn integration tests | 3 | — | pass |

The three gadgets:
`this.constructor.constructor('return process')()`,
`[].constructor.constructor('return this')()`,
`Function('return process')()` (no `new` — slips past the `new\s+Function` regex).

## Design notes (honesty)

- **Zero production dependencies preserved.** `acorn` is a devDependency for the example
  and tests only; the published package ships no parser. Bundling acorn/oxc would break
  the zero-dep guarantee — hence a seam, not a dependency.
- **Additive only.** Backend findings can only add detections; a throwing backend is
  swallowed (falls back to the regex result); unparseable code returns no findings.
- **Detection, not sandboxing.** This does not add a runtime sandbox — isolation stays a
  host concern (gVisor/Firecracker/E2B/WASM). The guard is the decision layer.
- **Intentional TS/Python divergence.** Python uses stdlib `ast` directly (v0.10.3, no
  seam needed); JS has no stdlib parser, so npm takes the pluggable-backend route. The
  TS↔Python parity gate covers `InputSanitizer` and is unaffected.

## Reproduce

```bash
npx vitest run tests/code-analyzer-backend.test.ts tests/code-analyzer-acorn.test.ts
npm run verify
```

## Sources (research current as of 2026-06; see RESEARCH_LOG.md)

- acorn vs babel vs espree (2026): https://www.pkgpulse.com/guides/acorn-vs-babel-parser-vs-espree-javascript-ast-parsers-2026
- oxc parser: https://oxc.rs/docs/learn/architecture/parser
