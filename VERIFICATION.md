# Verification standard

This repo ships a security library. We hold changes to an **eval-gated,
reproducibility-first** bar: nothing is pushed until an automated pipeline proves
it doesn't break the previous version, ships its own tests, is backed by
re-runnable numbers, and is documented for consumers.

> **Framing.** This is *our* standard, inspired by how eval-gated releases work in
> general. It is **not** a description of any third party's internal process —
> inventing that would violate the very "don't claim what you can't show" rule
> this document exists to enforce.

One command runs everything:

```bash
npm run verify          # = bash scripts/verify.sh
```

It is enforced in **two places** so "passed locally" and "passed in CI" mean the
same thing:

1. **Local** — `.githooks/pre-push` runs `scripts/verify.sh` before every push
   (and chains the Git-LFS pre-push hook). Install once: `bash scripts/install-hooks.sh`.
2. **CI** — `.github/workflows/ci.yml` runs the same script server-side, so it
   cannot be bypassed with `--no-verify`.

## The eight gates

| # | Gate | What it proves | The concern it answers |
|---|------|----------------|------------------------|
| G1 | Build / typecheck (`npm run build`) | code compiles & bundles | not breaking |
| G2 | Lint (non-blocking) | style | quality |
| G3 | Full unit suite passes (`vitest run`) | behavior intact | "all tests pass" / not breaking |
| G4 | Coverage thresholds (`vitest.config.ts`) | new code is exercised | "new changes have test cases" |
| G5 | **Regression**: WildChat block count ≤ `tests/adversarial/baseline.json`; curated benign probe = 0 blocked; adversarial bypass probe = 0 leaked | no FP/FN regression on real traffic | **"not breaking the previous version"** |
| G6 | **New-tests gate**: `src/` changed since last tag ⇒ `tests/` changed too (override `ALLOW_NO_TESTS=1`) | every change is tested | **"new changes should have test cases"** |
| G7 | **CHANGELOG gate**: top version == `package.json` version | release is documented | **"consumers know what changed"** |
| G8 | **Results gate**: `tests/adversarial/RESULTS-v<version>.md` exists | claims are published & reproducible | **"publish the basis for improvement claims"** |

G3, G4 and G5 run together in one `vitest run --coverage` (the regression and probe
assertions live in the suite: `tests/adversarial/wildchat-regression.test.ts`,
`tests/benign-context.test.ts`).

## How each recurring concern is now enforced, not remembered

- **"Is the research current as of <date>?"** → every change that cites a threat or
  technique adds a dated entry to [`RESEARCH_LOG.md`](./RESEARCH_LOG.md) with the
  queries run, source **links**, and an explicit *as-of* date. No source, no claim.
- **"Are we breaking the previous version?"** → G3 (suite) + G5 (locked WildChat
  baseline + bypass probe). A change that raises the FP rate or opens an escape
  hatch fails the build.
- **"Are we making numbers up?"** → every number in a CHANGELOG or RESULTS doc is
  produced by a committed script (G5/G8). The pipeline regenerates them. "Before"
  numbers are measured against the prior tag, not estimated.
- **"Do consumers know what changed?"** → G7 (CHANGELOG) + a per-release
  `RESULTS-v<version>.md` linked from it.
- **"New code without tests?"** → G6 fails the push.

## Release flow

```
1. Make the change + its tests.
2. Add a RESEARCH_LOG.md entry if any external claim/threat is involved.
3. Bump version (package.json) + update CHANGELOG.md (top entry == new version).
4. Write tests/adversarial/RESULTS-v<version>.md (numbers from a real run).
5. If a baseline intentionally moves, update baseline.json + justify it in RESULTS.
6. npm run verify   # must be green
7. git tag -a v<version> ; git push origin main && git push origin v<version>
8. git lfs push origin main   # if fixtures changed
```

## Overrides (use sparingly, and say why in the commit)

- `ALLOW_NO_TESTS=1 npm run verify` — pure refactor/doc change with no behavior delta.
- Moving a baseline (G5) requires a matching `RESULTS-v<version>.md` justification.
