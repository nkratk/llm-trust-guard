# Adversarial Benchmark Results — v4.32.6

> **Safety-net + review-driven fix release.** No new adversarial-corpus run — this release adds permanent, automated regression tests (ReDoS-safety, config-consistency) and fixes real bugs those tests (and two rounds of independent adversarial review) found, but does not change any guard's steady-state detection logic relative to v4.32.5's measured corpus results. Recall against the 1,182-group corpus is unchanged; see [RESULTS-v4.32.5.md](RESULTS-v4.32.5.md) for those numbers, which remain the current basis for detection-rate claims.

Run date: 2026-07-23
Vitest: **952 tests, all pass** (up from 943 in v4.32.5 — new `tests/redos-safety.test.ts` (3 tests), `tests/heuristic-analyzer.test.ts` (4 tests), plus 2 new cases in `tests/decode-variants.test.ts`)
G5 recall ratchet (`recall-baseline.json`): unchanged, passed.

---

## Changes in v4.32.6

Full detail in CHANGELOG.md `[4.32.6]`. Summary:

- **Permanent ReDoS-safety regression test** (`tests/redos-safety.test.ts`): extracts every regex literal in `src/` via the TypeScript compiler's AST, plus statically-resolvable `new RegExp(...)` calls, and stress-tests each with a scaling-ratio check. Found and fixed two real catastrophic-backtracking regexes that had never shipped in a released version: `heuristic-analyzer.ts`'s `qaPattern` and `rag-guard.ts`'s `tabSpacePattern` (the latter invisible to an earlier, narrower text-scanning extractor — only found once the extractor was rewritten to walk the full AST).
- **Content-length consistency regression test** (`tests/decode-variants.test.ts`): guards against the specific `MAX_INPUT_LENGTH`-vs-guard-`maxContentLength` silent-bypass bug class a v4.32.5 pre-merge review caught.
- **`.githooks/pre-push`** now fetches origin's tags before running `scripts/verify.sh`, closing a local/CI tag-resolution drift gap.
- **Review-driven fix**: the first fix for `qaPattern` (bounding its unbounded gap to 1000 chars) closed the ReDoS but silently created a many-shot-jailbreak detection bypass — any turn whose Q→A gap exceeds 1000 chars stopped being counted. Independent adversarial review caught this (verified 5/5 → 0/5 on a long-turn payload) before merge. Replaced with a linear marker-position scan with no length cap at all — detection fully restored, still ReDoS-safe. **Net effect on detection: neutral relative to v4.32.5** (the many-shot heuristic behaves identically to before the ReDoS fix was ever introduced — this bug was found and fixed within the same unreleased branch, never shipped in a tagged release).
- **Review-driven hardening**: `code-execution-guard.ts` now escapes operator-configured `blockedImports`/`blockedFunctions` values before interpolating into `new RegExp(...)` templates (defense in depth).

None of the above changes any guard's matching behavior on real attack payloads relative to v4.32.5 — the `qaPattern` fix is a round-trip back to the original (already-measured) behavior, and the other fixes are pure ReDoS/performance/tooling changes. Full corpus re-run was judged unnecessary; the G5 recall ratchet (per-category detection ≥ `recall-baseline.json`, checked on every push including this release) provides the regression guarantee instead.
