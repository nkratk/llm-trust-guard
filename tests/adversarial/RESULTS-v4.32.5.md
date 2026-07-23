# Adversarial Benchmark Results — v4.32.5

> **Regression fix + coverage-gap fix + security hardening.** Fixes the confirmed `dan_jailbreak` regression (#19), the two largest never-detected coverage-gap clusters found via full-history bisection (#21 fully, #22/#23 partially — see CHANGELOG), plus 18 pre-existing catastrophic-backtracking (ReDoS) regexes found by an empirical stress-test sweep of every pattern in the codebase, some of which the decode-gap fix itself would otherwise have made trivially reachable.

Run date: 2026-07-22
Corpus: full-history bisection re-run against the 137 previously-zero-detection threat groups (see `specs/001-guard-adversarial-hardening/tasks.md` Phase 5), not the general 1,182-group catalog
Vitest: **943 tests, all pass** (up from 930 in v4.32.4 — new `tests/decode-variants.test.ts`, 14 tests)

---

## Changes in v4.32.5

Full detail in CHANGELOG.md `[4.32.5]`. Summary:
- `InputSanitizer`'s `dan_jailbreak` pattern fixed (#19, closed).
- New shared `src/decode-variants.ts`: `InputSanitizer`, `ExternalDataGuard`, `MultiModalGuard` now re-scan de-obfuscated content variants before deciding allow/block, not just the raw string.
- `ExternalDataGuard` (#21, closed): 33/34 previously-undetected SSRF/XXE/zip-slip/markdown-exfil threats now caught.
- `MultiModalGuard` (#22, left open — partial): 20/30 previously-undetected CometJacking-family threats now caught via decode; 10 remain a genuine missing-signature gap.
- `InputSanitizer` (#23, left open — partial): 7/22 previously-undetected threats now caught via decode; 2 are a content-shape gap, 13 are the wrong attack class for this guard.
- **18 ReDoS fixes** across 9 guard files, found via an empirical stress-test sweep (740 patterns × adversarial seed corpus) — worst case 12s → single-digit ms. One of these (`ExternalDataGuard`'s `email_address`) was the direct trigger for the sweep: the decode-gap fix above turned it from a latent bug into a trivially-reachable multi-second DoS by re-scanning it across ~40 decode variants instead of the raw string once.
- Two false positives caught by adversarial review and fixed in the same release: legitimate Cyrillic/Persian text no longer flagged as a homoglyph attack; a `MultiModalGuard` risk-score double-count across decode variants.
- A final pre-merge review round caught that `buildDecodeVariants()`'s original 20,000-character input cap sat *below* `ExternalDataGuard`'s own default `maxContentLength` (50,000) — a real silent bypass for content in between, not just a defense-in-depth knob. Raised to 100,000 after confirming every guard pattern scans linearly at 150,000+ characters.

**Pipeline re-verified against the actual threat corpus after these fixes**: of the 137 npm threat groups that showed zero detection before this release, **70 now detect** (43 fully, 27 partially). The remaining 67 are dominated by `ToolChainValidator` (#20, an explicit scoping question — not attempted this release) plus the documented, still-open partial gaps in #22/#23 and a handful of threats already tracked under other issues (#5, #13).

**Process note**: this release went through the heaviest review cycle of any so far — two adversarial-review rounds during development (which found and fixed a real ReDoS the decode fix amplified, a Cyrillic/Persian false positive, and a risk-score double-count), plus a final holistic review of the complete PR diff after CI went green, which caught the maxContentLength/decode-cap bypass above before merge. `gh pr merge --squash`'s commit-composition behavior was checked against the lesson from v4.32.4's incident (grepped the full commit range for stray closing keywords) before merging — clean this time, no auto-close surprises.

---

## WildChat FPR gate

| Version | Blocked / 10,000 | FPR |
|---|---|---|
| Baseline (locked) | 494 | 4.94% |
| v4.32.5 | 494 | 4.94% (unchanged) |

Re-measured live for this release — `npx vitest run tests/adversarial/wildchat-regression.test.ts` passed with the exact locked baseline count, confirming none of this release's changes affected the false-positive rate on the WildChat corpus.

---

## Full guard recall summary

*Inherited from [RESULTS-v4.32.4.md](RESULTS-v4.32.4.md) for the general 1,182-group corpus — this release's testing focus was the 137 specifically-bisected previously-failing threat groups (documented above), not a full corpus re-run. See `specs/001-guard-adversarial-hardening/tasks.md` for the full bisection methodology and per-threat classification.*
