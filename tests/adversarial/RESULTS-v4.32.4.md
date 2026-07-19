# Adversarial Benchmark Results — v4.32.4

> **Bug-fix patch.** 15 guard-level fixes across `ExternalDataGuard`, `OutputFilter`, `OutputGuard`, `PromptLeakageGuard`, and `ToolResultGuard`, found by a live-verify adversarial sweep against the published v4.32.3 package. No new threat catalog groups. The 1,182-group / 5,883-payload corpus was not re-run for this patch (see note below) — numbers below are inherited from v4.32.3 except where noted.

Run date: 2026-07-19
Corpus: `tests/adversarial/threats-1000-catalog.json` (unchanged from v4.32.3)
Vitest: **930 tests, all pass** (up from 877 in v4.32.3 — includes a new permanent adversarial-sweep test file plus per-guard regression tests for every fix below)

---

## Changes in v4.32.4

Full detail in CHANGELOG.md `[4.32.4]`. Summary: 5 issues fully fixed (#6, #8, #9, #12, #14); 5 partially fixed with the unsafe portion of the initial fix reverted after independent adversarial review (#7, #10, #11, #15, #16 — each documented with its specific residual gap); 1 attempted and fully reverted (#5 — confirms the issue's own assessment that it needs semantic/LLM review, not regex); 1 needs scoping before a fix is attempted (#13, format-carrier bypass — no format-aware parsing exists at all).

Two more bugs (not filed as GitHub issues) were found and fixed by this release's own permanent adversarial-sweep test file (`tests/guard-adversarial-sweep.test.ts`) before it was even finished:
- `OutputGuard`: nested `` `$(...)` `` shell syntax (e.g. `` `$(date)` ``, standard inline bash documentation) double-counted into a false block.
- `PromptLeakageGuard`: `complete_you_are` pattern's rigid adjacency missed "Complete this: you are a..." phrasing.

**Process note**: this release is the first shipped under this repo's new `specs/001-guard-adversarial-hardening/` spec-kit tracking (see `.specify/memory/constitution.md`). It also surfaced a real merge-time incident worth recording here: squash-merging the fix PR pulled in stale `Closes #N` text from 3 early, since-reverted commits and auto-closed 3 issues (#5, #11, #15) that should have stayed open per their documented partial/unfixed status above. All 3 were manually reopened with an explanatory comment within minutes of the merge — see `specs/001-guard-adversarial-hardening/tasks.md` for the full incident record and the process fix adopted going forward (grep the full commit range for stale closing keywords before any squash-merge).

**Independent adversarial review caught real problems in the first implementation pass** — this is now standing practice (Constitution Principle I), not a one-off. 5 of the initial fix attempts across `ExternalDataGuard`, `OutputGuard`, and `PromptLeakageGuard` were found, on independent review, to have reintroduced worse regressions than the false positives they were meant to fix (missed body-based exfiltration, blocked ordinary documentation code spans, etc.) — all reverted before merge, documented in CHANGELOG's "Reverted" section.

---

## WildChat FPR gate

| Version | Blocked / 10,000 | FPR |
|---|---|---|
| Baseline (locked) | 494 | 4.94% |
| v4.32.4 | 494 | 4.94% (unchanged) |

Independently re-measured for this release (unlike v4.32.3, where the git-lfs fixture wasn't available locally) — `npx vitest run tests/adversarial/wildchat-regression.test.ts` passed live in this environment with the exact locked baseline count.

---

## Full guard recall summary

*Inherited from [RESULTS-v4.32.3.md](RESULTS-v4.32.3.md) — the 1,182-group corpus was not independently re-run for this patch. The 15 fixes above are independently verified via targeted regression tests (one per issue) plus the new permanent `tests/guard-adversarial-sweep.test.ts` file, not the full corpus runner (`run-corpus.ts`), which has a known unresolved hang issue in this environment (tracked separately, not part of this release).*
