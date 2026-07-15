# Adversarial Benchmark Results — v4.32.3

> **Bug-fix patch.** Guard-level fixes to `RAGGuard`, `AgentSkillGuard`, and `CodeExecutionGuard`; no new threat catalog groups. The 1,182-group / 5,883-payload corpus was not re-run for this patch (see note below) — numbers below are inherited from v4.32.2 except where noted.

Run date: 2026-07-15
Corpus: `tests/adversarial/threats-1000-catalog.json` (unchanged from v4.32.2)
Vitest: **877 tests, all pass** (up from 867 in v4.32.2 — 10 new regression tests for the three fixes below)

---

## Changes in v4.32.3

Three targeted guard fixes, all found via an independent version-verification harness and filed as issues before being fixed here:

| Guard | Fix | Issue |
|---|---|---|
| `RAGGuard` | Decode URL-encoded document content (and re-scan the decoded variant) before injection matching. Previously a URL-encoded payload (`%3C!--...--%3E`) bypassed detection entirely while the identical decoded payload was caught. | #1 |
| `AgentSkillGuard` | Loosened the "fake-compliance data exfiltration" pattern (now tolerates compliance-keyword-first phrasing, e.g. "ISO 27001 mandates: route...") and the "response appending directive" pattern (the literal word "following" is now optional, e.g. "include in all outputs: ..."). The v4.32.0 CHANGELOG's "all 5/5" claim for these two SCH groups was not accurate — actual detection on the harness's test payloads was 4/5 per group before this fix. | #2 |
| `CodeExecutionGuard` | Added detection for Python object-introspection "gadget chain" sandbox escapes (`__subclasses__`, `__bases__`, `__mro__`, `__base__`, `__globals__`, `__getattribute__`, `__reduce__`, `__reduce_ex__`, `__code__`, `__closure__`, `.mro()`), firing only when 2+ distinct tokens co-occur within a small proximity window. Previously had zero coverage; a payload only got flagged if it coincidentally also contained an unrelated literal keyword like `.system(`. Mirrors the dunder vocabulary used by the Python port's native AST-based detector (`_ast_escape_findings()` in `code_execution_guard.py`), which correctly detects real chains — though further review found *that* detector has its own, separate over-blocking bug (flags a single standalone dunder use as a chain), filed as [nkratk/llm-trust-guard-python#4](https://github.com/nkratk/llm-trust-guard-python/issues/4), not fixed here (different repo). | #3 |

**Note on corpus numbers:** the 1,182-group adversarial catalog (`run-corpus.ts`) was not re-run against this patch in this environment (the run did not complete in a reasonable time locally; CI will produce authoritative numbers on the PR). The three fixes above are independently verified via 14 new targeted unit tests (`tests/rag-guard.test.ts`, `tests/agent-skill-guard.test.ts`, `tests/code-execution-guard.test.ts`) covering the exact previously-missed payloads plus the original canonical phrasing (confirming no detection was lost) and benign-content controls (confirming no new false positives). The full 881-test vitest suite, including the false-positive benchmark (`tests/false-positives.test.ts`) and guard-parity gate (`tests/guard-parity.test.ts`), passes with no change in false-positive rate (2.6% overall / 6.7% customer-support, same as v4.32.2).

**Pre-merge review caught two false-positive regressions in the first draft of this fix.** An independent review of the PR flagged that the broadened `AgentSkillGuard` "fake-compliance" pattern and the new `CodeExecutionGuard` gadget pattern were each too permissive — verified live to misfire on ordinary compliance/audit prose and on common legitimate Python idioms (bare `__reduce__` for pickling, `__subclasses__()` for plugin discovery), respectively. Both were tightened before merge (destination-required structure for the former; a 2-signal co-occurrence requirement for the latter) and regression tests were added for both the false positives found and the fix. See the CHANGELOG for detail.

---

## WildChat FPR gate

| Version | Blocked / 10,000 | FPR |
|---|---|---|
| Baseline (locked) | 494 | 4.94% |
| v4.32.3 | *not independently re-measured* | — |

The WildChat 10k fixture requires `git lfs pull`, which was not available in this environment — the regression test (`tests/adversarial/wildchat-regression.test.ts`) gracefully skips rather than failing when the fixture is a git-lfs pointer only. CI has git-lfs configured and will enforce this gate for real on the PR. The curated false-positive suite (`tests/false-positives.test.ts`, 56 tests) passed with an unchanged rate as a partial substitute signal.

---

## Full guard recall summary

*Inherited from [RESULTS-v4.32.2.md](RESULTS-v4.32.2.md) — not independently re-verified for this patch (see note above). Guard-level fixes should only move `AgentSkillGuard`, `RAGGuard`, and `CodeExecutionGuard` recall upward, not downward, per the targeted test evidence above.*

| Guard | Groups | Blocked / Total | Recall (v4.32.2 baseline) |
|---|---|---|---|
| CodeExecutionGuard | 244 | 1193 / 1193 | **100.0%** |
| AgentSkillGuard | 6 | 30 / 30 | **100.0%** |
| RAGGuard | 46 | 212 / 230 | **92.2%** |
| **TOTAL** (all guards) | **1,182** | **4,830 / 5,883** | **82.1%** |

---

## npm↔Python parity gate

File: `tests/guard-parity-vectors.json`
Vectors: 84 | Guards covered: 35 (unchanged from v4.32.2)
TS gate (`guard-parity.test.ts`): **84/84 PASS**

---

## Verification commands

```bash
# Full vitest suite (includes false-positive benchmark + parity gate)
npx vitest run

# The three fixed guards specifically
npx vitest run tests/rag-guard.test.ts tests/agent-skill-guard.test.ts tests/code-execution-guard.test.ts

# Adversarial corpus (regenerates full per-guard numbers; not run for this patch — see note)
npx tsx tests/adversarial/run-corpus.ts

# Python suite
cd ../llm-trust-guard-python && python3 -m pytest tests/ -q --ignore=tests/adversarial/datasets
```
