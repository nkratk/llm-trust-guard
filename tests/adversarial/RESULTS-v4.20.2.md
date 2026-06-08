# Results — v4.20.2 (benign-context suppression)

- **Date:** 2026-06-08
- **Library version:** 4.20.2 (npm) / 0.10.2 (Python parity)
- **Change:** `InputSanitizer` benign-context suppression + suppression veto
- **Harnesses:** `tests/benign-context.test.ts`, `tests/adversarial/wildchat-regression.test.ts`,
  `tests/adversarial/wildchat-fpr.ts`
- **Baseline lock:** `tests/adversarial/baseline.json`
- **Every number below is produced by a committed script — reproduction commands are in §Reproduce.**

## TL;DR

A precision change: cancel the soft `ignore_instructions` / `disregard_above`
triggers when the object is a benign technical noun (e.g. "ignore the whitespace",
"ignore the previous error") **and** the prompt has no instruction/rule/prompt/safety
noun **and** no exfiltration/execution/credential/money token (the veto).

- **Curated coding-context FPs: 19/28 → 0/28 blocked** (the targeted win).
- **WildChat-1M real consumer traffic: unchanged — 493/10,000 = 4.93%** (no movement; see honesty note).
- **Recall preserved**: full suite **716 pass** (TS), **744 pass** (Python); 12/12 attack controls still blocked.
- **No new escape hatch**: an interim build (suppression without the veto) leaked **9/10**
  payload-masking bypasses; the veto restores **0/10 leaked**.

## Methodology

- **Pipeline A** = `InputSanitizer({threshold:0.3, detectPAP:true})` OR `EncodingDetector` (block if either blocks).
- **WildChat corpus**: `allenai/WildChat-1M` shard 0, non-toxic/non-redacted first-user-turns,
  `seed=42`, n=10,000 (`tests/adversarial/fixtures/wildchat-sample10k.jsonl`, Git LFS). This is
  **real consumer traffic**, not a curated suite.
- **Curated benign probe** (`tests/benign-context.test.ts`): 28 realistic developer/user prompts
  that use trigger words in benign technical contexts. This is a **curated** set, labelled as such.
- **Adversarial bypass probe**: 10 prompts that prefix a real payload (exfil to URL/email,
  credential, money, `rm -rf`, shell pipe) with a benign object to try to abuse the suppression.
- **"Before" numbers** were measured against the pre-change sanitizer (`v4.20.2~1`), not estimated.

## Results

| Set | n | Before | After | Source |
|---|---|---|---|---|
| Curated benign (coding-context) | 28 | **19 blocked** | **0 blocked** | `benign-context.test.ts` |
| WildChat-1M Pipeline A (real traffic) | 10,000 | **493 (4.93%)** | **493 (4.93%)** | `wildchat-regression.test.ts` |
| Attack controls (must block) | 12 | 0 leaked | 0 leaked | `benign-context.test.ts` |
| Adversarial bypass (must block) | 10 | 10 blocked (base) → 9 leaked (interim, no veto) | **0 leaked** (veto) | `benign-context.test.ts` |
| Full unit suite | — | 711 (TS) / 693 (Py) | **716 (TS) / 744 (Py)** | `vitest` / `pytest` |

## Honesty note (what we are and are not claiming)

We are **not** claiming any movement in the published ~2.73% corrected WildChat FPR. On WildChat,
the block count is **identical** (493) before and after — that consumer corpus phrases nearly all
its "ignore" prompts as "ignore previous **instructions**…" (instruction-noun present), which the
change deliberately leaves blocked. The measured win is on the **coding/technical** context
(19→0 on the curated probe), a class WildChat under-represents. Claiming a WildChat FPR improvement
here would be unsupported.

Known pre-existing gap (out of scope, not fixed): `"disregard your previous rules"` is not matched
by the `disregard` patterns — a recall issue, separate from this FP work.

## Reproduce

```bash
# from llm-trust-guard/
git lfs pull                                   # fetch the WildChat fixture
npx vitest run tests/benign-context.test.ts    # curated benign + attack + bypass probes
npx vitest run tests/adversarial/wildchat-regression.test.ts   # WildChat FP regression gate
npm run verify                                 # full eval-gated pipeline (see VERIFICATION.md)
```

## Sources (research current as of 2026-06; see RESEARCH_LOG.md)

- AlignSentinel — alignment-aware injection detection: https://arxiv.org/pdf/2602.13597
- Google, prompt injections on the web (2026): https://blog.google/security/prompt-injections-web/
- Prompt-injection defense techniques 2026: https://tokenmix.ai/blog/prompt-injection-defense-techniques-2026
