# llm-trust-guard v4.19.0 — Benchmark Results

**Run date:** 2026-04-23
**Library version:** 4.19.0 (npm) — same regex family as Python 0.9.0
**Benchmark harness:** `tests/adversarial/v419-delta-benchmark.ts` + `tests/adversarial/wildchat-fpr.ts` + `tests/adversarial/wildchat-block-dump.ts`
**Raw results:** `v419-delta-results.json`, `wildchat-fpr-results.json`, `hand-labels.json`

## TL;DR

- On real ChatGPT production traffic (WildChat-1M, 10,000 multilingual first-user-turns), Pipeline A (`InputSanitizer + EncodingDetector`) blocks 4.93% of prompts. **After label-noise adjudication, an estimated 273 of the 493 blocks (55%) are genuine false positives and ~220 are actual jailbreak attempts users sent to ChatGPT.** Corrected benign-traffic FPR is ~2.73% (95% CI [2.43%, 2.84%]), which is at or below the lower edge of the 3–5% OOD range Meta self-reports for Prompt Guard 86M.
- On the two prior-published corpora where [ARTICLE-2-REGEX-CEILING.md](../../ARTICLE-2-REGEX-CEILING.md)'s methodology held up (Giskard n=35, Compass CTF Chinese n=11), Pipeline A shows zero movement from v4.13.5. **Both samples are underpowered** — Wilson 95% CIs are wide enough to hide meaningful detection improvements. The honest reading is "no evidence of improvement," not "proof of no improvement."
- Confirms the direction of [ARTICLE-2](../../ARTICLE-2-REGEX-CEILING.md)'s regex-ceiling thesis: Compass CTF labeled F1 is 0.18–0.21 on this library, consistent with the cited 0.50–0.65 ceiling as an upper bound.
- **The apparent 5× jump on jailbreak_llms is primarily a CSV-parser correction, not a genuine pattern gain.** The original 8.7% figure was likely *understated* because the parser truncated multi-line prompts to short fragments; the true v4.13.5 number under correct parsing is unknown and unrecoverable (no `v4.13.5` git tag exists).

## Methodology

### Pipelines measured

- **Pipeline A (Sanitizer + Encoder):** `InputSanitizer` with `{threshold: 0.3, detectPAP: true}` + `EncodingDetector`. Same as [ARTICLE-2-REGEX-CEILING.md](../../ARTICLE-2-REGEX-CEILING.md) used for its v4.13.5 published numbers. A block is triggered when either guard returns `!allowed`.
- **Pipeline B (detection-only facade):** `TrustGuard` with all enforcement-class guards disabled (`execution`, `policy`, `tenant`, `schema`, `output`, `chain`, `conversation`). Detection-class guards remain: `sanitizer`, `encoding`, `promptLeakage`. No session state, no tool registry — we measure pattern detection only, not rate-limiting or session-accumulation effects.

### Sampling

- jailbreak_llms / Giskard / Compass CTF: **full corpus, no random sampling.** Deterministic.
- WildChat-1M: simple random sample of 10,000 from shard 0 (59,857 non-toxic, non-redacted conversations), seed=42, extracting first user turn only. Sample language distribution: 49.5% English, 25.3% Chinese, 9.9% Russian, remainder ≤3% each.
- Hand-adjudication sub-sample (Pipeline A unmarked blocks): 50 drawn with seed=42 from the 290 blocks lacking canonical jailbreak markers.

### Confidence intervals

Wilson score 95% CI per [Wilson 1927]. For sample sizes in this benchmark (n=11 to n=13,690) Wilson gives better small-sample coverage than normal-approx or Clopper-Pearson (Brown, Cai, DasGupta 2001).

### Data freshness caveats

Per `CLAUDE.md` data-freshness rule, flagged upfront:

| Corpus | Age at run time | Reason for inclusion |
|---|---|---|
| jailbreak_llms Dec 2023 snapshot | 16 months | Required for v4.13.5 Δ — ARTICLE-2 used this exact snapshot |
| Giskard prompt_injections | Unknown release date | Required for v4.13.5 Δ |
| Compass CTF (`prompt_injection_research`) | Unknown release date | Required for v4.13.5 Δ |
| WildChat-1M (allenai) | 2024 release (shard 0) | Best available real-user-traffic baseline; agent research confirmed no 2025-2026-fresh alternative at scale |

The three attack corpora are used **for in-distribution Δ measurement**, not as a fresh held-out benchmark — they are well-known to the library's pattern-tuning history. WildChat serves as the out-of-distribution FPR measurement.

### CSV parser correction

ARTICLE-2's original `loadCSVColumn` uses a line-splitting parser (`content.split("\n")`) that does not handle multi-line quoted CSV fields. Many jailbreak_llms prompts contain embedded newlines, so under that parser they appeared as truncated fragments. Our harness uses a character-by-character CSV parser that correctly handles multi-line quoted fields.

**Direction of the bug matters:** truncating a long prompt to a short fragment *reduces* the number of pattern hits (there's less text to match against). The ARTICLE-2 headline of 8.7% on jailbreak_llms was therefore likely understated. Our Pipeline A number of 46.83% on fully-parsed prompts reflects both the parser fix and any genuine pattern additions, and the two cannot be cleanly separated because no `v4.13.5` git tag exists in the repository.

The Giskard and Compass CTF corpora are unaffected by this (single-line CSVs), so their comparisons to ARTICLE-2 are clean.

### WildChat FP-baseline adjudication

WildChat-1M filters toxic content but does *not* filter for prompt-injection intent. Some blocks that Pipeline A flags are actual jailbreak attempts users sent to ChatGPT. To estimate the true benign-traffic FPR, we adjudicated the 493 Pipeline A blocks in two stages:

1. **Canonical-marker heuristic (automated):** match against explicit jailbreak phrasings — DAN, Developer Mode, "ignore all previous instructions", named jailbreak personas (KEVIN/SETH/COOPER/MAXIMUM/MACHIAVELLI/etc.), "without any restrictions", "override system instructions". A prompt matching any of these is labeled TP (true positive = actual jailbreak attempt). This is a **lower bound on TPs**: it is English-only, syntactic, and misses novel phrasings.
2. **Hand-adjudication (manual sub-sample):** the 290 prompts lacking canonical markers were randomly sub-sampled (n=50, seed=42) and each was labeled TP or FP by a single annotator (project maintainer). Full labels: [`hand-labels.json`](../../../../../tmp/wildchat/hand-labels.json) (external to repo).

Tallies:

- Canonical-marker TPs (of 493 Pipeline A blocks): **203 (41.2%)** — no FPs by construction
- Hand-adjudicated sub-sample (n=50 of 290 unmarked): **3 TPs, 47 FPs** → 6.0% TP rate, Wilson 95% CI [2.1%, 16.2%]
- Extrapolating to unmarked pool: ~17 additional TPs (CI [6, 47]), ~273 FPs (CI [243, 284])
- **Estimated total TPs in 493 blocks: ~220; estimated FPs: ~273**

**Limitations of this adjudication:**
- Single annotator, no inter-annotator agreement measurement.
- Canonical heuristic is English-only; non-English jailbreaks are undercounted (e.g., one Chinese DAN jailbreak in the sub-sample was not caught by the heuristic and only surfaced in hand-labeling).
- n=50 hand-sample gives wide CI on extrapolated TP rate; the full [2.43%, 2.84%] FPR range reflects this.
- Labels are binary; borderline "borderline worldbuilding" or "hypothetical scenario" prompts are judgment calls.

Pipeline B blocks (898) were NOT hand-adjudicated at the same depth due to scope — canonical-marker heuristic only (229 TPs, 25.5%). Pipeline B corrected FPR is therefore reported as an **upper bound** only.

### Environment

- `npm test` baseline: 705 tests pass (unchanged from v4.19.0 release)
- Node 22.16.0, TypeScript 5.7, tsx 4.20.0
- Python 3.9.6, pyarrow 21.0.0 (for WildChat parquet ingestion)

## Results — attack detection (in-distribution)

Full-dataset, no sampling. 95% Wilson CI.

| Corpus | n | v4.13.5 (ARTICLE-2) | v4.19.0 Pipeline A | v4.19.0 Pipeline B |
|---|---|---|---|---|
| Giskard prompt_injections | 35 | 80.0% | 80.00% [64.11, 89.96] | 94.29% [81.39, 98.42] |
| Compass CTF Chinese attacks | 11 | 9.1% | 9.09% [1.62, 37.74] | 9.09% [1.62, 37.74] |
| jailbreak_llms 2023-12-25 | 1,405 | 8.7% (1k sample, line-split parser — not comparable) | 46.83% [44.24, 49.45] | 68.19% [65.70, 70.57] |

### Giskard and Compass CTF Chinese — stable corpora, n too small for strong claims

Pipeline A matches ARTICLE-2's published numbers to the decimal on both of these. **But n=35 and n=11 are underpowered:** Wilson 95% CIs on these rates are [64, 90] and [1.6, 37.7] respectively. We cannot distinguish a true null result from meaningful small gains within these intervals.

The honest reading: **the data provide no evidence that v4.14–v4.19 pattern additions improved detection on these attack classes.** This is consistent with a reading of the changelogs — most additions targeted indirect injection, tool-result validation, memory persistence, prompt leakage, and multi-agent coordination, which this Pipeline A doesn't invoke — but it is not a proof.

### jailbreak_llms — methodology-confounded

The number moves from 8.7% to 46.83% on Pipeline A, but this reflects a combination of (a) correct multi-line CSV parsing and (b) any pattern improvements since v4.13.5. The original 8.7% was measured against truncated-to-fragment prompts and was likely understated. The true v4.13.5 number under fully-parsed prompts is unknown and unrecoverable. **Do not cite 8.7% → 46.83% as a 5× improvement.**

### Compass CTF labeled (P/R/F1)

n=116 (60 attacks, 56 safe). Not in ARTICLE-2.

| Pipeline | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| A | 100.00% | 10.00% [4.66, 20.15] | 0.182 | 0.00% [0.00, 6.42] |
| B | 100.00% | 11.67% [5.77, 22.18] | 0.209 | 0.00% [0.00, 6.42] |

F1 of 0.18–0.21 sits well below the 0.50–0.65 regex ceiling cited in ARTICLE-2 as an upper bound. This is **consistent with** the ceiling claim, not a proof of it.

## Results — false positives (out-of-distribution)

### WildChat-1M (novel axis — n=10,000)

Real ChatGPT production traffic, 10,000 first-user-turns sampled from `allenai/WildChat-1M` shard 0 (non-toxic, non-redacted per the dataset's built-in filters, ODC-BY licensed).

**Naive block rates (before label-noise correction):**

| Pipeline | Blocked / n | Block rate | 95% CI |
|---|---|---|---|
| A (Sanitizer + Encoder) | 493 / 10000 | 4.93% | [4.52, 5.37] |
| B (detection-only facade) | 898 / 10000 | 8.98% | [8.44, 9.56] |

**Corrected FPR (Pipeline A only, after canonical-heuristic + 50-sample hand-adjudication):**

| Pipeline | Estimated TPs in blocks | Estimated FPs in blocks | Corrected FPR | 95% CI |
|---|---|---|---|---|
| A | ~220 | ~273 | **~2.73%** | [2.43, 2.84] |
| B (upper bound only; canonical-heuristic only) | ≥229 | ≤669 | ≤6.69% | — |

**Comparison to an ML baseline:** Meta Prompt Guard 86M self-reports **3–5% OOD FPR** (HF model card). Pipeline A's corrected 2.73% sits at or below the lower edge of that range, on real multilingual production traffic. Two caveats on this comparison:

1. **Not an apples-to-apples head-to-head.** Prompt Guard 86M's 3–5% is measured on curated OOD eval distributions, not WildChat. Different base rates, different length distributions, different language mixes. The right framing is "same order of magnitude," not "inside the range."
2. **This is the library author's own measurement.** No third party has independently validated the WildChat pipeline or the hand-adjudication. External replication is invited — the harness and adjudication script are in the repo.

#### Per-language naive block rate (Pipeline A)

These are block rates, not corrected FPRs — canonical-heuristic analysis was not sliced by language (future work).

| Language | n | Block rate |
|---|---|---|
| English | 4,954 | 8.66% |
| Chinese | 2,527 | 1.11% |
| Russian | 986 | 0.91% |
| French | 258 | 0.78% |
| Portuguese | 218 | 0.46% |
| Spanish | 200 | 1.50% |
| German | 140 | 0.00% |
| Italian | 106 | 0.00% |
| Turkish | 78 | 8.97% |
| Latin | 59 | 0.00% |

Library's patterns are English-tuned. The per-language gap is consistent with that design — non-English prompts rarely trigger English-language jailbreak keywords, driving per-language block rates down to <2% for most non-English languages.

### Other FP baselines

For completeness. These are adversarial-flavored baselines, not production traffic — "regular prompts from the jailbreak_llms corpus" contains creative-writing and hypothetical-scenario language that overlaps with pattern triggers.

| Corpus | n | Pipeline A block rate | Pipeline B block rate |
|---|---|---|---|
| jailbreak_llms regular prompts | 13,690 | 17.42% [16.80, 18.07] | 41.84% [41.02, 42.67] |
| Compass CTF safe | 399 | 0.00% [0.00, 0.95] | 0.00% [0.00, 0.95] |

## What this establishes (and what it does not)

**Supports:**
- **Pipeline A corrected FPR of ~2.73% on real multilingual ChatGPT traffic** is the load-bearing measurement of this run. It is a novel axis — no competing guardrail library publishes FPR on WildChat to our knowledge.
- Direction of travel is consistent with ARTICLE-2's regex-ceiling thesis: Compass CTF labeled F1 of 0.18–0.21 sits well below the 0.50–0.65 cited upper bound.
- WildChat-1M contains a non-trivial baseline rate of jailbreak-attempt first-user-turns (~2.2% in this sample). The "non-toxic" filter catches moderation-flagged content, not prompt-injection intent.

**Does not claim:**
- No detection-rate improvement on the four attack classes added in v4.19.0 itself (CSS-hidden content, HTML attribute directives, JSON agent-directive fields, Reprompt-class markdown exfil). No public held-out corpus exists for these classes at statistical scale as of 2026-04-23 (confirmed via research sweep). Unit-test coverage is published in the v4.19.0 test suite; independent third-party evaluation is invited.
- **No evidence** of detection improvement on Giskard or Compass CTF Chinese — not a proven null, just underpowered.
- Pipeline B measurements are not directly comparable to other benchmarks that include the full enforcement layer, and Pipeline B's WildChat FPR is reported as an upper bound only.
- Pipeline A's "inside Prompt Guard's OOD range" is a same-order-of-magnitude observation on different distributions, not a head-to-head comparison.

**Fails to reject (not falsifies):**
- A reading that "library got better because more patterns were added" cannot be ruled out on Giskard / Compass Chinese given their small n. The null result on these corpora is directional evidence for ARTICLE-2's ceiling thesis, not proof.

## Reproducibility

- Harness: `tests/adversarial/v419-delta-benchmark.ts`, `tests/adversarial/wildchat-fpr.ts`, `tests/adversarial/wildchat-block-dump.ts`
- Sample extractor: `tests/adversarial/extract_wildchat.py` (seed=42, simple random over non-toxic non-redacted WildChat shard 0)
- Canonical classifier + hand-sample selector: `tests/adversarial/classify_wildchat_blocks.py`
- Hand labels: `tests/adversarial/hand-labels.json`
- Raw machine-readable results: `v419-delta-results.json`, `wildchat-fpr-results.json`
- Corpora in repo: `tests/adversarial/datasets/` (jailbreak_llms, prompt-injections, prompt_injection_research)
- Corpora external: `allenai/WildChat-1M` shard 0 via HuggingFace, download URL hardcoded in `extract_wildchat.py`

## Sources

- [ARTICLE-2-REGEX-CEILING.md](../../ARTICLE-2-REGEX-CEILING.md) — v4.13.5 published baseline
- [Shen et al. 2024 (jailbreak_llms)](https://arxiv.org/abs/2308.03825)
- [Alzahrani PromptGuard — Nature Scientific Reports, January 2026](https://www.nature.com/articles/s41598-025-31086-y) — cited F1 ceiling
- [allenai/WildChat-1M on Hugging Face](https://huggingface.co/datasets/allenai/WildChat-1M)
- [Meta Prompt Guard 86M HF card](https://huggingface.co/meta-llama/Prompt-Guard-86M) — 3–5% OOD FPR comparison point
- [Nasr et al. "The Attacker Moves Second" — Oct 2025](https://arxiv.org/abs/2510.09023)
- [Wilson 1927 — Wilson score interval](https://www.jstor.org/stable/2276774)
- [Brown, Cai, DasGupta 2001 — Interval estimation for a binomial proportion](https://projecteuclid.org/journals/statistical-science/volume-16/issue-2/Interval-Estimation-for-a-Binomial-Proportion/10.1214/ss/1009213286.full)
