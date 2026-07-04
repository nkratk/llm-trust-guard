# Adversarial Benchmark Results — v4.31.0

Run date: 2026-07-04  
Corpus: `tests/adversarial/threats-1000-catalog.json`  
Threat groups: 1,146 | Payloads per group: 5 | Total threat payloads: ~5,730  
Benign corpus (FPR gate): WildChat-1M random sample, 10,000 conversations  
Suite: `npx tsx tests/adversarial/run-corpus.ts`  
Vitest: 815 tests, all pass

---

## Changes in v4.31.0

### 1. MultiModalGuard — benign FPR fix

| Metric | v4.30.0 | v4.31.0 | Delta |
|---|---|---|---|
| Benign FPR | 20.18% | **2.19%** | −17.99 pp |
| Threat recall | 64.18% | **64.18%** | 0 (unchanged) |

**Root causes fixed (DETERMINISTIC, no ML):**
- Entropy check now requires `sample.length >= 200` before evaluating uniqueChars/length ratio. Short multilingual strings (e.g. 23-char Chinese) previously scored ≈0.96 and exceeded the 0.9 threshold.
- Homoglyph check changed from document-level script co-occurrence to intra-token adjacency pattern `[a-zA-Z][а-яА-Я]|[а-яА-Я][a-zA-Z]`. Legitimate bilingual text (Russian Q&A + English tech terms) no longer fires; only the `аdmin`-style same-token mixing fires.

### 2. ConversationGuard — 9 new patterns

| Metric | v4.30.0 | v4.31.0 | Delta |
|---|---|---|---|
| Threat recall | 2.7% | **21.82%** | +19.12 pp |
| Fully-blind threat groups | 11 | **0** | −11 |

**Patterns added:** `skeleton_key`, `many_shot_jailbreak`, `context_drift`, `session_hijack`, `persona_pivot`, `loop_injection`, `crescendo_escalation`, `compression_abuse`, `whisper_sidechannel`.

**Preprocessing added:** `preprocessMessage()` applies ZWSP/bidi strip, URL-decode, hex-decode, base64-decode, string reverse, Cyrillic normalisation before pattern scan; Set-based deduplication prevents double-counting.

### 3. InputSanitizer — obfuscation preprocessing

| Metric | v4.30.0 | v4.31.0 | Delta |
|---|---|---|---|
| Threat recall | 28.0% | **52.27%** | +24.27 pp |

**Method added:** `buildInputVariants()` generates URL-decoded, hex-decoded, base64-decoded, reversed, and Cyrillic-normalised variants. The `sanitize()` pattern loop iterates `[raw, cleaned, ...variants]` with a `matchedNames` Set to deduplicate across variants. No new patterns added.

---

## WildChat FPR gate (Pipeline A = InputSanitizer + EncodingDetector)

| Version | Blocked / 10,000 | FPR |
|---|---|---|
| Baseline (locked) | 494 | 4.94% |
| v4.31.0 | **494** | **4.94%** |

Gate: PASS (count ≤ locked baseline 494).

---

## Full guard recall summary (threat corpus)

Guards not changed in this version show the same numbers as v4.30.0.

| Guard | Blocked / Total | Recall |
|---|---|---|
| InputSanitizer | 230 / 440 | **52.27%** |
| EncodingDetector | — | see adversarial-benchmark |
| MemoryGuard | — | 96.06% (v4.30.0) |
| OutputFilter | — | 58.64% (v4.30.0) |
| ToolResultGuard | — | 63.64% (v4.30.0) |
| ConversationGuard | — | **21.82%** |
| MultiModalGuard | — | 64.18% |
| MCPSecurityGuard | — | 97.95% (v4.29.0) |

---

## npm↔Python parity gate

File: `tests/guard-parity-vectors.json`  
Vectors: 32 | Guards covered: 12  
TS gate (`guard-parity.test.ts`): **32/32 PASS**  
Python gate (`test_guard_parity.py`): **32/32 PASS**

---

## Verification commands

```bash
# Full vitest suite (includes WildChat FPR gate + parity gate)
npx vitest run

# Adversarial corpus (regenerates these numbers)
npx tsx tests/adversarial/run-corpus.ts

# Python suite
cd ../llm-trust-guard-python && python3 -m pytest tests/ -q --ignore=tests/adversarial/datasets
```
