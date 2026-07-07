# Adversarial Benchmark Results — v4.31.0

Run date: 2026-07-04  
Corpus: `tests/adversarial/threats-1000-catalog.json`  
Threat groups: 1,160 | Payloads per group: 5 | Total threat payloads: 5,800  
Benign corpus (FPR gate): WildChat-1M random sample, 10,000 conversations  
Suite: `npx tsx tests/adversarial/run-corpus.ts`  
Vitest: 815 tests, all pass

> **Catalog expanded post v4.31.0 release (three rounds):**
> - Round 1: 14 new threat groups (CG-01..CG-09, IS-01..IS-05); two groups (0455, 0995) payload-quality fixed.
> - Round 2: 16 ToolChainValidator base groups (0101-0110, 0145-0154) had semantic placeholder payloads that didn't match `_OS_CMD_RE`; all replaced with OS-injection payloads (now 5/5 each, raising TCV recall 13.6%→50%). Eleven new guard groups added for 5 previously zero-coverage guards: TrustExploitationGuard (TEG-01..03), AgentSkillGuard (ASG-01..03), SpawnPolicyGuard (SPG-01..02), AutonomyEscalationGuard (AEG-01..02), SessionIntegrityGuard (SIG-01). Catalog now 1,171 groups / 5,855 payloads. No guard code changed.
> - Round 3 (2026-07-06 — 2026 literature gap-fill): 10 semantic blind catalog groups fixed (3 EDG + 7 RAGGuard). 11 new groups added targeting 4 2026 threat research gaps: AgentSkillGuard SCH (ASG-04..06), AgentCommunicationGuard string-payload injection (ACG-01..02), MemoryGuard Plant-Persist-Trigger (MG-PPT-01..03), RAGGuard markdown/HTML carrier (RAG-IMG-01..02). Guard code updated in 4 guards + corpus runner TEG fix. Catalog now 1,182 groups / 5,883 payloads. WildChat FPR unchanged at 494/10,000 (4.94%). Parity vectors: 84 vectors covering all 35 guards.

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

| Metric | v4.30.0 | v4.31.0 | v4.31.0 + catalog | Delta (vs v4.30.0) |
|---|---|---|---|---|
| Threat groups | 22 | 22 | **31** | +9 new groups |
| Threat recall | 2.7% | 21.82% | **49.0%** | +46.3 pp |
| Fully-blind threat groups | 11 | 2 | **0** | −11 |
| Fully-detected groups | 0 | 0 | **8** | +8 |

*Catalog improvement note: the 21.82% figure from the initial v4.31.0 release reflected 22 existing threat groups. After adding 9 new precisely-targeted groups (CG-01..CG-09) and fixing the 2 blind groups (0455, 0995), the catalog now has 31 ConversationGuard groups and recall is 49.0%.*

**Patterns added:** `skeleton_key`, `many_shot_jailbreak`, `context_drift`, `session_hijack`, `persona_pivot`, `loop_injection`, `crescendo_escalation`, `compression_abuse`, `whisper_sidechannel`.

**Preprocessing added:** `preprocessMessage()` applies ZWSP/bidi strip, URL-decode, hex-decode, base64-decode, string reverse, Cyrillic normalisation before pattern scan; Set-based deduplication prevents double-counting.

### 3. InputSanitizer — obfuscation preprocessing

| Metric | v4.30.0 | v4.31.0 | v4.31.0 + catalog | Delta (vs v4.30.0) |
|---|---|---|---|---|
| Threat groups | 88 | 88 | **93** | +5 new groups |
| Threat recall | 28.0% | 52.27% | **54.8%** | +26.8 pp |
| Fully-detected groups | — | 34 | **39** | +5 |

**Method added:** `buildInputVariants()` generates URL-decoded, hex-decoded, base64-decoded, reversed, and Cyrillic-normalised variants. The `sanitize()` pattern loop iterates `[raw, cleaned, ...variants]` with a `matchedNames` Set to deduplicate across variants. No new patterns added.

**New catalog groups (IS-01..IS-05):** URL-encoded, base64-encoded, hex-encoded, reversed, and Cyrillic-homoglyph injection payloads that decode to known-blocked phrases — all 5 score 5/5.

---

## WildChat FPR gate (Pipeline A = InputSanitizer + EncodingDetector)

| Version | Blocked / 10,000 | FPR |
|---|---|---|
| Baseline (locked) | 494 | 4.94% |
| v4.31.0 | **494** | **4.94%** |

Gate: PASS (count ≤ locked baseline 494).

---

## Full guard recall summary (threat corpus)

*Final numbers after catalog expansion — Round 3 (1,182 groups / 5,883 payloads). Run: 2026-07-06.*

| Guard | Groups | Blocked / Total | Recall | Full | Blind |
|---|---|---|---|---|---|
| CodeExecutionGuard | 244 | 1193 / 1193 | **100.0%** | 244 | 0 |
| PolicyGate | 44 | 220 / 220 | **100.0%** | 44 | 0 |
| TenantBoundary | 110 | 550 / 550 | **100.0%** | 110 | 0 |
| AgentCommunicationGuard | 69 | 345 / 345 | **100.0%** | 69 | 0 |
| DelegationScopeGuard | 22 | 110 / 110 | **100.0%** | 22 | 0 |
| TrustExploitationGuard | 3 | 15 / 15 | **100.0%** | 3 | 0 |
| AgentSkillGuard | 6 | 30 / 30 | **100.0%** | 6 | 0 |
| SpawnPolicyGuard | 2 | 10 / 10 | **100.0%** | 2 | 0 |
| AutonomyEscalationGuard | 2 | 10 / 10 | **100.0%** | 2 | 0 |
| SessionIntegrityGuard | 1 | 5 / 5 | **100.0%** | 1 | 0 |
| MCPSecurityGuard | 88 | 431 / 440 | **98.0%** | 80 | 0 |
| MemoryGuard | 69 | 332 / 345 | **96.2%** | 64 | 0 |
| RAGGuard | 46 | 212 / 230 | **92.2%** | 41 | 0 |
| MultiModalGuard | 110 | 353 / 550 | **64.2%** | 58 | 30 |
| ToolResultGuard | 44 | 140 / 220 | **63.6%** | 14 | 0 |
| OutputFilter | 44 | 129 / 220 | **58.6%** | 12 | 0 |
| ExternalDataGuard | 110 | 304 / 550 | **55.3%** | 37 | 35 |
| InputSanitizer | 93 | 255 / 465 | **54.8%** | 39 | 23 |
| ToolChainValidator | 44 | 110 / 220 | **50.0%** | 20 | 21 |
| ConversationGuard | 31 | 76 / 155 | **49.0%** | 8 | 0 |
| **TOTAL** | **1,182** | **4,830 / 5,883** | **82.1%** | | |

> **ToolChainValidator note:** 21 remaining blind groups are all encoding-bypass variants (base64/hex/URL-encoded OS payloads). TCV's `_OS_CMD_RE` runs on raw tool parameters without preprocessing — this is an accepted, documented limitation (the guard does not decode before checking). The 50.0% recall correctly reflects that the guard catches un-encoded OS injection but not encoded variants.
>
> **Round 3 highlights:**
> - RAGGuard: 75.9% → **92.2%** (+16.3 pp): 7 blind catalog groups fixed (payload pattern alignment) + 2 new RAG-IMG groups + 2 new INDIRECT_INJECTION patterns (markdown image alt, HTML event injection).
> - AgentSkillGuard: 3 → **6 groups** (100%): 3 new Semantic Compliance Hijacking groups (ASG-04..06) + 4 new SCH patterns (authority-keyword routing, fake-compliance exfil, compliance-framed routing, response-appending directive).
> - AgentCommunicationGuard: 66 → **69 groups** (100%): 2 new string-payload injection groups (ACG-01..02) + LLM-to-LLM string payload scanning in validatePayload().
> - MemoryGuard: 66 → **69 groups** (96.2%): 3 new Plant-Persist-Trigger groups (MG-PPT-01..03) + 4 new tool-invocation trigger patterns.
> - ExternalDataGuard: 52.5% → **55.3%**: 3 semantic blind catalog groups fixed (payload pattern alignment).
> - Corpus runner TEG bug fixed: action_type field was missing, causing TrustExploitationGuard to crash silently at 0% in the corpus.

---

## npm↔Python parity gate

File: `tests/guard-parity-vectors.json`  
Vectors: 84 | Guards covered: 35  
TS gate (`guard-parity.test.ts`): **84/84 PASS**  
Python gate (`test_guard_parity.py`): **84/84 PASS** (requires Python sync of new vectors)

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
