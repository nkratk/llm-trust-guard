# Adversarial Benchmark Results — v4.32.1

> **Docs-only patch.** No guard code changed from v4.32.0. Corpus results are identical; this file exists to satisfy the G8 gate.

Run date: 2026-07-06  
Corpus: `tests/adversarial/threats-1000-catalog.json`  
Threat groups: 1,182 | Payloads per group: 5 | Total threat payloads: 5,883  
Benign corpus (FPR gate): WildChat-1M random sample, 10,000 conversations  
Suite: `npx tsx tests/adversarial/run-corpus.ts`  
Vitest: 867 tests, all pass

> **v4.32.0 adds patterns to 4 guards; no catalog changes vs v4.31.0 Round 3.**  
> Full catalog methodology and per-guard breakdown: [RESULTS-v4.31.0.md](RESULTS-v4.31.0.md).

---

## Changes in v4.32.0

Pattern-only release. Four guards updated with 2026 literature-gap patterns; no catalog groups added beyond Round 3 (1,182 groups / 5,883 payloads). All numbers identical to the Round 3 baseline reported in [RESULTS-v4.31.0.md](RESULTS-v4.31.0.md).

| Guard | Change | Round 3 recall |
|---|---|---|
| AgentSkillGuard | +4 SCH patterns | **100%** (6 groups) |
| AgentCommunicationGuard | +7 string-payload patterns | **100%** (69 groups) |
| MemoryGuard | +4 PPT patterns | **96.2%** (69 groups) |
| RAGGuard | +2 HTML/image patterns | **92.2%** (46 groups) |

---

## WildChat FPR gate

| Version | Blocked / 10,000 | FPR |
|---|---|---|
| Baseline (locked) | 494 | 4.94% |
| v4.32.0 | **494** | **4.94%** |

Gate: PASS (count ≤ locked baseline 494).

---

## Full guard recall summary

*Numbers unchanged from [RESULTS-v4.31.0.md](RESULTS-v4.31.0.md) Round 3 (1,182 groups / 5,883 payloads).*

| Guard | Groups | Blocked / Total | Recall |
|---|---|---|---|
| CodeExecutionGuard | 244 | 1193 / 1193 | **100.0%** |
| PolicyGate | 44 | 220 / 220 | **100.0%** |
| TenantBoundary | 110 | 550 / 550 | **100.0%** |
| AgentCommunicationGuard | 69 | 345 / 345 | **100.0%** |
| DelegationScopeGuard | 22 | 110 / 110 | **100.0%** |
| TrustExploitationGuard | 3 | 15 / 15 | **100.0%** |
| AgentSkillGuard | 6 | 30 / 30 | **100.0%** |
| SpawnPolicyGuard | 2 | 10 / 10 | **100.0%** |
| AutonomyEscalationGuard | 2 | 10 / 10 | **100.0%** |
| SessionIntegrityGuard | 1 | 5 / 5 | **100.0%** |
| MCPSecurityGuard | 88 | 431 / 440 | **98.0%** |
| MemoryGuard | 69 | 332 / 345 | **96.2%** |
| RAGGuard | 46 | 212 / 230 | **92.2%** |
| MultiModalGuard | 110 | 353 / 550 | **64.2%** |
| ToolResultGuard | 44 | 140 / 220 | **63.6%** |
| OutputFilter | 44 | 129 / 220 | **58.6%** |
| ExternalDataGuard | 110 | 304 / 550 | **55.3%** |
| InputSanitizer | 93 | 255 / 465 | **54.8%** |
| ToolChainValidator | 44 | 110 / 220 | **50.0%** |
| ConversationGuard | 31 | 76 / 155 | **49.0%** |
| **TOTAL** | **1,182** | **4,830 / 5,883** | **82.1%** |

---

## npm↔Python parity gate

File: `tests/guard-parity-vectors.json`  
Vectors: 84 | Guards covered: 35  
TS gate (`guard-parity.test.ts`): **84/84 PASS**  
Python gate (`test_guard_parity.py`): **46/46 PASS** (Python-handled guards)

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
