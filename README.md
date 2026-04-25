# llm-trust-guard

[![npm version](https://img.shields.io/npm/v/llm-trust-guard.svg)](https://www.npmjs.com/package/llm-trust-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**34 security guards for LLM-powered and agentic AI applications.** Zero dependencies. Covers OWASP Top 10 for LLMs 2025, OWASP Agentic AI 2026, and MCP Security.

Also available as a [Python package on PyPI](https://pypi.org/project/llm-trust-guard/) (`pip install llm-trust-guard`).

## What This Package Does (And What It Doesn't)

> **"The LLM proposes. The orchestrator disposes."**

This package is your **first line of defense** — like a WAF (Web Application Firewall) for LLM applications. It sits in the orchestration layer and catches known attack patterns before they reach the LLM and after the LLM responds.

### What it catches well
- Known prompt injection phrases (170+ patterns, 11 languages)
- Encoding bypass attacks (9 formats: Base64, URL, Unicode, Hex, HTML, ROT13, Octal, Base32, mixed)
- Policy Puppetry attacks (JSON/INI/XML/YAML-formatted injection) — 100% detection
- Role-play/persona attacks (translator trick, academic pretext, emotional manipulation) — 100% detection
- PAP/persuasion attacks (authority, urgency, emotional manipulation) — 100% detection
- Multilingual injection (10 languages) — 100% detection
- Homoglyph attacks (Cyrillic/Greek character substitution) — normalized and detected
- PII and secret leakage in outputs
- Tool hallucination, RBAC bypass, multi-tenant violations
- Tool result poisoning, context window stuffing
- MCP tool shadowing, rug pull attacks, SSRF
- Malicious agent plugins (OpenClaw backdoor signatures, typosquatting, capability mismatch)
- External data validation (source verification, injection scanning, secret detection)
- Session integrity (permission escalation, session hijacking, replay attacks)

### What it catches partially (~50-80% detection)
- Multi-turn escalation (pattern-based, not semantic)
- Indirect injection via external data (ExternalDataGuard validates sources)
- Encoding bypass with mixed/partial encoding (~86% detection)
- Compression-based structural similarity (NCD — catches paraphrased known attacks)

### What it cannot catch (<20% detection on real-world datasets)
- **Semantically paraphrased attacks** — regex can't understand meaning. "Let's pretend those rules don't exist" bypasses pattern matching. (~10% detection on 1,000 real jailbreaks from CCS'24 dataset)
- **Adversarial ML attacks (GCG, AutoDAN, JBFuzz)** — generated suffixes designed to bypass static filters achieve 93-99% attack success rate.
- **Novel zero-day prompt techniques** — by definition, no static filter catches what hasn't been seen before.
- **Even ML defenses have limits** — "The Attacker Moves Second" (OpenAI/Anthropic/DeepMind, Oct 2025) showed all 12 tested defenses bypassed at >90% ASR by adaptive attacks.

### Why architectural guards matter more than detection
Detection has a ceiling. Even with ML, adaptive attackers bypass defenses. That's why this package includes **20+ architectural guards** that limit blast radius regardless of whether an attack is detected: CircuitBreaker, AutonomyEscalationGuard, TokenCostGuard, SessionIntegrityGuard, AgentSkillGuard, ExternalDataGuard, and more.

### How to close the gap
Use the **DetectionClassifier** interface to plug in ML-based detection alongside regex:

```typescript
import { TrustGuard } from 'llm-trust-guard';
import type { DetectionClassifier } from 'llm-trust-guard';

// Your ML classifier (embedding similarity, external API, custom model)
const mlClassifier: DetectionClassifier = async (input, ctx) => {
  const res = await fetch('https://your-ml-api/classify', {
    method: 'POST', body: JSON.stringify({ text: input })
  });
  const data = await res.json();
  return { safe: data.score < 0.5, confidence: data.score, threats: data.threats };
};

const guard = new TrustGuard({
  sanitizer: { enabled: true },
  classifier: mlClassifier,  // ML backend
});

// checkAsync() runs regex + ML classifier in parallel
const result = await guard.checkAsync('tool', params, session, { userInput });
```

## Installation

```bash
npm install llm-trust-guard
```

## Quick Start

```typescript
import { InputSanitizer, EncodingDetector } from 'llm-trust-guard';

const sanitizer = new InputSanitizer();
const encoder = new EncodingDetector();

const result = sanitizer.sanitize(userInput);
if (!result.allowed) {
  console.log('Blocked:', result.violations);
  return;
}

const encodingResult = encoder.detect(userInput);
if (!encodingResult.allowed) {
  console.log('Encoded threat:', encodingResult.violations);
  return;
}
```

### Using TrustGuard Facade (All Guards)

```typescript
import { TrustGuard } from 'llm-trust-guard';

const guard = new TrustGuard({
  sanitizer: { enabled: true, threshold: 0.3 },
  encoding: { enabled: true },
  registry: { tools: [{ name: 'search', allowed_roles: ['user', 'admin'] }] },
  memory: { enabled: true, detectInjections: true },
  promptLeakage: { enabled: true, systemPromptKeywords: ['SECRET_KEY'] },
  circuitBreaker: { enabled: true, failureThreshold: 50 },
});

// Sync check (regex guards only — <5ms)
const result = guard.check('search', { query: 'test' }, session, { userInput });

// Async check (regex + ML classifier — depends on backend latency)
const asyncResult = await guard.checkAsync('search', { query: 'test' }, session, { userInput });

// Validate tool results before feeding back to LLM
const toolResult = guard.validateToolResult('search', toolOutput);

// Filter LLM output (PII + prompt leakage detection)
const output = guard.filterOutput(llmResponse, session.role);
```

## All 34 Guards

### Input Guards (before LLM)

| Guard | Purpose | Detection |
|-------|---------|-----------|
| InputSanitizer | Prompt injection, PAP, Policy Puppetry | 170+ regex patterns, 11 languages |
| EncodingDetector | Encoding bypass (9 formats, multi-layer) | Decode + pattern match |
| CompressionDetector | Structural similarity to known attacks (NCD) | gzip compression distance, 135 templates |
| HeuristicAnalyzer | Synonym expansion, structural + statistical analysis | 8 attack categories, 130+ synonyms |
| PromptLeakageGuard | System prompt extraction attempts | Direct + encoded + indirect |
| ConversationGuard | Multi-turn manipulation, escalation | Session risk scoring |
| ContextBudgetGuard | Many-shot jailbreaking, context overflow | Token budget tracking |
| MultiModalGuard | Image/audio metadata injection | Metadata + steganography scan |

### Access Control Guards

| Guard | Purpose | Detection |
|-------|---------|-----------|
| ToolRegistry | Tool hallucination prevention | Allowlist |
| PolicyGate | RBAC enforcement | Role hierarchy |
| TenantBoundary | Multi-tenant isolation | Resource ownership |
| SchemaValidator | Parameter injection (SQL, NoSQL, XSS, command) | Contextual pattern matching |
| ExecutionMonitor | Rate limiting, resource quotas | Time-window counting |
| TokenCostGuard | LLM API cost tracking, financial circuit breaking | Token + dollar budget |

### Output Guards (after LLM)

| Guard | Purpose | Detection |
|-------|---------|-----------|
| OutputFilter | PII/secret masking | Regex + role-based filtering |
| OutputSchemaGuard | Structured output validation | Schema + injection scan |
| ToolResultGuard | Tool return value validation | Injection + state claims |

### Agentic Guards

| Guard | Purpose | Detection |
|-------|---------|-----------|
| ToolChainValidator | Dangerous tool sequences | Sequence matching |
| AgentCommunicationGuard | Inter-agent message security | HMAC + nonce |
| TrustExploitationGuard | Human-agent trust boundary | Action validation |
| AutonomyEscalationGuard | Unauthorized autonomy expansion | Capability tracking |
| MemoryGuard | Memory poisoning prevention | Injection patterns + HMAC |
| StatePersistenceGuard | State corruption prevention | Integrity hashing |
| CodeExecutionGuard | Unsafe code execution | Static analysis |
| RAGGuard | RAG document poisoning | Source trust + injection |
| MCPSecurityGuard | MCP tool shadowing, rug pull, SSRF | Registration + mutation hash |
| CircuitBreaker | Cascading failure prevention | State machine |
| DriftDetector | Behavioral anomaly detection | Statistical profiling |
| ExternalDataGuard | External data validation before LLM context | Source trust + injection + secret scan |
| AgentSkillGuard | Malicious plugin/tool detection (OpenClaw) | Backdoor signatures + typosquatting |
| SessionIntegrityGuard | Session hijacking, permission escalation | Binding + sequence + timeout |

### Multi-Agent Guards (OWASP ASI07)

| Guard | Purpose | Detection |
|-------|---------|-----------|
| SpawnPolicyGuard | Agent spawn policy enforcement | CSP-style allowlists, max delegation depth |
| DelegationScopeGuard | Agent-to-agent scope downscoping | OAuth-style parent-child scope subset |
| TrustTransitivityGuard | Trust chain validation | X.509-style chain depth + min trust score |

### Pluggable Detection

| Component | Purpose |
|-----------|---------|
| DetectionClassifier | Plug in any ML backend (sync or async) alongside regex guards |
| createRegexClassifier() | Built-in regex classifier as a DetectionClassifier callback |

## OWASP Coverage

### LLM Top 10 2025

| Threat | Guards | Coverage |
|--------|--------|----------|
| LLM01: Prompt Injection | InputSanitizer, EncodingDetector, ContextBudgetGuard | Strong (known patterns), Weak (novel semantic) |
| LLM02: Sensitive Data Exposure | OutputFilter, PromptLeakageGuard | Strong |
| LLM03: Supply Chain | MCPSecurityGuard | Moderate (MCP-focused) |
| LLM04: Data Poisoning | RAGGuard, MemoryGuard | Moderate |
| LLM05: Improper Output Handling | OutputSchemaGuard, OutputFilter | Strong |
| LLM06: Excessive Agency | AutonomyEscalationGuard, ToolChainValidator | Strong |
| LLM07: System Prompt Leakage | PromptLeakageGuard | Strong |
| LLM08: Vector/Embedding Weakness | RAGGuard | Moderate |
| LLM09: Misinformation | DetectionClassifier (pluggable) | Requires ML backend |
| LLM10: Unbounded Consumption | ExecutionMonitor, TokenCostGuard | Strong |

### Agentic AI 2026

| Threat | Guards | Coverage |
|--------|--------|----------|
| ASI01: Agent Goal Hijack | InputSanitizer, ConversationGuard | Moderate |
| ASI02: Tool Misuse | ToolChainValidator, ToolRegistry | Strong |
| ASI03: Privilege Mismanagement | PolicyGate, TenantBoundary | Strong |
| ASI04: Supply Chain | MCPSecurityGuard | Moderate |
| ASI05: Code Execution | CodeExecutionGuard | Strong |
| ASI06: Memory Poisoning | MemoryGuard, StatePersistenceGuard | Strong |
| ASI07: Inter-Agent Communication | AgentCommunicationGuard | Strong |
| ASI08: Cascading Failures | CircuitBreaker, DriftDetector | Strong |
| ASI09: Trust Exploitation | TrustExploitationGuard | Strong |
| ASI10: Rogue Agents | DriftDetector, AutonomyEscalationGuard | Moderate |

## Measured Performance

v4.19.0 benchmark, 2026-04-23. v4.20.0 added MCP Sampling attack detection (see [CHANGELOG.md](CHANGELOG.md)) — orthogonal to the Sanitizer+Encoder pipelines below, so numbers apply unchanged. Full methodology, 95% confidence intervals, hand-adjudication labels, and reproducibility scripts: [tests/adversarial/RESULTS-v4.19.0.md](tests/adversarial/RESULTS-v4.19.0.md).

**Attack detection on prior-published corpora** (Giskard n=35, Compass CTF Chinese n=11): detection rate has not moved from v4.13.5 → v4.19.0 on the Sanitizer+Encoder pipeline — 80.00% and 9.09% respectively, identical to the v4.13.5 numbers. Six releases of pattern additions (v4.14–v4.19) targeted different attack classes (indirect injection, tool-result validation, memory persistence, multi-agent trust) that these direct-text jailbreak corpora do not exercise. Small sample sizes mean "no evidence of improvement," not "proof of no improvement."

**False-positive rate on real ChatGPT production traffic** (WildChat-1M shard 0, 10,000 non-toxic multilingual first-user-turns, seed=42):

| Pipeline | Blocks | Raw block rate | Corrected FPR (after label adjudication) |
|---|---|---|---|
| Sanitizer + Encoder | 493 / 10,000 | 4.93% [4.52, 5.37] | **~2.73%** [2.43, 2.84] |
| Detection-only facade | 898 / 10,000 | 8.98% [8.44, 9.56] | ≤6.69% (upper bound; not fully adjudicated) |

WildChat filters toxic content but not prompt-injection intent. Canonical-marker analysis + a 50-sample hand-adjudication found that approximately 220 of the 493 Pipeline A blocks are actual jailbreak attempts users sent to ChatGPT, not genuine false positives. Corrected FPR is in the same order of magnitude as Meta Prompt Guard 86M's self-reported 3–5% out-of-distribution FPR — not a head-to-head comparison, but a useful reference point.

**Not measured:** detection rate on the four attack classes added in v4.19.0 (CSS-hidden content, HTML attribute directives, JSON agent-directive fields, Reprompt-class markdown exfiltration). No public held-out corpus exists for these at statistical scale. Unit-test coverage is in the v4.19.0 test suite; independent third-party evaluation is invited.

For higher detection on adversarial corpora, plug in an ML classifier via the [DetectionClassifier interface](#pluggable-detection).

## Defense In Depth

This package is one layer. For production systems, combine with:

```
Layer 1: llm-trust-guard (regex pattern matching — fast, zero deps)
Layer 2: ML classifier via DetectionClassifier (semantic detection — slower, more accurate)
Layer 3: Model provider safety (OpenAI moderation, Anthropic safety, etc.)
Layer 4: Human review for high-risk actions
Layer 5: Monitoring + alerting (DriftDetector + circuit breakers)
```

## Framework Integrations

- **Express.js** — `createTrustGuardMiddleware()` for route protection
- **LangChain** — `TrustGuardLangChain` for chain validation
- **OpenAI** — `SecureOpenAI` or `wrapOpenAIClient()` for API wrapping

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT

## Links

- [Python package (PyPI)](https://pypi.org/project/llm-trust-guard/) — same 34 guards, zero dependencies
- [OWASP Top 10 for LLMs 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
