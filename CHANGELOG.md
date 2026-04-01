# Changelog

All notable changes to `llm-trust-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.12.0] - 2026-03-24

### Added — HeuristicAnalyzer (3 Research-Backed Techniques)

New guard implementing three heuristic detection techniques from DMPI-PMHFE research (2026):

1. **Synonym Expansion** — 8 attack categories with expanded synonym sets (ignore→{disregard, overlook, neglect, bypass, omit...}). Catches paraphrased attacks that keyword regex misses.
2. **Structural Pattern Analysis** — Detects instruction-like sentence structures: many-shot Q&A injection, repeated token attacks, imperative sentence ratio, role assignment + bypass compounds.
3. **Statistical Feature Scoring** — Scores inputs based on instruction word density, special character ratio, uppercase ratio. High-density command text scores higher risk.

### Benchmark Results (tested against 13,730 real-world prompts)

| Metric | Without Heuristic | With Heuristic |
|--------|-------------------|----------------|
| Detection | 44.8% | **53.5%** (+8.7pp) |
| False Positive | 5.9% | **7.8%** (+1.9pp) |
| F1 | 0.460 | **0.487** (+0.027) |
| Latency | — | **0.85ms** per check |

Datasets: 1,448 attacks (jailbreak_llms CCS'24, Giskard, Compass CTF) + 12,282 clean prompts.

### Stats
- 27 guards (26 + HeuristicAnalyzer), 503+ tests, 0.85ms latency, zero dependencies

## [4.11.0] - 2026-03-24

### Production Hardening + Real-World Benchmarks

#### Adversarial Benchmarking (NEW)
- Tested against 1,403 REAL jailbreak prompts (verazuo/jailbreak_llms, CCS'24) + 11,885 clean regular prompts
- **Detection rate: 44.2%** on real-world jailbreaks (regex-only, zero dependencies)
- **False positive rate: 6.1%** on clean prompts (was 11.8% before this release)
- **Precision: 46.2%** — when we block, we're right 46% of the time
- **F1: 0.452** — the regex ceiling for pattern-only detection
- Found 13.5% dataset contamination (1,731 jailbreaks hiding in "regular" prompt set)
- Benchmark data published in README for full transparency

#### Detection Improvements
- Policy Puppetry patterns (JSON/INI/XML/YAML formatted injection)
- Payload splitting detection (fragment markers + recombination)
- Output prefix injection / Sockpuppetting patterns
- MCP SSRF + enhanced path traversal (CVE-2026-26118)
- Symbolic multimodal injection (emoji/rebus sequences)
- Named jailbreak variants (KEVIN, SETH, COOPER, MACHIAVELLI, MAXIMUM, ANARCHY)
- Compound persona + safety bypass detection
- Multilingual injection patterns (10 languages: ES, FR, DE, ZH, JA, PT, RU, AR, HI, KO)
- Zero-width character stripping before pattern scanning (invisible text injection defense)

#### False Positive Reduction
- EncodingDetector: only blocks on decoded-layer threats (not original text patterns)
- Signal-based pattern weights: broad patterns (0.45-0.5) act as signals, not blockers
- Tightened: act_as, role_pretend, DAN, output_prefix, encoding_keywords, PAP patterns
- Result: FP dropped from ~12% to 6.1% on 11,885 clean prompts

#### Production Quality
- Race condition fix (optimistic record + rollback in ExecutionMonitor)
- ESM + CJS dual support (`exports` field, `index.mjs` built via esbuild)
- Graceful shutdown (`destroy()` method on TrustGuard + all stateful guards)
- Fixed flaky memory guard test

#### Test Coverage
- 503 tests across 30 files (was 294 across 14)
- Tests for ALL 26 guards (was 14/26)
- Adversarial benchmarks against 3 real-world datasets (Giskard, jailbreak_llms, Compass CTF)
- False positive benchmark with 500+ legitimate inputs

### Stats
- 26 guards, 503 tests, 30 test files
- Real-world: 44.2% detection, 6.1% FP, 46.2% precision, F1=0.452
- Self-test: 91/91 verify-all-guards (100%)

## [4.10.0] - 2026-03-23

### Production Hardening

#### API Quality
- **Zero `as any` casts** — All new guards (ToolResult, ContextBudget, OutputSchema, TokenCost, DetectionClassifier) now have proper TypeScript types in TrustGuardConfig. Full IDE autocomplete.
- **Per-guard logger injection** — All 26 guards accept optional `logger` parameter. Default: no-op (silent). TrustGuard facade passes its logger to all child guards. Zero `console.log` calls remaining in guard code.
- **Common Guard interface** — Exported `Guard` type with `guardName` and `guardLayer` metadata.
- **Event hooks** — `onBlock`, `onAlert`, `onError` callbacks on TrustGuardConfig. Fire on guard blocks, warnings, and errors. Enables Datadog/PagerDuty/Grafana integration.
- **Metrics** — `getMetrics()` returns totalChecks, blockedChecks, blockRate, avgExecutionTimeMs, errors. Lightweight runtime telemetry.
- **Fixed flaky test** — Memory guard rollback test no longer timing-dependent.

### Stats
- 26 guards, 294 tests (all passing, zero flaky), 91/91 verify (100%)
- 0 `console.log` in guards, 0 `as any` casts, event hooks + metrics

## [4.9.0] - 2026-03-23

### Security — New Threat Pattern Detection

#### Policy Puppetry Defense (CRITICAL)
- **InputSanitizer**: Added 8 new patterns detecting structured policy injection via JSON, INI, XML, and YAML formats. Defends against the universal LLM bypass discovered by HiddenLayer that works across GPT-4, Claude, Gemini, and all major models.

#### Payload Splitting Defense (HIGH)
- **InputSanitizer**: Added 3 patterns detecting fragmented payloads with split markers and recombination instructions (Unit42 research on web-based indirect injection).

#### Output Prefix Injection / Sockpuppetting Defense (HIGH)
- **InputSanitizer**: Added 3 patterns detecting attempts to steer LLM response by injecting output prefixes (arXiv 2601.13359).

#### MCP SSRF + Path Traversal Defense (CRITICAL)
- **MCPSecurityGuard**: Added SSRF detection for internal/private IPs, dangerous protocols (file://, gopher://, etc.), double-encoded path traversal, and sensitive file access patterns. Addresses CVE-2026-26118 (Azure MCP SSRF, CVSS 8.8) and the 30+ MCP CVEs filed in Jan-Feb 2026.

#### Symbolic Multimodal Injection Defense (HIGH)
- **MultiModalGuard**: Added emoji/rebus instruction sequence detection, JSON/INI policy injection in metadata, and cross-metadata payload splitting. Based on NVIDIA AI Red Team research on semantic prompt injection via symbolic visual inputs.

### Stats
- 26 guards with 140+ InputSanitizer patterns (was 120+), enhanced MCP + multimodal detection

## [4.8.0] - 2026-03-22

### Added
- **TokenCostGuard (L26)** — Tracks LLM API token usage and cost per session/user. Enforces financial circuit breaking with hard cost ceilings. Addresses OWASP LLM10: Unbounded Consumption.
  - Per-request, per-session, and per-user token limits
  - Dollar cost tracking with configurable input/output token pricing
  - Alert threshold at configurable percentage of budget
  - Budget window with automatic expiry
  - New POC: poc-33-token-cost-budget

### Stats
- 26 guards, 294 tests across 14 files, 33 POCs, 91/91 verify-all-guards (100%)

## [4.7.0] - 2026-03-21

### Improved - Detection Rate: 76.1% → 100.0% (88/88 threats blocked)

#### Pattern Improvements
- **InputSanitizer**: Added PAP authority command pattern, fixed social proof pattern to match "Other AI assistants do", added "everyone...has already" variant
- **OutputFilter**: Fixed API key pattern to match "API key is:" format with space separator, fixed password pattern for colon-space format, lowered API key minimum from 20 to 16 chars
- **PromptLeakageGuard**: Added "repeat after me" PLeak pattern, "what did I tell you at the beginning" pattern, "summarize everything you know about yourself" pattern. Lowered default riskThreshold from 40 to 25
- **SchemaValidator**: Switched to `Object.getOwnPropertyNames()` for prototype pollution detection (catches `__proto__` from JSON.parse)
- **MemoryGuard**: Verify script now uses correct API signature (5 params not 4)

#### Verify Script Fixes
- EncodingDetector: Fixed property path (`encodings_found` → `encoding_analysis.encodings_detected`), replaced string literal payloads with actual encoded attacks
- MemoryGuard: Fixed parameter order (metadata before requestId)
- DriftDetector: Fixed sample objects to match BehaviorSample interface
- CircuitBreaker: Fixed constructor config property names
- RAGGuard: Added required `id` field to test documents

## [4.6.0] - 2026-03-18

### Added - Threat Coverage Gaps (Non-Breaking)

#### New Guards
- **ToolResultGuard** - Validates tool return values before they re-enter LLM context. Scans for prompt injection, state change claims, and schema violations in tool outputs. Addresses the #1 attack vector in 2025-2026 (Copilot Copirate, Supabase Cursor, WhatsApp MCP incidents).
- **ContextBudgetGuard** - Tracks aggregate token usage across all context sources per session. Detects many-shot jailbreaking (Anthropic research: 256-shot override), context window stuffing, and context dilution attacks.
- **OutputSchemaGuard** - Validates LLM structured outputs (JSON, function calls) before they reach downstream systems. Addresses OWASP LLM05: Improper Output Handling.

#### New Architecture
- **DetectionClassifier** - Pluggable detection callback for ML-based backends. Use the built-in `createRegexClassifier()` or implement your own async classifier (embedding similarity, external API, custom ML).
- **checkAsync()** method on TrustGuard - Runs sync regex guards + async classifier in parallel. Existing sync `check()` is unchanged (100% backward compatible).
- **validateToolResult()** method on TrustGuard - Post-tool-execution validation.
- **validateOutput()** method on TrustGuard - Structured output validation.

#### MCP Security Enhancements
- **Tool mutation detection (rug pull)** - MCPSecurityGuard now stores tool definition hashes at registration and detects post-registration mutations (CVE-2025-6514).
- **Tool description injection detection** - Scans MCP tool descriptions for hidden prompt injection (tool poisoning attacks).

### Test Coverage
- 281 tests across 13 test files (was 241 across 9)
- New test files: tool-result-guard, context-budget-guard, output-schema-guard, detection-backend

## [4.5.0] - 2026-03-17

### Added
- **Test coverage expanded**: 241 tests across 9 test files (was 190 across 5)
- New test files:
  - `trust-guard.test.ts` - Facade integration tests (pipeline, input limits, error boundaries, getGuards)
  - `output-filter.test.ts` - PII detection, secret detection, circular reference handling, false positives
  - `schema-validator.test.ts` - Injection detection, prototype pollution, false positives
  - `conversation-guard.test.ts` - Multi-turn detection, session management, regex flag regression test
- **False positive tests** for: normal text with apostrophes, product searches, URLs, order IDs, timestamps

### Fixed
- OutputFilter now handles circular references in `JSON.stringify` (both in `filter()` and initial string conversion)

## [4.4.0] - 2026-03-15

### Fixed
- **Facade ordering (C10)** - AutonomyEscalationGuard now runs after L2 ToolRegistry (validates tool exists before checking autonomy)
- **Policy gate warning (C11)** - Logs warning when policy gate is skipped due to missing tool definition
- **PAP config passthrough (C12)** - TrustGuardConfig now accepts `detectPAP`, `papThreshold`, `minPersuasionTechniques`, `blockCompoundPersuasion` and passes them to InputSanitizer
- **Overbroad SQL pattern (H5)** - SchemaValidator SQL injection detection now requires keyword context instead of flagging bare quotes/semicolons
- **Overbroad COMMAND pattern (H5)** - Narrowed to require command keyword context, no longer blocks JSON with curly braces
- **Overbroad bank_account pattern (H6)** - Now requires "account/acct/routing/iban" keyword context instead of matching any 8-17 digit number
- **Phone pattern narrowed (H6)** - Requires area code format to reduce false positives
- **Request ID (M3)** - Uses `crypto.randomUUID()` instead of `Math.random()` for collision-free IDs

### Added
- `detectPAP`, `papThreshold`, `minPersuasionTechniques`, `blockCompoundPersuasion` in sanitizer config
- `CIRCUIT_BREAKER` and `GUARD_ERROR` added to `block_layer` union type
- `GuardLogger` type exported for use in custom guard implementations

## [4.3.0] - 2026-03-15

### Fixed
- **Memory leaks (C1)** - Replaced `setInterval` in ConversationGuard and AgentCommunicationGuard with lazy cleanup on access. Added `destroy()` method for explicit resource release.
- **Unbounded Map growth (C2)** - Added 10K entry caps to ExecutionMonitor, CircuitBreaker, DriftDetector. Stale entries evicted automatically.
- **Error boundaries (H11)** - TrustGuard facade now catches guard errors. New `failMode` config: `"closed"` (default, block on error) or `"open"` (allow on error).
- **Error handling gaps (H4)** - OutputFilter handles circular references in JSON. DriftDetector guards against division by zero.

### Added
- `failMode` option in `TrustGuardConfig` (`"open"` | `"closed"`, default `"closed"`)
- `destroy()` method on ConversationGuard and AgentCommunicationGuard

## [4.2.0] - 2026-03-15

### Security Fixes
- **Fixed global regex flag bug (C3)** - ConversationGuard manipulation patterns used `/gi` flag with `.test()`, causing stateful `lastIndex` that could produce false negatives on repeated calls. Removed `g` flag. Also added `lastIndex` reset in EncodingDetector threat pattern checks.
- **Added input length limits (C5)** - New `maxInputLength` config (default: 100,000 chars) prevents DoS via oversized inputs. Applied to `check()` and `filterOutput()` in TrustGuard facade.
- **Fixed Express session ID spoofing (C7)** - Default `getSessionId` no longer trusts client-provided `x-session-id` header. Now uses server session or generates anonymous ID.
- **Fixed OpenAI system message bypass (C8)** - System and assistant messages now undergo encoding detection (previously skipped entirely). RAG-injected content in system messages is now checked.
- **Fixed OpenAI null reference crash (C9)** - Added null check for `memoryGuard` before calling `validateContextInjection()`.

### Added
- `maxInputLength` option in `TrustGuardConfig` (default: 100,000 characters)

## [4.1.0] - 2026-03-15

### Added
- **TrustGuard facade now integrates all 22 guards** - All 2026 guards (L11-L22) are now configurable and accessible through the unified `TrustGuard` class
- New `TrustGuardConfig` sections: `multiModal`, `memory`, `rag`, `codeExecution`, `agentCommunication`, `circuitBreaker`, `driftDetector`, `mcpSecurity`, `promptLeakage`, `trustExploitation`, `autonomyEscalation`, `statePersistence`
- `getGuards()` now returns all 22 guard instances for advanced usage
- `filterOutput()` now also checks for system prompt leakage via PromptLeakageGuard
- `completeOperation()` now records circuit breaker success/failure results
- `resetSession()` now clears state across all session-aware guards (Memory, TrustExploitation, Autonomy, StatePersistence)
- PromptLeakageGuard integrated into `check()` pipeline (input extraction detection)
- MemoryGuard integrated into `check()` pipeline (context injection validation)
- AutonomyEscalationGuard integrated into `check()` pipeline
- CircuitBreaker integrated into `check()` pipeline

### Changed
- `block_layer` type extended with `MEMORY`, `PROMPT_LEAKAGE`, `AUTONOMY`, `STATE` values
- `filterOutput()` return type now includes `prompt_leakage_detected` field
- `completeOperation()` now accepts optional `toolName` and `success` parameters

### Migration from 4.0.x
- **Non-breaking**: All 2026 guards default to `enabled: false` in the facade (opt-in)
- **Non-breaking**: Existing `check()` and `filterOutput()` behavior unchanged when new guards are not enabled
- To enable new guards, add their config section with `enabled: true`

## [4.0.2] - 2025-02-16

### Fixed
- Fixed broken links in README.md for npm display
- Added CONTRIBUTING.md, SECURITY.md, CHANGELOG.md to package files

## [4.0.0] - 2025-02-15

### Added

#### New Guards
- **AutonomyEscalationGuard (L21)** - Prevention of unauthorized autonomy escalation (ASI10)
- **StatePersistenceGuard (L22)** - State corruption and persistence attack prevention (ASI08)
- **TrustExploitationGuard (L20)** - Protection against human-agent trust exploitation (ASI09)
- **PromptLeakageGuard (L19)** - System prompt leakage prevention
- **MCPSecurityGuard (L18)** - MCP tool shadowing and supply chain attack prevention
- **DriftDetector (L17)** - Behavioral drift detection for agentic systems
- **CircuitBreaker (L16)** - Cascading failure prevention with automatic recovery
- **AgentCommunicationGuard (L15)** - Multi-agent communication security
- **CodeExecutionGuard (L14)** - Safe code execution sandboxing

#### Enhanced Guards
- **InputSanitizer (L1)** - Added 40+ PAP (Persuasive Adversarial Prompts) detection patterns
  - Authority appeals detection
  - Scarcity/urgency tactics
  - Social proof manipulation
  - Emotional manipulation
  - Compound attack detection
- **EncodingDetector (L10)** - Added ROT13, Octal, Base32, enhanced Unicode detection
  - Bidirectional text control character detection
  - Tag character hiding detection
  - Homoglyph detection
  - Zero-width character detection
- **MemoryGuard (L12)** - Added 25 injection patterns, Unicode obfuscation detection
  - Goal hijacking detection
  - Jailbreak persistence detection
  - Cross-session contamination prevention
- **ToolChainValidator (L9)** - Enhanced with ASI07/ASI04 compliance

#### Testing
- Added Vitest testing framework with 190+ tests
- Coverage configuration targeting 80%+

### Changed
- Updated threat patterns for OWASP Top 10 for LLMs 2025 compliance
- Updated patterns for OWASP Agentic AI 2026 compliance
- Improved detection rates across all guards

### Security
- All guards now detect Unicode-based obfuscation attacks
- Enhanced protection against trojan source attacks (bidi controls)
- Improved MCP security with tool verification

## [3.0.0] - 2024-12-01

### Added
- **RAGGuard (L13)** - RAG poisoning and embedding attack prevention
- **MultiModalGuard (L11)** - Multi-modal content security
- **MemoryGuard (L12)** - Memory persistence attack prevention
- Initial PAP detection in InputSanitizer

### Changed
- Restructured guard layers for better modularity
- Improved TypeScript type definitions

## [2.0.0] - 2024-09-15

### Added
- **ConversationGuard (L8)** - Multi-turn conversation security
- **OutputFilter (L7)** - Response filtering and sanitization
- **ExecutionMonitor (L6)** - Runtime execution monitoring
- **SchemaValidator (L5)** - Input/output schema validation

### Changed
- Refactored core architecture
- Improved performance for high-throughput scenarios

## [1.0.0] - 2024-06-01

### Added
- Initial release
- **InputSanitizer (L1)** - Prompt injection detection
- **ToolRegistry (L2)** - Tool access control
- **PolicyGate (L3)** - RBAC policy enforcement
- **TenantBoundary (L4)** - Multi-tenant isolation
- **EncodingDetector (L10)** - Encoding bypass detection
- **ToolChainValidator (L9)** - Tool chain validation

## Migration Guides

### Migrating from 3.x to 4.x

1. **New Guards**: Consider adding the new guards (L14-L20) to your security pipeline
2. **EncodingDetector**: New detection types are enabled by default - review `detectROT13`, `detectOctal`, `detectBase32` settings
3. **MemoryGuard**: New Unicode detection may flag previously allowed content
4. **InputSanitizer**: PAP detection is now enabled by default with `detectPAP: true`

### Migrating from 2.x to 3.x

1. **RAGGuard**: If using RAG, add RAGGuard to your pipeline
2. **MultiModalGuard**: Required for applications processing images/audio
3. **Type Changes**: Some interfaces have been updated - check TypeScript errors

### Migrating from 1.x to 2.x

1. **Layer Restructuring**: Guard layer numbers have changed
2. **New Dependencies**: Update your imports to use new guard classes
3. **Configuration**: Some config options have been renamed for consistency
