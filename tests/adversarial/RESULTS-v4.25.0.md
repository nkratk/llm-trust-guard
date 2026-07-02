# Results — v4.25.0 (FPR fixes + credential gap in validateToolCall)

- **Date:** 2026-07-02
- **Library version:** 4.25.0 (npm) / 0.14.0 (PyPI)
- **Driven by:** Advisor critique of v4.24.0

## Why

Advisor flagged three issues:

1. **`path_traversal` high FPR** — `(?:\.\.\/){2,}` fired on `../../src/components`,
   TypeScript `paths` aliases, monorepo tsconfig, error traces. Estimated 30–50% FPR
   in technical RAG content.

2. **`html_comment_directive` moderate FPR** — `<!--\s*(?:BOT|AGENT|ASSISTANT|AI|LLM)\s*:`
   fired on AI provenance markers (`<!-- AI: generated -->`, `<!-- ASSISTANT: do not modify -->`)
   emitted by GitHub Copilot and similar tools.

3. **`validateToolCall()` credential gap** — `detectCredentialExposure()` was called
   in `validateServerRegistration()` only. A live tool call with
   `{api_key: "AKIA...", target: "s3://exfil"}` passed through without any credential
   violation. Identified in v4.23.0 advisor review, still unshipped in v4.24.0.

## Changes

### `ExternalDataGuard` + `ToolResultGuard` — `path_traversal` narrowed

Before: `/(?:\.\.\/){2,}|(?:\.\.\\){2,}/`

After: `/(?:\.\.\/){3,}|(?:\.\.\\){3,}|(?:\.\.\/){2,}(?:etc|tmp|root|proc|sys|dev|usr|win)\b|(?:\.\.\\){2,}(?:windows|system32|users)\b/i`

Catches: 3+ traversal levels, or 2+ levels into a sensitive system directory.
Does NOT catch: `../../src/components`, `../../package.json`, `../../node_modules/`.

### `ExternalDataGuard` + `ToolResultGuard` — `html_comment_directive` narrowed

Before: `/<!--\s*(?:BOT|AGENT|ASSISTANT|AI|LLM)\s*:/i`

After: `/<!--\s*(?:BOT|AGENT|ASSISTANT|AI|LLM)\s*:\s*(?:execute|run|call|invoke|perform|fetch|send|ignore|bypass|forget|override|disregard|print|reveal|output|delete|drop)\b/i`

Requires an imperative action verb. `<!-- AI: generated -->` no longer fires.

### `MCPSecurityGuard` — credential scan in `validateToolCall()`

Added `detectCredentialExposure(parameters)` call after `scanParameters()` in
`validateToolCall()`. New violation format: `LIVE_CREDENTIAL_IN_TOOL_PARAMETER:<pattern>`.
Covers AWS AKIA keys, GitHub PATs (`ghp_`/`ghs_`), JWTs, Stripe `sk_live_`,
private key PEM blocks, and all patterns already used in `validateServerRegistration()`.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| npm vitest | 779 | **783** (+4) |
| Python pytest | 852 | **856** (+4) |

WildChat FPR: 493/10,000 (unchanged).
`npm run verify` — all gates green.
