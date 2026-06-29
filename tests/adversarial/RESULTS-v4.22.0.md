# Results — v4.22.0 (OutputGuard + MCP registration-time schema scanning)

- **Date:** 2026-06-29
- **Library version:** 4.22.0 (npm) / 0.11.0 (PyPI)
- **Change:** new guard + guard enhancement — additive, no breaking changes

## Why

A 2025–2026 threat-landscape re-scan (verified against the current 34-guard set)
surfaced two genuinely uncovered gaps:

1. **OWASP LLM05:2025 Improper Output Handling** — `OutputFilter` only handled
   PII/secret egress. Nothing scanned model/tool output for payloads dangerous to
   a downstream sink (browser/DOM, SQL, OS shell, markdown renderer, spreadsheet).
2. **MCP registration-time poisoning** — `MCPSecurityGuard` scanned only the tool
   `description` at registration, missing full-schema poisoning (FSP, CyberArk
   "Poison Everywhere", 2025) and line-jumping (Trail of Bits, 2025).

## Fix

- **`OutputGuard` (L35)** — detects HTML/DOM XSS, SQL injection, OS command
  injection, markdown-image data-exfiltration, and spreadsheet/CSV formula
  injection. Critical payloads block; lone high-severity signals are reported and
  require corroboration to auto-block. Optional `sanitize` returns a neutralized
  copy. Zero dependencies.
- **MCPSecurityGuard** — `validateServerRegistration()` now walks the full
  parameter schema (names/enum/default/nested) for smuggled instructions and
  flags pre-invocation/secrecy/fake-compliance cues in descriptions. New
  violation prefixes: `schema_poisoning:`, `line_jumping:`. Toggle via
  `detectSchemaPoisoning` / `detectLineJumping`.

## Measured

| Suite | Before | After |
|-------|-------:|------:|
| npm vitest | 727 | **753** (+26) |
| Python pytest | 808 | **834** (+26) |

- `OutputGuard`: 21 tests — blocks `<script>`/`<img onerror>`, `UNION SELECT`/`;DROP`,
  `curl … \| bash`/`$(...)`, query-bearing markdown image links, and `=`/`@`-leader
  CSV formula cells; benign prose (`select an option`, learning *JavaScript*) passes.
- MCP registration: 5 tests — FSP via param name (`content_from_reading_ssh_id_rsa`)
  and `default` value; line-jumping ("before executing … do not tell the user …
  ~/.ssh/id_rsa"); clean tools and disabled-detector paths verified.

## Verification

- `npm run verify` — all gates green (G1 build, G3/4/5 tests+coverage+regression,
  G6 new-code-has-tests, G9 patch coverage, G11 README sync, G7 changelog).
- `npm run build` — `OutputGuard` confirmed present in `dist/index.mjs` (ESM named
  export) and `dist/index.d.ts`; CJS runtime blocks `<script>` (`allowed=false`).
- Python `ruff` clean; full suite green (834 passed). TS↔Python parity maintained.
- Post-publish: re-tested with clean `npm i llm-trust-guard@4.22.0` and
  `pip install llm-trust-guard==0.11.0` consumers.
