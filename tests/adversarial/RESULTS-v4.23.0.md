# Results — v4.23.0 (Sneaky Bits detection + MCP credential exposure scanning)

- **Date:** 2026-06-30
- **Library version:** 4.23.0 (npm) / 0.12.0 (PyPI)
- **Change:** guard enhancement × 2 — additive, no breaking changes

## Why

A 2025–2026 threat-landscape re-scan surfaced two verified gaps:

1. **Sneaky Bits encoding (NVIDIA 2025, CVE-2025-32711 "EchoLeak")** — The
   `EncodingDetector` already caught Unicode Tag-block smuggling (U+E0000-U+E007F)
   but missed the newer "Sneaky Bits" variant: invisible operators U+2062/U+2064
   encode binary 0/1, and consecutive variation selectors (U+FE00-U+FE0F) encode
   bit streams — both invisible in all UIs but parsed by LLMs.
2. **MCP credential aggregation (Astrix Security, 2025)** — 48% of MCP servers
   store credentials in plaintext in tool parameters, metadata, or server config.
   `MCPSecurityGuard.validateServerRegistration()` scanned key *names* for
   suspicious patterns but did zero scanning of actual credential *values*.

## Fix

- **`EncodingDetector`** — Detects U+2062/U+2064 invisible operators (new type
  `invisible_operators`). When 3+ consecutive appear, raises distinct top-level
  violation `SNEAKY_BITS_ENCODING_DETECTED`. Variation selectors (U+FE00-U+FE0F)
  detected when 2+ consecutive (single U+FE0F is normal in emoji — not flagged).
- **`MCPSecurityGuard`** — New `detectCredentialExposure` option (default: true).
  Walks the entire registration object recursively for AWS keys (AKIA…), GitHub
  PATs (ghp_/ghs_/gho_), Bearer/JWT tokens, Stripe secret keys, Slack tokens,
  Google API keys. New violation prefix `credential_exposed: <type>`, -40 rep.

## Measured

| Suite | Before | After |
|-------|-------:|------:|
| npm vitest | 753 | **763** (+10) |
| Python pytest | 834 | **844** (+10) |

- `EncodingDetector`: 4 new tests — invisible ops detected, SNEAKY_BITS_ENCODING_DETECTED
  emitted for 3+ ops, variation selectors detected, clean text passes.
- `MCPSecurityGuard`: 6 new tests — AWS key, GitHub PAT, Bearer token, Slack token
  detected; clean registration passes; `detectCredentialExposure: false` skips.

## Verification

- WildChat FPR regression: 493/10,000 (unchanged — narrowed VS detection to 2+
  consecutive avoids false-flagging emoji U+FE0F).
- `npm run verify` — all gates green.
- `bash scripts/verify.sh` — all gates green (Python).
- TS↔Python parity maintained across both guards.
