# Results — v4.21.2 (docs: CodeAnalyzerBackend + README-sync gate)

- **Date:** 2026-06-12
- **Library version:** 4.21.2 (npm)
- **Change:** documentation only — no code/behavior change

## Summary

A docs release closing a process gap surfaced during the 4.21.x publishing review:
the README did not document the public `CodeAnalyzerBackend` API (added in 4.21.0).

- **README**: added a "Pluggable Detection → CodeAnalyzerBackend" subsection with an
  acorn example; ESM + CommonJS both confirmed working (4.21.1 fix).
- **New gate G11**: `src/index.ts` (public exports) changing since the last tag now
  *requires* a `README.md` change (mirrors the G6 src↔tests gate). Override with
  `ALLOW_NO_README_UPDATE=1`. This is the durable fix so the README can't silently
  drift behind the public API again.

## Verification

- `npm run verify` — all 11 gates green (G11 added).
- No source change ⇒ recall/parity/coverage baselines unchanged from 4.21.1.

```bash
npm run verify
```
