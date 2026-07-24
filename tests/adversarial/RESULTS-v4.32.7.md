# Adversarial Benchmark Results — v4.32.7

> **False-positive/false-negative fix, no new adversarial-corpus run.** This release fixes `OutputFilter`'s `ip_address` PII pattern false-positiving on version strings (issue #10) and ports npm's already-fixed `role_override` false-positive fix to the Python sibling — no other guard's detection logic changed. Recall against the 1,182-group corpus is unchanged; see [RESULTS-v4.32.6.md](RESULTS-v4.32.6.md) for those numbers, which remain the current basis for detection-rate claims.

Run date: 2026-07-23
Vitest: **962 tests, all pass** (up from 958 in v4.32.6)
G5-equivalent (WildChat FPR regression gate): 494/10,000 = 4.94%, unchanged.

---

## Changes in v4.32.7

Full detail in CHANGELOG.md `[4.32.7]`. Summary:

- **`OutputFilter`'s `ip_address` false positive on version strings (#10), fixed properly across two independent-review rounds:**
  - Base fix: a negative lookbehind suppresses the match when a version-indicating keyword (`version`/`release`/`upgrade`/`update`) qualifies the number within the same clause.
  - Round 1 review caught two regressions in the first attempt: an over-permissive gap that silently left real IPs unmasked when an unrelated keyword sat nearby, and an obfuscation-scan-variant bypass (the reversed-text variant scrambles the keyword while preserving the IP shape).
  - Round 2 review (a second, deliberate re-probe of the already-twice-fixed logic before merge) caught two more regressions in those same fixes: the clause-break punctuation denylist (`:;.,`) still missed every other punctuation mark and digit/newline gaps, and the "skip for every scan variant" fix was scoped too broadly, itself disabling real-IP detection in base64/hex-obfuscated output.
  - Final design: an **allowlist** (letters + horizontal whitespace only) for the clause gap instead of an ever-growing denylist, and a narrowly-scoped skip for only the specific reversed scan variant instead of all variants. Verified exhaustively: every ASCII punctuation character correctly preserves detection when used as a clause-break; every non-reversal obfuscation variant (base64, hex, URL-encode, ZWSP-strip) still catches a real IP.
- **`ExternalDataGuard`'s `role_override` false positive on ordinary business language, ported to Python** (was already fixed on npm; Python had never received the port). A pre-existing, intentional gap in this same pattern ("act as a system administrator" isn't caught — the same tradeoff npm already shipped, dropping "system"/"developer"/"moderator" from the authority-noun list to avoid false-positiving on phrasing like "act as a developer advocate") is now documented with an explicit test in both repos rather than left as an untested gap.
- **Issues #7 and #5 investigated with genuinely different angles, not changed.** `fetch_url`/`markdown_image_exfil` (#7's remaining sub-bugs) and `html_comment_directive` (#5) were re-investigated with mechanisms structurally different from the original 2026-07-16 attempt (a verb-tier split for `fetch_url`, a value-shape heuristic for `markdown_image_exfil`, a dangerous-object-noun requirement for `html_comment_directive`) — all three independently reconfirmed the original conclusion: any pattern-based carve-out here either reopens a real bypass or is trivially gameable. No code change; both issues updated with the reasoning.

## Note on review process

This release went through **two full rounds of independent adversarial review**, both of which found real, previously-unnoticed regressions in the immediately-preceding fix — not hypothetical edge cases, but concrete reproductions (`"This release: connect to 10.4.32.3 for support"` leaking a real IP; base64-encoded real IPs bypassing detection entirely). Documenting this explicitly because it's a useful data point on this codebase's own history: a security-relevant regex fix that looks complete after one round of scrutiny has, more than once now, still had real gaps a second round found. The final design in this release (allowlist over denylist, narrowly-scoped exclusions verified exhaustively rather than against a handful of examples) is intended to close the *class* of bug, not just the specific reproductions found so far — but that claim is only as good as the next adversarial probe that tests it.
