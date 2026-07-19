---
description: "Living status ledger for guard adversarial hardening — READ THIS FIRST in a new session before trusting any prior summary"
---

# Tasks: Guard Adversarial Hardening

**Input**: `specs/001-guard-adversarial-hardening/{spec.md,plan.md}`

**How to use this file**: This is NOT a queue for `/speckit-implement` to
mechanically execute. It is a status ledger, updated at the end of every
guard-hardening work session. Before trusting it, reconcile against live
state: `gh issue list --repo nkratk/llm-trust-guard --state all`, `gh pr list
--repo nkratk/llm-trust-guard --state all`, `npm view llm-trust-guard
version`. **Last reconciled against live state: 2026-07-19 (post-release).**

**Current published version**: npm `llm-trust-guard` v4.32.4 — confirmed
live via `npm view llm-trust-guard version` after `gh release create`
triggered the publish workflow (GitHub Actions run succeeded). Release
tagging did not disturb any issue state — re-verified all 15 issue states
against this ledger's intended status after the release and confirmed they
still match exactly (see T023).

**Incident (2026-07-19, same day as merge): squash-merging PR #17 auto-closed
3 issues it should NOT have (#5, #11, #15).** `gh pr merge --squash` by
default composes the squash commit message from every individual commit's
message on the branch, not just the curated PR description. Three early
commits (written when a fix was first attempted, before a later adversarial-
review round found problems and reverted parts of that fix) still contained
stale `Closes #N` text that was never corrected once the revert happened.
The PR's own description was accurate throughout (never claimed to close
#5/#11/#15) — the drift was in individual commit messages the PR body didn't
override. All 3 issues were manually reopened with an explanatory comment
immediately after being caught (see issue timestamps ~19:36-19:37 UTC,
minutes after the ~19:35 merge). **Lesson for next time: before squash-
merging any PR whose branch contains a since-reverted commit, grep the full
commit range for stray `Closes #`/`Fixes #`/`Resolves #` text
(`git log <base>..<branch> --format="%B" | grep -oE "(Closes|Fixes|Resolves) #[0-9]+"`)
and either edit those commits or use `--admin`/a manual merge commit with a
clean message instead of trusting squash's default composition.**

## Phase 1: Fix batch #1 (issues #1-#3) — COMPLETE, RELEASED

- [x] T001 RAGGuard URL-decode gap (#1) — fixed, merged (PR #4), released v4.32.3
- [x] T002 AgentSkillGuard SCH regex brittleness (#2) — fixed, merged (PR #4), released v4.32.3
- [x] T003 CodeExecutionGuard gadget-chain pattern gap (#3) — fixed, merged (PR #4), released v4.32.3
- [x] T004 Close issues #1, #2, #3 on GitHub — done 2026-07-16 (they had stayed open post-merge; this was the housekeeping gap that first surfaced the cross-session drift problem)

## Phase 2: Fix batch #2 (issues #5-#16) — FIXED, TESTED, GATE-GREEN, **MERGED, NOT RELEASED**

**PR**: [#17](https://github.com/nkratk/llm-trust-guard/pull/17), branch
`fix/regex-threshold-batch-2`, **MERGED to main 2026-07-19 19:35 UTC**
(squash). 930/930 tests passing post-merge, all `scripts/verify.sh` gates
green. Already references `Closes #6`,
`Closes #8`, `Closes #9`, `Closes #14`, `Closes #12` (Constitution Principle
V, FR-002) — deliberately does NOT close #7, #10, #11, #15, #16 (partially
fixed, residual gap documented below) or #5 (reverted, still fully open).
**Correction (2026-07-19, same day): an earlier version of this file
incorrectly claimed no `Closes #N` references existed at all — an
independent judge review caught this before it was pushed anywhere. The
comma-list form `Closes #8, #9, #14` was also corrected to repeat the
keyword (`Closes #8, Closes #9, Closes #14`) since GitHub's closing-keyword
parser only recognizes the issue number immediately following each
`Closes`/`Fixes`/`Resolves` keyword, not a trailing comma-separated list.**

Fully fixed (issue closes cleanly once PR #17 merges + releases):
- [x] T005 `ftp://` missing from SSRF dangerous-scheme list (#6)
- [x] T006 OutputFilter phone_us regex misses unformatted/dash numbers (#8)
- [x] T007 OutputFilter password pattern misses "password is:" phrasing (#9)
- [x] T008 OutputGuard encoded (HTML-entity/URL) payload bypass (#12)
- [x] T009 OutputFilter credit-card grouping bypass, extended to Mastercard 2-series/Discover (#14)

Partially fixed — issue stays open with a documented residual gap even after
PR #17 merges (do not close these on merge; close only if/when the residual
gap itself is separately fixed):
- [~] T010 ExternalDataGuard role_override/fetch_url/markdown_image_exfil (#7) — role_override narrowed and fixed; fetch_url and markdown_image_exfil narrowings were REVERTED after adversarial review found they reopened worse bypasses (body-based exfil, C2 beacons, token-based exfil) — see CHANGELOG `[Unreleased]` "Reverted" section
- [~] T011 OutputFilter ip_address version-string false positive (#10) — octets now bounded 0-255, but a version string whose every octet happens to be valid (e.g. "10.4.32.3") remains inherently ambiguous with a real IP by shape alone — documented as a known regex-level limitation, not further fixable without context heuristics
- [~] T012 OutputGuard single-high-severity-threat non-blocking (#11) — chained-destructive-command and named-function CSV formula injection now block standalone; a broader backtick/`$()`-substitution promotion was attempted and REVERTED (blocked ordinary doc code spans identically to malicious ones)
- [~] T013 PromptLeakageGuard extraction rewording (#15) — 4 of 6 new pattern broadenings survived adversarial review; `beginning_conversation`'s "conversation started" and `summarize_guidelines`'s "instructions" additions were REVERTED (matched ordinary non-AI phrasing)
- [~] T014 PromptLeakageGuard fake similarity metric (#16) — replaced with real token-Jaccard similarity; paraphrase-evasion and generic-boilerplate-false-positive scenarios from the original report remain open (inherent limit of a lexical, non-semantic metric)

Not fixed — reverted back to original behavior, issue stays fully open:
- [ ] T015 ExternalDataGuard AGENT-directive filler-word tolerance (#5) — attempted, REVERTED: reopened the exact v4.25.0 false-positive class the pattern's verb-adjacency requirement was built to fix. Confirms the issue's own original assessment: needs semantic/LLM review, not a wider regex. **No further attempt planned without a different approach.**

Needs scoping before attempting a fix (not yet attempted):
- [ ] T016 ExternalDataGuard format-carrier bypass — PDF/CSS/OOXML/spreadsheet/SVG (#13) — the guard has zero format-aware parsing at all for these carriers; this is a design/scoping question (what carriers to support, how deep to parse), not a regex patch. Deliberately kept separate from the #5-#16 batch for this reason.

Bonus fixes found by this batch's own adversarial-sweep test file (not
originally filed as GitHub issues — found and fixed same-session, 2026-07-19):
- [x] T017 OutputGuard double-counts nested `` `$(...)` `` shell syntax into a false block (found + fixed via `tests/guard-adversarial-sweep.test.ts`)
- [x] T018 PromptLeakageGuard `complete_you_are` rigid adjacency misses "Complete this: you are a..." (found + fixed via same sweep)

## Phase 3: Process infrastructure — COMPLETE

- [x] T019 Permanent adversarial-sweep test file `tests/guard-adversarial-sweep.test.ts` — covers all 5 guards touched by batch #2 (ExternalDataGuard, OutputFilter, OutputGuard, PromptLeakageGuard, ToolResultGuard)
- [x] T020 spec-kit set up in this repo (`.specify/`, `.claude/skills/speckit-*`, this spec) — 2026-07-19, in response to the cross-session drift problem this ledger exists to solve

## Phase 4: Next steps

- [x] T021 ~~Add `Closes #N` references~~ — already present (see correction note above); the comma-list syntax bug was fixed 2026-07-19.
- [x] T022 **Explicit merge decision for PR #17** — user confirmed 2026-07-19; merged (squash) to main.
- [x] T022b **Squash-merge auto-closed 3 issues that should have stayed open (#5, #11, #15)** — see incident note above. All 3 reopened with explanatory comments same-day, minutes after merge.
- [x] T022c **Explicit release decision** — user confirmed 2026-07-19; `gh release create v4.32.4` run, publish workflow succeeded, confirmed live on the npm registry.
- [x] T023 Final issue-state pass after release: all 15 issues re-checked against this ledger's intended status — fully-fixed (#6, #8, #9, #12, #14) closed; partially-fixed (#7, #10, #11, #15, #16) and unfixed (#5) open. Release tagging triggered no further automation affecting issue state — matches the merge-time state exactly.
- [ ] T024 Scope T016 (#13, format-carrier bypass) as its own investigation before attempting a fix
- [ ] T025 Consider a fresh approach to T015 (#5) if one emerges — regex-based approaches are exhausted per the CHANGELOG note
- [ ] T026 Cross-check whether any of the #7-#16 batch's confirmed npm bugs also affect the Python sibling package (parity check not yet done — Constitution Principle VI)
