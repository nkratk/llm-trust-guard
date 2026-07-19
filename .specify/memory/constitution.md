<!--
SYNC IMPACT REPORT
==================
Version change: (none — template placeholder) → 1.0.0 (user-directed initial ratification)

Bump rationale: Initial ratification, not a template fill-in. All 7 principles
  are derived from concrete incidents in this repo's own guard-hardening
  history (2026-07-15 through 2026-07-19), not generic best practices —
  the project owner explicitly asked for spec-kit specifically because prior
  sessions lost track of state between each other (a memory summary said
  "5 bugs fixed and released, all good" while GitHub issues #1-#3 stayed open;
  a later live-verify sweep found 12 more bugs the prior "all good" summary
  didn't anticipate; this session's own adversarial-sweep test file found 2
  MORE bugs the just-finished fix batch had missed). Every principle below
  cites the specific incident that motivated it.

Principles, sections:
  - 7 principles (fewer than the template's 5-slot default would suggest is
    "standard," but each one earned its place from a real incident — no
    padding to hit a round number)
  - Principle I: tagged NON-NEGOTIABLE
  - Renamed [SECTION_2_NAME] -> Tech & Release Standards
  - Renamed [SECTION_3_NAME] -> Development Workflow & Quality Gates

Templates requiring updates:
  - .specify/templates/plan-template.md: Constitution Check gate resolves
    against this file at plan time; no template edit required.
  - .specify/templates/spec-template.md, tasks-template.md,
    checklist-template.md: no constitution-specific sections; no changes.

Follow-up TODOs: none.
-->

# llm-trust-guard Constitution

## Core Principles

### I. Adversarial-Test Every Detection-Pattern Change, Both Directions (NON-NEGOTIABLE)
Any change to a regex, threshold, or detection pattern in a guard MUST be
verified two ways before merge: (a) it still catches the attack(s) it's meant
to catch (recall), and (b) it does not newly flag plausible benign input
(precision) — verified with hand-constructed adversarial probes run against
the actual code, not reasoned about from the diff alone. A single self-review
pass is insufficient; an independent adversarial-review pass (a second agent
or reviewer specifically trying to break the change, not confirm it) MUST run
after every first-attempt fix to a detection pattern.
**Rationale**: on 2026-07-16, the first attempt at fixing 5 confirmed guard
bugs shipped with self-review only. A second, independent adversarial-review
round found that 3 of those 5 fixes had reintroduced worse regressions —
`AgentSkillGuard`'s broadened regex false-positived on ordinary compliance
prose, `CodeExecutionGuard`'s gadget-pattern flagged legitimate pickling code
— none of it caught by the ~900-test suite that was green the whole time. The
same pattern repeated on 2026-07-19: a fix batch's adversarial-sweep test file
found 2 more bugs (`OutputGuard` double-counting nested shell syntax,
`PromptLeakageGuard`'s rigid `complete_you_are` adjacency) that a first
implementation pass plus the existing suite both missed.

### II. Prefer Recall Over Precision for Security-Relevant Patterns When Forced to Choose
When a false-positive fix and full attack recall are mutually exclusive, keep
detecting the attack and accept the documented false positive, rather than
narrow a pattern to fix the false positive at the cost of missing real
attacks. Document the trade-off explicitly in code comments and CHANGELOG.
**Rationale**: on 2026-07-16, narrowing `ExternalDataGuard.fetch_url` to
require a suspicious query param fixed a cited false positive but silently
stopped catching body-based exfiltration (`curl --data-binary`) and bare C2
beacon URLs — a worse regression than the false positive it fixed. Reverted.
Same pattern with `markdown_image_exfil`'s "token" key removal (reopened a
real `?token=`-based exfil bypass) and `html_comment_directive`'s filler-word
tolerance (reopened the exact false-positive class a 2026-07-02 fix had
already closed). A documented nuisance beats a silent security regression.

### III. Every Bug Fix Ships With a Permanent Regression Test, Not Just an Assertion of the Reported Case
A fix for a reported detection gap MUST add a test that would fail without the
fix. Where the bug belongs to a class of "input nobody thought to test" (most
detection-gap bugs do), the fix SHOULD also extend the guard's permanent
adversarial-sweep test file (`tests/guard-adversarial-sweep.test.ts`, or the
per-guard `test_code_execution_ast.py`-style parametrized array in Python) —
not just assert the one literal reproduction string from the bug report.
**Rationale**: the existing per-guard test suites (`external-data-guard.test
.ts`, etc.) only ever encoded what the original author already thought to
test — that is precisely why 12 real, live-verified bugs (and 3 of their own
first-attempt fixes) were invisible to a suite that stayed 100% green
throughout. A one-off regression test for the literal reported string doesn't
close that gap; broadened, adversarially-constructed coverage does.

### IV. Live-Verify Against the Real Installed Package, Not the Source Diff
Before trusting that a fix resolves an issue, or that a suspected bug is real,
run the actual reproduction against the real installed/published package (or
the built local `dist/`), not just against reasoning about the source diff.
**Rationale**: the entire original 12-bug backlog (2026-07-15/16) was found
this way — installing the real `npm`/`PyPI` package and running adversarial
probes against it, not reading source and guessing. Every fix in this repo's
history was likewise judge-verified (a fresh reproduction run, not a diff
read) before being trusted as "fixed."

### V. Close the Loop: Merged + Released Fixes MUST Close Their GitHub Issue
Every PR that fixes a filed issue MUST include a closing reference
(`Closes #N`) in its description, for every issue it addresses.
**Rationale**: on 2026-07-15, PR #4 merged and shipped in v4.32.3 without
`Closes #N` references. Issues #1, #2, #3 stayed open on GitHub for days
after the fix was live, requiring a manual catch-up pass once the drift was
noticed — exactly the kind of cross-session state loss this constitution
exists to prevent.

### VI. npm/Python Guard Parity Is Not Automatic — Verify Both Sides Live
When a bug is found or fixed in one language's guard implementation, the
sibling implementation MUST be independently, live-tested before assuming it
either (a) needs the same fix, or (b) is already correct and needs no fix.
Never assume parity or divergence from a description alone.
**Rationale**: on 2026-07-15, Python's `code_execution_guard.py` was assumed
to need no fix and was cited as the "reference implementation" the npm port's
gadget-chain fix was modeled on. It turned out to have its own, different
over-blocking bug (no proximity check at all), caught only because it was
independently, adversarially tested rather than trusted on reputation.

### VII. Merging and Releasing Are Always Separate, Explicitly-Confirmed Steps From Fixing
A fix being correct, tested, and gate-green is necessary but not sufficient
to merge or release it. Merging to the default branch and publishing a new
package version are each their own explicit decision point — never bundled
into the approval that authorized writing the fix.
**Rationale**: standing operating rule for this project (and this Claude
Code session's user-level CLAUDE.md), reinforced by this repo's own practice
of shipping fix batches as reviewable, gate-verified PRs before any merge or
`gh release create` is even proposed, let alone executed.

## Tech & Release Standards
- Language/runtime: TypeScript, Node.js (pinned per `.nvmrc`/CI config)
- Zero runtime dependencies (see README — this is a load-bearing project
  property, not incidental)
- Release gate: `scripts/verify.sh` (G1-G13) MUST pass before any PR is
  opened; re-verified again by the pre-push hook.
- Adversarial regression floor: the WildChat FPR gate
  (`tests/adversarial/wildchat-regression.test.ts`) is a locked-baseline
  ratchet — block count may only stay flat or decrease, never increase,
  without an explicit, reviewed baseline update.
- CHANGELOG.md and README.md MUST be updated in the same PR as any
  user-visible guard behavior change (enforced by verify.sh gates G7/G11/G12).

## Development Workflow & Quality Gates
- Guard-hardening workflow: live-verify sweep against the published package →
  judge-verify each candidate issue → implement fix → adversarial-review pass
  (Principle I) → extend permanent test coverage (Principle III) → gates
  green → open PR with `Closes #N` (Principle V) → explicit merge/release
  decision (Principle VII).
- Spec Kit flow for larger initiatives: `/speckit-specify` →
  `/speckit-clarify` (as needed) → `/speckit-plan` → `/speckit-tasks` →
  `/speckit-implement`, with `/speckit-analyze` as an optional cross-artifact
  consistency pass. `specs/001-guard-adversarial-hardening/` is the living
  record of this repo's ongoing hardening effort — a future session should
  read its `tasks.md` for current ground truth before trusting any prior
  session's summary.
- Commits: Conventional Commits (`fix:`, `feat:`, `test:`, `docs:`, `chore:`).

## Governance
This constitution supersedes ad-hoc practice for guard-hardening work in this
repository. Amendments go through `/speckit-constitution`, updating this
file's Sync Impact Report, version line, and any dependent template. Every
`/speckit-plan` run executes a Constitution Check gate before and after
design. Versioning: MAJOR (principle removed/redefined incompatibly), MINOR
(principle added or materially expanded), PATCH (wording/typo clarification).
Day-to-day operational guidance (tool use, commit conventions, verification
ritual) lives in `CLAUDE.md`; this file holds the planning/design-time
principles a `/speckit-plan` run is checked against.

**Version**: 1.0.0 | **Ratified**: 2026-07-19 | **Last Amended**: 2026-07-19
