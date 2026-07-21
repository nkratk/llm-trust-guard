# Feature Specification: Guard Adversarial Hardening

**Feature Branch**: `001-guard-adversarial-hardening` (tracking-only — this is an ongoing initiative documented on `main`, not a single feature branch; see plan.md)

**Created**: 2026-07-19

**Status**: In Progress (ongoing — this spec is re-read and its tasks.md updated at the start of each future guard-hardening session, not "completed" once)

**Input**: User request: "we should use the spec kit to improve this process, otherwise we are losing track between sessions, and one session says things are good, in other sessions multiple bugs, it's not scaling."

## Problem Statement

Across multiple sessions of hardening this package's guards against adversarial
bypass, state repeatedly drifted between sessions:
- A session's memory summary declared "5 bugs fixed and released, all good"
  while GitHub issues #1-#3 still showed OPEN (the merging PR didn't reference
  `Closes #N`).
- A later session's live-verify sweep against the published package found 12
  MORE bugs the prior "all good" summary gave no indication of.
- This session's own permanent adversarial-sweep test file
  (`tests/guard-adversarial-sweep.test.ts`) found 2 MORE bugs the just-shipped
  fix batch had missed, before that batch was even merged.

Root cause: nothing durable and structured lived in the repo itself. Ground
truth was reconstructed each session from a mix of chat memory, `gh issue
list`, and re-reading source — all of which can and did drift from reality.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Systematic gap-finding, not report-driven firefighting (Priority: P1)

As the maintainer, I need a repeatable methodology for finding detection gaps
in shipped guards, so bugs surface from our own process before an external
report finds them.

**Why this priority**: Every bug found so far (12 in this repo, 1 in the
Python sibling) was found by live-verify adversarial sweeping, not by a bug
report. This is the core capability the whole effort depends on.

**Independent Test**: Run a live-verify sweep (install the published package,
construct adversarial probes per guard, run them) against the current
published version and confirm zero new findings, or file+fix what's found.

**Acceptance Scenarios**:

1. **Given** a guard has shipped detection patterns, **When** a live-verify
   sweep is run against the real published package, **Then** every finding is
   judge-verified (re-run against the real package, not just reasoned about)
   before being trusted as real.
2. **Given** a candidate fix for a detection gap, **When** the fix is
   implemented, **Then** an independent adversarial-review pass (not the same
   review that wrote the fix) runs before the fix is considered done.

---

### User Story 2 - Fixing a false positive must not silently reopen a false negative (Priority: P1)

As the maintainer, when I narrow a detection pattern to fix a reported false
positive, I need to verify I haven't reopened detection of a real attack the
original (broader) pattern used to catch.

**Why this priority**: 3 of 5 npm files' first-attempt fixes in the 2026-07-16
batch, and multiple more in the 2026-07-19 batch, did exactly this — a fix
that looked correct on paper (and passed the existing ~900-test suite)
silently reopened a worse detection gap than the false positive it fixed.

**Independent Test**: For every detection-pattern narrowing, run both the
original false-positive reproduction (must now pass) AND the pattern's
existing true-positive test cases plus new adversarial variants of the
original attack class (must still fail/block).

**Acceptance Scenarios**:

1. **Given** a pattern is narrowed to fix a false positive, **When** the
   fix is tested against attack variants the original broader pattern caught,
   **Then** none of those variants newly bypass detection.
2. **Given** ambiguity between "fix the false positive" and "keep full
   recall," **When** the two conflict, **Then** recall is kept and the
   false positive is documented, not silently traded away.

---

### User Story 3 - Current status is readable without reconstructing it from chat history (Priority: P1)

As the maintainer (or a future session), I need the current status of every
known guard issue — open, fixed-but-unmerged, merged, released — visible by
reading a file in the repo, not by asking a prior session or cross-checking
memory notes against `gh issue list`.

**Why this priority**: this is the literal problem statement that motivated
adopting spec-kit. Without this, every session partially re-derives state,
and re-derivation is where drift creeps in.

**Independent Test**: A fresh session, given only this repo and no prior chat
context, can read `specs/001-guard-adversarial-hardening/tasks.md` and
correctly state which issues are open/fixed/merged/released without running
`gh issue list` or asking the user.

**Acceptance Scenarios**:

1. **Given** a PR merges and its release ships, **When** the next session
   starts, **Then** `tasks.md` already reflects the merged/released status —
   it does not require a live `gh` query to discover this.
2. **Given** a new bug is found via live-verify sweeping, **When** it's
   filed as a GitHub issue, **Then** `tasks.md` is updated in the same
   work session, not left to drift until the next session notices.

### User Story 4 - Distinguishing "we broke it" from "it never worked" (Priority: P2)

As the maintainer, when a live-verify sweep finds a detection gap in the
currently-shipped version, I need to know whether that gap is a regression
(worked in an earlier release, broken by a later one) or a long-standing
coverage gap (never worked, at any version) before scoping a fix — a
regression that shipped silently is a different, higher-priority problem
than a gap that was simply never covered.

**Why this priority**: without this, every gap found by a sweep looks
equally urgent, and a real regression (a detection capability that existed
and was accidentally removed) can sit unnoticed in the same backlog as
gaps that were never going to be caught in the first place.

**Independent Test**: Given a set of currently-failing threat/guard pairs and
fresh installs of every historical published version, bisect each one's
blocked/total sequence across all versions and classify it as regression,
never-detected, or improved — then have an independent, fresh-context agent
live-reproduce the claimed regression against the specific before/after
version pair itself (not re-reading the bisection's own output) before it's
reported as confirmed.

**Acceptance Scenarios**:

1. **Given** a threat that a fresh-install sweep shows 0/5 blocked at the
   current version, **When** it is bisected across every historical version,
   **Then** the result records whether any earlier version ever blocked it,
   not just the current-version pass/fail.
2. **Given** a bisection finds blocked>0 at an earlier version and blocked=0
   at every version since, **When** it's reported, **Then** an independent
   agent has live-reproduced the before/after behavior itself and identified
   the source-level change responsible, before it's filed as a confirmed
   regression.
3. **Given** a single-version 1-of-N flicker with 0 everywhere else, **When**
   classifying, **Then** it is NOT reported as a confirmed regression without
   distinguishing it from a sustained, multi-version drop — isolated blips
   are noise-prone (non-deterministic guard-internal behavior) and are noted
   separately, not conflated with real regressions.

See `specs/001-guard-adversarial-hardening/tasks.md` Phase 5 (2026-07-20) for
this methodology's first full run: 137 npm / 133 Python failing
threat-groups bisected across all 50/36 historical versions; 135/132
confirmed as long-standing gaps, exactly one confirmed regression
(issue #19).

### Edge Cases

- What happens when a GitHub issue's state (open/closed) and this repo's
  `tasks.md` disagree? `tasks.md` is a snapshot as of its last edit, not a
  live query — a session picking up work MUST reconcile against `gh issue
  list --state all` at the start of a work session and correct `tasks.md` if
  it's stale, per Development Workflow in the constitution.
- How does the process handle a fix that's "partially" done (some of an
  issue's scope fixed, some reverted after adversarial review)? Recorded
  as-is in tasks.md with the specific residual gap named, not rounded up to
  "done" or down to "not done."
- What happens when npm and Python diverge (a fix applies to one but not the
  other)? Each repo's tasks.md records its own state; cross-repo parity
  status is called out explicitly per Constitution Principle VI, not assumed.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Every guard-hardening session MUST reconcile `tasks.md` against
  live GitHub issue/PR state at session start if picking up prior work.
- **FR-002**: Every merged PR that fixes a filed issue MUST reference
  `Closes #N` for each issue it resolves (Constitution Principle V).
- **FR-003**: Every detection-pattern fix MUST pass an independent
  adversarial-review pass before being considered complete (Constitution
  Principle I).
- **FR-004**: Every guard touched by a fix batch MUST have corresponding
  coverage in that guard's permanent adversarial-sweep test file
  (`tests/guard-adversarial-sweep.test.ts` for npm), not just a one-off
  regression test for the literal reported case (Constitution Principle III).
- **FR-005**: `tasks.md` MUST record known, intentionally-unfixed gaps (not
  just fixed ones) with the reason they were left open, so "not fixed" is
  distinguishable from "not yet investigated."
- **FR-006**: Merging and releasing MUST remain separate, explicitly-approved
  steps from implementing and testing a fix (Constitution Principle VII).

### Key Entities

- **Guard Issue**: A filed GitHub issue describing a detection gap in a
  specific guard. States: open (unfixed) → fixed-unmerged (PR open) →
  merged (on `main`, unreleased) → released (published, issue closed).
- **Adversarial-Sweep Test File**: Permanent, curated benign/attack test
  coverage per guard (`tests/guard-adversarial-sweep.test.ts` for npm),
  distinct from one-off regression tests — this is what's meant to prevent
  the next session from rediscovering an already-fixed class of bug.
- **Fix Batch**: A set of related guard fixes shipped together as one PR,
  tracked as one unit in `tasks.md` even though it may reference multiple
  GitHub issues with different individual statuses.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of merged guard-fix PRs from this point forward reference
  the issues they close via `Closes #N`.
- **SC-002**: Every guard touched by a fix batch from this point forward has
  a corresponding entry in that guard's permanent adversarial-sweep test file.
- **SC-003**: A fresh session reading `tasks.md` alone (no chat history) can
  correctly answer "what's currently open, what's fixed-but-unreleased, and
  what's released" for every known guard issue.
- **SC-004**: Zero instances, going forward, of a "fixed and released"
  session summary being contradicted by a later session's findings without
  an intervening `tasks.md` update explaining what changed.

## Assumptions

- This spec documents an ongoing practice/process, not a one-time feature
  with a completion date — `Status: In Progress` is expected to remain
  accurate indefinitely, unlike a typical feature spec that reaches `Done`.
- The Python sibling repo (`llm-trust-guard-python`) maintains its own
  mirrored spec at the same path (`specs/001-guard-adversarial-hardening/`)
  rather than sharing this one, since the two repos have independent
  release cycles and issue trackers (Constitution Principle VI).
- `/speckit-implement` is not used to execute this spec's "tasks" the way a
  normal feature's tasks.md would be executed — the tasks here are a status
  ledger for work that happens through the guard-hardening workflow
  described in the constitution, not a queue to be mechanically worked
  through by `/speckit-implement`.
