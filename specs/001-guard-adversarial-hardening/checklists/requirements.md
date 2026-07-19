# Spec Quality Checklist: Guard Adversarial Hardening

**Purpose**: Validate that spec.md is complete, unambiguous, and grounded in
real (not hypothetical) incidents before treating it as ratified.
**Created**: 2026-07-19
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] CHK001 Every user story traces to a specific, cited incident (not a
  generic "as a maintainer, I want X" without evidence) — see spec.md's
  "Why this priority" fields, each of which names the actual date and bug.
- [x] CHK002 Success criteria are measurable, not aspirational ("100% of
  merged PRs reference Closes #N" is checkable; "PRs should be good" is not).
- [x] CHK003 The spec explicitly documents that this is an ongoing-process
  spec, not a one-time feature — Status stays "In Progress" by design; a
  future session should not treat an unchanged Status as staleness.

## Requirement Completeness

- [x] CHK004 Every functional requirement (FR-001 through FR-006) maps to a
  constitution principle, so spec and constitution can't silently diverge.
- [x] CHK005 Edge cases address the actual failure modes already observed
  (tasks.md/GitHub drift, partial fixes, npm/Python divergence) rather than
  generic placeholders.

## Feature Readiness

- [x] CHK006 tasks.md was populated from a live `gh issue list` /
  `gh pr view` / `npm view` reconciliation at write time (2026-07-19), not
  from memory — see tasks.md's "Last reconciled against live state" line.
- [x] CHK007 tasks.md distinguishes fully-fixed, partially-fixed, and
  not-fixed issues rather than rounding every touched issue up to "done."

## Notes

- This checklist itself is a template for future spec-kit specs in this
  repo: validate against live state, cite real incidents, and keep the
  ongoing-process framing explicit when a spec documents a practice rather
  than a shippable feature.
- Reconciliation performed 2026-07-19: `gh issue list --repo nkratk/llm-trust-guard
  --state open` → 12 open (#5-#16); `gh pr view 17` → OPEN, not merged;
  `npm view llm-trust-guard version` → 4.32.3 (pre-batch-#2). All matched
  the state already recorded in prior session memory — no drift found this
  time, which is itself worth noting as evidence the discipline is working
  before spec-kit was even fully wired in.
