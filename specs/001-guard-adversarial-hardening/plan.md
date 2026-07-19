# Implementation Plan: Guard Adversarial Hardening

**Branch**: `main` (ongoing process documentation, not a single feature branch) | **Date**: 2026-07-19 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-guard-adversarial-hardening/spec.md`

## Summary

This is not a code-delivery plan in the usual spec-kit sense — there is no
single artifact to build. It documents the repeatable *process* (methodology
+ tooling + status-tracking convention) for finding and fixing guard
detection gaps, so that process itself becomes durable and legible across
sessions instead of living only in chat memory. The "implementation" is the
workflow described below, already proven across the 2026-07-15 through
2026-07-19 fix batches; this plan formalizes it and `tasks.md` becomes its
living status ledger.

## Technical Context

**Language/Version**: TypeScript (this repo), mirrored in Python in
`llm-trust-guard-python`

**Primary Dependencies**: None at runtime (zero-dependency guard package);
`vitest` for testing, `specify` CLI (spec-kit) for this process itself

**Storage**: N/A — status lives in `tasks.md` (this spec) + GitHub issues/PRs,
reconciled against each other at session start (spec.md FR-001)

**Testing**: `vitest` (`npx vitest run`), plus the permanent adversarial-sweep
file `tests/guard-adversarial-sweep.test.ts`; gate suite `scripts/verify.sh`
(G1-G13)

**Target Platform**: N/A (process/tooling, not a deployed artifact)

**Project Type**: Process documentation + status tracking for an existing
library project

**Performance Goals**: N/A

**Constraints**: Must not disrupt the existing, working guard-hardening
workflow — this formalizes what's already been proven to work, it doesn't
replace it with something unproven.

**Scale/Scope**: Currently tracking 16 known issues across both repos (12 npm
+ 1 npm-format-carrier-unscoped + 1 python, per tasks.md); expected to grow
as live-verify sweeps continue.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Compliance | Notes |
|---|---|---|
| I. Adversarial-test every change, both directions (NON-NEGOTIABLE) | ✅ | This plan doesn't change guard code; the workflow it documents already requires this for every future fix. |
| II. Prefer recall over precision for security patterns | ✅ | N/A to this plan directly; documented as a standing rule future fixes must follow. |
| III. Every fix ships with permanent regression + sweep coverage | ✅ | N/A to this plan directly; documented as a standing rule. |
| IV. Live-verify against the real installed package | ✅ | N/A to this plan directly (no code change); documented as a standing rule. |
| V. Close the loop — merged fixes close their issue | ✅ | This plan's own tasks.md explicitly flags PR #17 as needing `Closes #N` references before merge. |
| VI. npm/Python parity verified live, not assumed | ✅ | tasks.md tracks npm and Python status separately; no parity assumed without evidence. |
| VII. Merge/release always separate from fix | ✅ | tasks.md lists "decide merge/release for PR #17" as a distinct, not-yet-completed task. |

**Verdict**: No violations. This plan documents process, not code — it exists
specifically to make the constitution's principles checkable in future
sessions rather than re-litigated from memory each time.

## Project Structure

### Documentation (this feature)

```text
specs/001-guard-adversarial-hardening/
├── plan.md              # This file
├── spec.md              # Problem statement, user stories, requirements
├── tasks.md             # Living status ledger — READ THIS FIRST in a new session
└── checklists/
    └── requirements.md  # Spec quality checklist
```

### Source Code (repository root)

No new source directories. Existing structure this process operates on:

```text
src/guards/*.ts                          # Guard implementations
tests/*.test.ts                          # Per-guard unit test suites
tests/guard-adversarial-sweep.test.ts    # Permanent adversarial-sweep coverage (this process's key deliverable so far)
tests/adversarial/                       # Corpus-based benchmarks (WildChat FPR gate, recall baseline)
scripts/verify.sh                        # G1-G13 release gate suite
CHANGELOG.md, README.md                  # Must be updated alongside any guard behavior change
```

**Structure Decision**: No structural changes. This plan operates entirely
within the existing repo layout; its only new artifacts are this
`specs/001-guard-adversarial-hardening/` directory itself and (already
delivered, prior to this plan being written) `tests/guard-adversarial-sweep
.test.ts`.

## Complexity Tracking

No constitution violations. Table omitted.
