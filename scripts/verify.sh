#!/usr/bin/env bash
#
# Eval-gated verification — run before every push. See VERIFICATION.md.
# Exits non-zero if any blocking gate fails. CI and the .githooks/pre-push hook
# both call this script, so "it passed locally" and "it passed in CI" mean the
# same thing.
#
set -uo pipefail
cd "$(dirname "$0")/.." # repo root

FAILED=0
hr() { printf '%s\n' "────────────────────────────────────────────────────────"; }

gate() { # gate "Name" <command...>
  local name="$1"; shift
  hr; echo "▶ $name"
  if "$@"; then echo "  ✓ PASS — $name"; else echo "  ✗ FAIL — $name"; FAILED=1; fi
}

soft_gate() { # non-blocking
  local name="$1"; shift
  hr; echo "▶ $name (non-blocking)"
  if "$@" >/tmp/verify_soft.log 2>&1; then echo "  ✓ PASS — $name"; else echo "  ! WARN — $name (see issues; not blocking)"; fi
}

# ── G1: build / typecheck
gate "G1 build/typecheck" npm run build --silent

# ── G2: lint (non-blocking, mirrors CI)
soft_gate "G2 lint" npm run lint --silent

# ── G3 + G4 + G5: full suite with coverage thresholds.
# The suite includes the WildChat regression gate (wildchat-regression.test.ts),
# the curated benign probe and the adversarial bypass probe (benign-context.test.ts),
# and the coverage thresholds in vitest.config.ts.
gate "G3+G4+G5 tests + coverage + regression" npx vitest run --coverage

# ── G9: patch coverage — CHANGED src lines (since last tag) must be covered.
# Enforced in CI; degrades to a skip locally if diff-cover isn't installed.
patch_cov() {
  local dc=""
  if python3 -m diff_cover.diff_cover_tool --version >/dev/null 2>&1; then dc="python3 -m diff_cover.diff_cover_tool"
  elif command -v diff-cover >/dev/null 2>&1; then dc="diff-cover"
  else echo "  diff-cover not installed — skipping locally (CI enforces). pip install diff-cover"; return 0; fi
  local tag; tag=$(git describe --tags --abbrev=0 2>/dev/null) || { echo "  no tag — skipping"; return 0; }
  [ -f coverage/lcov.info ] || { echo "  coverage/lcov.info missing"; return 1; }
  $dc coverage/lcov.info --compare-branch "$tag" --fail-under "${PATCH_COV_MIN:-80}"
}
gate "G9 patch coverage (changed src lines >=${PATCH_COV_MIN:-80}%)" patch_cov

# ── G6: new code must ship with tests (hard gate; override ALLOW_NO_TESTS=1)
gate "G6 new code has tests" bash -c '
  tag=$(git describe --tags --abbrev=0 2>/dev/null) || { echo "  no tag yet — skipping G6"; exit 0; }
  changed=$( { git diff --name-only "$tag" --; git ls-files --others --exclude-standard; } | sort -u )
  src=$(echo "$changed" | grep -E "^src/" || true)
  tst=$(echo "$changed" | grep -E "^tests/" || true)
  if [ -n "$src" ] && [ -z "$tst" ]; then
    if [ "${ALLOW_NO_TESTS:-0}" = "1" ]; then echo "  src/ changed without tests/, but ALLOW_NO_TESTS=1"; exit 0; fi
    echo "  src/ changed since $tag but no tests/ change:"; echo "$src" | sed "s/^/    /"
    echo "  Add a test, or re-run with ALLOW_NO_TESTS=1 if this is a pure refactor/doc change."
    exit 1
  fi
  echo "  ok (changed since $tag)"; exit 0'

# ── G11: public API changed since last tag ⇒ README must change too
# (closes the "docs drift" gap; override ALLOW_NO_README_UPDATE=1).
gate "G11 README documents API changes" bash -c '
  tag=$(git describe --tags --abbrev=0 2>/dev/null) || { echo "  no tag yet — skipping G11"; exit 0; }
  changed=$( { git diff --name-only "$tag" --; git ls-files --others --exclude-standard; } | sort -u )
  api=$(echo "$changed" | grep -E "^src/index\.ts$" || true)
  readme=$(echo "$changed" | grep -E "^README\.md$" || true)
  if [ -n "$api" ] && [ -z "$readme" ]; then
    if [ "${ALLOW_NO_README_UPDATE:-0}" = "1" ]; then echo "  public API changed without README, but ALLOW_NO_README_UPDATE=1"; exit 0; fi
    echo "  src/index.ts (public exports) changed since $tag but README.md did not."
    echo "  Document the new/changed API, or re-run with ALLOW_NO_README_UPDATE=1 for a non-API export tweak."
    exit 1
  fi
  echo "  ok"; exit 0'

# ── G7: CHANGELOG top version == package version
gate "G7 changelog matches version" bash -c '
  pv=$(node -p "require(\"./package.json\").version")
  cv=$(grep -m1 -oE "## \[[0-9]+\.[0-9]+\.[0-9]+\]" CHANGELOG.md | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
  echo "  package.json=$pv  CHANGELOG=$cv"
  if git rev-parse "v$pv" >/dev/null 2>&1; then echo "  note: v$pv already tagged (post-release commits)"; fi
  [ "$pv" = "$cv" ]'

# ── G8: published results doc exists for this version
gate "G8 results doc present" bash -c '
  pv=$(node -p "require(\"./package.json\").version")
  f="tests/adversarial/RESULTS-v$pv.md"
  echo "  expecting $f"
  test -f "$f"'

# ── G10: freshness — research re-check cadence not lapsed (date-only, no network).
# The weekly freshness workflow does the active link/standards re-scan.
gate "G10 freshness (re-check cadence)" python3 scripts/check-freshness.py

hr
if [ "$FAILED" = "0" ]; then
  echo "✅ verify: ALL GATES PASSED"
else
  echo "❌ verify: ONE OR MORE GATES FAILED — push is not allowed"
fi
exit $FAILED
