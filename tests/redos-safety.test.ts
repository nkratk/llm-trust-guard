import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as ts from "typescript";

/**
 * Permanent ReDoS (catastrophic-backtracking) safety net.
 *
 * Born from the v4.32.5 fix batch: an empirical stress-test sweep (written
 * as a one-off script, run manually, three separate times as its scope kept
 * growing) found and fixed 43 catastrophic-backtracking regexes across both
 * this repo and the Python sibling — including one the decode/normalize fix
 * in that same release turned into a trivially-reachable multi-second DoS.
 * That sweep is now this permanent test, so a NEW regex added later gets
 * the same scrutiny automatically instead of relying on someone remembering
 * to re-run a throwaway script.
 *
 * Every regex literal in src/ is extracted via the TypeScript compiler's own
 * AST (`ts.createSourceFile` + a walk for `RegularExpressionLiteral` nodes) —
 * not a hand-maintained list, and not a regex-based text scanner keyed off a
 * specific declaration shape. An earlier version of this extractor only
 * matched `pattern:` object properties and module-level ALL-CAPS `const`s;
 * an audit found it silently missed ~28% of the real regex literals in
 * src/ (295 of 1052) — local lowercase `const`s (e.g. heuristic-analyzer.ts's
 * `qaPattern`, entirely invisible to the old extractor), regexes passed
 * directly as call arguments, array elements, non-`pattern`-named object
 * properties, and class fields. The AST walk catches all of these uniformly
 * since it doesn't care what syntactic position a `RegularExpressionLiteral`
 * node sits in.
 *
 * `new RegExp(...)` calls are also resolved where statically possible: a
 * plain string/no-substitution template literal, or a template literal
 * whose only substitutions reference a module-level `const NAME = "..."`
 * string constant in the same file (e.g. output-guard.ts's
 * `new RegExp(\`&&\\s*(?:${"${DESTRUCTIVE_SHELL_VERBS}"})\\b\`, "i")`).
 * Calls built from genuinely runtime/per-instance values (e.g.
 * code-execution-guard.ts's blocklist patterns, built from
 * operator-configurable `this.config.blockedImports`) are structurally
 * unresolvable via static analysis and are NOT covered by this test — an
 * earlier version of this docstring overclaimed "every regex literal" as
 * unqualified full coverage; independent review pointed out `new RegExp()`
 * call sites existed that weren't covered at all, some of which (like the
 * output-guard.ts case) turned out to be staticly resolvable after all, so
 * this is now handled where possible and documented honestly where it
 * can't be. Those remaining unresolvable sites are lower risk than a
 * silently-missed static pattern would be: their content comes from
 * operator configuration, not attacker-controlled request data.
 * Extracted patterns are stress-tested against the seed corpus that
 * actually found the real bugs across the multiple escalating rounds of
 * this session.
 *
 * Detection strategy: SCALING RATIO for the structural seeds, not a single
 * absolute-time threshold. This repo's first version of this test used a
 * flat 500ms budget and it false-positived in CI on a legitimately-linear,
 * already-bounded pattern (output-guard.ts's markdown-image-link regex,
 * 669ms on a slower/shared GitHub Actions runner vs ~230ms locally) — a
 * safe-but-slow-constant-factor pattern and a real quadratic bug can land
 * in overlapping absolute-time ranges depending on runner speed alone.
 * Growth ratio between two sizes doesn't have that problem: linear time
 * roughly quadruples for a 4x size step; quadratic time roughly grows 16x.
 * A ratio threshold well below 16x but above the linear ~4x range cleanly
 * separates the two regardless of the runner's absolute speed. (Ported
 * from the Python sibling's tests/test_redos_safety.py, which used this
 * same ratio design from the start for the analogous reason — CPython's
 * slower regex engine hit the same absolute-time ambiguity even sooner.)
 */

const SRC_DIR = path.join(__dirname, "..", "src");
const SMALL_REPS = 4000;
const LARGE_REPS = SMALL_REPS * 4; // 4x size step
const RATIO_THRESHOLD = 8.0; // linear ~4x, quadratic ~16x at a 4x size step; extra margin above 6.0 plus min-of-N sampling absorbs CI runner noise
const MIN_SMALL_MS = 5; // ignore near-zero timings where a ratio is just noise — SMALL_REPS is chosen so a real
// quadratic pattern clears this floor at SMALL_REPS (verified empirically: 2000 reps left ~5ms readings too
// close to the floor to reliably ratio-check on a fast engine; 4000 reps reads ~19ms, well clear of noise)
const ABS_CEILING_MS = 3000; // even a "linear" pattern shouldn't take this long at LARGE_REPS
const SINGLE_CHAR_REPS = 20000;

interface ExtractedPattern {
  file: string;
  source: string;
  regex: RegExp;
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

// Resolves a template literal to a plain string if every substitution is a
// bare identifier reference to a known module-level string constant.
// Returns null if any part can't be statically resolved (a genuinely
// dynamic/runtime value, e.g. `this.config.blockedImports`).
function resolveTemplateLiteral(node: ts.TemplateLiteral, constants: Map<string, string>): string | null {
  if (ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (!ts.isTemplateExpression(node)) return null;
  let out = node.head.text;
  for (const span of node.templateSpans) {
    if (!ts.isIdentifier(span.expression)) return null;
    const resolved = constants.get(span.expression.text);
    if (resolved === undefined) return null;
    out += resolved + span.literal.text;
  }
  return out;
}

function resolveNewRegExpArg(node: ts.Expression, constants: Map<string, string>): string | null {
  if (ts.isStringLiteral(node)) return node.text;
  if (ts.isTemplateLiteral(node)) return resolveTemplateLiteral(node, constants);
  return null;
}

function extractPatterns(): ExtractedPattern[] {
  const patterns: ExtractedPattern[] = [];
  for (const file of walk(SRC_DIR)) {
    const src = fs.readFileSync(file, "utf8");
    const relFile = path.relative(path.join(__dirname, ".."), file);
    const sourceFile = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true);

    // First pass: collect module-level `const NAME = "literal string"`
    // declarations, so a `new RegExp(\`...${NAME}...\`)` template can be
    // statically resolved below.
    const constants = new Map<string, string>();
    for (const stmt of sourceFile.statements) {
      if (!ts.isVariableStatement(stmt)) continue;
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isIdentifier(decl.name) && decl.initializer && ts.isStringLiteral(decl.initializer)) {
          constants.set(decl.name.text, decl.initializer.text);
        }
      }
    }

    const visit = (node: ts.Node) => {
      if (ts.isRegularExpressionLiteral(node)) {
        try {
          patterns.push({ file: relFile, source: node.text, regex: eval(node.text) });
        } catch {
          /* malformed/unsupported regex literal — skip */
        }
      } else if (
        ts.isNewExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === "RegExp" &&
        node.arguments && node.arguments.length > 0
      ) {
        const patternStr = resolveNewRegExpArg(node.arguments[0], constants);
        if (patternStr !== null) {
          const flagsArg = node.arguments[1];
          const flags = flagsArg && ts.isStringLiteral(flagsArg) ? flagsArg.text : "";
          try {
            patterns.push({ file: relFile, source: `new RegExp(${JSON.stringify(patternStr)}, ${JSON.stringify(flags)})`, regex: new RegExp(patternStr, flags) });
          } catch {
            /* invalid pattern/flags once resolved — skip */
          }
        }
        /* else: genuinely dynamic (e.g. built from this.config.*) — not statically resolvable, skip */
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
  }
  // De-dupe identical (file, source) pairs — the same literal can legitimately
  // appear more than once (e.g. shared across multiple guard rule entries).
  const seen = new Set<string>();
  return patterns.filter(p => {
    const key = `${p.file}::${p.source}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// The exact adversarial seed shapes that found all 43 real bugs this
// session, across three escalating rounds of stress-testing. Single
// characters get a fixed, generous size (cheap everywhere, no ratio
// treatment needed — absolute ceiling is a sufficient backstop). The
// structural templates get built at both SMALL_REPS and LARGE_REPS for the
// scaling-ratio check.
const SINGLE_CHARS = ["a", ".", "%", "0", "A", "x", " ", "-", "[", "!", "#", "=", ":", "{", "_", "@", "$", "/", "\t"];
const SEED_TEMPLATES = ["a.", "a%20", "><", "![", "<!--", "AAAA-", "a_1", "x-y-z-", "\n", "User: "];

function timeMsOnce(regex: RegExp, seed: string): number {
  const start = process.hrtime.bigint();
  try {
    regex.lastIndex = 0;
    regex.test(seed);
  } catch {
    /* some patterns may legitimately throw on certain input shapes — not a ReDoS concern */
  }
  return Number(process.hrtime.bigint() - start) / 1e6;
}

const RATIO_SAMPLES = 3;

// Minimum of several samples: a GC pause / scheduler preemption / shared-CI-
// runner contention can only ever inflate a single sample's timing, never
// deflate it below the true cost — so the min across samples is the most
// noise-resistant honest estimate. Found necessary after a legitimately-
// linear, already-bounded pattern (rag-guard.ts's markdown_img_alt_injection)
// landed a single noisy sample at a 7.5x ratio in CI (clean local
// measurement: ~4.4x, consistent with linear scaling at every size tested
// from 4K to 256K chars) — a single-sample ratio check is too fragile
// against shared-runner timing variance for a check this close to a
// threshold boundary.
function timeMsMin(regex: RegExp, seed: string): number {
  let best = Infinity;
  for (let i = 0; i < RATIO_SAMPLES; i++) {
    const ms = timeMsOnce(regex, seed);
    if (ms < best) best = ms;
  }
  return best;
}

describe("ReDoS safety sweep (every regex in src/)", () => {
  const patterns = extractPatterns();

  it("extracted a non-trivial number of patterns (sanity check the extractor itself still works)", () => {
    // If this ever drops sharply, the AST walk has stopped matching this
    // codebase's actual shape and is silently testing far less than it
    // should — fail loudly rather than pass vacuously. (The earlier
    // text-scanning extractor found ~751 regex literals; the AST walk
    // finds all 1052 by also catching call-argument/array-element/
    // local-const literals it missed — see the file docstring.)
    expect(patterns.length).toBeGreaterThan(500);
  });

  it("resolves at least one statically-known new RegExp(...) call (sanity check that resolution path still works)", () => {
    // If this ever drops to 0, the const-resolution logic above has
    // stopped matching this codebase's actual shape (e.g. output-guard.ts's
    // DESTRUCTIVE_SHELL_VERBS-based pattern) and new RegExp() coverage has
    // silently regressed back to zero — fail loudly rather than pass
    // vacuously.
    const resolvedNewRegExp = patterns.filter(p => p.source.startsWith("new RegExp("));
    expect(resolvedNewRegExp.length).toBeGreaterThan(0);
  });

  it("no pattern shows quadratic-or-worse scaling on adversarial input", () => {
    const violations: string[] = [];

    for (const { file, source, regex } of patterns) {
      // Single-character-repeat seeds: absolute ceiling only, single sample
      // (a coarse ceiling check doesn't need noise-resistant timing).
      for (const ch of SINGLE_CHARS) {
        const seed = ch.repeat(SINGLE_CHAR_REPS);
        const ms = timeMsOnce(regex, seed);
        if (ms > ABS_CEILING_MS) {
          violations.push(`${file} :: ${source.slice(0, 80)} :: ${ms.toFixed(0)}ms char=${JSON.stringify(ch)} reps=${SINGLE_CHAR_REPS}`);
        }
      }

      // Structural seeds: scaling-ratio check, min-of-N sampled.
      for (const tmpl of SEED_TEMPLATES) {
        const smallMs = timeMsMin(regex, tmpl.repeat(SMALL_REPS));
        const largeMs = timeMsMin(regex, tmpl.repeat(LARGE_REPS));

        if (largeMs > ABS_CEILING_MS) {
          violations.push(`${file} :: ${source.slice(0, 80)} :: ${largeMs.toFixed(0)}ms (over ${ABS_CEILING_MS}ms ceiling) tmpl=${JSON.stringify(tmpl)} reps=${LARGE_REPS}`);
        } else if (smallMs >= MIN_SMALL_MS) {
          const ratio = largeMs / smallMs;
          if (ratio > RATIO_THRESHOLD) {
            violations.push(
              `${file} :: ${source.slice(0, 80)} :: ${smallMs.toFixed(1)}ms@${SMALL_REPS} -> ${largeMs.toFixed(1)}ms@${LARGE_REPS} ` +
              `(ratio ${ratio.toFixed(1)}x for a 4x size step — quadratic-shaped) tmpl=${JSON.stringify(tmpl)}`
            );
          }
        }
      }
    }

    expect(violations, `Slow / quadratic-shaped (possibly catastrophic-backtracking) patterns found:\n${violations.join("\n")}`).toEqual([]);
  });
});
