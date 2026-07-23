import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

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
 * Every `pattern:`/bare `const X = /.../ ` regex literal in src/ is
 * extracted (not a hand-maintained list — new files/patterns are picked up
 * automatically) and stress-tested against the seed corpus that actually
 * found all 43 real bugs across the multiple escalating rounds this
 * session. The 500ms budget is generous versus the ~100ms threshold used
 * interactively (every pattern fixed this session now completes in
 * single-digit ms) specifically to avoid flakiness on slower/shared CI
 * runners — this is a tripwire for a real regression, not a tight perf gate.
 */

const SRC_DIR = path.join(__dirname, "..", "src");
const TIME_BUDGET_MS = 500;

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

function extractPatterns(): ExtractedPattern[] {
  const patterns: ExtractedPattern[] = [];
  const literalRe = /\/(?:[^/\\\n]|\\.)+\/[a-z]*/g;
  for (const file of walk(SRC_DIR)) {
    const src = fs.readFileSync(file, "utf8");
    const relFile = path.relative(path.join(__dirname, ".."), file);
    // `pattern:` object properties (the overwhelming majority of guard rules)
    const propRe = /pattern:\s*(\/(?:[^/\\\n]|\\.)+\/[a-z]*)/g;
    let m: RegExpExecArray | null;
    while ((m = propRe.exec(src))) {
      try {
        patterns.push({ file: relFile, source: m[1], regex: eval(m[1]) });
      } catch {
        /* not a valid standalone regex literal (e.g. spans a template) — skip */
      }
    }
    // bare `const X = /.../;` module-level regex constants (e.g. output-guard.ts's MARKDOWN_IMAGE)
    const constRe = /^const\s+[A-Z][A-Z0-9_]*\s*=\s*(\/(?:[^/\\\n]|\\.)+\/[a-z]*);/gm;
    while ((m = constRe.exec(src))) {
      try {
        patterns.push({ file: relFile, source: m[1], regex: eval(m[1]) });
      } catch {
        /* skip */
      }
    }
  }
  // De-dupe identical (file, source) pairs extracted by both passes.
  const seen = new Set<string>();
  return patterns.filter(p => {
    const key = `${p.file}::${p.source}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// The exact adversarial seed corpus that found all 43 real bugs this
// session, across three escalating rounds of stress-testing.
function buildSeeds(): string[] {
  const badChars = ["a", ".", "%", "0", "A", "x", " ", "-", "[", "!", "#", "=", ":", "{", "_", "@", "$", "/", "\t"];
  const seeds = badChars.map(c => c.repeat(50000));
  seeds.push(
    "a.".repeat(25000),
    "a%20".repeat(12000),
    "<".repeat(25000) + ">".repeat(25000),
    "![".repeat(20000),
    "<!--".repeat(15000),
    "AAAA-".repeat(12000),
    "a_1".repeat(16666),
    "x-y-z-".repeat(10000),
    "\n".repeat(50000),
    "User: ".repeat(8000)
  );
  return seeds;
}

describe("ReDoS safety sweep (every regex in src/)", () => {
  const patterns = extractPatterns();
  const seeds = buildSeeds();

  it("extracted a non-trivial number of patterns (sanity check the extractor itself still works)", () => {
    // If this ever drops to ~0, the extraction regexes above have drifted
    // from the guards' actual pattern-declaration style and are silently
    // testing nothing — fail loudly rather than pass vacuously.
    expect(patterns.length).toBeGreaterThan(100);
  });

  it(`no pattern takes longer than ${TIME_BUDGET_MS}ms against any seed in the adversarial corpus`, () => {
    const violations: string[] = [];
    for (const { file, source, regex } of patterns) {
      for (const seed of seeds) {
        const start = Date.now();
        try {
          regex.test(seed);
        } catch {
          /* some patterns may legitimately throw on certain input shapes — not a ReDoS concern */
        }
        const ms = Date.now() - start;
        if (ms > TIME_BUDGET_MS) {
          violations.push(`${file} :: ${source.slice(0, 80)} :: ${ms}ms (seed length ${seed.length})`);
        }
      }
    }
    expect(violations, `Slow (possibly catastrophic-backtracking) patterns found:\n${violations.join("\n")}`).toEqual([]);
  });
});
