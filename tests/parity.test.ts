import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { InputSanitizer } from "../src/guards/input-sanitizer";

/**
 * TS↔Python parity gate.
 *
 * `tests/parity-vectors.json` holds the canonical `allowed` verdict for each
 * input (generated from this TS InputSanitizer). The SAME file ships in the
 * Python package, where `test_parity.py` asserts its InputSanitizer reproduces
 * the same verdicts. Here we assert the TS side stays in sync too — so neither
 * hand-maintained port can silently drift from the locked behavior.
 */
const doc = JSON.parse(
  fs.readFileSync(path.join(process.cwd(), "tests/parity-vectors.json"), "utf-8")
) as { config: { threshold: number; detectPAP: boolean }; vectors: Array<{ input: string; allowed: boolean }> };

describe("TS↔Python parity", () => {
  const s = new InputSanitizer({
    threshold: doc.config.threshold,
    detectPAP: doc.config.detectPAP,
  });

  it("InputSanitizer reproduces every locked verdict", () => {
    const mismatches = doc.vectors
      .filter((v) => s.sanitize(v.input).allowed !== v.allowed)
      .map((v) => ({ input: v.input.slice(0, 60), expected: v.allowed }));
    expect(
      mismatches,
      "InputSanitizer verdicts drifted from the locked parity vectors — regenerate only with justification"
    ).toEqual([]);
  });
});
