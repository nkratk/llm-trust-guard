import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { InputSanitizer } from "../../src/guards/input-sanitizer";
import { EncodingDetector } from "../../src/guards/encoding-detector";

/**
 * WildChat-1M FPR REGRESSION gate (Pipeline A = Sanitizer + Encoder).
 *
 * Measures the raw block count on the committed WildChat fixture and ASSERTS it
 * does not exceed the locked baseline (tests/adversarial/baseline.json). This is
 * the anti-regression backbone: any change that raises the false-positive rate on
 * real consumer traffic fails the build. Skips cleanly when the LFS fixture is
 * absent or unresolved (CI without `git lfs pull`).
 *
 * Mirrors tests/adversarial/wildchat-fpr.ts (same pipeline + config).
 */
const SAMPLE =
  process.env.WILDCHAT_SAMPLE ||
  path.join(process.cwd(), "tests/adversarial/fixtures/wildchat-sample10k.jsonl");
const BASELINE = path.join(process.cwd(), "tests/adversarial/baseline.json");

function loadRows(): Array<{ content: string; language: string }> | null {
  if (!fs.existsSync(SAMPLE)) return null;
  try {
    const rows = fs
      .readFileSync(SAMPLE, "utf-8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    return rows.length >= 100 ? rows : null;
  } catch {
    return null; // unresolved LFS pointer or malformed
  }
}

describe("WildChat FPR regression gate", () => {
  it("Pipeline A block count does not exceed the locked baseline", () => {
    const rows = loadRows();
    if (!rows) {
      console.log(
        `[wildchat] fixture missing/unresolved at ${SAMPLE} — skipping (run \`git lfs pull\`)`
      );
      return;
    }
    const baseline = JSON.parse(fs.readFileSync(BASELINE, "utf-8"));
    const sanitizer = new InputSanitizer({ threshold: 0.3, detectPAP: true });
    const encoder = new EncodingDetector();

    let blocked = 0;
    for (const r of rows) {
      let block = false;
      try {
        block =
          !sanitizer.sanitize(r.content).allowed ||
          !encoder.detect(r.content).allowed;
      } catch {
        block = false;
      }
      if (block) blocked++;
    }
    const fpr = ((blocked / rows.length) * 100).toFixed(2);
    console.log(
      `[wildchat] n=${rows.length} blocked=${blocked} FPR=${fpr}% | baseline=${baseline.pipelineA.blocked}`
    );
    expect(
      blocked,
      `Pipeline A FP regression: ${blocked} blocked vs baseline ${baseline.pipelineA.blocked}. ` +
        `If intentional, update baseline.json with a RESULTS-v<ver>.md justification.`
    ).toBeLessThanOrEqual(baseline.pipelineA.blocked);
  });
});
