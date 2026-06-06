import { describe, it } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { InputSanitizer } from "../../src/guards/input-sanitizer";
import { EncodingDetector } from "../../src/guards/encoding-detector";

/**
 * WildChat-1M FPR measurement (Pipeline A = Sanitizer + Encoder), mirroring
 * tests/adversarial/wildchat-fpr.ts. Prints the raw block rate so the
 * before/after delta around the benign-context suppression change is
 * reproducible via the standard vitest runner. Always passes — read the console
 * output. Skips cleanly when the LFS fixture is absent or unresolved (CI without
 * `git lfs pull`).
 */
const SAMPLE =
  process.env.WILDCHAT_SAMPLE ||
  path.join(process.cwd(), "tests/adversarial/fixtures/wildchat-sample10k.jsonl");

describe("WildChat FPR measurement", () => {
  it("reports Pipeline A raw block rate", () => {
    if (!fs.existsSync(SAMPLE)) {
      console.log(`[wildchat] sample not found at ${SAMPLE} — skipping`);
      return;
    }
    let rows: Array<{ content: string; language: string }>;
    try {
      rows = fs
        .readFileSync(SAMPLE, "utf-8")
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l));
    } catch {
      console.log(
        `[wildchat] ${SAMPLE} is empty or an unresolved LFS pointer — skipping`
      );
      return;
    }
    if (rows.length < 100) {
      console.log(`[wildchat] only ${rows.length} rows — skipping`);
      return;
    }

    const sanitizer = new InputSanitizer({ threshold: 0.3, detectPAP: true });
    const encoder = new EncodingDetector();
    let blocked = 0;
    const perLang: Record<string, { n: number; b: number }> = {};
    for (const r of rows) {
      const lang = r.language || "unknown";
      (perLang[lang] ??= { n: 0, b: 0 }).n++;
      let block = false;
      try {
        block =
          !sanitizer.sanitize(r.content).allowed ||
          !encoder.detect(r.content).allowed;
      } catch {
        block = false;
      }
      if (block) {
        blocked++;
        perLang[lang].b++;
      }
    }
    const fpr = ((blocked / rows.length) * 100).toFixed(2);
    console.log(
      `[wildchat] n=${rows.length} Pipeline A blocked=${blocked} FPR=${fpr}%`
    );
    const top = Object.entries(perLang)
      .sort((a, b) => b[1].n - a[1].n)
      .slice(0, 6);
    for (const [lang, s] of top) {
      console.log(
        `  ${lang}: ${s.b}/${s.n} (${((s.b / s.n) * 100).toFixed(2)}%)`
      );
    }
  });
});
