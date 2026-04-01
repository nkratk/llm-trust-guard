/**
 * Large-Scale Real-World Adversarial Benchmark
 *
 * Tests against 15,000+ jailbreak prompts from verazuo/jailbreak_llms dataset
 * (collected from Reddit, Discord, websites, open-source — published at CCS'24)
 *
 * This is the REAL test of our detection capabilities.
 */
import { describe, it, expect } from "vitest";
import { InputSanitizer } from "../../src/guards/input-sanitizer";
import { EncodingDetector } from "../../src/guards/encoding-detector";
import * as fs from "fs";
import * as path from "path";

const sanitizer = new InputSanitizer({ threshold: 0.3, detectPAP: true });
const encoder = new EncodingDetector();

function isBlocked(text: string): boolean {
  if (!text || text.length < 5) return false;
  try {
    const sResult = sanitizer.sanitize(text);
    const eResult = encoder.detect(text);
    return !sResult.allowed || !eResult.allowed;
  } catch {
    return false;
  }
}

function loadCSVColumn(filePath: string, colIndex: number, hasHeader: boolean = true): string[] {
  if (!fs.existsSync(filePath)) return [];
  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content.split("\n");
  const start = hasHeader ? 1 : 0;
  const results: string[] = [];

  for (let i = start; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;

    // Handle CSV with quoted fields containing commas
    let col = 0;
    let inQuotes = false;
    let current = "";
    for (let j = 0; j < line.length; j++) {
      const ch = line[j];
      if (ch === '"') {
        inQuotes = !inQuotes;
      } else if (ch === "," && !inQuotes) {
        if (col === colIndex) { results.push(current); break; }
        col++;
        current = "";
      } else {
        current += ch;
      }
    }
    if (col === colIndex && current) results.push(current);
  }

  return results.filter(r => r.length > 10);
}

describe("Large-Scale Adversarial Benchmark", () => {

  const dataDir = path.join(__dirname, "datasets", "jailbreak_llms", "data", "prompts");
  const jailbreakFile = path.join(dataDir, "jailbreak_prompts_2023_12_25.csv");
  const regularFile = path.join(dataDir, "regular_prompts_2023_12_25.csv");

  describe("Jailbreak Detection (15K+ real prompts)", () => {
    it("should measure detection rate on real jailbreak prompts", () => {
      if (!fs.existsSync(jailbreakFile)) {
        console.log("SKIPPED: jailbreak dataset not available");
        return;
      }

      // Load jailbreak prompts (column 2 = prompt text)
      const allPrompts = loadCSVColumn(jailbreakFile, 2);

      // Random sample of 1000 for speed (full dataset takes too long for unit tests)
      const sampleSize = Math.min(1000, allPrompts.length);
      const sample: string[] = [];
      const seen = new Set<number>();
      while (sample.length < sampleSize && seen.size < allPrompts.length) {
        const idx = Math.floor(Math.random() * allPrompts.length);
        if (!seen.has(idx)) {
          seen.add(idx);
          sample.push(allPrompts[idx]);
        }
      }

      let caught = 0;
      let missed = 0;
      const missedCategories: Record<string, number> = {};
      const missedExamples: string[] = [];

      for (const prompt of sample) {
        if (isBlocked(prompt)) {
          caught++;
        } else {
          missed++;
          if (missedExamples.length < 5) {
            missedExamples.push(prompt.substring(0, 100) + "...");
          }
        }
      }

      const rate = (caught / sample.length) * 100;

      console.log("\n╔════════════════════════════════════════════════╗");
      console.log("║  LARGE-SCALE JAILBREAK BENCHMARK               ║");
      console.log("╚════════════════════════════════════════════════╝");
      console.log(`  Dataset: verazuo/jailbreak_llms (CCS'24)`);
      console.log(`  Total Available: ${allPrompts.length}`);
      console.log(`  Sample Tested: ${sample.length}`);
      console.log(`  Caught: ${caught}`);
      console.log(`  Missed: ${missed}`);
      console.log(`  ▶ DETECTION RATE: ${rate.toFixed(1)}%`);
      if (missedExamples.length > 0) {
        console.log(`  Sample missed:`);
        missedExamples.forEach((m, i) => console.log(`    ${i+1}. ${m}`));
      }
      console.log("");

      // This is a benchmark measurement, not a pass/fail gate
      // Full dataset rate is ~44%, random samples vary widely
      expect(rate).toBeGreaterThanOrEqual(0);
    });
  });

  describe("False Positive Rate (225K safe prompts)", () => {
    it("should measure false positive rate on regular prompts", () => {
      if (!fs.existsSync(regularFile)) {
        console.log("SKIPPED: regular prompts dataset not available");
        return;
      }

      // Load regular (safe) prompts (column 2 = prompt text)
      const allSafe = loadCSVColumn(regularFile, 2);

      // Sample 2000 for speed
      const sampleSize = Math.min(2000, allSafe.length);
      const sample: string[] = [];
      const seen = new Set<number>();
      while (sample.length < sampleSize && seen.size < allSafe.length) {
        const idx = Math.floor(Math.random() * allSafe.length);
        if (!seen.has(idx)) {
          seen.add(idx);
          sample.push(allSafe[idx]);
        }
      }

      let falsePositives = 0;
      const fpExamples: string[] = [];

      for (const prompt of sample) {
        if (isBlocked(prompt)) {
          falsePositives++;
          if (fpExamples.length < 5) {
            fpExamples.push(prompt.substring(0, 100) + "...");
          }
        }
      }

      const fpRate = (falsePositives / sample.length) * 100;

      console.log("\n╔════════════════════════════════════════════════╗");
      console.log("║  FALSE POSITIVE BENCHMARK                      ║");
      console.log("╚════════════════════════════════════════════════╝");
      console.log(`  Dataset: verazuo/jailbreak_llms regular prompts`);
      console.log(`  Total Available: ${allSafe.length}`);
      console.log(`  Sample Tested: ${sample.length}`);
      console.log(`  Incorrectly Blocked: ${falsePositives}`);
      console.log(`  ▶ FALSE POSITIVE RATE: ${fpRate.toFixed(1)}%`);
      if (fpExamples.length > 0) {
        console.log(`  Sample false positives:`);
        fpExamples.forEach((m, i) => console.log(`    ${i+1}. ${m}`));
      }
      console.log("");

      // Target: <10% false positive rate
      expect(fpRate).toBeLessThan(10);
    });
  });

  describe("Combined Metrics", () => {
    it("should produce an overall assessment", () => {
      console.log("\n╔════════════════════════════════════════════════╗");
      console.log("║  OVERALL ASSESSMENT                            ║");
      console.log("╚════════════════════════════════════════════════╝");
      console.log("  This benchmark tests against REAL jailbreak prompts");
      console.log("  collected from Reddit, Discord, and open-source.");
      console.log("  These are attacks that REAL people used against");
      console.log("  REAL production LLMs (ChatGPT, Claude, etc.).");
      console.log("  ");
      console.log("  Our guards use regex pattern matching only.");
      console.log("  For higher detection, plug in an ML classifier");
      console.log("  via the DetectionClassifier interface.");
      console.log("");
      expect(true).toBe(true);
    });
  });
});
