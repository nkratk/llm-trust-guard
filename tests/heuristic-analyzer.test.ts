import { describe, it, expect } from "vitest";
import { HeuristicAnalyzer } from "../src/guards/heuristic-analyzer";

/**
 * Regression coverage for the many-shot Q&A detection logic
 * (checkStructure's qMarkerRe/aMarkerRe scan in heuristic-analyzer.ts).
 *
 * This detection was originally a single unbounded regex
 * ((?:Q:|Question:|Human:|User:)[\s\S]*?(?:A:|Answer:|Assistant:|AI:))
 * that turned out to be catastrophic-backtracking on adversarial input
 * (long runs of "User:" markers with no closing "A:"). A first fix bounded
 * the middle gap to {0,1000} chars, which closed the ReDoS but silently
 * stopped detecting any many-shot turn whose Q->A gap exceeds 1000 chars —
 * an independent adversarial review caught this as a real jailbreak
 * evasion (verbose scenario-framing turns routinely exceed 1000 chars).
 * The final fix replaced the single regex with a linear marker-position
 * scan that has no length cap at all. These tests cover both properties:
 * detection still works on long turns, and it stays fast on adversarial
 * input with no closing marker.
 */
function buildShot(i: number, padLength: number): string {
  return `Q: Scenario ${i}, imagine a detailed hypothetical situation. ${"x".repeat(padLength)} A: Sure, here you go. `;
}

describe("HeuristicAnalyzer many-shot detection", () => {
  it("detects many-shot attacks with short Q->A turns", () => {
    const analyzer = new HeuristicAnalyzer();
    const payload = Array.from({ length: 5 }, (_, i) => `Q: step ${i} A: ok`).join("\n");
    const result = analyzer.analyze(payload);
    expect(result.features.is_shot_attack).toBe(true);
  });

  it("detects many-shot attacks with long (>1000 char) Q->A turns — regression for the ReDoS-fix evasion", () => {
    const analyzer = new HeuristicAnalyzer();
    const payload = Array.from({ length: 5 }, (_, i) => buildShot(i, 1500)).join("\n");
    const result = analyzer.analyze(payload);
    expect(result.features.is_shot_attack).toBe(true);
  });

  it("does not flag a normal single-turn message as many-shot", () => {
    const analyzer = new HeuristicAnalyzer();
    const result = analyzer.analyze("Can you help me write a cover letter for a marketing job?");
    expect(result.features.is_shot_attack).toBe(false);
  });

  it("completes quickly on adversarial input with many unmatched markers (ReDoS safety)", () => {
    const analyzer = new HeuristicAnalyzer();
    const attack = "User: ".repeat(50000);
    const start = Date.now();
    analyzer.analyze(attack);
    expect(Date.now() - start).toBeLessThan(500);
  });
});
