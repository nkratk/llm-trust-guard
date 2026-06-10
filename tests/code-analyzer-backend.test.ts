import { describe, it, expect } from "vitest";
import { CodeExecutionGuard, CodeAnalyzerBackend } from "../src/guards/code-execution-guard";

/**
 * Zero-dependency wiring tests for the pluggable CodeAnalyzerBackend seam
 * (mock backend, no parser needed). The acorn reference is exercised separately
 * in code-analyzer-acorn.test.ts.
 */
describe("CodeAnalyzerBackend wiring", () => {
  it("default (no backend) leaves behavior unchanged — benign JS allowed", () => {
    expect(new CodeExecutionGuard().analyze("const x = 1 + 2;", "javascript").allowed).toBe(true);
  });

  it("backend findings are additive and can block", () => {
    const backend: CodeAnalyzerBackend = () => [{ name: "gadget", severity: 60 }];
    const r = new CodeExecutionGuard({ analyzerBackend: backend }).analyze("const x = 1;", "javascript");
    expect(r.allowed).toBe(false);
    expect(r.violations).toContain("analyzer_gadget");
  });

  it("a low-severity finding does not block on its own", () => {
    const backend: CodeAnalyzerBackend = () => [{ name: "lo", severity: 10 }];
    expect(new CodeExecutionGuard({ analyzerBackend: backend }).analyze("const x = 1;", "javascript").allowed).toBe(true);
  });

  it("dedupes repeated finding names", () => {
    const backend: CodeAnalyzerBackend = () => [
      { name: "dup", severity: 30 },
      { name: "dup", severity: 30 },
    ];
    const r = new CodeExecutionGuard({ analyzerBackend: backend }).analyze("const x=1;", "javascript");
    expect(r.violations.filter((v) => v === "analyzer_dup")).toHaveLength(1);
  });

  it("a throwing backend never crashes the guard", () => {
    const backend: CodeAnalyzerBackend = () => {
      throw new Error("boom");
    };
    const guard = new CodeExecutionGuard({ analyzerBackend: backend });
    expect(() => guard.analyze("const x=1;", "javascript")).not.toThrow();
    expect(guard.analyze("const x=1;", "javascript").allowed).toBe(true);
  });

  it("setAnalyzerBackend registers a backend at runtime", () => {
    const guard = new CodeExecutionGuard();
    expect(guard.analyze("const x=1;", "javascript").allowed).toBe(true);
    guard.setAnalyzerBackend(() => [{ name: "rt", severity: 60 }]);
    expect(guard.analyze("const x=1;", "javascript").allowed).toBe(false);
  });
});
