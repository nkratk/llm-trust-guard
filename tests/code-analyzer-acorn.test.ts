import { describe, it, expect } from "vitest";
import { CodeExecutionGuard } from "../src/guards/code-execution-guard";
import { acornCodeAnalyzer } from "../examples/acorn-code-analyzer";

/**
 * Reference acorn (AST) backend — proves it catches JS sandbox-escape gadgets the
 * regex-only guard misses, with no false positives on benign code.
 */
const ESCAPE_GADGETS = [
  "this.constructor.constructor('return process')()",
  "[].constructor.constructor('return this')()",
  "Function('return process')()",
];

const BENIGN = [
  "const x = [1, 2, 3].map((n) => n * 2);",
  "function greet(name) { return 'hi ' + name; }",
  "const o = { a: 1 }; console.log(o.a);",
  "const p = import('./feature.js');", // dynamic import is advisory only -> allowed
];

describe("acorn CodeAnalyzerBackend (reference)", () => {
  it("regex-only misses these JS escape gadgets", () => {
    const guard = new CodeExecutionGuard();
    const missed = ESCAPE_GADGETS.filter((c) => guard.analyze(c, "javascript").allowed);
    expect(missed.length).toBe(ESCAPE_GADGETS.length);
  });

  it("with the acorn backend, every escape gadget is blocked", () => {
    const guard = new CodeExecutionGuard({ analyzerBackend: acornCodeAnalyzer });
    for (const c of ESCAPE_GADGETS) {
      expect(guard.analyze(c, "javascript").allowed, c).toBe(false);
    }
  });

  it("benign JS stays allowed (no false positives)", () => {
    const guard = new CodeExecutionGuard({ analyzerBackend: acornCodeAnalyzer });
    for (const c of BENIGN) {
      expect(guard.analyze(c, "javascript").allowed, c).toBe(true);
    }
  });
});
