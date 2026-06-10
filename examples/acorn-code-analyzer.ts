/**
 * Reference `CodeAnalyzerBackend` using acorn (AST).
 *
 * The built-in CodeExecutionGuard is regex-only (zero dependencies). Regex
 * cannot reliably see JS sandbox-escape gadget chains. This backend parses the
 * code with acorn and flags the gadget classes regex misses:
 *
 *   this.constructor.constructor('return process')()   // constructor escape
 *   Function('return process')()                        // Function ctor (no `new`)
 *   import('child_process')                             // dynamic import (advisory)
 *   obj.__proto__                                       // prototype access
 *
 * Usage:
 *   import { CodeExecutionGuard } from 'llm-trust-guard';
 *   import { acornCodeAnalyzer } from './examples/acorn-code-analyzer';
 *   const guard = new CodeExecutionGuard({ analyzerBackend: acornCodeAnalyzer });
 *
 * acorn is a peer of the example, not of the library — install it yourself:
 *   npm i acorn
 */
import { parse } from "acorn";
import type { CodeAnalyzerBackend, CodeFinding } from "../src/guards/code-execution-guard";

/** Minimal ESTree walker — no acorn-walk dependency. */
function walk(node: unknown, visit: (n: Record<string, any>) => void): void {
  if (!node || typeof node !== "object") return;
  const n = node as Record<string, any>;
  if (typeof n.type === "string") visit(n);
  for (const key of Object.keys(n)) {
    const child = n[key];
    if (Array.isArray(child)) child.forEach((c) => walk(c, visit));
    else if (child && typeof child === "object") walk(child, visit);
  }
}

export const acornCodeAnalyzer: CodeAnalyzerBackend = (code, language) => {
  if (language !== "javascript" && language !== "typescript") return [];
  let ast: unknown;
  try {
    ast = parse(code, { ecmaVersion: "latest", sourceType: "module", allowReturnOutsideFunction: true });
  } catch {
    return []; // unparseable — the guard's regex pass still ran
  }

  const findings: CodeFinding[] = [];
  const seen = new Set<string>();
  const add = (name: string, severity: number, kind: string) => {
    if (!seen.has(name)) {
      seen.add(name);
      findings.push({ name, severity, kind });
    }
  };

  walk(ast, (node) => {
    // X.constructor.constructor(...) — classic JS sandbox escape
    if (
      node.type === "CallExpression" &&
      node.callee?.type === "MemberExpression" &&
      node.callee.property?.name === "constructor" &&
      node.callee.object?.type === "MemberExpression" &&
      node.callee.object.property?.name === "constructor"
    ) {
      add("constructor_escape", 60, "sandbox_escape");
    }
    // Function('...') as a call (aliased/no-`new` Function constructor)
    if (node.type === "CallExpression" && node.callee?.type === "Identifier" && node.callee.name === "Function") {
      add("function_constructor_call", 50, "dangerous_call");
    }
    // __proto__ member access
    if (node.type === "MemberExpression" && node.property?.name === "__proto__") {
      add("proto_access", 45, "sandbox_escape");
    }
    // dynamic import() — advisory (benign code-splitting uses it too)
    if (node.type === "ImportExpression") {
      add("dynamic_import", 30, "dynamic_import");
    }
  });

  return findings;
};
