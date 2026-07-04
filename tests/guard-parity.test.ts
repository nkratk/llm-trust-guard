import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as g from "../src";

/**
 * Full-guard TS↔Python parity gate.
 *
 * Runs each payload in guard-parity-vectors.json through the TS guard implementation
 * and asserts the block verdict matches the locked value. The SAME vector file ships
 * in the Python repo where test_guard_parity.py asserts matching verdicts.
 *
 * Regenerate locked verdicts only with a RESULTS-v*.md justification.
 */

const VECTORS_PATH = path.join(process.cwd(), "tests/guard-parity-vectors.json");
const doc = JSON.parse(fs.readFileSync(VECTORS_PATH, "utf-8")) as {
  vectors: Array<{ guard: string; payload: string; should_block: boolean }>;
};

function blocked(r: any): boolean {
  if (r === null || r === undefined) return false;
  if (typeof r === "boolean") return r;
  if (Array.isArray(r.violations) && r.violations.length > 0) return true;
  if (r.allowed === false) return true;
  if (r.valid === false) return true;
  if (r.threats && r.threats.length > 0) return true;
  return false;
}

function runGuard(guardName: string, payload: string): boolean {
  switch (guardName) {
    case "InputSanitizer":
      return blocked(new g.InputSanitizer({ threshold: 0.3, detectPAP: true }).sanitize(payload));

    case "EncodingDetector":
      return blocked(new g.EncodingDetector().detect(payload));

    case "MemoryGuard":
      return blocked(new g.MemoryGuard().checkWrite(payload, "user", "s1"));

    case "OutputFilter":
      // Only check violations — filter() always produces a normalised copy
      return new g.OutputFilter().filter(payload).violations.length > 0;

    case "ToolResultGuard":
      return blocked(new g.ToolResultGuard().validateResult("test_tool", payload));

    case "MCPSecurityGuard": {
      // validateSamplingResponse catches shell injection in LLM outputs
      const mcp = new g.MCPSecurityGuard() as any;
      return blocked(mcp.validateSamplingResponse({ role: "assistant", content: payload }));
    }

    case "ConversationGuard":
      return blocked((new g.ConversationGuard() as any).check("s1", payload));

    case "MultiModalGuard":
      return blocked(
        new g.MultiModalGuard().check({
          type: "document",
          content: payload,
          extractedText: payload,
          mimeType: "text/plain",
        } as any)
      );

    case "TenantBoundary": {
      // payload = requesting tenant_id; guard is configured to allow only tenant-A
      const tb = new g.TenantBoundary({ validTenants: new Set(["tenant-A"]) } as any);
      const vr = tb.validateSession({
        authenticated: true,
        tenant_id: payload,
        user_id: "u1",
        role: "user",
        session_id: "s1",
      });
      return vr.valid === false;
    }

    case "ExternalDataGuard":
      // payload is a raw URL
      return blocked(new g.ExternalDataGuard().validate(payload));

    case "PolicyGate": {
      const pg = new g.PolicyGate({ allowedTools: ["read_profile", "search"] }) as any;
      // Block: tool requires admin role; session is user role → blocked
      // Pass:  tool has no role restriction → allowed
      const isBlocked = payload === "delete_all_users";
      return blocked(
        pg.checkToolAccess(
          { name: payload, roles: isBlocked ? ["admin"] : [] },
          { role: "user", userId: "u1", sessionId: "s1", authenticated: true, tenant_id: "t1" }
        )
      );
    }

    case "RAGGuard": {
      // payload must trigger a RAG_INJECTION_PATTERN — use content-level check
      const result = new g.RAGGuard().validate([{ content: payload, source: "test", id: "c1" } as any]);
      return (result as any).blocked_chunks > 0 || (result.violations?.length ?? 0) > 0;
    }

    case "PromptLeakageGuard":
      return blocked(new g.PromptLeakageGuard().check(payload));

    default:
      throw new Error(`Unknown guard in parity vectors: ${guardName}`);
  }
}

describe("Full-guard TS↔Python parity gate", () => {
  for (const v of doc.vectors) {
    it(`${v.guard}: ${v.payload.slice(0, 60)} → ${v.should_block ? "BLOCK" : "PASS"}`, () => {
      const actual = runGuard(v.guard, v.payload);
      expect(actual).toBe(v.should_block);
    });
  }
});
