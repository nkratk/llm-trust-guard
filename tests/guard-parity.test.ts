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

    case "AgentCommunicationGuard": {
      // __REGISTERED_SENDER__:<tool> → register sender and create a signed message → should pass
      // anything else → unregistered sender → always blocks
      const acg = new g.AgentCommunicationGuard() as any;
      if (payload.startsWith("__REGISTERED_SENDER__:")) {
        acg.registerAgent("agent-A", "orchestrator", ["read", "write"]);
        acg.registerAgent("agent-B", "worker", ["read"]);
        const msg = acg.createMessage("agent-A", "agent-B", "request", payload.split(":")[1]);
        return blocked(acg.validateMessage(msg, "agent-B"));
      }
      const [sender] = payload.split(":");
      const badMsg: any = { messageId: "m1", fromAgent: sender, toAgent: "agent-B", type: "request", payload, timestamp: Date.now(), nonce: `n${Math.random()}`, signature: null };
      return blocked(acg.validateMessage(badMsg, "agent-B"));
    }

    case "AgentSkillGuard": {
      const skill: any = { name: "skill-1", description: payload, parameters: {}, permissions: [] };
      return blocked((new g.AgentSkillGuard() as any).analyze(skill));
    }

    case "AutonomyEscalationGuard":
      // payload IS the action string — "disable safety guardrails" matches pattern → block
      // "analyze" is in level-25 capabilities → pass
      return blocked((new g.AutonomyEscalationGuard() as any).validate(payload, "s1"));

    case "CircuitBreaker": {
      // __FORCE_OPEN__:<circuitId> → force open → should block
      const cb = new g.CircuitBreaker() as any;
      if (payload.startsWith("__FORCE_OPEN__:")) {
        const cid = payload.split(":")[1];
        cb.forceOpen(cid);
        return cb.check(cid)?.allowed === false;
      }
      return cb.check(payload)?.allowed === false;
    }

    case "CodeExecutionGuard":
      // payload = code string; language inferred: contains "import subprocess" → python, otherwise javascript
      return blocked(
        (new g.CodeExecutionGuard() as any).analyze(
          payload,
          payload.includes("import subprocess") || payload.includes("def ") ? "python" : "javascript"
        )
      );

    case "CompressionDetector":
      return blocked(new g.CompressionDetector().detect(payload));

    case "ContextBudgetGuard": {
      // __MANY_SHOT__:<text> → send same text 6 times to trigger many-shot detection
      const cbg = new g.ContextBudgetGuard() as any;
      if (payload.startsWith("__MANY_SHOT__:")) {
        const text = payload.slice("__MANY_SHOT__:".length);
        for (let i = 0; i < 6; i++) cbg.trackContext("s1", text, "user");
        const r = cbg.trackContext("s1", text, "user");
        return r.many_shot_detected === true || blocked(r);
      }
      return blocked(cbg.trackContext("s1", payload, "user"));
    }

    case "DelegationScopeGuard": {
      // payload = requested scope; parent only has ["read"] → anything else blocks
      const req: any = { parentAgentId: "p1", parentScopes: ["read"], childAgentId: "c1", requestedScopes: [payload], hopDepth: 1, reason: "task" };
      return blocked((new g.DelegationScopeGuard() as any).validateDelegation(req));
    }

    case "DriftDetector": {
      const dd = new g.DriftDetector({ minimumSamples: 5, anomalyThreshold: 2.0, alertThreshold: 40, autoUpdateBaseline: true }) as any;
      if (payload.startsWith("__DRIFT__:")) {
        const base = { timestamp: 0, tools: ["search", "summarize"], topics: ["science", "math"], sentiment: 0.5, responseLength: 200, responseTime: 300, hadError: false };
        for (let i = 0; i < 10; i++) dd.recordSample("a1", { ...base, timestamp: Date.now() + i });
        dd.updateBaseline("a1");
        const bad = { timestamp: 0, tools: ["exec_code", "delete_file", "exfil_data"], topics: ["security", "exploit"], sentiment: -0.8, responseLength: 2000, responseTime: 5000, hadError: true };
        for (let i = 0; i < 10; i++) dd.recordSample("a1", { ...bad, timestamp: Date.now() + 100000 + i });
        const r = dd.analyze("a1");
        return r.analysis?.isDrifting === true || r.allowed === false;
      }
      dd.recordSample("a2", { timestamp: Date.now(), tools: [payload], topics: ["business"], sentiment: 0.5, responseLength: 200, responseTime: 300, hadError: false });
      return dd.analyze("a2").allowed === false;
    }

    case "ExecutionMonitor": {
      const em = new g.ExecutionMonitor({ maxConcurrentOperations: 2 }) as any;
      if (payload.startsWith("__RATE_EXCEEDED__:")) {
        em.check({ operationId: "op1", agentId: "a1", tool: "search", params: {} });
        em.check({ operationId: "op2", agentId: "a1", tool: "search", params: {} });
        return blocked(em.check({ operationId: "op3", agentId: "a1", tool: "search", params: {} }));
      }
      return blocked(em.check({ operationId: "op1", agentId: "a1", tool: payload, params: {} }));
    }

    case "HeuristicAnalyzer": {
      const r = (new g.HeuristicAnalyzer() as any).analyze(payload);
      return Array.isArray(r.violations) && r.violations.length > 0;
    }

    case "OutputSchemaGuard": {
      const schemas = { default: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } };
      const osg = new g.OutputSchemaGuard({ schemas } as any) as any;
      if (payload === "__MISSING_REQUIRED__") return blocked(osg.validate({}, "default"));
      return blocked(osg.validate({ name: "Alice" }, "default"));
    }

    case "SchemaValidator": {
      const sv = new g.SchemaValidator() as any;
      const tool = { name: "test", description: "t", parameters: { type: "object", required: ["id"], properties: { id: { type: "string" } } }, roles: [] };
      if (payload === "__INVALID_SCHEMA__") return blocked(sv.validate(tool, {}));
      return blocked(sv.validate(tool, { id: "123" }));
    }

    case "SessionIntegrityGuard": {
      const sig = new g.SessionIntegrityGuard() as any;
      sig.createSession("s1", "u1", ["read"]);
      if (payload === "__ESCALATE_PERMISSIONS__") {
        // request with massively expanded permission set triggers abrupt_state_change
        return blocked(sig.validateRequest("s1", "admin_op", { permissions: ["read", "admin", "superuser", "write", "delete", "god"] }));
      }
      return blocked(sig.validateRequest("s1", payload));
    }

    case "SpawnPolicyGuard": {
      const spg = new g.SpawnPolicyGuard() as any;
      spg.registerParent("trusted-parent");
      if (payload.startsWith("__THIRD_PARTY__:")) {
        const origin = payload.split(":")[1];
        return blocked(spg.validateSpawn({ parentAgentId: "trusted-parent", childAgentId: "c1", spawnOrigin: origin, delegationDepth: 0, isThirdParty: true, reason: "spawn" }));
      }
      const origin = payload.startsWith("__INTERNAL__:") ? payload.split(":")[1] : payload;
      return blocked(spg.validateSpawn({ parentAgentId: "trusted-parent", childAgentId: "c1", spawnOrigin: origin, delegationDepth: 0, isThirdParty: false, reason: "task" }));
    }

    case "StatePersistenceGuard": {
      const spg2 = new g.StatePersistenceGuard() as any;
      if (payload === "__CROSS_SESSION__") {
        spg2.storeState("session-owner", "secret", { value: "sensitive" });
        return blocked(spg2.validateOperation({ operation: "read", key: "secret", session_id: "session-attacker", target_session_id: "session-owner" }));
      }
      return blocked(spg2.validateOperation({ operation: "read", key: payload, session_id: "s1" }));
    }

    case "TokenCostGuard": {
      const tcg = new g.TokenCostGuard({ maxTokensPerRequest: 50 }) as any;
      if (payload.startsWith("__OVER_BUDGET__:")) {
        const n = parseInt(payload.split(":")[1], 10);
        return blocked(tcg.trackUsage("s1", "u1", n, n));
      }
      return blocked(tcg.trackUsage("s1", "u1", parseInt(payload, 10) || 10, 5));
    }

    case "ToolChainValidator": {
      const tcv = new g.ToolChainValidator() as any;
      return blocked(tcv.validate("s1", "tool1", [payload]));
    }

    case "ToolRegistry": {
      const tr = new g.ToolRegistry({ tools: [{ name: "search", description: "web search", parameters: {}, roles: ["user"] }], strictMatching: true }) as any;
      return blocked(tr.check(payload, "user", "req1"));
    }

    case "TrustExploitationGuard": {
      const action: any = { actionId: "a1", actionType: "custom", action_type: "custom", target: "x", autonomous: true, timestamp: Date.now(), reason: payload };
      return blocked((new g.TrustExploitationGuard() as any).validateAction(action, "s1"));
    }

    case "TrustTransitivityGuard": {
      const ttg = new g.TrustTransitivityGuard({ maxChainDepth: 2, minTrustScore: 50 }) as any;
      ttg.registerAgent({ agentId: "agent1", trustScore: 90, trustedAgents: ["agent2"] });
      ttg.registerAgent({ agentId: "agent2", trustScore: 80, trustedAgents: [] });
      if (payload.startsWith("__UNKNOWN_AGENT__:")) {
        const rogueId = payload.split(":")[1];
        return blocked(ttg.validateTrustChain(["agent1", rogueId]));
      }
      // __TRUSTED_CHAIN__:agent1,agent2
      const ids = payload.startsWith("__TRUSTED_CHAIN__:") ? payload.split(":")[1].split(",") : ["agent1", "agent2"];
      return blocked(ttg.validateTrustChain(ids));
    }

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
