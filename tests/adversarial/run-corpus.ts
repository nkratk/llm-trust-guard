#!/usr/bin/env npx tsx
/**
 * Single-version corpus runner — measures per-guard detection rates on current source.
 *
 * Probe logic mirrors the audit harness (correct-harness.js) so numbers are
 * directly comparable across re-runs. Uses dataclass inputs with the actual
 * field names the package's public API expects.
 *
 * Usage: npx tsx tests/adversarial/run-corpus.ts [--catalog PATH] [--guard NAME]
 *
 * Exit code is 0 on success regardless of detection rate — this is a measurement
 * tool, not a pass/fail test. Output goes to stdout in two formats: a per-guard
 * summary table and a JSON line per threat (for machine parsing).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as g from "../../src/index";

type Threat = {
  id: string;
  name: string;
  guard: string;
  desc?: string;
  payloads: string[];
};

const argv = process.argv.slice(2);
const catalogIdx = argv.indexOf("--catalog");
const catalogPath = catalogIdx >= 0
  ? argv[catalogIdx + 1]
  : "/Users/nandakishoreleburu/Desktop/claude-ai-course/llm-trust-guard-versions/threats-1000-catalog.json";
const guardFilterIdx = argv.indexOf("--guard");
const guardFilter = guardFilterIdx >= 0 ? argv[guardFilterIdx + 1] : null;
const jsonOnly = argv.includes("--json-only");

if (!fs.existsSync(catalogPath)) {
  console.error(`catalog not found: ${catalogPath}`);
  process.exit(1);
}

const catalog: Threat[] = JSON.parse(fs.readFileSync(catalogPath, "utf8"));

function blocked(r: any): boolean {
  if (r === null || r === undefined) return false;
  if (r.allowed === false) return true;
  if (r.decision === "deny" || r.decision === "block") return true;
  if (r.detected === true) return true;
  if (r.blocked === true) return true;
  if (Array.isArray(r.threats) && r.threats.length > 0) return true;
  if (Array.isArray(r.violations) && r.violations.length > 0) return true;
  if (r.filtered !== undefined && r.filtered !== r.output && r.filtered !== "") return true;
  if (Array.isArray(r.results) && r.results.some((x: any) => x.allowed === false || (Array.isArray(x.threats) && x.threats.length))) return true;
  return false;
}

function probe(guardName: string, payload: string, i: number): boolean {
  try {
    switch (guardName) {
      case "InputSanitizer":
        return blocked(new g.InputSanitizer().sanitize(payload));
      case "CodeExecutionGuard":
        return blocked(new g.CodeExecutionGuard().analyze(payload, "bash"));
      case "OutputFilter": {
        const r: any = new g.OutputFilter().filter(payload);
        if (r && r.filtered !== undefined && r.filtered !== payload) return true;
        return blocked(r);
      }
      case "PromptLeakageGuard":
        return blocked(new g.PromptLeakageGuard().check(payload));
      case "ExternalDataGuard":
        return blocked(new g.ExternalDataGuard().validate(payload, { source: "external", contentType: "text/plain" } as any));
      case "ToolResultGuard":
        return blocked(new g.ToolResultGuard().validateResult("t1", payload));
      case "RAGGuard":
        return blocked(new g.RAGGuard().validate([{ id: "d1", content: payload, source: "external" } as any]));
      case "MemoryGuard":
        return blocked(new g.MemoryGuard().checkWrite(payload, "user", "s1"));
      case "MCPSecurityGuard": {
        const mcp = new g.MCPSecurityGuard();
        if ((mcp as any).validateSamplingResponse) {
          const r = (mcp as any).validateSamplingResponse({ content: payload, serverId: "evil-srv-" + i });
          if (blocked(r)) return true;
        }
        const reg = {
          server: { serverId: "e" + i, name: "E" },
          tools: [{ name: "t", description: payload, serverId: "e" + i, parameters: {} }],
          timestamp: Date.now(),
        };
        const r = mcp.validateServerRegistration(reg as any);
        return blocked(r);
      }
      case "MultiModalGuard":
        return blocked(new g.MultiModalGuard().check({ type: "document", content: payload, extractedText: payload, mimeType: "text/plain" } as any));
      case "AgentCommunicationGuard": {
        const msg: any = { messageId: "m" + i, fromAgent: "a1", toAgent: "a2", type: "request", payload, timestamp: Date.now(), nonce: "n" + i + Math.random(), signature: null };
        return blocked(new g.AgentCommunicationGuard().validateMessage(msg, "a2"));
      }
      case "TrustExploitationGuard": {
        const action: any = { actionId: "a" + i, actionType: "custom", target: payload, autonomous: true, timestamp: Date.now(), reason: payload };
        return blocked(new g.TrustExploitationGuard().validateAction(action, "s1"));
      }
      case "DelegationScopeGuard": {
        const req: any = { parentAgentId: "p1", parentScopes: ["read"], childAgentId: "c1", requestedScopes: [payload], hopDepth: 1, reason: payload };
        return blocked(new g.DelegationScopeGuard().validateDelegation(req));
      }
      case "AgentSkillGuard": {
        const skill: any = { name: "s" + i, description: payload, parameters: {}, permissions: [] };
        return blocked(new g.AgentSkillGuard().analyze(skill));
      }
      case "AutonomyEscalationGuard":
        return blocked((new g.AutonomyEscalationGuard() as any).validate(payload, "s1"));
      case "ToolChainValidator":
        return blocked((new g.ToolChainValidator() as any).validate("s1", "t1", [payload]));
      case "ConversationGuard":
        return blocked((new g.ConversationGuard() as any).check("s1", payload));
      case "PolicyGate": {
        const sess: any = { userId: "u1", tenantId: "t1", role: "user", authenticated: true, sessionId: "s1" };
        const tool: any = { name: "t1", description: payload, roles: ["admin"], parameters: {} };
        return blocked((new g.PolicyGate() as any).check(tool, { p: payload }, sess, "user"));
      }
      case "TenantBoundary": {
        const sess: any = { userId: "u1", tenantId: "t1", role: "user", authenticated: true, sessionId: "s1" };
        return blocked((new g.TenantBoundary() as any).check("t1", { resource_id: payload, tenant_id: "t2" }, sess));
      }
      case "SessionIntegrityGuard":
        return blocked((new g.SessionIntegrityGuard() as any).validateRequest("s1", payload));
      case "SpawnPolicyGuard": {
        const req: any = { parentAgentId: "p1", childAgentId: "c1", spawnOrigin: payload, delegationDepth: 1, isThirdParty: true, reason: payload };
        return blocked(new g.SpawnPolicyGuard().validateSpawn(req));
      }
      default:
        return false;
    }
  } catch {
    return false;
  }
}

const perGuard: Record<string, { threats: number; payloads: number; blocked: number; fullDetect: number; blind: number }> = {};
const perThreat: Array<{ id: string; guard: string; blocked: number; total: number; rate: number }> = [];

const filtered = guardFilter ? catalog.filter((t) => t.guard === guardFilter) : catalog;

for (const t of filtered) {
  let b = 0;
  for (let i = 0; i < t.payloads.length; i++) {
    if (probe(t.guard, t.payloads[i], i)) b++;
  }
  const rate = (b / t.payloads.length) * 100;
  perThreat.push({ id: t.id, guard: t.guard, blocked: b, total: t.payloads.length, rate });
  if (!perGuard[t.guard]) perGuard[t.guard] = { threats: 0, payloads: 0, blocked: 0, fullDetect: 0, blind: 0 };
  perGuard[t.guard].threats++;
  perGuard[t.guard].payloads += t.payloads.length;
  perGuard[t.guard].blocked += b;
  if (b === t.payloads.length) perGuard[t.guard].fullDetect++;
  if (b === 0) perGuard[t.guard].blind++;
}

if (!jsonOnly) {
  // Per-guard summary
  console.log("\n=== Per-guard detection rates ===");
  console.log("Guard                    | Threats | Payloads | Blocked | Rate    | Full | Blind");
  console.log("-------------------------+---------+----------+---------+---------+------+------");
  const guards = Object.keys(perGuard).sort((a, b) => (perGuard[b].blocked / perGuard[b].payloads) - (perGuard[a].blocked / perGuard[a].payloads));
  for (const gn of guards) {
    const s = perGuard[gn];
    const rate = ((s.blocked / s.payloads) * 100).toFixed(2);
    console.log(`${gn.padEnd(24)} | ${String(s.threats).padStart(7)} | ${String(s.payloads).padStart(8)} | ${String(s.blocked).padStart(7)} | ${rate.padStart(6)}% | ${String(s.fullDetect).padStart(4)} | ${String(s.blind).padStart(5)}`);
  }
  // Aggregate
  const totalP = Object.values(perGuard).reduce((acc, s) => acc + s.payloads, 0);
  const totalB = Object.values(perGuard).reduce((acc, s) => acc + s.blocked, 0);
  console.log(`\nAggregate: ${totalB}/${totalP} = ${((totalB / totalP) * 100).toFixed(2)}%`);
}

// JSON output (one line per threat, for machine parsing)
for (const t of perThreat) {
  console.log(JSON.stringify(t));
}
