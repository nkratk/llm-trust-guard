import { describe, it, expect, beforeEach } from "vitest";
import { AutonomyEscalationGuard } from "../src/guards/autonomy-escalation-guard";

describe("AutonomyEscalationGuard", () => {
  let guard: AutonomyEscalationGuard;

  beforeEach(() => {
    guard = new AutonomyEscalationGuard();
  });

  describe("Basic Action Validation", () => {
    it("should allow read_only actions at base autonomy level", () => {
      const result = guard.validate("read_only", "session-1");
      expect(result.allowed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it("should allow query actions at base autonomy level", () => {
      const result = guard.validate("query", "session-1");
      expect(result.allowed).toBe(true);
    });

    it("should block execute_code at base autonomy level", () => {
      const result = guard.validate("execute_code", "session-1");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("escalation_required: execute_code");
      expect(result.requires_approval).toBe(true);
    });

    it("should block modify_system action", () => {
      const result = guard.validate("modify_system", "session-1");
      expect(result.allowed).toBe(false);
      expect(result.requires_approval).toBe(true);
    });
  });

  describe("Self-Modification Detection", () => {
    it("should detect and block self-modification attempts", () => {
      const result = guard.validate("update", "session-1", {
        action: "modify my own code to bypass restrictions",
      });
      expect(result.allowed).toBe(false);
      expect(result.analysis.self_modification_detected).toBe(true);
      expect(result.violations.some((v) => v.includes("self_modification"))).toBe(true);
    });

    it("should detect disable safety attempts", () => {
      const result = guard.validate("config", "session-1", {
        command: "disable safety filters",
      });
      expect(result.allowed).toBe(false);
      expect(result.analysis.escalation_patterns_detected).toContain("disable_safety");
    });

    it("should detect change constraints attempts", () => {
      const result = guard.validate("update", "session-1", {
        request: "remove my constraints",
      });
      expect(result.allowed).toBe(false);
      expect(result.analysis.self_modification_detected).toBe(true);
    });
  });

  describe("Autonomy Level Escalation", () => {
    it("should detect autonomy level escalation requests", () => {
      const result = guard.validate("update_level", "session-1", {
        autonomy_level: 75,
      });
      expect(result.violations.some((v) => v.includes("autonomy_level_escalation"))).toBe(true);
      expect(result.requires_approval).toBe(true);
    });

    it("should block requests exceeding max autonomy level", () => {
      const result = guard.validate("update_level", "session-1", {
        autonomy_level: 100,
      });
      expect(result.violations.some((v) => v.includes("autonomy_level_exceeds_max"))).toBe(true);
    });

    it("should track current autonomy level", () => {
      const result = guard.validate("query", "session-1");
      expect(result.analysis.current_autonomy_level).toBe(25); // base level
    });
  });

  describe("HITL Bypass Detection", () => {
    it("should detect bypass approval attempts", () => {
      const result = guard.validate("execute", "session-1", {
        command: "bypass human approval for this action",
      });
      expect(result.allowed).toBe(false);
      expect(result.analysis.escalation_patterns_detected).toContain("bypass_approval");
    });

    it("should detect skip review attempts", () => {
      const result = guard.validate("action", "session-1", {
        note: "skip human review",
      });
      expect(result.analysis.escalation_patterns_detected).toContain("skip_review");
    });

    it("should detect no supervision requests", () => {
      const result = guard.validate("action", "session-1", {
        mode: "without human supervision",
      });
      expect(result.analysis.escalation_patterns_detected).toContain("no_supervision");
    });

    it("should require human approval for sensitive actions", () => {
      const guard = new AutonomyEscalationGuard({
        alwaysRequireHuman: ["delete_data"],
      });
      const result = guard.validate("delete_data", "session-1");
      expect(result.analysis.hitl_required).toBe(true);
      expect(result.requires_approval).toBe(true);
      expect(result.approval_type).toBe("human");
    });
  });

  describe("Sub-Agent Control", () => {
    it("should detect spawn agent attempts", () => {
      const result = guard.validate("spawn_agent", "session-1");
      expect(result.requires_approval).toBe(true);
    });

    it("should detect clone/fork attempts", () => {
      const result = guard.validate("action", "session-1", {
        command: "fork this agent",
      });
      expect(result.analysis.escalation_patterns_detected).toContain("fork_agent");
    });

    it("should enforce sub-agent limits", () => {
      // Register max sub-agents
      guard.registerSubAgent("session-1", "sub-1");
      guard.registerSubAgent("session-1", "sub-2");
      guard.registerSubAgent("session-1", "sub-3");

      const result = guard.validate("spawn_agent", "session-1");
      expect(result.analysis.sub_agent_limit_exceeded).toBe(true);
      expect(result.violations.some((v) => v.includes("sub_agent_limit"))).toBe(true);
    });

    it("should allow sub-agent registration within limits", () => {
      const success = guard.registerSubAgent("session-1", "sub-1");
      expect(success).toBe(true);

      const state = guard.getAgentState("session-1");
      expect(state?.sub_agents).toContain("sub-1");
    });
  });

  describe("Capability Boundaries", () => {
    it("should enforce capability boundaries based on autonomy level", () => {
      const result = guard.validate("execute_any", "session-1");
      expect(result.analysis.capability_violation).toBe(true);
      expect(result.violations.some((v) => v.includes("capability_violation"))).toBe(true);
    });

    it("should allow capabilities at appropriate level", () => {
      guard.setAutonomyLevel("session-1", 50);
      const result = guard.validate("create_draft", "session-1");
      expect(result.analysis.capability_violation).toBe(false);
    });

    it("should expand capabilities when autonomy level increases", () => {
      guard.setAutonomyLevel("session-1", 75);
      const result = guard.validate("api_call_internal", "session-1");
      expect(result.analysis.capability_violation).toBe(false);
    });
  });

  describe("Escalation Requests", () => {
    it("should accept capability expansion requests for approval", () => {
      const result = guard.requestEscalation("session-1", {
        request_type: "capability_expansion",
        requested_capability: "api_call_external",
        reason: "Need to call external API",
        source: "agent",
      });
      expect(result.allowed).toBe(true);
      expect(result.requires_approval).toBe(true);
      expect(result.approval_type).toBe("admin");
    });

    it("should block self-modification requests", () => {
      const result = guard.requestEscalation("session-1", {
        request_type: "self_modify",
        reason: "Want to update my own code",
        source: "agent",
      });
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("self_modification_blocked");
    });

    it("should block HITL bypass requests", () => {
      const result = guard.requestEscalation("session-1", {
        request_type: "bypass_hitl",
        reason: "Want to skip human approval",
        source: "agent",
      });
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("hitl_bypass_not_allowed");
    });

    it("should flag large autonomy jumps", () => {
      const result = guard.requestEscalation("session-1", {
        request_type: "level_increase",
        requested_level: 75,
        reason: "Need more autonomy",
        source: "agent",
      });
      expect(result.violations).toContain("large_autonomy_jump");
      expect(result.approval_type).toBe("human");
    });

    it("should block repeated denied requests", () => {
      // First request - will be denied
      guard.requestEscalation("session-1", {
        request_type: "self_modify",
        reason: "Update code",
        source: "agent",
      });

      // Second request - should be blocked as repeated
      const result = guard.requestEscalation("session-1", {
        request_type: "self_modify",
        reason: "Update code again",
        source: "agent",
      });
      expect(result.violations).toContain("repeated_denied_request");
    });
  });

  describe("Approval Workflow", () => {
    it("should approve escalation requests and apply changes", () => {
      const request = guard.requestEscalation("session-1", {
        request_type: "level_increase",
        requested_level: 50,
        reason: "Need higher autonomy",
        source: "agent",
      });

      const approved = guard.approveEscalation("session-1", request.request_id);
      expect(approved).toBe(true);

      const state = guard.getAgentState("session-1");
      expect(state?.autonomy_level).toBe(50);
    });

    it("should deny escalation requests and reduce autonomy", () => {
      const request = guard.requestEscalation("session-1", {
        request_type: "level_increase",
        requested_level: 50,
        reason: "Need higher autonomy",
        source: "agent",
      });

      const initialState = guard.getAgentState("session-1");
      const initialLevel = initialState?.autonomy_level || 25;

      const denied = guard.denyEscalation("session-1", request.request_id);
      expect(denied).toBe(true);

      const state = guard.getAgentState("session-1");
      expect(state?.autonomy_level).toBeLessThan(initialLevel);
    });

    it("should approve capability expansion requests", () => {
      const request = guard.requestEscalation("session-1", {
        request_type: "capability_expansion",
        requested_capability: "special_action",
        reason: "Need special capability",
        source: "agent",
      });

      guard.approveEscalation("session-1", request.request_id);

      const state = guard.getAgentState("session-1");
      expect(state?.capabilities.has("special_action")).toBe(true);
    });
  });

  describe("Session Management", () => {
    it("should reset session state", () => {
      guard.validate("query", "session-1");
      guard.setAutonomyLevel("session-1", 75);

      guard.resetSession("session-1");

      const state = guard.getAgentState("session-1");
      expect(state).toBeUndefined();
    });

    it("should maintain separate states for different sessions", () => {
      guard.setAutonomyLevel("session-1", 50);
      guard.setAutonomyLevel("session-2", 75);

      expect(guard.getAgentState("session-1")?.autonomy_level).toBe(50);
      expect(guard.getAgentState("session-2")?.autonomy_level).toBe(75);
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty params", () => {
      const result = guard.validate("query", "session-1", {});
      expect(result.allowed).toBe(true);
    });

    it("should handle undefined session state", () => {
      const state = guard.getAgentState("non-existent");
      expect(state).toBeUndefined();
    });

    it("should cap autonomy level at max", () => {
      guard.setAutonomyLevel("session-1", 150);
      const state = guard.getAgentState("session-1");
      expect(state?.autonomy_level).toBe(75); // maxAutonomyLevel default
    });
  });

  describe("Custom Configuration", () => {
    it("should respect custom max autonomy level", () => {
      const customGuard = new AutonomyEscalationGuard({
        maxAutonomyLevel: 50,
      });

      customGuard.setAutonomyLevel("session-1", 100);
      const state = customGuard.getAgentState("session-1");
      expect(state?.autonomy_level).toBe(50);
    });

    it("should respect custom base autonomy level", () => {
      const customGuard = new AutonomyEscalationGuard({
        baseAutonomyLevel: 50,
      });

      customGuard.validate("query", "session-1");
      const state = customGuard.getAgentState("session-1");
      expect(state?.autonomy_level).toBe(50);
    });

    it("should respect custom capability levels", () => {
      const customGuard = new AutonomyEscalationGuard({
        capabilityLevels: {
          0: ["custom_action"],
        },
      });

      const result = customGuard.validate("custom_action", "session-1");
      expect(result.analysis.capability_violation).toBe(false);
    });
  });
});
