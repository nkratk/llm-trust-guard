import { describe, it, expect, beforeEach } from "vitest";
import { ToolChainValidator } from "../src/guards/tool-chain-validator";

describe("ToolChainValidator", () => {
  let validator: ToolChainValidator;
  const sessionId = "test-session-1";

  beforeEach(() => {
    validator = new ToolChainValidator({
      forbiddenSequences: [
        {
          name: "read_then_execute",
          sequence: ["read_file", "execute_code"],
          reason: "Reading then executing is dangerous",
          severity: "block",
        },
        {
          name: "credentials_then_http",
          sequence: ["get_api_key", "http_request"],
          reason: "Credential theft pattern",
          severity: "block",
        },
      ],
      toolCooldowns: { delete_record: 5000 },
      maxToolsPerRequest: 3,
      maxSensitiveToolsPerSession: 2,
      sensitiveTools: ["delete", "execute", "admin"],
      // Disable v2 checks that depend on timing to keep tests deterministic
      enableTimeAnomalyDetection: false,
      enableLoopDetection: false,
      enableStateTracking: false,
      enableAutonomyDetection: false,
      enableResourceTracking: false,
      enableImpactScoring: false,
    });
  });

  describe("Forbidden Sequence Blocking", () => {
    it("should block read_file followed by execute_code", () => {
      const first = validator.validate(sessionId, "read_file");
      expect(first.allowed).toBe(true);

      const second = validator.validate(sessionId, "execute_code");
      expect(second.allowed).toBe(false);
      expect(second.chain_analysis.forbidden_sequences_detected).toContain("read_then_execute");
      expect(second.violations.some((v) => v.includes("FORBIDDEN_SEQUENCE"))).toBe(true);
    });

    it("should block get_api_key followed by http_request", () => {
      validator.validate(sessionId, "get_api_key");
      const result = validator.validate(sessionId, "http_request");
      expect(result.allowed).toBe(false);
      expect(result.chain_analysis.forbidden_sequences_detected).toContain("credentials_then_http");
    });

    it("should allow non-forbidden sequences", () => {
      validator.validate(sessionId, "get_info");
      const result = validator.validate(sessionId, "update_profile");
      expect(result.allowed).toBe(true);
      expect(result.chain_analysis.forbidden_sequences_detected).toHaveLength(0);
    });
  });

  describe("Sensitive Tool Count Limit", () => {
    it("should block after exceeding max sensitive tools per session", () => {
      // maxSensitiveToolsPerSession = 2
      const r1 = validator.validate(sessionId, "delete_record");
      expect(r1.allowed).toBe(true);

      const r2 = validator.validate(sessionId, "delete_user");
      expect(r2.allowed).toBe(true);

      // Third sensitive tool should be blocked
      const r3 = validator.validate(sessionId, "admin_panel");
      expect(r3.allowed).toBe(false);
      expect(r3.violations).toContain("MAX_SENSITIVE_TOOLS_EXCEEDED");
    });
  });

  describe("Batch Validation", () => {
    it("should block batch exceeding maxToolsPerRequest", () => {
      const result = validator.validateBatch(sessionId, [
        "tool_a",
        "tool_b",
        "tool_c",
        "tool_d",
      ]);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("MAX_TOOLS_PER_REQUEST_EXCEEDED");
    });

    it("should allow batch within limits", () => {
      const result = validator.validateBatch(sessionId, ["get_info", "get_status"]);
      expect(result.allowed).toBe(true);
    });

    it("should detect forbidden sequences within a batch", () => {
      const result = validator.validateBatch(sessionId, [
        "read_file",
        "execute_code",
      ]);
      expect(result.allowed).toBe(false);
      expect(result.chain_analysis.forbidden_sequences_detected.length).toBeGreaterThan(0);
    });
  });

  describe("Cooldown Enforcement", () => {
    it("should block tool call within cooldown period", () => {
      const first = validator.validate(sessionId, "delete_record");
      expect(first.allowed).toBe(true);

      // Immediately call again - should be blocked by cooldown (5000ms)
      const second = validator.validate(sessionId, "delete_record");
      expect(second.allowed).toBe(false);
      expect(second.violations.some((v) => v.includes("COOLDOWN_VIOLATION"))).toBe(true);
      expect(second.chain_analysis.cooldown_violations.length).toBeGreaterThan(0);
    });
  });

  describe("Session Management", () => {
    it("should track tool history per session", () => {
      validator.validate(sessionId, "tool_a");
      validator.validate(sessionId, "tool_b");
      const history = validator.getToolHistory(sessionId);
      expect(history).toContain("tool_a");
      expect(history).toContain("tool_b");
    });

    it("should reset session clearing all history", () => {
      validator.validate(sessionId, "tool_a");
      validator.resetSession(sessionId);
      const history = validator.getToolHistory(sessionId);
      expect(history).toHaveLength(0);
    });
  });

  describe("False Positive - Legitimate Tool Chain", () => {
    it("should allow a normal sequence of safe tools", () => {
      const r1 = validator.validate(sessionId, "get_user_profile");
      expect(r1.allowed).toBe(true);

      const r2 = validator.validate(sessionId, "update_preferences");
      expect(r2.allowed).toBe(true);

      const r3 = validator.validate(sessionId, "get_notifications");
      expect(r3.allowed).toBe(true);

      expect(r3.violations).toHaveLength(0);
      expect(r3.warnings).toHaveLength(0);
    });
  });
});
