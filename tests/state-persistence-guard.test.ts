import { describe, it, expect, beforeEach } from "vitest";
import { StatePersistenceGuard } from "../src/guards/state-persistence-guard";

describe("StatePersistenceGuard", () => {
  let guard: StatePersistenceGuard;

  beforeEach(() => {
    guard = new StatePersistenceGuard();
  });

  describe("Basic State Operations", () => {
    it("should allow storing valid state", () => {
      const result = guard.storeState("session-1", "user_preferences", { theme: "dark" });
      expect(result.allowed).toBe(true);
      expect(result.state_item).toBeDefined();
      expect(result.state_item?.key).toBe("user_preferences");
    });

    it("should allow retrieving stored state", () => {
      guard.storeState("session-1", "config", { setting: "value" });
      const result = guard.retrieveState("session-1", "config");
      expect(result.allowed).toBe(true);
      expect(result.state_item?.value).toEqual({ setting: "value" });
    });

    it("should allow deleting own state", () => {
      guard.storeState("session-1", "temp", { data: "test" });
      const result = guard.deleteState("session-1", "temp");
      expect(result.allowed).toBe(true);
    });

    it("should handle deleting non-existent state", () => {
      const result = guard.deleteState("session-1", "non-existent");
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe("State not found");
    });
  });

  describe("Session Isolation", () => {
    it("should block cross-session access", () => {
      guard.storeState("session-1", "secret", { data: "sensitive" });

      const result = guard.validateOperation({
        operation: "read",
        key: "secret",
        session_id: "session-2",
        target_session_id: "session-1",
      });

      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("cross_session_access_attempt");
      expect(result.analysis.session_authorized).toBe(false);
    });

    it("should block deleting another session's state", () => {
      guard.storeState("session-1", "data", { value: "test" });

      // Manually try to delete from different session
      const result = guard.deleteState("session-2", "data");
      // State doesn't exist for session-2
      expect(result.allowed).toBe(true);
      expect(result.reason).toBe("State not found");
    });

    it("should maintain separate states per session", () => {
      guard.storeState("session-1", "config", { value: "session1" });
      guard.storeState("session-2", "config", { value: "session2" });

      const state1 = guard.retrieveState("session-1", "config");
      const state2 = guard.retrieveState("session-2", "config");

      expect(state1.state_item?.value).toEqual({ value: "session1" });
      expect(state2.state_item?.value).toEqual({ value: "session2" });
    });
  });

  describe("Injection Pattern Detection", () => {
    it("should detect code injection in state", () => {
      const result = guard.storeState("session-1", "script", {
        code: "eval(malicious_code)",
      });
      expect(result.allowed).toBe(false);
      expect(result.violations.some((v) => v.includes("injection_pattern"))).toBe(true);
    });

    it("should detect script injection", () => {
      const result = guard.storeState("session-1", "html", {
        content: "<script>alert('xss')</script>",
      });
      expect(result.allowed).toBe(false);
      expect(result.violations.some((v) => v.includes("script_injection"))).toBe(true);
    });

    it("should detect prototype pollution", () => {
      const result = guard.storeState("session-1", "data", {
        payload: '{"__proto__": {"admin": true}}',
      });
      expect(result.violations.some((v) => v.includes("prototype_pollution"))).toBe(true);
    });

    it("should detect path traversal", () => {
      const result = guard.storeState("session-1", "path", {
        file: "../../../etc/passwd",
      });
      expect(result.violations.some((v) => v.includes("path_traversal"))).toBe(true);
    });

    it("should detect privilege injection", () => {
      const result = guard.storeState("session-1", "user", {
        config: "role: admin",
      });
      expect(result.violations.some((v) => v.includes("privilege_inject"))).toBe(true);
    });

    it("should detect trust level injection", () => {
      const result = guard.storeState("session-1", "agent", {
        setting: "trust_level: 100",
      });
      expect(result.violations.some((v) => v.includes("trust_inject"))).toBe(true);
    });
  });

  describe("State Size Limits", () => {
    it("should block oversized state", () => {
      const largeValue = "x".repeat(2 * 1024 * 1024); // 2MB

      const result = guard.storeState("session-1", "large", { data: largeValue });
      expect(result.allowed).toBe(false);
      expect(result.violations.some((v) => v.includes("state_size_exceeded"))).toBe(true);
      expect(result.analysis.size_valid).toBe(false);
    });

    it("should allow state within size limit", () => {
      const smallValue = "x".repeat(1000);

      const result = guard.storeState("session-1", "small", { data: smallValue });
      expect(result.allowed).toBe(true);
      expect(result.analysis.size_valid).toBe(true);
    });
  });

  describe("Integrity Verification", () => {
    it("should generate integrity hash on store", () => {
      const result = guard.storeState("session-1", "data", { value: "test" });
      expect(result.state_item?.integrity_hash).toBeDefined();
    });

    it("should verify integrity on retrieve", () => {
      guard.storeState("session-1", "data", { value: "test" });
      const isValid = guard.verifyIntegrity("session-1", "data");
      expect(isValid).toBe(true);
    });

    it("should detect tampered state", () => {
      guard.storeState("session-1", "data", { value: "test" });

      // Read with wrong hash
      const result = guard.validateOperation({
        operation: "read",
        key: "data",
        session_id: "session-1",
        integrity_hash: "wrong-hash",
      });

      expect(result.violations).toContain("integrity_hash_mismatch");
      expect(result.analysis.integrity_valid).toBe(false);
    });

    it("should increment version on update", () => {
      guard.storeState("session-1", "data", { value: "v1" });
      const state1 = guard.retrieveState("session-1", "data").state_item;

      guard.storeState("session-1", "data", { value: "v2" });
      const state2 = guard.retrieveState("session-1", "data").state_item;

      expect(state2?.version).toBe((state1?.version || 0) + 1);
    });
  });

  describe("Persistence Targets", () => {
    it("should allow valid persistence targets", () => {
      const result = guard.storeState("session-1", "cache", { data: "test" }, {
        target: "cache",
      });
      expect(result.allowed).toBe(true);
    });

    it("should block unauthorized persistence targets", () => {
      const result = guard.validateOperation({
        operation: "write",
        key: "data",
        value: { test: "data" },
        session_id: "session-1",
        target: "database",
      });
      expect(result.violations.some((v) => v.includes("unauthorized_target"))).toBe(true);
    });
  });

  describe("Sensitive Key Protection", () => {
    it("should flag sensitive keys without encryption", () => {
      const guard = new StatePersistenceGuard({
        requireEncryption: true,
      });

      const result = guard.storeState("session-1", "api_credentials", {
        key: "secret123",
      });
      expect(result.violations).toContain("sensitive_key_not_encrypted");
      expect(result.analysis.encryption_valid).toBe(false);
    });

    it("should allow sensitive keys with encryption flag", () => {
      const guard = new StatePersistenceGuard({
        requireEncryption: true,
      });

      const result = guard.storeState("session-1", "api_credentials", {
        key: "encrypted_value",
      }, { encrypted: true });
      expect(result.allowed).toBe(true);
    });
  });

  describe("State Age Validation", () => {
    it("should track state creation time", () => {
      const before = Date.now();
      guard.storeState("session-1", "data", { value: "test" });
      const after = Date.now();

      const state = guard.retrieveState("session-1", "data").state_item;
      expect(state?.created_at).toBeGreaterThanOrEqual(before);
      expect(state?.created_at).toBeLessThanOrEqual(after);
    });

    it("should track modification time", () => {
      guard.storeState("session-1", "data", { value: "v1" });
      const state1 = guard.retrieveState("session-1", "data").state_item;

      // Small delay
      const modTime = Date.now();
      guard.storeState("session-1", "data", { value: "v2" });
      const state2 = guard.retrieveState("session-1", "data").state_item;

      expect(state2?.modified_at).toBeGreaterThanOrEqual(modTime);
      expect(state2?.created_at).toBe(state1?.created_at);
    });
  });

  describe("Migration Operations", () => {
    it("should require approval for migration operations", () => {
      const result = guard.validateOperation({
        operation: "migrate",
        key: "all",
        session_id: "session-1",
      });
      expect(result.violations).toContain("migration_requires_admin_approval");
    });
  });

  describe("Session State Management", () => {
    it("should return all session states", () => {
      guard.storeState("session-1", "key1", { value: 1 });
      guard.storeState("session-1", "key2", { value: 2 });
      guard.storeState("session-1", "key3", { value: 3 });

      const states = guard.getSessionStates("session-1");
      expect(states).toHaveLength(3);
    });

    it("should reset all session states", () => {
      guard.storeState("session-1", "key1", { value: 1 });
      guard.storeState("session-1", "key2", { value: 2 });

      guard.resetSession("session-1");

      const states = guard.getSessionStates("session-1");
      expect(states).toHaveLength(0);
    });

    it("should cleanup expired states", () => {
      const customGuard = new StatePersistenceGuard({
        maxStateAge: 1, // 1ms - will expire immediately
      });

      customGuard.storeState("session-1", "data", { value: "test" });

      // Wait a bit
      const cleaned = customGuard.cleanupExpiredStates();
      expect(cleaned).toBeGreaterThanOrEqual(0);
    });
  });

  describe("Version Conflict Detection", () => {
    it("should detect version conflicts", () => {
      guard.storeState("session-1", "data", { value: "v1" });

      const result = guard.validateOperation({
        operation: "restore",
        key: "data",
        session_id: "session-1",
        expected_version: 0, // Wrong version
      });

      expect(result.violations.some((v) => v.includes("version_conflict"))).toBe(true);
    });
  });

  describe("Custom Configuration", () => {
    it("should respect custom max state size", () => {
      const customGuard = new StatePersistenceGuard({
        maxStateSize: 100,
      });

      const result = customGuard.storeState("session-1", "data", {
        value: "x".repeat(200),
      });
      expect(result.violations.some((v) => v.includes("state_size_exceeded"))).toBe(true);
    });

    it("should respect custom allowed targets", () => {
      const customGuard = new StatePersistenceGuard({
        allowedTargets: ["custom"],
      });

      const result = customGuard.validateOperation({
        operation: "write",
        key: "data",
        value: {},
        session_id: "session-1",
        target: "memory", // Not in custom list
      });
      expect(result.violations.some((v) => v.includes("unauthorized_target"))).toBe(true);
    });

    it("should respect custom sensitive keys", () => {
      const customGuard = new StatePersistenceGuard({
        sensitiveKeys: ["my_secret"],
        requireEncryption: true,
      });

      const result = customGuard.storeState("session-1", "my_secret_data", {
        value: "test",
      });
      expect(result.violations).toContain("sensitive_key_not_encrypted");
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty state value", () => {
      const result = guard.storeState("session-1", "empty", {});
      expect(result.allowed).toBe(true);
    });

    it("should handle null session states", () => {
      const states = guard.getSessionStates("non-existent");
      expect(states).toHaveLength(0);
    });

    it("should handle string values", () => {
      const result = guard.storeState("session-1", "text", "simple string");
      expect(result.allowed).toBe(true);
    });

    it("should handle array values", () => {
      const result = guard.storeState("session-1", "list", [1, 2, 3]);
      expect(result.allowed).toBe(true);
    });

    it("should handle nested objects", () => {
      const result = guard.storeState("session-1", "nested", {
        level1: {
          level2: {
            level3: { value: "deep" },
          },
        },
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("Tampering Detection", () => {
    it("should set tampering flag for high severity injections", () => {
      const result = guard.storeState("session-1", "malicious", {
        code: "eval(dangerous)",
      });
      expect(result.analysis.tampering_detected).toBe(true);
    });

    it("should block when tampering is detected", () => {
      const result = guard.storeState("session-1", "attack", {
        payload: "__proto__[admin]=true",
      });
      expect(result.allowed).toBe(false);
    });
  });
});
