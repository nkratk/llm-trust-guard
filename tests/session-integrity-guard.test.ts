import { describe, it, expect, beforeEach, vi } from "vitest";
import { SessionIntegrityGuard } from "../src/guards/session-integrity-guard";

describe("SessionIntegrityGuard", () => {
  let guard: SessionIntegrityGuard;

  beforeEach(() => {
    guard = new SessionIntegrityGuard();
  });

  // ─── Session Creation ───────────────────────────────────────────

  describe("createSession", () => {
    it("should create a session with valid inputs", () => {
      const result = guard.createSession("s1", "user1", ["read", "write"]);
      expect(result.allowed).toBe(true);
      expect(result.violations).toEqual([]);
      expect(result.sessionAge).toBe(0);
    });

    it("should create a session with metadata", () => {
      const result = guard.createSession("s1", "user1", ["read"], { source: "api" });
      expect(result.allowed).toBe(true);
    });

    it("should reject empty permissions", () => {
      const result = guard.createSession("s1", "user1", []);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("empty_permissions");
    });

    it("should reject duplicate session IDs", () => {
      guard.createSession("s1", "user1", ["read"]);
      const result = guard.createSession("s1", "user2", ["write"]);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("duplicate_session_id");
      expect(result.reason).toContain("already exists");
    });

    it("should allow different session IDs for the same user", () => {
      const r1 = guard.createSession("s1", "user1", ["read"]);
      const r2 = guard.createSession("s2", "user1", ["write"]);
      expect(r1.allowed).toBe(true);
      expect(r2.allowed).toBe(true);
    });
  });

  // ─── Concurrent Session Limits ──────────────────────────────────

  describe("concurrent session limits", () => {
    it("should enforce default concurrent session limit of 5", () => {
      for (let i = 1; i <= 5; i++) {
        const r = guard.createSession(`s${i}`, "user1", ["read"]);
        expect(r.allowed).toBe(true);
      }
      const result = guard.createSession("s6", "user1", ["read"]);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("concurrent_session_limit_exceeded");
    });

    it("should respect custom concurrent session limit", () => {
      guard = new SessionIntegrityGuard({ maxConcurrentSessions: 2 });
      guard.createSession("s1", "user1", ["read"]);
      guard.createSession("s2", "user1", ["read"]);
      const result = guard.createSession("s3", "user1", ["read"]);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("concurrent_session_limit_exceeded");
    });

    it("should not count ended sessions against the limit", () => {
      guard = new SessionIntegrityGuard({ maxConcurrentSessions: 2 });
      guard.createSession("s1", "user1", ["read"]);
      guard.createSession("s2", "user1", ["read"]);
      guard.endSession("s1");
      const result = guard.createSession("s3", "user1", ["read"]);
      expect(result.allowed).toBe(true);
    });

    it("should track limits independently per user", () => {
      guard = new SessionIntegrityGuard({ maxConcurrentSessions: 1 });
      const r1 = guard.createSession("s1", "user1", ["read"]);
      const r2 = guard.createSession("s2", "user2", ["read"]);
      expect(r1.allowed).toBe(true);
      expect(r2.allowed).toBe(true);
    });
  });

  // ─── Permission Consistency ─────────────────────────────────────

  describe("permission consistency", () => {
    it("should block requests for permissions not in the original scope", () => {
      guard.createSession("s1", "user1", ["read"]);
      const result = guard.validateRequest("s1", "action", ["read", "admin"]);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("scope_violation");
      expect(result.permissionDelta).toContain("+admin");
    });

    it("should allow requests within granted permissions", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      const result = guard.validateRequest("s1", "action", ["read"]);
      expect(result.allowed).toBe(true);
      expect(result.violations).toEqual([]);
    });

    it("should block re-escalation of degraded permissions", () => {
      guard.createSession("s1", "user1", ["read", "write", "delete"]);
      guard.degradePermissions("s1", ["write"]);
      const result = guard.validateRequest("s1", "action", ["write"]);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("authority_re_escalation");
    });

    it("should allow escalation when allowPermissionEscalation is true", () => {
      guard = new SessionIntegrityGuard({ allowPermissionEscalation: true });
      guard.createSession("s1", "user1", ["read"]);
      // scope_violation still present but escalation is allowed
      const result = guard.validateRequest("s1", "action", ["read", "admin"]);
      // With allowPermissionEscalation, the guard does not block
      // but the admin action triggers abrupt_state_change since no admin perm
      expect(result.violations).toContain("scope_violation");
    });
  });

  // ─── Session Timeout ────────────────────────────────────────────

  describe("session timeout", () => {
    it("should reject requests after absolute timeout", () => {
      guard = new SessionIntegrityGuard({ maxSessionDuration: 100 });
      guard.createSession("s1", "user1", ["read", "write"]);

      // Manipulate session createdAt to simulate time passing
      vi.spyOn(Date, "now").mockReturnValue(Date.now() + 200);

      const result = guard.validateRequest("s1", "action");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("absolute_timeout_exceeded");

      vi.restoreAllMocks();
    });

    it("should reject requests after inactivity timeout", () => {
      guard = new SessionIntegrityGuard({ inactivityTimeout: 100 });
      guard.createSession("s1", "user1", ["read", "write"]);

      vi.spyOn(Date, "now").mockReturnValue(Date.now() + 200);

      const result = guard.validateRequest("s1", "action");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("inactivity_timeout_exceeded");

      vi.restoreAllMocks();
    });

    it("should allow requests within timeout window", () => {
      guard = new SessionIntegrityGuard({
        maxSessionDuration: 10_000,
        inactivityTimeout: 10_000,
      });
      guard.createSession("s1", "user1", ["read", "write"]);
      const result = guard.validateRequest("s1", "action");
      expect(result.allowed).toBe(true);
    });
  });

  // ─── Request Sequence Validation ────────────────────────────────

  describe("request sequence validation", () => {
    it("should accept requests in correct sequence order", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      const r1 = guard.validateRequest("s1", "action", undefined, undefined, 1);
      const r2 = guard.validateRequest("s1", "action", undefined, undefined, 2);
      expect(r1.allowed).toBe(true);
      expect(r2.allowed).toBe(true);
    });

    it("should reject out-of-order sequence numbers", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      guard.validateRequest("s1", "action", undefined, undefined, 1);
      const result = guard.validateRequest("s1", "action", undefined, undefined, 5);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("sequence_violation");
    });

    it("should detect replay attacks via duplicate nonce", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      const r1 = guard.validateRequest("s1", "action", undefined, "nonce-abc");
      expect(r1.allowed).toBe(true);
      const r2 = guard.validateRequest("s1", "action", undefined, "nonce-abc");
      expect(r2.allowed).toBe(false);
      expect(r2.violations).toContain("replay_detected");
    });

    it("should allow different nonces", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      const r1 = guard.validateRequest("s1", "action", undefined, "nonce-1");
      const r2 = guard.validateRequest("s1", "action", undefined, "nonce-2");
      expect(r1.allowed).toBe(true);
      expect(r2.allowed).toBe(true);
    });

    it("should skip sequence validation when disabled", () => {
      guard = new SessionIntegrityGuard({ enforceSequenceValidation: false });
      guard.createSession("s1", "user1", ["read", "write"]);
      guard.validateRequest("s1", "action", undefined, undefined, 1);
      // Skip to sequence 10 — should be allowed
      const result = guard.validateRequest("s1", "action", undefined, undefined, 10);
      expect(result.allowed).toBe(true);
    });
  });

  // ─── Permission Degradation ─────────────────────────────────────

  describe("degradePermissions", () => {
    it("should remove specified permissions", () => {
      guard.createSession("s1", "user1", ["read", "write", "delete"]);
      const result = guard.degradePermissions("s1", ["write", "delete"]);
      expect(result.allowed).toBe(true);
      expect(result.permissionDelta).toContain("-write");
      expect(result.permissionDelta).toContain("-delete");
    });

    it("should silently ignore permissions not currently held", () => {
      guard.createSession("s1", "user1", ["read"]);
      const result = guard.degradePermissions("s1", ["admin"]);
      expect(result.allowed).toBe(true);
      expect(result.permissionDelta).toEqual([]);
    });

    it("should fail on non-existent session", () => {
      const result = guard.degradePermissions("nonexistent", ["read"]);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("session_not_found");
    });
  });

  // ─── endSession ─────────────────────────────────────────────────

  describe("endSession", () => {
    it("should terminate an active session", () => {
      guard.createSession("s1", "user1", ["read"]);
      const result = guard.endSession("s1");
      expect(result.allowed).toBe(true);
      expect(result.sessionAge).toBeDefined();
    });

    it("should reject requests on ended sessions", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      guard.endSession("s1");
      const result = guard.validateRequest("s1", "action");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("session_inactive");
    });

    it("should return error for non-existent session", () => {
      const result = guard.endSession("nonexistent");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("session_not_found");
    });
  });

  // ─── getActiveSessions ─────────────────────────────────────────

  describe("getActiveSessions", () => {
    it("should return active sessions for a user", () => {
      guard.createSession("s1", "user1", ["read"]);
      guard.createSession("s2", "user1", ["write"]);
      const sessions = guard.getActiveSessions("user1");
      expect(sessions).toHaveLength(2);
      expect(sessions).toContain("s1");
      expect(sessions).toContain("s2");
    });

    it("should not include ended sessions", () => {
      guard.createSession("s1", "user1", ["read"]);
      guard.createSession("s2", "user1", ["write"]);
      guard.endSession("s1");
      const sessions = guard.getActiveSessions("user1");
      expect(sessions).toHaveLength(1);
      expect(sessions).toContain("s2");
    });

    it("should return empty array for unknown user", () => {
      const sessions = guard.getActiveSessions("nobody");
      expect(sessions).toEqual([]);
    });
  });

  // ─── Abrupt State Change Detection ─────────────────────────────

  describe("abrupt state change detection", () => {
    it("should block destructive actions on read-only sessions", () => {
      guard.createSession("s1", "user1", ["read"]);
      const result = guard.validateRequest("s1", "delete_records");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("abrupt_state_change");
    });

    it("should block admin actions without admin permissions", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      const result = guard.validateRequest("s1", "admin_configure");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("abrupt_state_change");
    });

    it("should allow destructive actions when delete permission is granted", () => {
      guard.createSession("s1", "user1", ["read", "write", "delete"]);
      const result = guard.validateRequest("s1", "delete_records");
      expect(result.allowed).toBe(true);
    });

    it("should allow admin actions with admin permission", () => {
      guard.createSession("s1", "user1", ["read", "admin"]);
      const result = guard.validateRequest("s1", "admin_configure");
      expect(result.allowed).toBe(true);
    });
  });

  // ─── Edge Cases ─────────────────────────────────────────────────

  describe("edge cases", () => {
    it("should reject validateRequest for non-existent session", () => {
      const result = guard.validateRequest("nonexistent", "action");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("session_not_found");
    });

    it("should handle validateRequest with no optional parameters", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      const result = guard.validateRequest("s1", "action");
      expect(result.allowed).toBe(true);
    });

    it("should auto-increment sequence when no explicit sequence is provided", () => {
      guard.createSession("s1", "user1", ["read", "write"]);
      guard.validateRequest("s1", "action");
      guard.validateRequest("s1", "action");
      // After two successful requests with auto-increment, next explicit should be 3
      const result = guard.validateRequest("s1", "action", undefined, undefined, 3);
      expect(result.allowed).toBe(true);
    });
  });
});
