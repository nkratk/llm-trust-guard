import { describe, it, expect, beforeEach } from "vitest";
import { DelegationScopeGuard } from "../src/guards/delegation-scope-guard";

describe("DelegationScopeGuard", () => {
  let guard: DelegationScopeGuard;

  beforeEach(() => {
    guard = new DelegationScopeGuard();
  });

  describe("Basic scope enforcement", () => {
    it("allows child to receive a strict subset of parent scopes", () => {
      const result = guard.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["read", "write", "admin"],
        childAgentId: "child",
        requestedScopes: ["read"],
        hopDepth: 0,
      });
      expect(result.allowed).toBe(true);
      expect(result.scope_analysis.granted_scopes).toEqual(["read"]);
    });

    it("allows child to receive all parent scopes", () => {
      const result = guard.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["read", "write"],
        childAgentId: "child",
        requestedScopes: ["read", "write"],
        hopDepth: 0,
      });
      expect(result.allowed).toBe(true);
    });

    it("blocks scopes not held by parent (privilege amplification)", () => {
      const result = guard.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["read"],
        childAgentId: "child",
        requestedScopes: ["read", "admin"],
        hopDepth: 0,
      });
      expect(result.allowed).toBe(false);
      expect(result.scope_analysis.out_of_parent_scopes).toContain("admin");
      expect(result.violations.some((v) => v.includes("scopes_exceed_parent"))).toBe(true);
    });
  });

  describe("Blocked scopes", () => {
    it("blocks configured blocked scopes even if parent holds them", () => {
      const g = new DelegationScopeGuard({ blockedScopes: ["admin", "superuser"] });
      const result = g.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["read", "write", "admin"],
        childAgentId: "child",
        requestedScopes: ["read", "admin"],
        hopDepth: 0,
      });
      expect(result.allowed).toBe(false);
      expect(result.scope_analysis.blocked_scopes_found).toContain("admin");
    });

    it("allows delegation of non-blocked scopes", () => {
      const g = new DelegationScopeGuard({ blockedScopes: ["admin"] });
      const result = g.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["read", "write", "admin"],
        childAgentId: "child",
        requestedScopes: ["read", "write"],
        hopDepth: 0,
      });
      expect(result.allowed).toBe(true);
      expect(result.scope_analysis.blocked_scopes_found).toHaveLength(0);
    });
  });

  describe("Scope decay per hop", () => {
    it("reduces allowed scope count per hop", () => {
      const g = new DelegationScopeGuard({ scopeDecayPerHop: 0.5 });
      // parent has 4 scopes; at hop 2 max = floor(4 * 1.0 * (1-0.5)^2) = floor(4*0.25) = 1
      const result = g.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["a", "b", "c", "d"],
        childAgentId: "child",
        requestedScopes: ["a", "b"],
        hopDepth: 2,
      });
      expect(result.allowed).toBe(false);
      expect(result.scope_analysis.decay_applied).toBe(true);
      expect(result.scope_analysis.exceeds_inheritance_limit).toBe(true);
    });

    it("allows within decayed limit", () => {
      const g = new DelegationScopeGuard({ scopeDecayPerHop: 0.5 });
      // at hop 1, max = floor(4 * 1.0 * 0.5^1) = 2
      const result = g.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["a", "b", "c", "d"],
        childAgentId: "child",
        requestedScopes: ["a", "b"],
        hopDepth: 1,
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("maxScopeInheritance", () => {
    it("limits to a fraction of parent scopes", () => {
      const g = new DelegationScopeGuard({ maxScopeInheritance: 0.5 });
      // parent has 4 scopes; max = floor(4 * 0.5) = 2
      const result = g.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["a", "b", "c", "d"],
        childAgentId: "child",
        requestedScopes: ["a", "b", "c"],
        hopDepth: 0,
      });
      expect(result.allowed).toBe(false);
      expect(result.scope_analysis.exceeds_inheritance_limit).toBe(true);
    });

    it("allows exact fraction", () => {
      const g = new DelegationScopeGuard({ maxScopeInheritance: 0.5 });
      const result = g.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["a", "b", "c", "d"],
        childAgentId: "child",
        requestedScopes: ["a", "b"],
        hopDepth: 0,
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("allowedScopes allowlist", () => {
    it("blocks scopes not in the allowlist", () => {
      const g = new DelegationScopeGuard({ allowedScopes: ["read", "list"] });
      const result = g.validateDelegation({
        parentAgentId: "parent",
        parentScopes: ["read", "write"],
        childAgentId: "child",
        requestedScopes: ["read", "write"],
        hopDepth: 0,
      });
      expect(result.allowed).toBe(false);
      expect(result.violations.some((v) => v.includes("scopes_not_in_allowlist"))).toBe(true);
    });
  });

  describe("Audit log", () => {
    it("stores delegation results in audit log", () => {
      const result = guard.validateDelegation(
        {
          parentAgentId: "parent",
          parentScopes: ["read"],
          childAgentId: "child",
          requestedScopes: ["read"],
          hopDepth: 0,
        },
        "test-req-id"
      );
      const logged = guard.getAuditLog("test-req-id");
      expect(logged).toBeDefined();
      expect(logged?.allowed).toBe(result.allowed);
    });
  });
});
