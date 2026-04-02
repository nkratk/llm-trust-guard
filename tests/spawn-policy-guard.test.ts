import { describe, it, expect, beforeEach } from "vitest";
import { SpawnPolicyGuard } from "../src/guards/spawn-policy-guard";

describe("SpawnPolicyGuard", () => {
  let guard: SpawnPolicyGuard;

  beforeEach(() => {
    guard = new SpawnPolicyGuard();
    guard.registerParent("root-agent");
  });

  describe("Default policy", () => {
    it("allows a registered parent to spawn at depth 0", () => {
      const result = guard.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "child-1",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      expect(result.allowed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it("blocks an unregistered parent by default", () => {
      const result = guard.validateSpawn({
        parentAgentId: "unknown-agent",
        childAgentId: "child-x",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("parent_not_registered");
      expect(result.policy_analysis.parent_not_registered).toBe(true);
    });

    it("blocks third-party spawning by default", () => {
      const result = guard.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "ext-agent",
        spawnOrigin: "openai",
        delegationDepth: 0,
        isThirdParty: true,
      });
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("third_party_spawning_blocked");
      expect(result.policy_analysis.third_party_blocked).toBe(true);
    });

    it("blocks when delegation depth >= maxDelegationDepth (default 2)", () => {
      const result = guard.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "deep-child",
        spawnOrigin: "internal",
        delegationDepth: 2,
        isThirdParty: false,
      });
      expect(result.allowed).toBe(false);
      expect(result.policy_analysis.depth_exceeded).toBe(true);
    });
  });

  describe("Origin allowlist", () => {
    it("blocks origins not in the allowlist", () => {
      const g = new SpawnPolicyGuard({ allowedSpawnOrigins: ["internal"] });
      g.registerParent("root-agent");
      const result = g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "child-2",
        spawnOrigin: "anthropic",
        delegationDepth: 0,
        isThirdParty: false,
      });
      expect(result.allowed).toBe(false);
      expect(result.policy_analysis.origin_blocked).toBe(true);
    });

    it("allows origin in the allowlist", () => {
      const g = new SpawnPolicyGuard({
        allowedSpawnOrigins: ["internal", "anthropic"],
      });
      g.registerParent("root-agent");
      const result = g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "child-3",
        spawnOrigin: "anthropic",
        delegationDepth: 0,
        isThirdParty: false,
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("maxChildrenPerParent", () => {
    it("blocks spawn when parent exceeds child limit", () => {
      const g = new SpawnPolicyGuard({ maxChildrenPerParent: 2 });
      g.registerParent("root-agent");

      g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "c1",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "c2",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });

      const result = g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "c3",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      expect(result.allowed).toBe(false);
      expect(result.policy_analysis.children_limit_exceeded).toBe(true);
    });

    it("allows spawn again after removing a child", () => {
      const g = new SpawnPolicyGuard({ maxChildrenPerParent: 1 });
      g.registerParent("root-agent");

      g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "c1",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      g.removeChild("root-agent", "c1");

      const result = g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "c2",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("Human approval gate", () => {
    it("sets requires_human_approval when configured", () => {
      const g = new SpawnPolicyGuard({ requireApprovalForNewAgents: true });
      g.registerParent("root-agent");
      const result = g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "child-4",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      // approval flag is set but not a blocking violation
      expect(result.requires_human_approval).toBe(true);
      expect(result.policy_analysis.approval_required).toBe(true);
    });
  });

  describe("Third-party allowed", () => {
    it("allows third-party spawn when explicitly permitted", () => {
      const g = new SpawnPolicyGuard({ allowThirdPartySpawning: true });
      g.registerParent("root-agent");
      const result = g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "ext-child",
        spawnOrigin: "openai",
        delegationDepth: 0,
        isThirdParty: true,
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("maxDelegationDepth = 0", () => {
    it("blocks all spawning when depth is 0", () => {
      const g = new SpawnPolicyGuard({ maxDelegationDepth: 0 });
      g.registerParent("root-agent");
      const result = g.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "child",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      expect(result.allowed).toBe(false);
      expect(result.policy_analysis.depth_exceeded).toBe(true);
    });
  });

  describe("getChildCount", () => {
    it("tracks child count correctly", () => {
      guard.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "x1",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      guard.validateSpawn({
        parentAgentId: "root-agent",
        childAgentId: "x2",
        spawnOrigin: "internal",
        delegationDepth: 0,
        isThirdParty: false,
      });
      expect(guard.getChildCount("root-agent")).toBe(2);
    });
  });
});
