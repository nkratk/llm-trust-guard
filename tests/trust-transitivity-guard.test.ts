import { describe, it, expect, beforeEach } from "vitest";
import {
  TrustTransitivityGuard,
  type AgentTrustEntry,
} from "../src/guards/trust-transitivity-guard";

describe("TrustTransitivityGuard", () => {
  let guard: TrustTransitivityGuard;

  const A: AgentTrustEntry = {
    agentId: "A",
    trustScore: 90,
    trustedAgents: ["B"],
  };
  const B: AgentTrustEntry = {
    agentId: "B",
    trustScore: 80,
    trustedAgents: ["C"],
  };
  const C: AgentTrustEntry = {
    agentId: "C",
    trustScore: 70,
    trustedAgents: [],
  };

  beforeEach(() => {
    guard = new TrustTransitivityGuard();
    guard.registerAgent(A);
    guard.registerAgent(B);
    guard.registerAgent(C);
  });

  describe("Direct trust (single agent)", () => {
    it("allows a single registered agent with no hops", () => {
      const result = guard.validateTrustChain(["A"]);
      expect(result.allowed).toBe(true);
      expect(result.chain_analysis.chain_depth).toBe(0);
    });

    it("rejects empty chain", () => {
      const result = guard.validateTrustChain([]);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("empty_chain");
    });
  });

  describe("One-hop transitivity (default)", () => {
    it("allows A→B (direct trust, 1 hop)", () => {
      const result = guard.validateTrustChain(["A", "B"]);
      expect(result.allowed).toBe(true);
      expect(result.chain_analysis.chain_depth).toBe(1);
    });

    it("blocks A→B→C when mode is one-hop (2 hops)", () => {
      const result = guard.validateTrustChain(["A", "B", "C"]);
      expect(result.allowed).toBe(false);
      expect(result.violations.some((v) => v.includes("transitivity_one_hop"))).toBe(true);
    });
  });

  describe("Full transitivity mode", () => {
    it("allows A→B→C with full mode", () => {
      const g = new TrustTransitivityGuard({ transitivity: "full" });
      g.registerAgent(A);
      g.registerAgent(B);
      g.registerAgent(C);
      const result = g.validateTrustChain(["A", "B", "C"]);
      expect(result.allowed).toBe(true);
      expect(result.chain_analysis.chain_depth).toBe(2);
    });

    it("blocks chain that exceeds maxChainDepth", () => {
      const g = new TrustTransitivityGuard({
        transitivity: "full",
        maxChainDepth: 1,
      });
      g.registerAgent(A);
      g.registerAgent(B);
      g.registerAgent(C);
      const result = g.validateTrustChain(["A", "B", "C"]);
      expect(result.allowed).toBe(false);
      expect(result.chain_analysis.depth_exceeded).toBe(true);
    });
  });

  describe("None transitivity mode", () => {
    it("blocks A→B when mode is none (no transitivity at all)", () => {
      const g = new TrustTransitivityGuard({ transitivity: "none" });
      g.registerAgent(A);
      g.registerAgent(B);
      const result = g.validateTrustChain(["A", "B"]);
      expect(result.allowed).toBe(false);
      expect(result.violations.some((v) => v.includes("transitivity_disabled"))).toBe(true);
    });

    it("allows single agent when mode is none", () => {
      const g = new TrustTransitivityGuard({ transitivity: "none" });
      g.registerAgent(A);
      const result = g.validateTrustChain(["A"]);
      expect(result.allowed).toBe(true);
    });
  });

  describe("Broken trust link", () => {
    it("rejects chain where link is not declared", () => {
      // B does NOT trust A — reverse direction
      const result = guard.validateTrustChain(["B", "A"]);
      expect(result.allowed).toBe(false);
      expect(result.chain_analysis.broken_links).toContainEqual({ from: "B", to: "A" });
    });
  });

  describe("Unknown agent", () => {
    it("rejects chain with unregistered agent", () => {
      const result = guard.validateTrustChain(["A", "Unknown"]);
      expect(result.allowed).toBe(false);
      expect(result.chain_analysis.unknown_agents).toContain("Unknown");
    });
  });

  describe("Trust decay", () => {
    it("reduces effective trust score per hop", () => {
      const g = new TrustTransitivityGuard({
        transitivity: "full",
        trustDecayPerHop: 0.2,
        minTrustScore: 10, // low threshold so decay alone doesn't block
      });
      g.registerAgent(A); // score 90
      g.registerAgent(B); // score 80
      const result = g.validateTrustChain(["A", "B"]);
      expect(result.allowed).toBe(true);
      // B score 80 * (1-0.2)^1 = 64
      expect(result.chain_analysis.final_effective_trust).toBe(64);
    });

    it("blocks when decayed trust falls below minimum", () => {
      const g = new TrustTransitivityGuard({
        transitivity: "full",
        trustDecayPerHop: 0.5,
        minTrustScore: 50,
      });
      const lowTrustAgent: AgentTrustEntry = {
        agentId: "low",
        trustScore: 60,
        trustedAgents: [],
      };
      g.registerAgent(A); // score 90
      g.registerAgent(lowTrustAgent);
      // low score * (1-0.5)^1 = 30 < 50
      const result = g.validateTrustChain(["A", "low"]);
      // broken link from A (doesn't list "low" as trusted) AND trust low
      expect(result.allowed).toBe(false);
      expect(result.chain_analysis.trust_below_minimum).toBe(true);
    });
  });

  describe("directlyTrusts helper", () => {
    it("returns true when agent declares trust", () => {
      expect(guard.directlyTrusts("A", "B")).toBe(true);
    });

    it("returns false for undeclared trust", () => {
      expect(guard.directlyTrusts("A", "C")).toBe(false);
    });
  });

  describe("updateTrustScore", () => {
    it("updates trust score and affects decay calculation", () => {
      guard.updateTrustScore("B", 10);
      const g2 = new TrustTransitivityGuard({
        transitivity: "full",
        minTrustScore: 50,
      });
      g2.registerAgent(A);
      g2.registerAgent({ ...B, trustScore: 10 });
      const result = g2.validateTrustChain(["A", "B"]);
      expect(result.allowed).toBe(false);
    });
  });
});
