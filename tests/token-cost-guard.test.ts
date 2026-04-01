import { describe, it, expect, beforeEach } from "vitest";
import { TokenCostGuard } from "../src/guards/token-cost-guard";

describe("TokenCostGuard", () => {
  let guard: TokenCostGuard;

  beforeEach(() => {
    guard = new TokenCostGuard({
      maxTokensPerSession: 10000,
      maxTokensPerUser: 50000,
      maxCostPerSession: 1.0,
      maxCostPerUser: 5.0,
      maxTokensPerRequest: 5000,
      inputTokenCostPer1K: 0.003,
      outputTokenCostPer1K: 0.015,
      alertThreshold: 0.8,
    });
  });

  describe("Token Tracking", () => {
    it("should allow usage within limits", () => {
      const result = guard.trackUsage("s1", "u1", 100, 50);
      expect(result.allowed).toBe(true);
      expect(result.usage.request.totalTokens).toBe(150);
      expect(result.usage.session.totalTokens).toBe(150);
    });

    it("should accumulate usage across requests", () => {
      guard.trackUsage("s1", "u1", 1000, 500);
      guard.trackUsage("s1", "u1", 1000, 500);
      const result = guard.trackUsage("s1", "u1", 1000, 500);
      expect(result.usage.session.totalTokens).toBe(4500);
    });

    it("should block when session token limit exceeded", () => {
      // Use up most of the budget (stay under 5000 per-request limit)
      guard.trackUsage("s1", "u1", 2000, 2000); // 4000
      guard.trackUsage("s1", "u1", 2000, 2000); // 8000
      const result = guard.trackUsage("s1", "u1", 2000, 1000); // would be 11000 > 10000
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("SESSION_TOKEN_LIMIT_EXCEEDED");
    });

    it("should block when per-request limit exceeded", () => {
      const result = guard.trackUsage("s1", "u1", 3000, 3000); // 6000 > 5000 maxPerRequest
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("REQUEST_TOKEN_LIMIT_EXCEEDED");
    });
  });

  describe("Cost Tracking", () => {
    it("should calculate cost correctly", () => {
      const result = guard.trackUsage("s1", "u1", 1000, 1000);
      // 1000/1000 * 0.003 + 1000/1000 * 0.015 = 0.003 + 0.015 = 0.018
      expect(result.usage.request.estimatedCost).toBeCloseTo(0.018, 4);
    });

    it("should block when session cost limit exceeded", () => {
      const costGuard = new TokenCostGuard({
        maxTokensPerSession: 1000000,
        maxCostPerSession: 0.05,
        inputTokenCostPer1K: 0.003,
        outputTokenCostPer1K: 0.015,
      });
      // Each request costs ~0.018
      costGuard.trackUsage("s1", "u1", 1000, 1000); // 0.018
      costGuard.trackUsage("s1", "u1", 1000, 1000); // 0.036
      const result = costGuard.trackUsage("s1", "u1", 1000, 1000); // 0.054 > 0.05
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("SESSION_COST_LIMIT_EXCEEDED");
    });
  });

  describe("User Budget", () => {
    it("should track across sessions for the same user", () => {
      guard.trackUsage("s1", "u1", 3000, 2000);
      guard.trackUsage("s2", "u1", 3000, 2000);
      const result = guard.trackUsage("s3", "u1", 1000, 500);
      expect(result.usage.user.totalTokens).toBe(11500);
    });

    it("should block when user token limit exceeded", () => {
      const smallGuard = new TokenCostGuard({ maxTokensPerUser: 5000, maxTokensPerSession: 100000 });
      smallGuard.trackUsage("s1", "u1", 2000, 1000);
      const result = smallGuard.trackUsage("s2", "u1", 2000, 1000); // 6000 > 5000
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("USER_TOKEN_LIMIT_EXCEEDED");
    });
  });

  describe("Alert Threshold", () => {
    it("should trigger alert at 80% usage", () => {
      guard.trackUsage("s1", "u1", 2000, 2000); // 4000
      guard.trackUsage("s1", "u1", 2000, 2000); // 8000 of 10000 = 80%
      const result = guard.trackUsage("s1", "u1", 100, 50);
      expect(result.budget.alert).toBe(true);
      expect(result.budget.alert_message).toContain("approaching limit");
    });

    it("should not alert below threshold", () => {
      const result = guard.trackUsage("s1", "u1", 100, 50);
      expect(result.budget.alert).toBe(false);
    });
  });

  describe("Budget Query", () => {
    it("should return remaining budget", () => {
      guard.trackUsage("s1", "u1", 2000, 1000);
      const budget = guard.getBudget("s1", "u1");
      expect(budget.session_remaining_tokens).toBe(7000);
    });

    it("should return full budget for unknown session", () => {
      const budget = guard.getBudget("unknown", "unknown");
      expect(budget.session_remaining_tokens).toBe(10000);
    });
  });

  describe("Reset", () => {
    it("should reset session budget", () => {
      guard.trackUsage("s1", "u1", 5000, 3000);
      guard.resetSession("s1");
      const result = guard.trackUsage("s1", "u1", 100, 50);
      expect(result.usage.session.totalTokens).toBe(150);
    });
  });
});
