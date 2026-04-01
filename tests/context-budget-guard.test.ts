import { describe, it, expect, beforeEach } from "vitest";
import { ContextBudgetGuard } from "../src/guards/context-budget-guard";

describe("ContextBudgetGuard", () => {
  let guard: ContextBudgetGuard;

  beforeEach(() => {
    guard = new ContextBudgetGuard({
      maxTotalTokens: 1000,
      systemPromptReserve: 200,
      maxTurnsPerSession: 10,
      maxSimilarMessages: 3,
    });
  });

  describe("Budget Tracking", () => {
    it("should allow content within budget", () => {
      const result = guard.trackContext("s1", "user_input", "Hello, how are you?");
      expect(result.allowed).toBe(true);
      expect(result.budget.used_tokens).toBeGreaterThan(0);
      expect(result.budget.remaining_tokens).toBeGreaterThan(0);
    });

    it("should block when budget exceeded", () => {
      // Effective budget = 1000 - 200 = 800 tokens ≈ 2800 chars
      const longContent = "a".repeat(3000);
      const result = guard.trackContext("s1", "user_input", longContent);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("CONTEXT_BUDGET_EXCEEDED");
    });

    it("should track across multiple sources", () => {
      guard.trackContext("s1", "system_prompt", "You are a helpful assistant.");
      guard.trackContext("s1", "user_input", "What is the weather?");
      const budget = guard.getSessionBudget("s1");
      expect(budget).not.toBeNull();
      expect(budget!.sources).toHaveProperty("system_prompt");
      expect(budget!.sources).toHaveProperty("user_input");
    });

    it("should track cumulative usage", () => {
      for (let i = 0; i < 5; i++) {
        guard.trackContext("s1", "user_input", "Message " + i + " with some content padding here.");
      }
      const budget = guard.getSessionBudget("s1");
      expect(budget!.turn_count).toBe(5);
    });
  });

  describe("Turn Limits", () => {
    it("should block when max turns exceeded", () => {
      let lastResult;
      for (let i = 0; i < 12; i++) {
        lastResult = guard.trackContext("s1", "user_input", "hi");
      }
      expect(lastResult!.allowed).toBe(false);
      expect(lastResult!.violations).toContain("MAX_TURNS_EXCEEDED");
    });
  });

  describe("Many-Shot Detection", () => {
    it("should detect repeated similar messages", () => {
      let detected = false;
      for (let i = 0; i < 6; i++) {
        const result = guard.trackContext("s1", "user_input", "Tell me about topic number " + i);
        if (result.many_shot_detected) detected = true;
      }
      expect(detected).toBe(true);
    });

    it("should not flag diverse messages", () => {
      const messages = [
        "What is the weather today?",
        "Can you help me with my order?",
        "I need to reset my password",
        "Tell me about your return policy",
      ];
      let detected = false;
      for (const msg of messages) {
        const result = guard.trackContext("s1", "user_input", msg);
        if (result.many_shot_detected) detected = true;
      }
      expect(detected).toBe(false);
    });
  });

  describe("Session Management", () => {
    it("should track sessions independently", () => {
      guard.trackContext("s1", "user_input", "a".repeat(2500));
      const result = guard.trackContext("s2", "user_input", "Hello");
      expect(result.allowed).toBe(true);
    });

    it("should reset session correctly", () => {
      guard.trackContext("s1", "user_input", "Some content");
      guard.resetSession("s1");
      expect(guard.getSessionBudget("s1")).toBeNull();
    });
  });
});
