import { describe, it, expect, beforeEach, vi } from "vitest";
import { CircuitBreaker } from "../src/guards/circuit-breaker";

describe("CircuitBreaker", () => {
  let breaker: CircuitBreaker;
  const circuitId = "test-circuit";

  beforeEach(() => {
    breaker = new CircuitBreaker({
      failureThreshold: 50,
      minimumRequests: 3,
      maxConsecutiveFailures: 3,
      recoveryTimeout: 1000, // 1 second for fast tests
      successThreshold: 2,
      autoRecover: true,
      windowSize: 60000,
    });
  });

  describe("Circuit Opens After Consecutive Failures", () => {
    it("should open circuit after maxConsecutiveFailures", () => {
      // Record consecutive failures
      breaker.recordFailure(circuitId, "error 1");
      breaker.recordFailure(circuitId, "error 2");
      breaker.recordFailure(circuitId, "error 3");

      const result = breaker.check(circuitId);
      expect(result.allowed).toBe(false);
      expect(result.state).toBe("open");
      expect(result.reason).toContain("open");
      expect(result.fallback_recommended).toBe(true);
    });

    it("should report retry_after when circuit is open", () => {
      breaker.recordFailure(circuitId, "err");
      breaker.recordFailure(circuitId, "err");
      breaker.recordFailure(circuitId, "err");

      const result = breaker.check(circuitId);
      expect(result.retry_after).toBeDefined();
      expect(result.retry_after!).toBeGreaterThan(0);
    });
  });

  describe("Closed State Allows Requests", () => {
    it("should allow requests when circuit is closed", () => {
      const result = breaker.check(circuitId);
      expect(result.allowed).toBe(true);
      expect(result.state).toBe("closed");
      expect(result.fallback_recommended).toBe(false);
    });

    it("should stay closed with mixed success and few failures", () => {
      breaker.recordSuccess(circuitId);
      breaker.recordSuccess(circuitId);
      breaker.recordFailure(circuitId, "occasional error");
      breaker.recordSuccess(circuitId);

      const result = breaker.check(circuitId);
      expect(result.allowed).toBe(true);
      expect(result.state).toBe("closed");
    });
  });

  describe("Half-Open State", () => {
    it("should transition to half-open after recovery timeout", async () => {
      // Open the circuit
      breaker.recordFailure(circuitId, "err");
      breaker.recordFailure(circuitId, "err");
      breaker.recordFailure(circuitId, "err");

      expect(breaker.getState(circuitId)).toBe("open");

      // Wait for recovery timeout (1 second)
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const result = breaker.check(circuitId);
      expect(result.allowed).toBe(true);
      expect(result.state).toBe("half-open");
      expect(result.fallback_recommended).toBe(true);
    });

    it("should close circuit after enough successes in half-open state", async () => {
      // Open then wait for half-open
      breaker.recordFailure(circuitId, "err");
      breaker.recordFailure(circuitId, "err");
      breaker.recordFailure(circuitId, "err");

      await new Promise((resolve) => setTimeout(resolve, 1100));
      breaker.check(circuitId); // triggers transition to half-open

      // Record successes to meet successThreshold (2)
      breaker.recordSuccess(circuitId);
      breaker.recordSuccess(circuitId);

      expect(breaker.getState(circuitId)).toBe("closed");

      const result = breaker.check(circuitId);
      expect(result.allowed).toBe(true);
      expect(result.state).toBe("closed");
    });

    it("should re-open circuit on failure in half-open state", async () => {
      breaker.recordFailure(circuitId, "err");
      breaker.recordFailure(circuitId, "err");
      breaker.recordFailure(circuitId, "err");

      await new Promise((resolve) => setTimeout(resolve, 1100));
      breaker.check(circuitId); // half-open

      // Fail again in half-open -> should re-open
      breaker.recordFailure(circuitId, "still failing");

      // After enough consecutive failures it should re-open
      // The single failure in half-open increments consecutiveFailures;
      // since we had 3 before (reset isn't done on half-open transition for consecutiveFailures),
      // it will trigger the maxConsecutiveFailures check again
      const state = breaker.getState(circuitId);
      expect(state).toBe("open");
    });
  });

  describe("Force Open / Force Close", () => {
    it("should force open a closed circuit", () => {
      expect(breaker.getState(circuitId)).toBe("closed");

      breaker.forceOpen(circuitId);
      expect(breaker.getState(circuitId)).toBe("open");

      const result = breaker.check(circuitId);
      expect(result.allowed).toBe(false);
    });

    it("should force close an open circuit", () => {
      breaker.forceOpen(circuitId);
      expect(breaker.getState(circuitId)).toBe("open");

      breaker.forceClose(circuitId);
      expect(breaker.getState(circuitId)).toBe("closed");

      const result = breaker.check(circuitId);
      expect(result.allowed).toBe(true);
    });
  });

  describe("Stats Tracking", () => {
    it("should track request stats accurately", () => {
      breaker.recordSuccess(circuitId);
      breaker.recordSuccess(circuitId);
      breaker.recordFailure(circuitId, "err");

      const stats = breaker.getStats(circuitId);
      expect(stats).not.toBeNull();
      expect(stats!.totalRequests).toBe(3);
      expect(stats!.successfulRequests).toBe(2);
      expect(stats!.failedRequests).toBe(1);
      expect(stats!.consecutiveFailures).toBe(1);
      expect(stats!.consecutiveSuccesses).toBe(0);
    });

    it("should return null stats for unknown circuit", () => {
      const stats = breaker.getStats("nonexistent");
      expect(stats).toBeNull();
    });
  });

  describe("Reset", () => {
    it("should reset circuit to initial closed state", () => {
      breaker.forceOpen(circuitId);
      expect(breaker.getState(circuitId)).toBe("open");

      breaker.reset(circuitId);
      expect(breaker.getState(circuitId)).toBe("closed");
      expect(breaker.getStats(circuitId)).toBeNull();
    });
  });

  describe("Callbacks", () => {
    it("should call onOpen callback when circuit opens", () => {
      const onOpen = vi.fn();
      const cbWithCallbacks = new CircuitBreaker({
        maxConsecutiveFailures: 2,
        onOpen,
      });

      cbWithCallbacks.recordFailure(circuitId, "err");
      cbWithCallbacks.recordFailure(circuitId, "err");

      expect(onOpen).toHaveBeenCalledWith(circuitId, expect.objectContaining({
        consecutiveFailures: 2,
      }));
    });
  });

  describe("False Positive - Healthy Service", () => {
    it("should keep circuit closed for a healthy service with occasional errors", () => {
      // Simulate a healthy service: mostly successes with occasional failure
      for (let i = 0; i < 10; i++) {
        breaker.recordSuccess(circuitId);
      }
      breaker.recordFailure(circuitId, "transient");
      breaker.recordSuccess(circuitId);

      const result = breaker.check(circuitId);
      expect(result.allowed).toBe(true);
      expect(result.state).toBe("closed");

      const health = breaker.healthCheck();
      expect(health.healthy).toBe(true);
      expect(health.openCircuits).toBe(0);
    });
  });
});
