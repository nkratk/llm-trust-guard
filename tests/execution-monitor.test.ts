import { describe, it, expect, beforeEach } from "vitest";
import { ExecutionMonitor } from "../src/guards/execution-monitor";

describe("ExecutionMonitor", () => {
  let monitor: ExecutionMonitor;

  beforeEach(() => {
    monitor = new ExecutionMonitor({
      maxRequestsPerMinute: 5,
      maxRequestsPerHour: 100,
      maxConcurrentOperations: 2,
      operationCosts: {
        generate_report: 10,
        simple_query: 1,
      },
      maxCostPerMinute: 20,
      maxCostPerHour: 200,
      trackByUser: true,
      trackBySession: true,
    });
  });

  describe("Rate Limit Blocking (Per Minute)", () => {
    it("should allow requests within the per-minute limit", () => {
      for (let i = 0; i < 5; i++) {
        const result = monitor.check("simple_query", "user-1", "session-1");
        expect(result.allowed).toBe(true);
        monitor.completeOperation("user-1", "session-1");
      }
    });

    it("should block when per-minute rate limit is exceeded", () => {
      // Send 5 requests (the limit) - all should pass
      for (let i = 0; i < 5; i++) {
        const result = monitor.check("simple_query", "user-1", "session-1");
        expect(result.allowed).toBe(true);
        monitor.completeOperation("user-1", "session-1");
      }

      // 6th request should be blocked
      const blocked = monitor.check("simple_query", "user-1", "session-1");
      expect(blocked.allowed).toBe(false);
      expect(blocked.throttled).toBe(true);
      expect(blocked.violations).toContain("RATE_LIMIT_MINUTE_EXCEEDED");
      expect(blocked.retry_after_ms).toBeDefined();
      expect(blocked.retry_after_ms!).toBeGreaterThan(0);
    });

    it("should track rate limits per session independently", () => {
      // Fill up session-1
      for (let i = 0; i < 5; i++) {
        monitor.check("simple_query", "user-1", "session-1");
        monitor.completeOperation("user-1", "session-1");
      }

      // session-2 should still be allowed
      const result = monitor.check("simple_query", "user-1", "session-2");
      expect(result.allowed).toBe(true);
    });
  });

  describe("Cost Tracking", () => {
    it("should track operation costs and block when cost limit exceeded", () => {
      // generate_report costs 10 each, maxCostPerMinute = 20
      const r1 = monitor.check("generate_report", "user-1", "session-1");
      expect(r1.allowed).toBe(true);
      expect(r1.cost_info.operation_cost).toBe(10);
      monitor.completeOperation("user-1", "session-1");

      const r2 = monitor.check("generate_report", "user-1", "session-1");
      expect(r2.allowed).toBe(true);
      monitor.completeOperation("user-1", "session-1");

      // Third report (cost = 30 total) should exceed maxCostPerMinute (20)
      const r3 = monitor.check("generate_report", "user-1", "session-1");
      expect(r3.allowed).toBe(false);
      expect(r3.violations).toContain("COST_LIMIT_MINUTE_EXCEEDED");
    });

    it("should default cost to 1 for unknown operations", () => {
      const result = monitor.check("unknown_tool", "user-1", "session-1");
      expect(result.allowed).toBe(true);
      expect(result.cost_info.operation_cost).toBe(1);
    });
  });

  describe("Concurrent Operation Limit", () => {
    it("should block when concurrent operations exceed limit", () => {
      // maxConcurrentOperations = 2
      const r1 = monitor.check("simple_query", "user-1", "session-1");
      expect(r1.allowed).toBe(true);

      const r2 = monitor.check("simple_query", "user-1", "session-1");
      expect(r2.allowed).toBe(true);

      // 3rd concurrent (without completing any) should be blocked
      const r3 = monitor.check("simple_query", "user-1", "session-1");
      expect(r3.allowed).toBe(false);
      expect(r3.violations).toContain("MAX_CONCURRENT_OPERATIONS_EXCEEDED");
    });

    it("should allow new operations after completing previous ones", () => {
      monitor.check("simple_query", "user-1", "session-1");
      monitor.check("simple_query", "user-1", "session-1");

      // Complete one operation
      monitor.completeOperation("user-1", "session-1");

      // Now another should be allowed
      const result = monitor.check("simple_query", "user-1", "session-1");
      expect(result.allowed).toBe(true);
    });
  });

  describe("Optimistic-Record-Then-Rollback Pattern", () => {
    it("should rollback recorded request when blocked", () => {
      // Fill up to limit
      for (let i = 0; i < 5; i++) {
        monitor.check("simple_query", "user-1", "session-1");
        monitor.completeOperation("user-1", "session-1");
      }

      // This will be blocked - the optimistic record should be rolled back
      const blocked = monitor.check("simple_query", "user-1", "session-1");
      expect(blocked.allowed).toBe(false);

      // Verify the status reflects the rollback (should show 5, not 6)
      const status = monitor.getStatus("user-1", "session-1");
      expect(status.requests_per_minute).toBe(5);
    });
  });

  describe("Reset Functionality", () => {
    it("should reset session limits", () => {
      for (let i = 0; i < 5; i++) {
        monitor.check("simple_query", "user-1", "session-1");
        monitor.completeOperation("user-1", "session-1");
      }

      // Should be at limit
      const blocked = monitor.check("simple_query", "user-1", "session-1");
      expect(blocked.allowed).toBe(false);

      // Reset session
      monitor.reset("user-1", "session-1");

      // Should be allowed again
      const result = monitor.check("simple_query", "user-1", "session-1");
      expect(result.allowed).toBe(true);
    });

    it("should reset global limits when no user/session specified", () => {
      const globalMonitor = new ExecutionMonitor({
        maxRequestsPerMinute: 2,
        trackByUser: false,
        trackBySession: false,
      });

      globalMonitor.check("tool_a");
      globalMonitor.completeOperation();
      globalMonitor.check("tool_b");
      globalMonitor.completeOperation();

      const blocked = globalMonitor.check("tool_c");
      expect(blocked.allowed).toBe(false);

      globalMonitor.reset();

      const allowed = globalMonitor.check("tool_d");
      expect(allowed.allowed).toBe(true);
    });
  });

  describe("Rate Limit Info in Response", () => {
    it("should include accurate rate limit info in result", () => {
      const result = monitor.check("simple_query", "user-1", "session-1");
      expect(result.rate_limit_info).toBeDefined();
      expect(result.rate_limit_info.requests_this_minute).toBe(1);
      expect(result.rate_limit_info.max_per_minute).toBe(5);
      expect(result.rate_limit_info.max_per_hour).toBe(100);
    });
  });

  describe("False Positive - Normal Usage", () => {
    it("should allow steady normal usage without blocking", () => {
      for (let i = 0; i < 3; i++) {
        const result = monitor.check("simple_query", "user-1", "session-1");
        expect(result.allowed).toBe(true);
        expect(result.throttled).toBe(false);
        monitor.completeOperation("user-1", "session-1");
      }
    });
  });
});
