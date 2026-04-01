/**
 * L6: Execution Monitor
 *
 * Prevents resource exhaustion attacks by enforcing:
 * - Rate limiting per user/session
 * - Timeout limits on operations
 * - Resource quotas (max operations per window)
 * - Cost tracking for expensive operations
 */

import { GuardLogger } from "../types";

export interface ExecutionMonitorConfig {
  // Rate limiting
  maxRequestsPerMinute?: number;
  maxRequestsPerHour?: number;
  // Timeout limits
  defaultTimeoutMs?: number;
  maxTimeoutMs?: number;
  // Resource quotas
  maxConcurrentOperations?: number;
  // Cost tracking
  operationCosts?: Record<string, number>;
  maxCostPerMinute?: number;
  maxCostPerHour?: number;
  // Per-user/session tracking
  trackByUser?: boolean;
  trackBySession?: boolean;
  logger?: GuardLogger;
}

export interface ExecutionMonitorResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  rate_limit_info: {
    requests_this_minute: number;
    requests_this_hour: number;
    max_per_minute: number;
    max_per_hour: number;
  };
  cost_info: {
    cost_this_minute: number;
    cost_this_hour: number;
    operation_cost: number;
    max_per_minute: number;
    max_per_hour: number;
  };
  throttled: boolean;
  retry_after_ms?: number;
}

interface RateLimitEntry {
  requests: number[];
  costs: { timestamp: number; cost: number }[];
  concurrentOperations: number;
}

export class ExecutionMonitor {
  private config: ExecutionMonitorConfig;
  private logger: GuardLogger;
  private userLimits: Map<string, RateLimitEntry> = new Map();
  private sessionLimits: Map<string, RateLimitEntry> = new Map();
  private globalLimits: RateLimitEntry = {
    requests: [],
    costs: [],
    concurrentOperations: 0,
  };

  constructor(config: ExecutionMonitorConfig = {}) {
    this.config = {
      maxRequestsPerMinute: config.maxRequestsPerMinute ?? 60,
      maxRequestsPerHour: config.maxRequestsPerHour ?? 1000,
      defaultTimeoutMs: config.defaultTimeoutMs ?? 30000,
      maxTimeoutMs: config.maxTimeoutMs ?? 120000,
      maxConcurrentOperations: config.maxConcurrentOperations ?? 10,
      operationCosts: config.operationCosts ?? {},
      maxCostPerMinute: config.maxCostPerMinute ?? 100,
      maxCostPerHour: config.maxCostPerHour ?? 1000,
      trackByUser: config.trackByUser ?? true,
      trackBySession: config.trackBySession ?? true,
    };
    this.logger = config.logger || (() => {});
  }

  /**
   * Check if an operation should be allowed based on rate limits and quotas
   */
  check(
    toolName: string,
    userId?: string,
    sessionId?: string,
    requestId: string = ""
  ): ExecutionMonitorResult {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    const oneHourAgo = now - 3600000;
    const violations: string[] = [];

    // Get operation cost
    const operationCost = this.config.operationCosts?.[toolName] ?? 1;

    // Get or create rate limit entries
    const entry = this.getEntry(userId, sessionId);

    // Clean up old entries
    this.cleanupEntries(entry, oneMinuteAgo, oneHourAgo);

    // Optimistic record: add FIRST, then check (prevents TOCTOU race)
    entry.requests.push(now);
    entry.costs.push({ timestamp: now, cost: operationCost });
    entry.concurrentOperations++;

    // Count requests (including the one we just added)
    const requestsThisMinute = entry.requests.filter(
      (t) => t > oneMinuteAgo
    ).length;
    const requestsThisHour = entry.requests.filter(
      (t) => t > oneHourAgo
    ).length;

    // Calculate costs (including the one we just added)
    const costThisMinute = entry.costs
      .filter((c) => c.timestamp > oneMinuteAgo)
      .reduce((sum, c) => sum + c.cost, 0);
    const costThisHour = entry.costs
      .filter((c) => c.timestamp > oneHourAgo)
      .reduce((sum, c) => sum + c.cost, 0);

    // Check rate limits
    let throttled = false;
    let retryAfterMs: number | undefined;

    // Counts include current request (optimistic record)
    if (requestsThisMinute > this.config.maxRequestsPerMinute!) {
      violations.push("RATE_LIMIT_MINUTE_EXCEEDED");
      throttled = true;
      // Calculate when the oldest request in the minute window will expire
      const oldestInMinute = entry.requests
        .filter((t) => t > oneMinuteAgo)
        .sort()[0];
      retryAfterMs = oldestInMinute
        ? oldestInMinute + 60000 - now
        : 60000;
    }

    if (requestsThisHour > this.config.maxRequestsPerHour!) {
      violations.push("RATE_LIMIT_HOUR_EXCEEDED");
      throttled = true;
      const oldestInHour = entry.requests
        .filter((t) => t > oneHourAgo)
        .sort()[0];
      retryAfterMs = Math.max(
        retryAfterMs ?? 0,
        oldestInHour ? oldestInHour + 3600000 - now : 3600000
      );
    }

    // Check cost limits
    // Cost already includes current request (optimistic record)
    if (costThisMinute > this.config.maxCostPerMinute!) {
      violations.push("COST_LIMIT_MINUTE_EXCEEDED");
      throttled = true;
    }

    if (costThisHour > this.config.maxCostPerHour!) {
      violations.push("COST_LIMIT_HOUR_EXCEEDED");
      throttled = true;
    }

    // Check concurrent operations
    // concurrentOperations already includes current request (optimistic record)
    if (entry.concurrentOperations > this.config.maxConcurrentOperations!) {
      violations.push("MAX_CONCURRENT_OPERATIONS_EXCEEDED");
      throttled = true;
    }

    const allowed = !throttled;

    // Rollback optimistic record if blocked
    if (!allowed) {
      entry.requests.pop();
      entry.costs.pop();
      entry.concurrentOperations--;
      this.logger(
        `[ExecutionMonitor:${requestId}] BLOCKED: ${violations.join(", ")}`, "info"
      );
    }

    return {
      allowed,
      reason: allowed ? undefined : `Rate limit exceeded: ${violations.join(", ")}`,
      violations,
      rate_limit_info: {
        requests_this_minute: requestsThisMinute,
        requests_this_hour: requestsThisHour,
        max_per_minute: this.config.maxRequestsPerMinute!,
        max_per_hour: this.config.maxRequestsPerHour!,
      },
      cost_info: {
        cost_this_minute: costThisMinute,
        cost_this_hour: costThisHour,
        operation_cost: operationCost,
        max_per_minute: this.config.maxCostPerMinute!,
        max_per_hour: this.config.maxCostPerHour!,
      },
      throttled,
      retry_after_ms: retryAfterMs,
    };
  }

  /**
   * Mark an operation as complete (decrements concurrent operation count)
   */
  completeOperation(userId?: string, sessionId?: string): void {
    const entry = this.getEntry(userId, sessionId);
    if (entry.concurrentOperations > 0) {
      entry.concurrentOperations--;
    }
  }

  /**
   * Get rate limit status for a user/session
   */
  getStatus(
    userId?: string,
    sessionId?: string
  ): {
    requests_per_minute: number;
    requests_per_hour: number;
    concurrent_operations: number;
    cost_per_minute: number;
    cost_per_hour: number;
  } {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    const oneHourAgo = now - 3600000;
    const entry = this.getEntry(userId, sessionId);

    return {
      requests_per_minute: entry.requests.filter((t) => t > oneMinuteAgo)
        .length,
      requests_per_hour: entry.requests.filter((t) => t > oneHourAgo).length,
      concurrent_operations: entry.concurrentOperations,
      cost_per_minute: entry.costs
        .filter((c) => c.timestamp > oneMinuteAgo)
        .reduce((sum, c) => sum + c.cost, 0),
      cost_per_hour: entry.costs
        .filter((c) => c.timestamp > oneHourAgo)
        .reduce((sum, c) => sum + c.cost, 0),
    };
  }

  /**
   * Reset rate limits for a user/session
   */
  reset(userId?: string, sessionId?: string): void {
    if (sessionId && this.config.trackBySession) {
      this.sessionLimits.delete(sessionId);
    }
    if (userId && this.config.trackByUser) {
      this.userLimits.delete(userId);
    }
    if (!userId && !sessionId) {
      this.globalLimits = {
        requests: [],
        costs: [],
        concurrentOperations: 0,
      };
    }
  }

  private capMapSize(map: Map<string, RateLimitEntry>): void {
    if (map.size > 10_000) {
      const keysToDelete = Array.from(map.keys()).slice(0, map.size - 10_000);
      for (const key of keysToDelete) map.delete(key);
    }
  }

  private getEntry(userId?: string, sessionId?: string): RateLimitEntry {
    // Priority: session > user > global
    if (sessionId && this.config.trackBySession) {
      if (!this.sessionLimits.has(sessionId)) {
        this.capMapSize(this.sessionLimits);
        this.sessionLimits.set(sessionId, {
          requests: [],
          costs: [],
          concurrentOperations: 0,
        });
      }
      return this.sessionLimits.get(sessionId)!;
    }

    if (userId && this.config.trackByUser) {
      if (!this.userLimits.has(userId)) {
        this.capMapSize(this.userLimits);
        this.userLimits.set(userId, {
          requests: [],
          costs: [],
          concurrentOperations: 0,
        });
      }
      return this.userLimits.get(userId)!;
    }

    return this.globalLimits;
  }

  private cleanupEntries(
    entry: RateLimitEntry,
    oneMinuteAgo: number,
    oneHourAgo: number
  ): void {
    // Keep only requests within the hour window
    entry.requests = entry.requests.filter((t) => t > oneHourAgo);
    entry.costs = entry.costs.filter((c) => c.timestamp > oneHourAgo);
  }
}
