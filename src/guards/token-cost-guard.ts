/**
 * TokenCostGuard
 *
 * Tracks LLM API token usage and cost per session/user.
 * Enforces financial circuit breaking with hard cost ceilings.
 *
 * Addresses OWASP LLM10: Unbounded Consumption — insufficient controls
 * on resource usage leading to excessive API costs, denial-of-service,
 * or financial exploitation.
 *
 * Real-world context:
 * - A single runaway agent loop can burn $10K+ in API costs in minutes
 * - Deloitte 2026: only 20% of orgs have mature governance for AI spending
 * - LLMjacking: stolen credentials used to run up bills on victim accounts
 */

export interface TokenCostGuardConfig {
  /** Max tokens per session before blocking (default: 100000) */
  maxTokensPerSession?: number;
  /** Max tokens per user across all sessions (default: 500000) */
  maxTokensPerUser?: number;
  /** Max cost in dollars per session (default: 10.0) */
  maxCostPerSession?: number;
  /** Max cost in dollars per user (default: 50.0) */
  maxCostPerUser?: number;
  /** Cost per 1K input tokens in dollars (default: 0.003) */
  inputTokenCostPer1K?: number;
  /** Cost per 1K output tokens in dollars (default: 0.015) */
  outputTokenCostPer1K?: number;
  /** Max single request token count (default: 32000) */
  maxTokensPerRequest?: number;
  /** Alert threshold as percentage of budget (default: 0.8 = 80%) */
  alertThreshold?: number;
  /** Session budget window in milliseconds (default: 3600000 = 1 hour) */
  budgetWindowMs?: number;
}

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  estimatedCost: number;
}

export interface TokenCostResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  usage: {
    session: TokenUsage;
    user: TokenUsage;
    request: TokenUsage;
  };
  budget: {
    session_remaining_tokens: number;
    session_remaining_cost: number;
    user_remaining_tokens: number;
    user_remaining_cost: number;
    alert: boolean;
    alert_message?: string;
  };
}

interface UsageEntry {
  inputTokens: number;
  outputTokens: number;
  cost: number;
  timestamp: number;
}

interface SessionUsage {
  entries: UsageEntry[];
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCost: number;
  lastActivity: number;
}

export class TokenCostGuard {
  private config: Required<TokenCostGuardConfig>;
  private sessionUsage: Map<string, SessionUsage> = new Map();
  private userUsage: Map<string, SessionUsage> = new Map();

  constructor(config: TokenCostGuardConfig = {}) {
    this.config = {
      maxTokensPerSession: config.maxTokensPerSession ?? 100_000,
      maxTokensPerUser: config.maxTokensPerUser ?? 500_000,
      maxCostPerSession: config.maxCostPerSession ?? 10.0,
      maxCostPerUser: config.maxCostPerUser ?? 50.0,
      inputTokenCostPer1K: config.inputTokenCostPer1K ?? 0.003,
      outputTokenCostPer1K: config.outputTokenCostPer1K ?? 0.015,
      maxTokensPerRequest: config.maxTokensPerRequest ?? 32_000,
      alertThreshold: config.alertThreshold ?? 0.8,
      budgetWindowMs: config.budgetWindowMs ?? 3_600_000,
    };
  }

  /**
   * Track token usage for a request and check against budgets
   */
  trackUsage(
    sessionId: string,
    userId: string,
    inputTokens: number,
    outputTokens: number,
    requestId?: string
  ): TokenCostResult {
    const violations: string[] = [];
    const totalTokens = inputTokens + outputTokens;
    const requestCost = this.calculateCost(inputTokens, outputTokens);

    // Per-request check
    if (totalTokens > this.config.maxTokensPerRequest) {
      violations.push("REQUEST_TOKEN_LIMIT_EXCEEDED");
    }

    // Get or create session/user usage
    const session = this.getOrCreateUsage(this.sessionUsage, sessionId);
    const user = this.getOrCreateUsage(this.userUsage, userId);

    // Clean old entries outside budget window
    this.cleanEntries(session);
    this.cleanEntries(user);

    // Check session limits BEFORE recording
    if (session.totalInputTokens + session.totalOutputTokens + totalTokens > this.config.maxTokensPerSession) {
      violations.push("SESSION_TOKEN_LIMIT_EXCEEDED");
    }
    if (session.totalCost + requestCost > this.config.maxCostPerSession) {
      violations.push("SESSION_COST_LIMIT_EXCEEDED");
    }

    // Check user limits
    if (user.totalInputTokens + user.totalOutputTokens + totalTokens > this.config.maxTokensPerUser) {
      violations.push("USER_TOKEN_LIMIT_EXCEEDED");
    }
    if (user.totalCost + requestCost > this.config.maxCostPerUser) {
      violations.push("USER_COST_LIMIT_EXCEEDED");
    }

    const allowed = violations.length === 0;

    // Record usage only if allowed
    if (allowed) {
      const entry: UsageEntry = {
        inputTokens,
        outputTokens,
        cost: requestCost,
        timestamp: Date.now(),
      };
      session.entries.push(entry);
      session.totalInputTokens += inputTokens;
      session.totalOutputTokens += outputTokens;
      session.totalCost += requestCost;
      session.lastActivity = Date.now();

      user.entries.push(entry);
      user.totalInputTokens += inputTokens;
      user.totalOutputTokens += outputTokens;
      user.totalCost += requestCost;
      user.lastActivity = Date.now();
    }

    // Alert check
    const sessionTokenRatio = (session.totalInputTokens + session.totalOutputTokens) / this.config.maxTokensPerSession;
    const sessionCostRatio = session.totalCost / this.config.maxCostPerSession;
    const userTokenRatio = (user.totalInputTokens + user.totalOutputTokens) / this.config.maxTokensPerUser;
    const userCostRatio = user.totalCost / this.config.maxCostPerUser;

    const alert = Math.max(sessionTokenRatio, sessionCostRatio, userTokenRatio, userCostRatio) >= this.config.alertThreshold;
    let alertMessage: string | undefined;
    if (alert && allowed) {
      const highestRatio = Math.max(sessionTokenRatio, sessionCostRatio, userTokenRatio, userCostRatio);
      alertMessage = `Token/cost budget at ${(highestRatio * 100).toFixed(0)}% — approaching limit`;
    }

    return {
      allowed,
      reason: allowed ? undefined : `Token/cost limit exceeded: ${violations.join(", ")}`,
      violations,
      usage: {
        session: {
          inputTokens: session.totalInputTokens,
          outputTokens: session.totalOutputTokens,
          totalTokens: session.totalInputTokens + session.totalOutputTokens,
          estimatedCost: session.totalCost,
        },
        user: {
          inputTokens: user.totalInputTokens,
          outputTokens: user.totalOutputTokens,
          totalTokens: user.totalInputTokens + user.totalOutputTokens,
          estimatedCost: user.totalCost,
        },
        request: {
          inputTokens,
          outputTokens,
          totalTokens,
          estimatedCost: requestCost,
        },
      },
      budget: {
        session_remaining_tokens: Math.max(0, this.config.maxTokensPerSession - session.totalInputTokens - session.totalOutputTokens),
        session_remaining_cost: Math.max(0, this.config.maxCostPerSession - session.totalCost),
        user_remaining_tokens: Math.max(0, this.config.maxTokensPerUser - user.totalInputTokens - user.totalOutputTokens),
        user_remaining_cost: Math.max(0, this.config.maxCostPerUser - user.totalCost),
        alert,
        alert_message: alertMessage,
      },
    };
  }

  /**
   * Get current budget status without recording usage
   */
  getBudget(sessionId: string, userId: string): TokenCostResult["budget"] {
    const session = this.sessionUsage.get(sessionId);
    const user = this.userUsage.get(userId);

    return {
      session_remaining_tokens: this.config.maxTokensPerSession - (session ? session.totalInputTokens + session.totalOutputTokens : 0),
      session_remaining_cost: this.config.maxCostPerSession - (session?.totalCost ?? 0),
      user_remaining_tokens: this.config.maxTokensPerUser - (user ? user.totalInputTokens + user.totalOutputTokens : 0),
      user_remaining_cost: this.config.maxCostPerUser - (user?.totalCost ?? 0),
      alert: false,
    };
  }

  /**
   * Reset session budget
   */
  resetSession(sessionId: string): void {
    this.sessionUsage.delete(sessionId);
  }

  /**
   * Reset user budget
   */
  resetUser(userId: string): void {
    this.userUsage.delete(userId);
  }

  /**
   * Destroy and release all resources
   */
  destroy(): void {
    this.sessionUsage.clear();
    this.userUsage.clear();
  }

  private calculateCost(inputTokens: number, outputTokens: number): number {
    return (inputTokens / 1000) * this.config.inputTokenCostPer1K +
           (outputTokens / 1000) * this.config.outputTokenCostPer1K;
  }

  private getOrCreateUsage(map: Map<string, SessionUsage>, key: string): SessionUsage {
    // Evict if map too large
    if (!map.has(key) && map.size > 10_000) {
      const oldest = map.keys().next().value;
      if (oldest) map.delete(oldest);
    }

    if (!map.has(key)) {
      map.set(key, {
        entries: [],
        totalInputTokens: 0,
        totalOutputTokens: 0,
        totalCost: 0,
        lastActivity: Date.now(),
      });
    }
    return map.get(key)!;
  }

  private cleanEntries(usage: SessionUsage): void {
    const cutoff = Date.now() - this.config.budgetWindowMs;
    const validEntries = usage.entries.filter(e => e.timestamp > cutoff);

    if (validEntries.length < usage.entries.length) {
      usage.entries = validEntries;
      usage.totalInputTokens = validEntries.reduce((sum, e) => sum + e.inputTokens, 0);
      usage.totalOutputTokens = validEntries.reduce((sum, e) => sum + e.outputTokens, 0);
      usage.totalCost = validEntries.reduce((sum, e) => sum + e.cost, 0);
    }
  }
}
