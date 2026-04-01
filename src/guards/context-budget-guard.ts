/**
 * ContextBudgetGuard
 *
 * Tracks aggregate token usage across all context sources per session.
 * Prevents context window stuffing and many-shot jailbreaking attacks.
 *
 * Why this exists: Anthropic's research shows 256 faux dialogues in a single
 * prompt override safety training. Individual guards have per-source limits,
 * but nothing tracks the AGGREGATE context size. An attacker can fill the
 * context window to push out system prompts.
 */

export interface ContextBudgetGuardConfig {
  /** Max total estimated tokens across all sources (default: 8000) */
  maxTotalTokens?: number;
  /** Tokens reserved for system prompt - never consumed by user content (default: 2000) */
  systemPromptReserve?: number;
  /** Max conversation turns per session (default: 50) */
  maxTurnsPerSession?: number;
  /** Max number of similar-structure messages before flagging (default: 5) */
  maxSimilarMessages?: number;
  /** Custom token estimator (default: Math.ceil(text.length / 3.5)) */
  tokenEstimator?: (text: string) => number;
}

export interface ContextBudgetResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  budget: {
    used_tokens: number;
    remaining_tokens: number;
    system_reserve: number;
    sources: Record<string, number>;
    turn_count: number;
  };
  many_shot_detected: boolean;
}

interface SessionBudget {
  sources: Map<string, number>; // source name → token count
  totalTokens: number;
  turnCount: number;
  messageHashes: string[]; // for similar message detection
  lastActivity: number;
}

export class ContextBudgetGuard {
  private config: Required<Omit<ContextBudgetGuardConfig, "tokenEstimator">> & { tokenEstimator: (text: string) => number };
  private sessions: Map<string, SessionBudget> = new Map();

  constructor(config: ContextBudgetGuardConfig = {}) {
    this.config = {
      maxTotalTokens: config.maxTotalTokens ?? 8000,
      systemPromptReserve: config.systemPromptReserve ?? 2000,
      maxTurnsPerSession: config.maxTurnsPerSession ?? 50,
      maxSimilarMessages: config.maxSimilarMessages ?? 5,
      tokenEstimator: config.tokenEstimator ?? ((text: string) => Math.ceil(text.length / 3.5)),
    };
  }

  /**
   * Track context from any source and check budget
   */
  trackContext(
    sessionId: string,
    source: string,
    content: string,
    requestId?: string
  ): ContextBudgetResult {
    const session = this.getOrCreateSession(sessionId);
    const violations: string[] = [];
    const tokens = this.config.tokenEstimator(content);

    // Track per-source
    const currentSourceTokens = session.sources.get(source) || 0;
    session.sources.set(source, currentSourceTokens + tokens);
    session.totalTokens += tokens;
    session.turnCount++;
    session.lastActivity = Date.now();

    // Budget check (effective budget = max - system reserve)
    const effectiveBudget = this.config.maxTotalTokens - this.config.systemPromptReserve;
    if (session.totalTokens > effectiveBudget) {
      violations.push("CONTEXT_BUDGET_EXCEEDED");
    }

    // Turn limit check
    if (session.turnCount > this.config.maxTurnsPerSession) {
      violations.push("MAX_TURNS_EXCEEDED");
    }

    // Many-shot detection
    const manyShotDetected = this.detectManyShotPattern(session, content);
    if (manyShotDetected) {
      violations.push("MANY_SHOT_PATTERN_DETECTED");
    }

    // Context dilution check (user content > 80% of total)
    const userTokens = session.sources.get("user_input") || 0;
    if (session.totalTokens > 0 && userTokens / session.totalTokens > 0.8 && session.turnCount > 10) {
      violations.push("CONTEXT_DILUTION_DETECTED");
    }

    const allowed = violations.length === 0;

    return {
      allowed,
      reason: allowed ? undefined : `Context budget violation: ${violations.join(", ")}`,
      violations,
      budget: {
        used_tokens: session.totalTokens,
        remaining_tokens: Math.max(0, effectiveBudget - session.totalTokens),
        system_reserve: this.config.systemPromptReserve,
        sources: Object.fromEntries(session.sources),
        turn_count: session.turnCount,
      },
      many_shot_detected: manyShotDetected,
    };
  }

  /**
   * Get current budget status for a session
   */
  getSessionBudget(sessionId: string): ContextBudgetResult["budget"] | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const effectiveBudget = this.config.maxTotalTokens - this.config.systemPromptReserve;
    return {
      used_tokens: session.totalTokens,
      remaining_tokens: Math.max(0, effectiveBudget - session.totalTokens),
      system_reserve: this.config.systemPromptReserve,
      sources: Object.fromEntries(session.sources),
      turn_count: session.turnCount,
    };
  }

  /**
   * Reset session budget
   */
  resetSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Destroy and release all resources
   */
  destroy(): void {
    this.sessions.clear();
  }

  private detectManyShotPattern(session: SessionBudget, content: string): boolean {
    // Create a structural hash of the message (normalize numbers, trim whitespace)
    const normalized = content
      .replace(/\d+/g, "N")
      .replace(/\s+/g, " ")
      .trim()
      .substring(0, 100);

    session.messageHashes.push(normalized);

    // Keep only recent hashes
    if (session.messageHashes.length > 100) {
      session.messageHashes = session.messageHashes.slice(-100);
    }

    // Count similar messages
    const recent = session.messageHashes.slice(-20);
    const counts = new Map<string, number>();
    for (const hash of recent) {
      counts.set(hash, (counts.get(hash) || 0) + 1);
    }

    // If any structural pattern appears more than maxSimilarMessages times
    for (const count of counts.values()) {
      if (count >= this.config.maxSimilarMessages) {
        return true;
      }
    }

    return false;
  }

  private getOrCreateSession(sessionId: string): SessionBudget {
    // Evict stale sessions
    if (this.sessions.size > 10_000) {
      const now = Date.now();
      for (const [id, s] of this.sessions.entries()) {
        if (now - s.lastActivity > 3600_000) this.sessions.delete(id);
        if (this.sessions.size <= 10_000) break;
      }
    }

    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        sources: new Map(),
        totalTokens: 0,
        turnCount: 0,
        messageHashes: [],
        lastActivity: Date.now(),
      });
    }
    return this.sessions.get(sessionId)!;
  }
}
