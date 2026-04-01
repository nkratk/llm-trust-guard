/**
 * CircuitBreaker (L13)
 *
 * Prevents cascade failures in agentic workflows.
 * Implements the circuit breaker pattern for LLM operations.
 *
 * Threat Model:
 * - ASI08: Cascading Failures
 * - Runaway agent behavior
 * - Resource exhaustion via retries
 *
 * Protection Capabilities:
 * - Failure rate monitoring
 * - Automatic circuit opening
 * - Graceful degradation
 * - Recovery detection
 * - Rollback triggers
 */

export interface CircuitBreakerConfig {
  /** Failure threshold percentage to open circuit (0-100) */
  failureThreshold?: number;
  /** Minimum number of requests before threshold applies */
  minimumRequests?: number;
  /** Time window for failure counting in milliseconds */
  windowSize?: number;
  /** Time to wait before attempting recovery in milliseconds */
  recoveryTimeout?: number;
  /** Number of successful requests to close circuit */
  successThreshold?: number;
  /** Enable automatic recovery attempts */
  autoRecover?: boolean;
  /** Maximum consecutive failures before forced open */
  maxConsecutiveFailures?: number;
  /** Callback when circuit opens */
  onOpen?: (circuitId: string, stats: CircuitStats) => void;
  /** Callback when circuit closes */
  onClose?: (circuitId: string, stats: CircuitStats) => void;
  /** Callback when circuit half-opens */
  onHalfOpen?: (circuitId: string) => void;
}

export type CircuitState = "closed" | "open" | "half-open";

export interface CircuitStats {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  failureRate: number;
  lastFailure?: number;
  lastSuccess?: number;
  stateChangedAt: number;
}

export interface CircuitBreakerResult {
  allowed: boolean;
  state: CircuitState;
  reason: string;
  request_id: string;
  stats: CircuitStats;
  fallback_recommended: boolean;
  retry_after?: number;
}

export interface OperationResult {
  success: boolean;
  duration: number;
  error?: string;
}

export class CircuitBreaker {
  private config: Required<Omit<CircuitBreakerConfig, "onOpen" | "onClose" | "onHalfOpen">> & {
    onOpen?: (circuitId: string, stats: CircuitStats) => void;
    onClose?: (circuitId: string, stats: CircuitStats) => void;
    onHalfOpen?: (circuitId: string) => void;
  };

  // Per-circuit state tracking
  private circuits: Map<string, {
    state: CircuitState;
    stats: CircuitStats;
    requestTimestamps: number[];
    failureTimestamps: number[];
    openedAt?: number;
  }> = new Map();

  constructor(config: CircuitBreakerConfig = {}) {
    this.config = {
      failureThreshold: config.failureThreshold ?? 50,
      minimumRequests: config.minimumRequests ?? 5,
      windowSize: config.windowSize ?? 60 * 1000, // 1 minute
      recoveryTimeout: config.recoveryTimeout ?? 30 * 1000, // 30 seconds
      successThreshold: config.successThreshold ?? 3,
      autoRecover: config.autoRecover ?? true,
      maxConsecutiveFailures: config.maxConsecutiveFailures ?? 5,
      onOpen: config.onOpen,
      onClose: config.onClose,
      onHalfOpen: config.onHalfOpen,
    };
  }

  /**
   * Check if operation should be allowed through circuit
   */
  check(circuitId: string, requestId?: string): CircuitBreakerResult {
    const reqId = requestId || `cb-${Date.now()}`;
    const circuit = this.getOrCreateCircuit(circuitId);

    // Clean old data outside window
    this.cleanupWindow(circuit);

    switch (circuit.state) {
      case "closed":
        return {
          allowed: true,
          state: "closed",
          reason: "Circuit is closed, operation allowed",
          request_id: reqId,
          stats: { ...circuit.stats },
          fallback_recommended: false,
        };

      case "open":
        // Check if recovery timeout has passed
        if (circuit.openedAt && Date.now() - circuit.openedAt >= this.config.recoveryTimeout) {
          if (this.config.autoRecover) {
            this.transitionToHalfOpen(circuitId, circuit);
            return {
              allowed: true,
              state: "half-open",
              reason: "Circuit is half-open, testing recovery",
              request_id: reqId,
              stats: { ...circuit.stats },
              fallback_recommended: true,
            };
          }
        }

        const retryAfter = circuit.openedAt
          ? Math.max(0, this.config.recoveryTimeout - (Date.now() - circuit.openedAt))
          : this.config.recoveryTimeout;

        return {
          allowed: false,
          state: "open",
          reason: "Circuit is open, operation blocked",
          request_id: reqId,
          stats: { ...circuit.stats },
          fallback_recommended: true,
          retry_after: retryAfter,
        };

      case "half-open":
        // Allow limited requests in half-open state
        return {
          allowed: true,
          state: "half-open",
          reason: "Circuit is half-open, testing recovery",
          request_id: reqId,
          stats: { ...circuit.stats },
          fallback_recommended: true,
        };

      default:
        return {
          allowed: false,
          state: "open",
          reason: "Unknown circuit state",
          request_id: reqId,
          stats: { ...circuit.stats },
          fallback_recommended: true,
        };
    }
  }

  /**
   * Record operation result
   */
  recordResult(circuitId: string, result: OperationResult): void {
    const circuit = this.getOrCreateCircuit(circuitId);
    const now = Date.now();

    circuit.requestTimestamps.push(now);
    circuit.stats.totalRequests++;

    if (result.success) {
      circuit.stats.successfulRequests++;
      circuit.stats.consecutiveSuccesses++;
      circuit.stats.consecutiveFailures = 0;
      circuit.stats.lastSuccess = now;

      // Check for recovery in half-open state
      if (circuit.state === "half-open") {
        if (circuit.stats.consecutiveSuccesses >= this.config.successThreshold) {
          this.closeCircuit(circuitId, circuit);
        }
      }
    } else {
      circuit.stats.failedRequests++;
      circuit.stats.consecutiveFailures++;
      circuit.stats.consecutiveSuccesses = 0;
      circuit.stats.lastFailure = now;
      circuit.failureTimestamps.push(now);

      // Check for circuit opening conditions
      if (circuit.state === "closed" || circuit.state === "half-open") {
        // Check consecutive failures
        if (circuit.stats.consecutiveFailures >= this.config.maxConsecutiveFailures) {
          this.openCircuit(circuitId, circuit);
          return;
        }

        // Check failure rate
        const windowedFailures = this.countInWindow(circuit.failureTimestamps);
        const windowedRequests = this.countInWindow(circuit.requestTimestamps);

        if (windowedRequests >= this.config.minimumRequests) {
          const failureRate = (windowedFailures / windowedRequests) * 100;
          circuit.stats.failureRate = failureRate;

          if (failureRate >= this.config.failureThreshold) {
            this.openCircuit(circuitId, circuit);
          }
        }
      }
    }

    // Update failure rate
    const windowedFailures = this.countInWindow(circuit.failureTimestamps);
    const windowedRequests = this.countInWindow(circuit.requestTimestamps);
    circuit.stats.failureRate = windowedRequests > 0
      ? (windowedFailures / windowedRequests) * 100
      : 0;
  }

  /**
   * Record a successful operation
   */
  recordSuccess(circuitId: string, duration?: number): void {
    this.recordResult(circuitId, { success: true, duration: duration ?? 0 });
  }

  /**
   * Record a failed operation
   */
  recordFailure(circuitId: string, error?: string, duration?: number): void {
    this.recordResult(circuitId, {
      success: false,
      duration: duration ?? 0,
      error,
    });
  }

  /**
   * Get current state of a circuit
   */
  getState(circuitId: string): CircuitState {
    return this.circuits.get(circuitId)?.state ?? "closed";
  }

  /**
   * Get stats for a circuit
   */
  getStats(circuitId: string): CircuitStats | null {
    const circuit = this.circuits.get(circuitId);
    return circuit ? { ...circuit.stats } : null;
  }

  /**
   * Get all circuit IDs
   */
  getCircuitIds(): string[] {
    return [...this.circuits.keys()];
  }

  /**
   * Force open a circuit
   */
  forceOpen(circuitId: string): void {
    const circuit = this.getOrCreateCircuit(circuitId);
    this.openCircuit(circuitId, circuit);
  }

  /**
   * Force close a circuit
   */
  forceClose(circuitId: string): void {
    const circuit = this.getOrCreateCircuit(circuitId);
    this.closeCircuit(circuitId, circuit);
  }

  /**
   * Reset a circuit to initial state
   */
  reset(circuitId: string): void {
    this.circuits.delete(circuitId);
  }

  /**
   * Reset all circuits
   */
  resetAll(): void {
    this.circuits.clear();
  }

  /**
   * Execute operation with circuit breaker protection
   */
  async execute<T>(
    circuitId: string,
    operation: () => Promise<T>,
    fallback?: () => Promise<T>
  ): Promise<{ result?: T; fallbackUsed: boolean; error?: string }> {
    const checkResult = this.check(circuitId);

    if (!checkResult.allowed) {
      if (fallback) {
        try {
          const result = await fallback();
          return { result, fallbackUsed: true };
        } catch (err) {
          return {
            fallbackUsed: true,
            error: `Circuit open and fallback failed: ${err}`,
          };
        }
      }
      return {
        fallbackUsed: false,
        error: checkResult.reason,
      };
    }

    const startTime = Date.now();
    try {
      const result = await operation();
      this.recordSuccess(circuitId, Date.now() - startTime);
      return { result, fallbackUsed: false };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      this.recordFailure(circuitId, error, Date.now() - startTime);

      // Try fallback if available and circuit is now recommending it
      const newCheck = this.check(circuitId);
      if (newCheck.fallback_recommended && fallback) {
        try {
          const result = await fallback();
          return { result, fallbackUsed: true };
        } catch (fallbackErr) {
          return {
            fallbackUsed: true,
            error: `Primary failed: ${error}. Fallback also failed.`,
          };
        }
      }

      return { fallbackUsed: false, error };
    }
  }

  /**
   * Health check across all circuits
   */
  healthCheck(): {
    healthy: boolean;
    circuits: Array<{
      id: string;
      state: CircuitState;
      failureRate: number;
    }>;
    openCircuits: number;
  } {
    const circuitStatuses: Array<{ id: string; state: CircuitState; failureRate: number }> = [];
    let openCircuits = 0;

    for (const [id, circuit] of this.circuits) {
      const status = {
        id,
        state: circuit.state,
        failureRate: circuit.stats.failureRate,
      };
      circuitStatuses.push(status);

      if (circuit.state === "open") {
        openCircuits++;
      }
    }

    return {
      healthy: openCircuits === 0,
      circuits: circuitStatuses,
      openCircuits,
    };
  }

  private getOrCreateCircuit(circuitId: string) {
    let circuit = this.circuits.get(circuitId);

    if (!circuit) {
      // Evict stale circuits if map is too large
      if (this.circuits.size > 10_000) {
        const now = Date.now();
        for (const [id, c] of this.circuits.entries()) {
          if (now - c.stats.stateChangedAt > 3600_000) this.circuits.delete(id);
          if (this.circuits.size <= 10_000) break;
        }
      }
      circuit = {
        state: "closed",
        stats: {
          totalRequests: 0,
          successfulRequests: 0,
          failedRequests: 0,
          consecutiveFailures: 0,
          consecutiveSuccesses: 0,
          failureRate: 0,
          stateChangedAt: Date.now(),
        },
        requestTimestamps: [],
        failureTimestamps: [],
      };
      this.circuits.set(circuitId, circuit);
    }

    return circuit;
  }

  private openCircuit(
    circuitId: string,
    circuit: ReturnType<typeof this.getOrCreateCircuit>
  ): void {
    circuit.state = "open";
    circuit.openedAt = Date.now();
    circuit.stats.stateChangedAt = Date.now();

    if (this.config.onOpen) {
      this.config.onOpen(circuitId, { ...circuit.stats });
    }
  }

  private closeCircuit(
    circuitId: string,
    circuit: ReturnType<typeof this.getOrCreateCircuit>
  ): void {
    circuit.state = "closed";
    circuit.openedAt = undefined;
    circuit.stats.stateChangedAt = Date.now();
    circuit.stats.consecutiveFailures = 0;

    if (this.config.onClose) {
      this.config.onClose(circuitId, { ...circuit.stats });
    }
  }

  private transitionToHalfOpen(
    circuitId: string,
    circuit: ReturnType<typeof this.getOrCreateCircuit>
  ): void {
    circuit.state = "half-open";
    circuit.stats.stateChangedAt = Date.now();
    circuit.stats.consecutiveSuccesses = 0;

    if (this.config.onHalfOpen) {
      this.config.onHalfOpen(circuitId);
    }
  }

  private cleanupWindow(circuit: ReturnType<typeof this.getOrCreateCircuit>): void {
    const cutoff = Date.now() - this.config.windowSize;

    circuit.requestTimestamps = circuit.requestTimestamps.filter((t) => t > cutoff);
    circuit.failureTimestamps = circuit.failureTimestamps.filter((t) => t > cutoff);
  }

  private countInWindow(timestamps: number[]): number {
    const cutoff = Date.now() - this.config.windowSize;
    return timestamps.filter((t) => t > cutoff).length;
  }
}
