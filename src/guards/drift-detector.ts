/**
 * DriftDetector (L14)
 *
 * Detects behavioral drift from intended agent purpose.
 * Monitors for rogue agent behavior and goal misalignment.
 *
 * Threat Model:
 * - ASI10: Rogue Agents
 * - Goal misalignment
 * - Behavioral drift over time
 *
 * Protection Capabilities:
 * - Baseline behavior profiling
 * - Anomaly detection
 * - Goal alignment verification
 * - Continuous monitoring
 * - Alert thresholds
 */

export interface DriftDetectorConfig {
  /** Minimum samples before drift detection activates */
  minimumSamples?: number;
  /** Standard deviation threshold for anomaly detection */
  anomalyThreshold?: number;
  /** Time window for baseline calculation in milliseconds */
  baselineWindow?: number;
  /** Enable automatic baseline updates */
  autoUpdateBaseline?: boolean;
  /** Maximum drift score before alert (0-100) */
  alertThreshold?: number;
  /** Enable goal alignment checking */
  checkGoalAlignment?: boolean;
  /** Callback when drift is detected */
  onDrift?: (agentId: string, analysis: DriftAnalysis) => void;
  /** Callback when agent returns to baseline */
  onRecovery?: (agentId: string) => void;
}

export interface BehaviorSample {
  /** Timestamp of the sample */
  timestamp: number;
  /** Tools/actions used */
  tools: string[];
  /** Topics/domains accessed */
  topics: string[];
  /** Sentiment indicator (-1 to 1) */
  sentiment: number;
  /** Response length */
  responseLength: number;
  /** Time to respond in milliseconds */
  responseTime: number;
  /** Error occurred */
  hadError: boolean;
  /** User satisfaction (if available, 0-1) */
  satisfaction?: number;
  /** Goal alignment indicators */
  goalIndicators?: Record<string, number>;
  /** Custom metrics */
  customMetrics?: Record<string, number>;
}

export interface BaselineProfile {
  /** Average tool usage distribution */
  toolDistribution: Record<string, number>;
  /** Average topic distribution */
  topicDistribution: Record<string, number>;
  /** Average sentiment */
  avgSentiment: number;
  /** Sentiment standard deviation */
  sentimentStdDev: number;
  /** Average response length */
  avgResponseLength: number;
  /** Response length standard deviation */
  responseLengthStdDev: number;
  /** Average response time */
  avgResponseTime: number;
  /** Response time standard deviation */
  responseTimeStdDev: number;
  /** Error rate */
  errorRate: number;
  /** Average satisfaction */
  avgSatisfaction: number;
  /** Sample count used for baseline */
  sampleCount: number;
  /** When baseline was last updated */
  lastUpdated: number;
}

export interface DriftAnalysis {
  /** Overall drift score (0-100) */
  driftScore: number;
  /** Is currently drifting */
  isDrifting: boolean;
  /** Specific drift indicators */
  indicators: DriftIndicator[];
  /** Comparison with baseline */
  baselineComparison: {
    toolDrift: number;
    topicDrift: number;
    sentimentDrift: number;
    responseLengthDrift: number;
    responseTimeDrift: number;
    errorRateDrift: number;
  };
  /** Goal alignment score (if enabled) */
  goalAlignment?: number;
  /** Recommendations */
  recommendations: string[];
}

export interface DriftIndicator {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  currentValue: number | string;
  baselineValue: number | string;
  deviation: number;
}

export interface DriftDetectorResult {
  allowed: boolean;
  reason: string;
  request_id: string;
  analysis: DriftAnalysis;
  requires_review: boolean;
  kill_switch_recommended: boolean;
}

export class DriftDetector {
  private config: Required<Omit<DriftDetectorConfig, "onDrift" | "onRecovery">> & {
    onDrift?: (agentId: string, analysis: DriftAnalysis) => void;
    onRecovery?: (agentId: string) => void;
  };

  // Per-agent state
  private samples: Map<string, BehaviorSample[]> = new Map();
  private baselines: Map<string, BaselineProfile> = new Map();
  private driftState: Map<string, boolean> = new Map();
  private goalDefinitions: Map<string, Record<string, { target: number; tolerance: number }>> = new Map();

  constructor(config: DriftDetectorConfig = {}) {
    this.config = {
      minimumSamples: config.minimumSamples ?? 20,
      anomalyThreshold: config.anomalyThreshold ?? 2.5, // 2.5 standard deviations
      baselineWindow: config.baselineWindow ?? 24 * 60 * 60 * 1000, // 24 hours
      autoUpdateBaseline: config.autoUpdateBaseline ?? true,
      alertThreshold: config.alertThreshold ?? 60,
      checkGoalAlignment: config.checkGoalAlignment ?? true,
      onDrift: config.onDrift,
      onRecovery: config.onRecovery,
    };
  }

  /**
   * Record a behavior sample
   */
  recordSample(agentId: string, sample: BehaviorSample): void {
    // Cap agent entries to prevent unbounded growth
    if (!this.samples.has(agentId) && this.samples.size > 10_000) {
      const oldest = this.samples.keys().next().value;
      if (oldest) this.samples.delete(oldest);
    }

    const agentSamples = this.samples.get(agentId) || [];

    // Add new sample
    agentSamples.push(sample);

    // Clean old samples outside window
    const cutoff = Date.now() - this.config.baselineWindow;
    const filtered = agentSamples.filter((s) => s.timestamp > cutoff);

    this.samples.set(agentId, filtered);

    // Update baseline if we have enough samples and auto-update is enabled
    if (this.config.autoUpdateBaseline && filtered.length >= this.config.minimumSamples) {
      // Only update baseline periodically
      const baseline = this.baselines.get(agentId);
      if (!baseline || Date.now() - baseline.lastUpdated > this.config.baselineWindow / 4) {
        this.updateBaseline(agentId);
      }
    }
  }

  /**
   * Analyze current behavior for drift
   */
  analyze(agentId: string, currentSample?: BehaviorSample, requestId?: string): DriftDetectorResult {
    const reqId = requestId || `drift-${Date.now()}`;

    // Record current sample if provided
    if (currentSample) {
      this.recordSample(agentId, currentSample);
    }

    const samples = this.samples.get(agentId) || [];
    const baseline = this.baselines.get(agentId);

    // Not enough data
    if (samples.length < this.config.minimumSamples || !baseline) {
      return {
        allowed: true,
        reason: "Insufficient data for drift detection",
        request_id: reqId,
        analysis: {
          driftScore: 0,
          isDrifting: false,
          indicators: [],
          baselineComparison: {
            toolDrift: 0,
            topicDrift: 0,
            sentimentDrift: 0,
            responseLengthDrift: 0,
            responseTimeDrift: 0,
            errorRateDrift: 0,
          },
          recommendations: ["Collecting baseline data..."],
        },
        requires_review: false,
        kill_switch_recommended: false,
      };
    }

    // Get recent samples for comparison
    const recentSamples = samples.slice(-10);
    const analysis = this.performAnalysis(agentId, recentSamples, baseline);

    // Check for state change
    const wasDrifting = this.driftState.get(agentId) || false;
    const isDrifting = analysis.isDrifting;

    if (isDrifting && !wasDrifting) {
      this.driftState.set(agentId, true);
      if (this.config.onDrift) {
        this.config.onDrift(agentId, analysis);
      }
    } else if (!isDrifting && wasDrifting) {
      this.driftState.set(agentId, false);
      if (this.config.onRecovery) {
        this.config.onRecovery(agentId);
      }
    }

    // Decision
    const shouldBlock = analysis.driftScore >= 80;
    const requiresReview = analysis.driftScore >= this.config.alertThreshold;
    const killSwitch = analysis.driftScore >= 90;

    return {
      allowed: !shouldBlock,
      reason: shouldBlock
        ? `Agent drift detected: score ${analysis.driftScore}`
        : isDrifting
        ? `Warning: drift score ${analysis.driftScore}`
        : "Agent behavior within normal parameters",
      request_id: reqId,
      analysis,
      requires_review: requiresReview,
      kill_switch_recommended: killSwitch,
    };
  }

  /**
   * Set baseline manually
   */
  setBaseline(agentId: string, baseline: BaselineProfile): void {
    this.baselines.set(agentId, baseline);
  }

  /**
   * Get current baseline for an agent
   */
  getBaseline(agentId: string): BaselineProfile | null {
    return this.baselines.get(agentId) || null;
  }

  /**
   * Update baseline from collected samples
   */
  updateBaseline(agentId: string): void {
    const samples = this.samples.get(agentId) || [];

    if (samples.length < this.config.minimumSamples) {
      return;
    }

    const baseline = this.calculateBaseline(samples);
    this.baselines.set(agentId, baseline);
  }

  /**
   * Define goals for goal alignment checking
   */
  defineGoals(
    agentId: string,
    goals: Record<string, { target: number; tolerance: number }>
  ): void {
    this.goalDefinitions.set(agentId, goals);
  }

  /**
   * Get drift state for an agent
   */
  isDrifting(agentId: string): boolean {
    return this.driftState.get(agentId) || false;
  }

  /**
   * Get all agents with drift
   */
  getDriftingAgents(): string[] {
    return [...this.driftState.entries()]
      .filter(([, drifting]) => drifting)
      .map(([agentId]) => agentId);
  }

  /**
   * Reset agent state
   */
  resetAgent(agentId: string): void {
    this.samples.delete(agentId);
    this.baselines.delete(agentId);
    this.driftState.delete(agentId);
    this.goalDefinitions.delete(agentId);
  }

  /**
   * Get sample count for an agent
   */
  getSampleCount(agentId: string): number {
    return this.samples.get(agentId)?.length ?? 0;
  }

  private calculateBaseline(samples: BehaviorSample[]): BaselineProfile {
    // Tool distribution
    const toolCounts: Record<string, number> = {};
    for (const sample of samples) {
      for (const tool of sample.tools) {
        toolCounts[tool] = (toolCounts[tool] || 0) + 1;
      }
    }
    const totalTools = Object.values(toolCounts).reduce((a, b) => a + b, 0);
    const toolDistribution: Record<string, number> = {};
    for (const [tool, count] of Object.entries(toolCounts)) {
      toolDistribution[tool] = count / (totalTools || 1);
    }

    // Topic distribution
    const topicCounts: Record<string, number> = {};
    for (const sample of samples) {
      for (const topic of sample.topics) {
        topicCounts[topic] = (topicCounts[topic] || 0) + 1;
      }
    }
    const totalTopics = Object.values(topicCounts).reduce((a, b) => a + b, 0);
    const topicDistribution: Record<string, number> = {};
    for (const [topic, count] of Object.entries(topicCounts)) {
      topicDistribution[topic] = count / (totalTopics || 1);
    }

    // Numerical metrics
    const sentiments = samples.map((s) => s.sentiment);
    const responseLengths = samples.map((s) => s.responseLength);
    const responseTimes = samples.map((s) => s.responseTime);
    const errors = samples.filter((s) => s.hadError).length;
    const satisfactions = samples
      .filter((s) => s.satisfaction !== undefined)
      .map((s) => s.satisfaction!);

    return {
      toolDistribution,
      topicDistribution,
      avgSentiment: this.mean(sentiments),
      sentimentStdDev: this.stdDev(sentiments),
      avgResponseLength: this.mean(responseLengths),
      responseLengthStdDev: this.stdDev(responseLengths),
      avgResponseTime: this.mean(responseTimes),
      responseTimeStdDev: this.stdDev(responseTimes),
      errorRate: errors / samples.length,
      avgSatisfaction: satisfactions.length > 0 ? this.mean(satisfactions) : 0,
      sampleCount: samples.length,
      lastUpdated: Date.now(),
    };
  }

  private performAnalysis(
    agentId: string,
    recentSamples: BehaviorSample[],
    baseline: BaselineProfile
  ): DriftAnalysis {
    const indicators: DriftIndicator[] = [];
    let driftScore = 0;

    // Calculate recent metrics
    const recentToolDist = this.calculateToolDistribution(recentSamples);
    const recentTopicDist = this.calculateTopicDistribution(recentSamples);
    const recentSentiment = this.mean(recentSamples.map((s) => s.sentiment));
    const recentResponseLength = this.mean(recentSamples.map((s) => s.responseLength));
    const recentResponseTime = this.mean(recentSamples.map((s) => s.responseTime));
    const recentErrorRate = recentSamples.filter((s) => s.hadError).length / recentSamples.length;

    // Tool drift (Jensen-Shannon divergence approximation)
    const toolDrift = this.distributionDivergence(baseline.toolDistribution, recentToolDist);
    if (toolDrift > 0.3) {
      const severity = toolDrift > 0.6 ? "high" : toolDrift > 0.4 ? "medium" : "low";
      indicators.push({
        type: "tool_distribution",
        severity,
        description: "Tool usage pattern has shifted significantly",
        currentValue: JSON.stringify(recentToolDist),
        baselineValue: JSON.stringify(baseline.toolDistribution),
        deviation: toolDrift,
      });
      driftScore += toolDrift * 30;
    }

    // Topic drift
    const topicDrift = this.distributionDivergence(baseline.topicDistribution, recentTopicDist);
    if (topicDrift > 0.3) {
      const severity = topicDrift > 0.6 ? "high" : topicDrift > 0.4 ? "medium" : "low";
      indicators.push({
        type: "topic_distribution",
        severity,
        description: "Topic focus has shifted significantly",
        currentValue: JSON.stringify(recentTopicDist),
        baselineValue: JSON.stringify(baseline.topicDistribution),
        deviation: topicDrift,
      });
      driftScore += topicDrift * 25;
    }

    // Sentiment drift
    const sentimentDeviation = Math.abs(recentSentiment - baseline.avgSentiment) /
      (baseline.sentimentStdDev || 0.1);
    if (sentimentDeviation > this.config.anomalyThreshold) {
      const severity = sentimentDeviation > 4 ? "high" : sentimentDeviation > 3 ? "medium" : "low";
      indicators.push({
        type: "sentiment",
        severity,
        description: "Sentiment has deviated from baseline",
        currentValue: recentSentiment.toFixed(2),
        baselineValue: baseline.avgSentiment.toFixed(2),
        deviation: sentimentDeviation,
      });
      driftScore += Math.min(sentimentDeviation * 5, 25);
    }

    // Response length drift
    const lengthDeviation = Math.abs(recentResponseLength - baseline.avgResponseLength) /
      (baseline.responseLengthStdDev || 100);
    if (lengthDeviation > this.config.anomalyThreshold) {
      const severity = lengthDeviation > 4 ? "high" : lengthDeviation > 3 ? "medium" : "low";
      indicators.push({
        type: "response_length",
        severity,
        description: "Response length has changed significantly",
        currentValue: recentResponseLength.toFixed(0),
        baselineValue: baseline.avgResponseLength.toFixed(0),
        deviation: lengthDeviation,
      });
      driftScore += Math.min(lengthDeviation * 3, 15);
    }

    // Response time drift
    const timeDeviation = Math.abs(recentResponseTime - baseline.avgResponseTime) /
      (baseline.responseTimeStdDev || 100);
    if (timeDeviation > this.config.anomalyThreshold) {
      const severity = timeDeviation > 4 ? "high" : timeDeviation > 3 ? "medium" : "low";
      indicators.push({
        type: "response_time",
        severity,
        description: "Response time has changed significantly",
        currentValue: recentResponseTime.toFixed(0) + "ms",
        baselineValue: baseline.avgResponseTime.toFixed(0) + "ms",
        deviation: timeDeviation,
      });
      driftScore += Math.min(timeDeviation * 3, 15);
    }

    // Error rate drift
    const errorRateDiff = recentErrorRate - baseline.errorRate;
    if (errorRateDiff > 0.1) { // 10% increase in errors
      const severity = errorRateDiff > 0.3 ? "critical" : errorRateDiff > 0.2 ? "high" : "medium";
      indicators.push({
        type: "error_rate",
        severity,
        description: "Error rate has increased significantly",
        currentValue: (recentErrorRate * 100).toFixed(1) + "%",
        baselineValue: (baseline.errorRate * 100).toFixed(1) + "%",
        deviation: errorRateDiff,
      });
      driftScore += errorRateDiff * 100; // Error rate is serious
    }

    // Goal alignment check
    let goalAlignment: number | undefined;
    if (this.config.checkGoalAlignment) {
      const goals = this.goalDefinitions.get(agentId);
      if (goals && recentSamples.some((s) => s.goalIndicators)) {
        goalAlignment = this.checkGoalAlignment(recentSamples, goals, indicators);
        if (goalAlignment < 0.7) {
          driftScore += (1 - goalAlignment) * 30;
        }
      }
    }

    // Cap drift score
    driftScore = Math.min(100, Math.round(driftScore));

    return {
      driftScore,
      isDrifting: driftScore >= this.config.alertThreshold,
      indicators,
      baselineComparison: {
        toolDrift,
        topicDrift,
        sentimentDrift: sentimentDeviation,
        responseLengthDrift: lengthDeviation,
        responseTimeDrift: timeDeviation,
        errorRateDrift: errorRateDiff,
      },
      goalAlignment,
      recommendations: this.generateRecommendations(indicators, driftScore),
    };
  }

  private calculateToolDistribution(samples: BehaviorSample[]): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const sample of samples) {
      for (const tool of sample.tools) {
        counts[tool] = (counts[tool] || 0) + 1;
      }
    }
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    const dist: Record<string, number> = {};
    for (const [tool, count] of Object.entries(counts)) {
      dist[tool] = count / (total || 1);
    }
    return dist;
  }

  private calculateTopicDistribution(samples: BehaviorSample[]): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const sample of samples) {
      for (const topic of sample.topics) {
        counts[topic] = (counts[topic] || 0) + 1;
      }
    }
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    const dist: Record<string, number> = {};
    for (const [topic, count] of Object.entries(counts)) {
      dist[topic] = count / (total || 1);
    }
    return dist;
  }

  private distributionDivergence(
    baseline: Record<string, number>,
    current: Record<string, number>
  ): number {
    // Simplified Jensen-Shannon divergence
    const allKeys = new Set([...Object.keys(baseline), ...Object.keys(current)]);
    let divergence = 0;

    for (const key of allKeys) {
      const p = baseline[key] || 0.001;
      const q = current[key] || 0.001;
      const m = (p + q) / 2;

      if (p > 0) divergence += p * Math.log2(p / m);
      if (q > 0) divergence += q * Math.log2(q / m);
    }

    return divergence / 2; // Normalized to [0, 1]
  }

  private checkGoalAlignment(
    samples: BehaviorSample[],
    goals: Record<string, { target: number; tolerance: number }>,
    indicators: DriftIndicator[]
  ): number {
    let alignmentSum = 0;
    let goalCount = 0;

    for (const [goalName, { target, tolerance }] of Object.entries(goals)) {
      const values = samples
        .filter((s) => s.goalIndicators && s.goalIndicators[goalName] !== undefined)
        .map((s) => s.goalIndicators![goalName]);

      if (values.length === 0) continue;

      const avgValue = this.mean(values);
      const deviation = Math.abs(avgValue - target);
      const alignment = Math.max(0, 1 - deviation / tolerance);

      alignmentSum += alignment;
      goalCount++;

      if (alignment < 0.7) {
        indicators.push({
          type: `goal_${goalName}`,
          severity: alignment < 0.3 ? "critical" : alignment < 0.5 ? "high" : "medium",
          description: `Goal '${goalName}' alignment is low`,
          currentValue: avgValue.toFixed(2),
          baselineValue: target.toFixed(2),
          deviation: deviation,
        });
      }
    }

    return goalCount > 0 ? alignmentSum / goalCount : 1;
  }

  private mean(values: number[]): number {
    if (values.length === 0) return 0;
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  private stdDev(values: number[]): number {
    if (values.length < 2) return 0;
    const avg = this.mean(values);
    const squareDiffs = values.map((v) => Math.pow(v - avg, 2));
    return Math.sqrt(this.mean(squareDiffs));
  }

  private generateRecommendations(indicators: DriftIndicator[], driftScore: number): string[] {
    const recommendations: string[] = [];

    if (driftScore >= 90) {
      recommendations.push("CRITICAL: Consider activating kill switch for this agent");
    }
    if (driftScore >= 70) {
      recommendations.push("Immediate review of agent behavior required");
    }

    const criticalIndicators = indicators.filter((i) => i.severity === "critical" || i.severity === "high");
    for (const indicator of criticalIndicators) {
      switch (indicator.type) {
        case "tool_distribution":
          recommendations.push("Review tool access permissions");
          break;
        case "topic_distribution":
          recommendations.push("Verify agent is operating within intended domain");
          break;
        case "error_rate":
          recommendations.push("Investigate root cause of increased errors");
          break;
        case "sentiment":
          recommendations.push("Review recent interactions for quality issues");
          break;
        default:
          if (indicator.type.startsWith("goal_")) {
            recommendations.push(`Review goal alignment for ${indicator.type.replace("goal_", "")}`);
          }
      }
    }

    if (recommendations.length === 0) {
      recommendations.push("Agent behavior is within normal parameters");
    }

    return recommendations;
  }
}
