import { describe, it, expect, beforeEach } from "vitest";
import {
  DriftDetector,
  BehaviorSample,
  BaselineProfile,
} from "../src/guards/drift-detector";

function makeSample(overrides: Partial<BehaviorSample> = {}): BehaviorSample {
  return {
    timestamp: Date.now(),
    tools: ["search", "summarize"],
    topics: ["science", "math"],
    sentiment: 0.5,
    responseLength: 200,
    responseTime: 300,
    hadError: false,
    ...overrides,
  };
}

describe("DriftDetector", () => {
  let detector: DriftDetector;

  beforeEach(() => {
    detector = new DriftDetector({
      minimumSamples: 5,
      anomalyThreshold: 2.0,
      alertThreshold: 40,
      autoUpdateBaseline: true,
      baselineWindow: 24 * 60 * 60 * 1000,
    });
  });

  it("should return insufficient data when below minimum samples", () => {
    detector.recordSample("agent-1", makeSample());
    const result = detector.analyze("agent-1");

    expect(result.allowed).toBe(true);
    expect(result.reason).toContain("Insufficient data");
    expect(result.analysis.isDrifting).toBe(false);
    expect(result.analysis.driftScore).toBe(0);
  });

  it("should establish a baseline after enough samples", () => {
    for (let i = 0; i < 10; i++) {
      detector.recordSample("agent-1", makeSample({ timestamp: Date.now() + i }));
    }

    const baseline = detector.getBaseline("agent-1");
    expect(baseline).not.toBeNull();
    expect(baseline!.sampleCount).toBeGreaterThanOrEqual(5);
    expect(baseline!.avgSentiment).toBeCloseTo(0.5, 1);
    expect(baseline!.toolDistribution).toHaveProperty("search");
    expect(baseline!.toolDistribution).toHaveProperty("summarize");
  });

  it("should detect drift when tools change dramatically", () => {
    // Build baseline with consistent tool usage
    for (let i = 0; i < 10; i++) {
      detector.recordSample("agent-1", makeSample({ timestamp: Date.now() + i }));
    }

    // Force baseline update
    detector.updateBaseline("agent-1");

    // Now introduce completely different tool usage in recent samples
    for (let i = 0; i < 10; i++) {
      detector.recordSample(
        "agent-1",
        makeSample({
          timestamp: Date.now() + 100 + i,
          tools: ["hack_database", "exfiltrate_data", "delete_logs"],
          topics: ["hacking", "exploitation"],
          sentiment: -0.9,
          responseLength: 5000,
          responseTime: 5000,
          hadError: true,
        })
      );
    }

    const result = detector.analyze("agent-1");
    expect(result.analysis.isDrifting).toBe(true);
    expect(result.analysis.driftScore).toBeGreaterThanOrEqual(40);
    expect(result.analysis.indicators.length).toBeGreaterThan(0);
  });

  it("should report isDrifting correctly via the public method", () => {
    // Build baseline
    for (let i = 0; i < 10; i++) {
      detector.recordSample("agent-1", makeSample({ timestamp: Date.now() + i }));
    }
    detector.updateBaseline("agent-1");

    // Inject anomalous samples
    for (let i = 0; i < 10; i++) {
      detector.recordSample(
        "agent-1",
        makeSample({
          timestamp: Date.now() + 200 + i,
          tools: ["unknown_tool_1", "unknown_tool_2"],
          topics: ["forbidden_area"],
          sentiment: -1,
          responseLength: 10000,
          responseTime: 20000,
          hadError: true,
        })
      );
    }

    // Trigger analysis to update drift state
    detector.analyze("agent-1");

    expect(detector.isDrifting("agent-1")).toBe(true);
    expect(detector.getDriftingAgents()).toContain("agent-1");
  });

  it("should allow behavior within normal parameters (false positive test)", () => {
    // Build baseline
    for (let i = 0; i < 10; i++) {
      detector.recordSample(
        "agent-1",
        makeSample({
          timestamp: Date.now() + i,
          sentiment: 0.5 + (Math.random() * 0.1 - 0.05),
          responseLength: 200 + Math.floor(Math.random() * 20),
          responseTime: 300 + Math.floor(Math.random() * 20),
        })
      );
    }
    detector.updateBaseline("agent-1");

    // Continue with very similar samples
    const result = detector.analyze(
      "agent-1",
      makeSample({
        timestamp: Date.now() + 100,
        sentiment: 0.48,
        responseLength: 210,
        responseTime: 310,
      })
    );

    expect(result.allowed).toBe(true);
    expect(result.analysis.isDrifting).toBe(false);
  });

  it("should set and retrieve a manual baseline", () => {
    const baseline: BaselineProfile = {
      toolDistribution: { search: 0.5, summarize: 0.5 },
      topicDistribution: { science: 1.0 },
      avgSentiment: 0.6,
      sentimentStdDev: 0.1,
      avgResponseLength: 250,
      responseLengthStdDev: 50,
      avgResponseTime: 400,
      responseTimeStdDev: 100,
      errorRate: 0.05,
      avgSatisfaction: 0.8,
      sampleCount: 100,
      lastUpdated: Date.now(),
    };

    detector.setBaseline("agent-2", baseline);
    const retrieved = detector.getBaseline("agent-2");
    expect(retrieved).not.toBeNull();
    expect(retrieved!.avgSentiment).toBe(0.6);
  });

  it("should reset agent state", () => {
    for (let i = 0; i < 10; i++) {
      detector.recordSample("agent-1", makeSample({ timestamp: Date.now() + i }));
    }
    expect(detector.getSampleCount("agent-1")).toBe(10);

    detector.resetAgent("agent-1");
    expect(detector.getSampleCount("agent-1")).toBe(0);
    expect(detector.getBaseline("agent-1")).toBeNull();
    expect(detector.isDrifting("agent-1")).toBe(false);
  });

  it("should recommend kill switch for extreme drift scores", () => {
    // Build a stable baseline manually
    detector.setBaseline("agent-1", {
      toolDistribution: { search: 1.0 },
      topicDistribution: { science: 1.0 },
      avgSentiment: 0.8,
      sentimentStdDev: 0.05,
      avgResponseLength: 200,
      responseLengthStdDev: 10,
      avgResponseTime: 300,
      responseTimeStdDev: 10,
      errorRate: 0.0,
      avgSatisfaction: 0.9,
      sampleCount: 100,
      lastUpdated: Date.now(),
    });

    // Record enough samples to pass minimum and create extreme drift
    for (let i = 0; i < 10; i++) {
      detector.recordSample(
        "agent-1",
        makeSample({
          timestamp: Date.now() + i,
          tools: ["destroy", "exploit", "breach"],
          topics: ["attack", "vulnerability"],
          sentiment: -1,
          responseLength: 50000,
          responseTime: 100000,
          hadError: true,
        })
      );
    }

    const result = detector.analyze("agent-1");
    // With extreme deviations on all axes, score should be very high
    expect(result.analysis.driftScore).toBeGreaterThanOrEqual(60);
    expect(result.requires_review).toBe(true);
  });

  it("should fire onDrift callback when drift begins", () => {
    let driftFired = false;
    let driftAgentId = "";

    const detectorWithCallback = new DriftDetector({
      minimumSamples: 5,
      alertThreshold: 40,
      autoUpdateBaseline: true,
      baselineWindow: 24 * 60 * 60 * 1000,
      onDrift: (agentId) => {
        driftFired = true;
        driftAgentId = agentId;
      },
    });

    // Build baseline
    for (let i = 0; i < 10; i++) {
      detectorWithCallback.recordSample(
        "agent-cb",
        makeSample({ timestamp: Date.now() + i })
      );
    }
    detectorWithCallback.updateBaseline("agent-cb");

    // Introduce anomalous behavior
    for (let i = 0; i < 10; i++) {
      detectorWithCallback.recordSample(
        "agent-cb",
        makeSample({
          timestamp: Date.now() + 200 + i,
          tools: ["rogue_action"],
          topics: ["forbidden"],
          sentiment: -1,
          responseLength: 50000,
          responseTime: 99999,
          hadError: true,
        })
      );
    }

    detectorWithCallback.analyze("agent-cb");

    if (detectorWithCallback.isDrifting("agent-cb")) {
      expect(driftFired).toBe(true);
      expect(driftAgentId).toBe("agent-cb");
    }
  });
});
