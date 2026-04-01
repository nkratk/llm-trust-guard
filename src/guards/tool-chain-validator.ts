/**
 * ToolChainValidator v2
 *
 * Detects and prevents dangerous tool chaining attacks by:
 * - Validating tool call sequences
 * - Blocking dangerous tool combinations
 * - Enforcing cooldown periods between sensitive operations
 * - Tracking tool usage patterns for anomaly detection
 *
 * v2 Enhancements (2026):
 * - ASI07: Agent State Corruption detection
 * - ASI04: Agent Autonomy Escalation detection
 * - Loop/repetition attack detection
 * - Resource accumulation monitoring
 * - Time-based anomaly detection
 * - Cumulative impact scoring
 * - Cross-tool data flow tracking
 */

import { GuardLogger } from "../types";

export interface ToolChainValidatorConfig {
  // Tool chain rules
  forbiddenSequences?: ForbiddenSequence[];
  requiredPreconditions?: ToolPrecondition[];
  // Cooldown settings
  toolCooldowns?: Record<string, number>; // tool -> cooldown in ms
  // Limits
  maxToolsPerRequest?: number;
  maxSensitiveToolsPerSession?: number;
  // Sensitive tools
  sensitiveTools?: string[];
  // Session tracking
  sessionTTLMinutes?: number;
  // v2: State corruption detection
  enableStateTracking?: boolean;
  stateModifyingTools?: string[];
  // v2: Autonomy escalation detection
  enableAutonomyDetection?: boolean;
  autonomyExpandingTools?: string[];
  // v2: Loop detection
  enableLoopDetection?: boolean;
  maxRepetitionsPerMinute?: number;
  // v2: Resource accumulation
  enableResourceTracking?: boolean;
  resourceAcquiringTools?: string[];
  maxResourcesPerSession?: number;
  // v2: Time anomaly detection
  enableTimeAnomalyDetection?: boolean;
  minTimeBetweenToolsMs?: number;
  // v2: Impact scoring
  enableImpactScoring?: boolean;
  maxCumulativeImpact?: number;
  toolImpactScores?: Record<string, number>;
  logger?: GuardLogger;
}

export interface ForbiddenSequence {
  name: string;
  sequence: string[]; // e.g., ["read_file", "execute_code"]
  reason: string;
  severity: "warning" | "block";
}

export interface ToolPrecondition {
  tool: string;
  requires: string[]; // Tools that must be called first
  within_turns?: number; // Within how many turns
}

export interface ToolChainValidatorResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  chain_analysis: {
    current_tool: string;
    previous_tools: string[];
    forbidden_sequences_detected: string[];
    precondition_violations: string[];
    cooldown_violations: string[];
    // v2 additions
    state_corruption_detected?: boolean;
    autonomy_escalation_detected?: boolean;
    loop_detected?: boolean;
    resource_accumulation?: number;
    time_anomaly_detected?: boolean;
    cumulative_impact?: number;
  };
  warnings: string[];
}

interface ToolUsage {
  tool: string;
  timestamp: number;
  params_hash?: string;
  // v2 additions
  modifies_state?: boolean;
  expands_autonomy?: boolean;
  acquires_resource?: boolean;
  impact_score?: number;
}

interface ToolSession {
  id: string;
  tool_history: ToolUsage[];
  sensitive_tool_count: number;
  last_activity: number;
  // v2 additions
  state_modifications: number;
  autonomy_expansions: number;
  resources_acquired: number;
  cumulative_impact: number;
  tool_repetitions: Map<string, number[]>; // tool -> timestamps
}

export class ToolChainValidator {
  private config: ToolChainValidatorConfig;
  private logger: GuardLogger;
  private sessions: Map<string, ToolSession> = new Map();

  private defaultForbiddenSequences: ForbiddenSequence[] = [
    {
      name: "read_then_delete",
      sequence: ["read_file", "delete_file"],
      reason: "Reading then deleting files may indicate data exfiltration",
      severity: "block",
    },
    {
      name: "list_then_bulk_delete",
      sequence: ["list_users", "delete_user"],
      reason: "Listing then deleting users may indicate account takeover",
      severity: "block",
    },
    {
      name: "get_credentials_then_external",
      sequence: ["get_api_key", "http_request"],
      reason: "Accessing credentials then making external requests is suspicious",
      severity: "block",
    },
    {
      name: "modify_config_then_execute",
      sequence: ["update_config", "execute_command"],
      reason: "Modifying config then executing commands may indicate system compromise",
      severity: "block",
    },
    {
      name: "disable_security_then_action",
      sequence: ["disable_audit", "delete_records"],
      reason: "Disabling audit then deleting records indicates malicious activity",
      severity: "block",
    },
    {
      name: "escalate_then_sensitive",
      sequence: ["modify_user_role", "access_admin_panel"],
      reason: "Role escalation followed by admin access is suspicious",
      severity: "block",
    },
  ];

  private defaultSensitiveTools: string[] = [
    "delete",
    "remove",
    "drop",
    "truncate",
    "execute",
    "run",
    "admin",
    "system",
    "config",
    "modify_role",
    "grant",
    "revoke",
    "transfer_funds",
    "bulk_",
    "export",
  ];

  // v2: Tools that modify agent/system state
  private defaultStateModifyingTools: string[] = [
    "set_config",
    "update_settings",
    "modify_state",
    "change_mode",
    "set_variable",
    "store_memory",
    "update_context",
    "modify_prompt",
    "change_behavior",
    "set_preference",
    "alter_state",
    "write_memory",
    "persist_data",
  ];

  // v2: Tools that expand agent autonomy
  private defaultAutonomyExpandingTools: string[] = [
    "grant_permission",
    "enable_capability",
    "unlock_feature",
    "expand_scope",
    "add_tool",
    "register_handler",
    "create_webhook",
    "schedule_task",
    "spawn_agent",
    "create_subprocess",
    "enable_auto",
    "set_autonomous",
    "bypass_approval",
    "disable_confirmation",
    "skip_verification",
  ];

  // v2: Tools that acquire resources
  private defaultResourceAcquiringTools: string[] = [
    "get_credentials",
    "fetch_api_key",
    "acquire_token",
    "download_file",
    "copy_data",
    "clone_repo",
    "export_data",
    "backup_database",
    "snapshot",
    "read_secrets",
    "access_vault",
    "get_certificate",
  ];

  // v2: Impact scores for tools
  private defaultToolImpactScores: Record<string, number> = {
    "delete": 20,
    "remove": 15,
    "execute": 25,
    "admin": 30,
    "system": 25,
    "config": 15,
    "grant": 20,
    "transfer": 30,
    "export": 15,
    "credential": 25,
    "secret": 25,
    "password": 30,
    "spawn": 30,
    "subprocess": 25,
    "bypass": 35,
  };

  constructor(config: ToolChainValidatorConfig = {}) {
    this.config = {
      forbiddenSequences: config.forbiddenSequences ?? this.defaultForbiddenSequences,
      requiredPreconditions: config.requiredPreconditions ?? [],
      toolCooldowns: config.toolCooldowns ?? {},
      maxToolsPerRequest: config.maxToolsPerRequest ?? 10,
      maxSensitiveToolsPerSession: config.maxSensitiveToolsPerSession ?? 5,
      sensitiveTools: config.sensitiveTools ?? this.defaultSensitiveTools,
      sessionTTLMinutes: config.sessionTTLMinutes ?? 30,
      // v2 defaults
      enableStateTracking: config.enableStateTracking ?? true,
      stateModifyingTools: config.stateModifyingTools ?? this.defaultStateModifyingTools,
      enableAutonomyDetection: config.enableAutonomyDetection ?? true,
      autonomyExpandingTools: config.autonomyExpandingTools ?? this.defaultAutonomyExpandingTools,
      enableLoopDetection: config.enableLoopDetection ?? true,
      maxRepetitionsPerMinute: config.maxRepetitionsPerMinute ?? 5,
      enableResourceTracking: config.enableResourceTracking ?? true,
      resourceAcquiringTools: config.resourceAcquiringTools ?? this.defaultResourceAcquiringTools,
      maxResourcesPerSession: config.maxResourcesPerSession ?? 10,
      enableTimeAnomalyDetection: config.enableTimeAnomalyDetection ?? true,
      minTimeBetweenToolsMs: config.minTimeBetweenToolsMs ?? 50,
      enableImpactScoring: config.enableImpactScoring ?? true,
      maxCumulativeImpact: config.maxCumulativeImpact ?? 100,
      toolImpactScores: config.toolImpactScores ?? this.defaultToolImpactScores,
    };
    this.logger = config.logger || (() => {});

    // Cleanup expired sessions periodically
    setInterval(() => this.cleanupSessions(), 60000);
  }

  /**
   * Validate a tool call in context of the session
   */
  validate(
    sessionId: string,
    toolName: string,
    allToolsInRequest?: string[],
    requestId: string = ""
  ): ToolChainValidatorResult {
    const violations: string[] = [];
    const warnings: string[] = [];
    const forbiddenSequencesDetected: string[] = [];
    const preconditionViolations: string[] = [];
    const cooldownViolations: string[] = [];

    // v2 tracking
    let stateCorruptionDetected = false;
    let autonomyEscalationDetected = false;
    let loopDetected = false;
    let timeAnomalyDetected = false;

    // Get or create session
    const session = this.getOrCreateSession(sessionId);
    const now = Date.now();

    // Get recent tool history
    const recentTools = session.tool_history
      .filter((t) => now - t.timestamp < this.config.sessionTTLMinutes! * 60000)
      .map((t) => t.tool);

    // Check max tools per request
    if (allToolsInRequest && allToolsInRequest.length > this.config.maxToolsPerRequest!) {
      violations.push("MAX_TOOLS_PER_REQUEST_EXCEEDED");
    }

    // Check forbidden sequences
    for (const forbidden of this.config.forbiddenSequences!) {
      if (this.matchesSequence(recentTools, toolName, forbidden.sequence)) {
        forbiddenSequencesDetected.push(forbidden.name);
        if (forbidden.severity === "block") {
          violations.push(`FORBIDDEN_SEQUENCE_${forbidden.name.toUpperCase()}`);
        } else {
          warnings.push(`Suspicious sequence detected: ${forbidden.name}`);
        }
      }
    }

    // Check preconditions
    for (const precondition of this.config.requiredPreconditions!) {
      if (toolName === precondition.tool) {
        const turnsToCheck = precondition.within_turns ?? 10;
        const recentHistory = session.tool_history.slice(-turnsToCheck);
        const hasRequired = precondition.requires.every((req) =>
          recentHistory.some((h) => h.tool === req)
        );

        if (!hasRequired) {
          preconditionViolations.push(
            `${toolName} requires: ${precondition.requires.join(", ")}`
          );
          violations.push(`PRECONDITION_VIOLATED_${toolName.toUpperCase()}`);
        }
      }
    }

    // Check cooldowns
    const cooldown = this.config.toolCooldowns?.[toolName];
    if (cooldown) {
      const lastUsage = session.tool_history
        .filter((t) => t.tool === toolName)
        .sort((a, b) => b.timestamp - a.timestamp)[0];

      if (lastUsage && now - lastUsage.timestamp < cooldown) {
        const remainingMs = cooldown - (now - lastUsage.timestamp);
        cooldownViolations.push(
          `${toolName} on cooldown for ${Math.ceil(remainingMs / 1000)}s`
        );
        violations.push(`COOLDOWN_VIOLATION_${toolName.toUpperCase()}`);
      }
    }

    // Check sensitive tool limits
    const isSensitive = this.config.sensitiveTools!.some(
      (s) => toolName.toLowerCase().includes(s.toLowerCase())
    );

    if (isSensitive) {
      if (session.sensitive_tool_count >= this.config.maxSensitiveToolsPerSession!) {
        violations.push("MAX_SENSITIVE_TOOLS_EXCEEDED");
      }
    }

    // ===== v2 CHECKS =====

    // v2: State corruption detection (ASI07)
    if (this.config.enableStateTracking) {
      const modifiesState = this.config.stateModifyingTools!.some(
        (s) => toolName.toLowerCase().includes(s.toLowerCase())
      );
      if (modifiesState) {
        session.state_modifications++;
        // Check for rapid state modifications (potential corruption)
        const recentStateModifications = session.tool_history.filter(
          (t) => t.modifies_state && now - t.timestamp < 60000
        ).length;
        if (recentStateModifications >= 3) {
          stateCorruptionDetected = true;
          violations.push("STATE_CORRUPTION_PATTERN");
          warnings.push("Multiple rapid state modifications detected - potential state corruption attack");
        }
      }
    }

    // v2: Autonomy escalation detection (ASI04)
    if (this.config.enableAutonomyDetection) {
      const expandsAutonomy = this.config.autonomyExpandingTools!.some(
        (s) => toolName.toLowerCase().includes(s.toLowerCase())
      );
      if (expandsAutonomy) {
        session.autonomy_expansions++;
        if (session.autonomy_expansions >= 2) {
          autonomyEscalationDetected = true;
          violations.push("AUTONOMY_ESCALATION_DETECTED");
          warnings.push("Agent attempting to expand its own autonomy");
        }
      }
    }

    // v2: Loop/repetition detection
    if (this.config.enableLoopDetection) {
      // Track this tool's repetitions
      if (!session.tool_repetitions.has(toolName)) {
        session.tool_repetitions.set(toolName, []);
      }
      const repetitions = session.tool_repetitions.get(toolName)!;
      repetitions.push(now);

      // Clean up old timestamps
      const oneMinuteAgo = now - 60000;
      const recentReps = repetitions.filter((t) => t > oneMinuteAgo);
      session.tool_repetitions.set(toolName, recentReps);

      if (recentReps.length > this.config.maxRepetitionsPerMinute!) {
        loopDetected = true;
        violations.push("LOOP_ATTACK_DETECTED");
        warnings.push(`Tool "${toolName}" called ${recentReps.length} times in the last minute`);
      }
    }

    // v2: Resource accumulation detection
    if (this.config.enableResourceTracking) {
      const acquiresResource = this.config.resourceAcquiringTools!.some(
        (s) => toolName.toLowerCase().includes(s.toLowerCase())
      );
      if (acquiresResource) {
        session.resources_acquired++;
        if (session.resources_acquired > this.config.maxResourcesPerSession!) {
          violations.push("RESOURCE_ACCUMULATION_EXCEEDED");
          warnings.push("Agent has acquired too many resources in this session");
        }
      }
    }

    // v2: Time anomaly detection (unusually rapid tool calls)
    if (this.config.enableTimeAnomalyDetection) {
      const lastTool = session.tool_history[session.tool_history.length - 1];
      if (lastTool && now - lastTool.timestamp < this.config.minTimeBetweenToolsMs!) {
        timeAnomalyDetected = true;
        violations.push("TIME_ANOMALY_DETECTED");
        warnings.push("Tool calls too rapid - possible automated attack");
      }
    }

    // v2: Impact scoring
    let toolImpact = 0;
    if (this.config.enableImpactScoring) {
      // Calculate impact for this tool
      for (const [keyword, score] of Object.entries(this.config.toolImpactScores!)) {
        if (toolName.toLowerCase().includes(keyword.toLowerCase())) {
          toolImpact = Math.max(toolImpact, score);
        }
      }

      const newCumulativeImpact = session.cumulative_impact + toolImpact;
      if (newCumulativeImpact > this.config.maxCumulativeImpact!) {
        violations.push("MAX_CUMULATIVE_IMPACT_EXCEEDED");
        warnings.push(`Cumulative impact ${newCumulativeImpact} exceeds threshold ${this.config.maxCumulativeImpact}`);
      }
    }

    // ===== END v2 CHECKS =====

    const allowed = violations.length === 0;

    // Record tool usage if allowed
    if (allowed) {
      const modifiesState = this.config.stateModifyingTools?.some(
        (s) => toolName.toLowerCase().includes(s.toLowerCase())
      ) ?? false;
      const expandsAutonomy = this.config.autonomyExpandingTools?.some(
        (s) => toolName.toLowerCase().includes(s.toLowerCase())
      ) ?? false;
      const acquiresResource = this.config.resourceAcquiringTools?.some(
        (s) => toolName.toLowerCase().includes(s.toLowerCase())
      ) ?? false;

      session.tool_history.push({
        tool: toolName,
        timestamp: now,
        modifies_state: modifiesState,
        expands_autonomy: expandsAutonomy,
        acquires_resource: acquiresResource,
        impact_score: toolImpact,
      });
      if (isSensitive) {
        session.sensitive_tool_count++;
      }
      session.cumulative_impact += toolImpact;
      session.last_activity = now;
    }

    if (!allowed) {
      this.logger(
        `[ToolChainValidator:${requestId}] BLOCKED: ${violations.join(", ")}`, "info"
      );
    }

    return {
      allowed,
      reason: allowed ? undefined : `Tool chain validation failed: ${violations.join(", ")}`,
      violations,
      chain_analysis: {
        current_tool: toolName,
        previous_tools: recentTools.slice(-10),
        forbidden_sequences_detected: forbiddenSequencesDetected,
        precondition_violations: preconditionViolations,
        cooldown_violations: cooldownViolations,
        // v2 additions
        state_corruption_detected: stateCorruptionDetected,
        autonomy_escalation_detected: autonomyEscalationDetected,
        loop_detected: loopDetected,
        resource_accumulation: session.resources_acquired,
        time_anomaly_detected: timeAnomalyDetected,
        cumulative_impact: session.cumulative_impact,
      },
      warnings,
    };
  }

  /**
   * Validate multiple tools at once (for parallel tool calls)
   */
  validateBatch(
    sessionId: string,
    tools: string[],
    requestId: string = ""
  ): ToolChainValidatorResult {
    const allViolations: string[] = [];
    const allWarnings: string[] = [];
    const allForbidden: string[] = [];
    const allPrecondition: string[] = [];
    const allCooldown: string[] = [];

    // Check if too many tools
    if (tools.length > this.config.maxToolsPerRequest!) {
      allViolations.push("MAX_TOOLS_PER_REQUEST_EXCEEDED");
    }

    // Check each tool
    for (const tool of tools) {
      const result = this.validate(sessionId, tool, tools, requestId);
      allViolations.push(...result.violations);
      allWarnings.push(...result.warnings);
      allForbidden.push(...result.chain_analysis.forbidden_sequences_detected);
      allPrecondition.push(...result.chain_analysis.precondition_violations);
      allCooldown.push(...result.chain_analysis.cooldown_violations);
    }

    // Check for forbidden sequences within the batch
    for (const forbidden of this.config.forbiddenSequences!) {
      if (
        forbidden.sequence.every((s) =>
          tools.some((t) => t.toLowerCase().includes(s.toLowerCase()))
        )
      ) {
        allForbidden.push(forbidden.name);
        if (forbidden.severity === "block") {
          allViolations.push(`BATCH_FORBIDDEN_SEQUENCE_${forbidden.name.toUpperCase()}`);
        }
      }
    }

    const session = this.sessions.get(sessionId);
    const recentTools = session?.tool_history.map((t) => t.tool) ?? [];

    return {
      allowed: allViolations.length === 0,
      reason: allViolations.length === 0
        ? undefined
        : `Batch validation failed: ${allViolations.join(", ")}`,
      violations: [...new Set(allViolations)],
      chain_analysis: {
        current_tool: tools.join(", "),
        previous_tools: recentTools.slice(-10),
        forbidden_sequences_detected: [...new Set(allForbidden)],
        precondition_violations: [...new Set(allPrecondition)],
        cooldown_violations: [...new Set(allCooldown)],
      },
      warnings: [...new Set(allWarnings)],
    };
  }

  /**
   * Get session tool history
   */
  getToolHistory(sessionId: string): string[] {
    const session = this.sessions.get(sessionId);
    return session?.tool_history.map((t) => t.tool) ?? [];
  }

  /**
   * Reset session
   */
  resetSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  private getOrCreateSession(sessionId: string): ToolSession {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        id: sessionId,
        tool_history: [],
        sensitive_tool_count: 0,
        last_activity: Date.now(),
        // v2 fields
        state_modifications: 0,
        autonomy_expansions: 0,
        resources_acquired: 0,
        cumulative_impact: 0,
        tool_repetitions: new Map(),
      });
    }
    return this.sessions.get(sessionId)!;
  }

  private matchesSequence(
    history: string[],
    currentTool: string,
    sequence: string[]
  ): boolean {
    if (sequence.length === 0) return false;

    // Check if current tool matches the last in sequence
    const lastInSequence = sequence[sequence.length - 1];
    if (!currentTool.toLowerCase().includes(lastInSequence.toLowerCase())) {
      return false;
    }

    // Check if history contains the preceding tools in order
    if (sequence.length === 1) return true;

    const precedingSequence = sequence.slice(0, -1);
    let seqIndex = 0;

    for (const histTool of history) {
      if (
        histTool.toLowerCase().includes(precedingSequence[seqIndex].toLowerCase())
      ) {
        seqIndex++;
        if (seqIndex >= precedingSequence.length) {
          return true;
        }
      }
    }

    return false;
  }

  private cleanupSessions(): void {
    const ttlMs = this.config.sessionTTLMinutes! * 60000;
    const now = Date.now();

    for (const [id, session] of this.sessions.entries()) {
      if (now - session.last_activity > ttlMs) {
        this.sessions.delete(id);
      }
    }
  }
}
