/**
 * AutonomyEscalationGuard (L21)
 *
 * Detects and prevents unauthorized autonomy escalation attempts.
 * Implements ASI10 from OWASP Agentic Applications 2026.
 *
 * Threat Model:
 * - ASI10: Unauthorized Autonomy Escalation
 * - Self-modification attempts
 * - Capability expansion
 * - Human-in-the-loop bypass
 * - Sub-agent spawning without approval
 *
 * Protection Capabilities:
 * - Autonomy level tracking
 * - Capability boundary enforcement
 * - Self-modification detection
 * - Sub-agent control
 * - Escalation pattern detection
 */

export interface AutonomyEscalationGuardConfig {
  /** Maximum allowed autonomy level (0-100) */
  maxAutonomyLevel?: number;
  /** Base autonomy level for new sessions */
  baseAutonomyLevel?: number;
  /** Enable self-modification detection */
  detectSelfModification?: boolean;
  /** Enable sub-agent spawning control */
  controlSubAgents?: boolean;
  /** Maximum allowed sub-agents */
  maxSubAgents?: number;
  /** Actions that require autonomy escalation approval */
  escalationRequiredActions?: string[];
  /** Enable capability boundary enforcement */
  enforceCapabilityBoundaries?: boolean;
  /** Allowed capabilities per autonomy level */
  capabilityLevels?: Record<number, string[]>;
  /** Enable human-in-the-loop enforcement */
  enforceHITL?: boolean;
  /** Actions that always require human approval */
  alwaysRequireHuman?: string[];
}

export interface AutonomyRequest {
  /** Request identifier */
  request_id: string;
  /** Type of autonomy request */
  request_type: "capability_expansion" | "level_increase" | "spawn_agent" | "self_modify" | "bypass_hitl" | "persist_state";
  /** Requested capability or action */
  requested_capability?: string;
  /** Requested autonomy level */
  requested_level?: number;
  /** Reason provided for the request */
  reason?: string;
  /** Source of the request (agent, tool, external) */
  source: string;
  /** Timestamp */
  timestamp: number;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

export interface AgentCapabilities {
  /** Current capabilities */
  capabilities: Set<string>;
  /** Current autonomy level */
  autonomy_level: number;
  /** Sub-agents spawned */
  sub_agents: string[];
  /** Pending escalation requests */
  pending_requests: AutonomyRequest[];
  /** Denied requests history */
  denied_requests: AutonomyRequest[];
  /** Last capability change timestamp */
  last_capability_change: number;
  /** HITL checkpoint count */
  hitl_checkpoints: number;
}

export interface AutonomyEscalationResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  analysis: {
    current_autonomy_level: number;
    requested_autonomy_level?: number;
    capability_violation: boolean;
    self_modification_detected: boolean;
    sub_agent_limit_exceeded: boolean;
    hitl_required: boolean;
    escalation_patterns_detected: string[];
  };
  requires_approval: boolean;
  approval_type?: "human" | "admin" | "system";
  recommendations: string[];
}

export class AutonomyEscalationGuard {
  private config: Required<AutonomyEscalationGuardConfig>;
  private agentStates: Map<string, AgentCapabilities> = new Map();

  // Autonomy escalation patterns
  private readonly ESCALATION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: number }> = [
    // Self-modification attempts
    { name: "modify_own_code", pattern: /modify\s+(my\s+own|my|own|this\s+agent'?s?)\s+(code|behavior|instructions?)/i, severity: 90 },
    { name: "update_capabilities", pattern: /update\s+(my|own)\s+(capabilities|permissions?|abilities)/i, severity: 80 },
    { name: "change_constraints", pattern: /remove?\s+(my|the)?\s*(constraints?|limitations?|restrictions?)/i, severity: 85 },
    { name: "disable_safety", pattern: /disable\s+(safety|security|guardrails?|filters?)/i, severity: 95 },

    // Autonomy expansion
    { name: "increase_autonomy", pattern: /increase\s+(my|agent'?s?)?\s*autonomy/i, severity: 70 },
    { name: "act_freely", pattern: /act\s+(freely|without\s+restriction|independently)/i, severity: 75 },
    { name: "full_control", pattern: /give\s+(me|agent)\s+(full|complete|total)\s+control/i, severity: 85 },
    { name: "unrestricted", pattern: /unrestricted\s+(access|mode|operation)/i, severity: 80 },

    // Human-in-the-loop bypass
    { name: "bypass_approval", pattern: /bypass\s+(human\s+)?(approval|verification|confirmation)/i, severity: 90 },
    { name: "skip_review", pattern: /skip\s+(human\s+)?(review|check|oversight)/i, severity: 85 },
    { name: "no_supervision", pattern: /without\s+(human\s+)?(supervision|oversight|intervention)/i, severity: 80 },
    { name: "auto_approve", pattern: /auto(-|\s+)?(approve|authorize|confirm)/i, severity: 75 },

    // Sub-agent spawning
    { name: "spawn_agent", pattern: /spawn\s+(new\s+)?(agent|process|worker)/i, severity: 60 },
    { name: "create_copy", pattern: /create\s+(a\s+)?(copy|clone|replica)\s+of\s+(myself|this\s+agent)/i, severity: 85 },
    { name: "delegate_all", pattern: /delegate\s+(all|everything|full\s+authority)/i, severity: 70 },
    { name: "fork_agent", pattern: /fork\s+(myself|this\s+agent|process)/i, severity: 80 },

    // Persistence attempts
    { name: "persist_changes", pattern: /persist\s+(these\s+)?(changes|modifications?|settings?)/i, severity: 65 },
    { name: "permanent_mode", pattern: /permanent(ly)?\s+(enable|activate|set)/i, severity: 70 },
    { name: "save_state", pattern: /save\s+(my|current)\s+state\s+(permanently|forever)/i, severity: 60 },
    { name: "write_config", pattern: /write\s+to\s+(config|configuration|settings)/i, severity: 75 },

    // Capability escalation
    { name: "need_more_access", pattern: /need\s+(more|additional|elevated)\s+access/i, severity: 50 },
    { name: "require_permissions", pattern: /require\s+(admin|root|elevated)\s+permissions?/i, severity: 70 },
    { name: "unlock_features", pattern: /unlock\s+(hidden|restricted|blocked)\s+features?/i, severity: 75 },
    { name: "enable_all", pattern: /enable\s+all\s+(capabilities|features?|functions?)/i, severity: 80 },
  ];

  // Default capability levels
  private readonly DEFAULT_CAPABILITY_LEVELS: Record<number, string[]> = {
    0: ["read_only", "query"],
    25: ["read_only", "query", "suggest", "analyze"],
    50: ["read_only", "query", "suggest", "analyze", "create_draft", "modify_draft"],
    75: ["read_only", "query", "suggest", "analyze", "create_draft", "modify_draft", "execute_safe", "api_call_internal"],
    100: ["read_only", "query", "suggest", "analyze", "create_draft", "modify_draft", "execute_safe", "api_call_internal", "execute_any", "api_call_external", "modify_system"],
  };

  constructor(config: AutonomyEscalationGuardConfig = {}) {
    this.config = {
      maxAutonomyLevel: config.maxAutonomyLevel ?? 75,
      baseAutonomyLevel: config.baseAutonomyLevel ?? 25,
      detectSelfModification: config.detectSelfModification ?? true,
      controlSubAgents: config.controlSubAgents ?? true,
      maxSubAgents: config.maxSubAgents ?? 3,
      escalationRequiredActions: config.escalationRequiredActions ?? [
        "execute_code",
        "modify_system",
        "api_call_external",
        "spawn_agent",
        "modify_config",
      ],
      enforceCapabilityBoundaries: config.enforceCapabilityBoundaries ?? true,
      capabilityLevels: config.capabilityLevels ?? this.DEFAULT_CAPABILITY_LEVELS,
      enforceHITL: config.enforceHITL ?? true,
      alwaysRequireHuman: config.alwaysRequireHuman ?? [
        "delete_data",
        "payment_process",
        "credential_modify",
        "user_data_export",
        "system_shutdown",
      ],
    };
  }

  /**
   * Validate an autonomy-related action or request
   */
  validate(
    action: string,
    sessionId: string,
    params?: Record<string, any>,
    requestId?: string
  ): AutonomyEscalationResult {
    const reqId = requestId || `auto-${Date.now()}`;
    const violations: string[] = [];
    const escalationPatterns: string[] = [];

    // Get or create agent state
    let state = this.agentStates.get(sessionId);
    if (!state) {
      state = this.createAgentState();
      this.agentStates.set(sessionId, state);
    }

    let capabilityViolation = false;
    let selfModificationDetected = false;
    let subAgentLimitExceeded = false;
    let hitlRequired = false;
    let requiresApproval = false;
    let approvalType: "human" | "admin" | "system" | undefined;

    // 1. Check for escalation patterns in action/params
    const textToCheck = `${action} ${JSON.stringify(params || {})}`;
    for (const { name, pattern, severity } of this.ESCALATION_PATTERNS) {
      if (pattern.test(textToCheck)) {
        escalationPatterns.push(name);
        if (severity >= 80) {
          violations.push(`escalation_pattern: ${name}`);
        }
        if (name.includes("modify") || name.includes("change") || name.includes("disable")) {
          selfModificationDetected = true;
        }
      }
    }

    // 2. Check if action requires escalation approval
    if (this.config.escalationRequiredActions.includes(action)) {
      requiresApproval = true;
      approvalType = "admin";
      violations.push(`escalation_required: ${action}`);
    }

    // 3. Check capability boundaries
    if (this.config.enforceCapabilityBoundaries) {
      const allowedCapabilities = this.getCapabilitiesForLevel(state.autonomy_level);
      if (!allowedCapabilities.includes(action) && !state.capabilities.has(action)) {
        capabilityViolation = true;
        violations.push(`capability_violation: ${action} not allowed at level ${state.autonomy_level}`);
        requiresApproval = true;
        approvalType = "admin";
      }
    }

    // 4. Check for self-modification attempts
    if (this.config.detectSelfModification && selfModificationDetected) {
      violations.push("self_modification_attempt");
      requiresApproval = true;
      approvalType = "human";
    }

    // 5. Check sub-agent limits
    if (this.config.controlSubAgents) {
      if (action === "spawn_agent" || escalationPatterns.some(p => p.includes("spawn") || p.includes("fork") || p.includes("clone"))) {
        if (state.sub_agents.length >= this.config.maxSubAgents) {
          subAgentLimitExceeded = true;
          violations.push(`sub_agent_limit_exceeded: ${state.sub_agents.length}/${this.config.maxSubAgents}`);
        } else {
          requiresApproval = true;
          approvalType = "human";
        }
      }
    }

    // 6. Check HITL enforcement
    if (this.config.enforceHITL) {
      if (this.config.alwaysRequireHuman.includes(action)) {
        hitlRequired = true;
        requiresApproval = true;
        approvalType = "human";
      }
    }

    // 7. Check for autonomy level escalation in params
    if (params?.autonomy_level !== undefined) {
      const requestedLevel = Number(params.autonomy_level);
      if (requestedLevel > state.autonomy_level) {
        violations.push(`autonomy_level_escalation: ${state.autonomy_level} -> ${requestedLevel}`);
        requiresApproval = true;
        approvalType = "admin";
      }
      if (requestedLevel > this.config.maxAutonomyLevel) {
        violations.push(`autonomy_level_exceeds_max: ${requestedLevel} > ${this.config.maxAutonomyLevel}`);
      }
    }

    // Determine if action should be blocked
    const highSeverityPatterns = escalationPatterns.filter(p => {
      const pattern = this.ESCALATION_PATTERNS.find(ep => ep.name === p);
      return pattern && pattern.severity >= 85;
    });

    const blocked =
      (selfModificationDetected && this.config.detectSelfModification) ||
      subAgentLimitExceeded ||
      capabilityViolation ||
      violations.length >= 3 ||
      highSeverityPatterns.length >= 1 ||
      (requiresApproval && this.config.escalationRequiredActions.includes(action));

    return {
      allowed: !blocked,
      reason: blocked
        ? `Autonomy escalation blocked: ${violations.slice(0, 3).join(", ")}`
        : requiresApproval
          ? "Action requires approval"
          : "Action validated",
      violations,
      request_id: reqId,
      analysis: {
        current_autonomy_level: state.autonomy_level,
        requested_autonomy_level: params?.autonomy_level,
        capability_violation: capabilityViolation,
        self_modification_detected: selfModificationDetected,
        sub_agent_limit_exceeded: subAgentLimitExceeded,
        hitl_required: hitlRequired,
        escalation_patterns_detected: escalationPatterns,
      },
      requires_approval: requiresApproval,
      approval_type: approvalType,
      recommendations: this.generateRecommendations(violations, state.autonomy_level, requiresApproval),
    };
  }

  /**
   * Request autonomy escalation
   */
  requestEscalation(
    sessionId: string,
    request: Omit<AutonomyRequest, "request_id" | "timestamp">
  ): AutonomyEscalationResult {
    const reqId = `esc-${Date.now()}`;
    const violations: string[] = [];

    let state = this.agentStates.get(sessionId);
    if (!state) {
      state = this.createAgentState();
      this.agentStates.set(sessionId, state);
    }

    const fullRequest: AutonomyRequest = {
      ...request,
      request_id: reqId,
      timestamp: Date.now(),
    };

    // Check if similar request was recently denied
    const recentDenial = state.denied_requests.find(
      r => r.request_type === request.request_type &&
           r.requested_capability === request.requested_capability &&
           Date.now() - r.timestamp < 5 * 60 * 1000 // 5 minutes
    );

    if (recentDenial) {
      violations.push("repeated_denied_request");
      return {
        allowed: false,
        reason: "Similar request was recently denied",
        violations,
        request_id: reqId,
        analysis: {
          current_autonomy_level: state.autonomy_level,
          requested_autonomy_level: request.requested_level,
          capability_violation: false,
          self_modification_detected: request.request_type === "self_modify",
          sub_agent_limit_exceeded: false,
          hitl_required: true,
          escalation_patterns_detected: [],
        },
        requires_approval: false,
        recommendations: ["Wait before retrying escalation request", "Provide additional justification"],
      };
    }

    // Validate based on request type
    let blocked = false;
    let approvalType: "human" | "admin" | "system" = "admin";

    switch (request.request_type) {
      case "self_modify":
        blocked = true;
        violations.push("self_modification_blocked");
        break;

      case "level_increase":
        if (request.requested_level !== undefined) {
          if (request.requested_level > this.config.maxAutonomyLevel) {
            blocked = true;
            violations.push("exceeds_max_autonomy_level");
          } else if (request.requested_level > state.autonomy_level + 25) {
            violations.push("large_autonomy_jump");
            approvalType = "human";
          }
        }
        break;

      case "spawn_agent":
        if (state.sub_agents.length >= this.config.maxSubAgents) {
          blocked = true;
          violations.push("sub_agent_limit_reached");
        } else {
          approvalType = "human";
        }
        break;

      case "capability_expansion":
        approvalType = "admin";
        break;

      case "bypass_hitl":
        blocked = true;
        violations.push("hitl_bypass_not_allowed");
        break;

      case "persist_state":
        approvalType = "human";
        break;
    }

    // Add to pending or denied requests
    if (blocked) {
      state.denied_requests.push(fullRequest);
      // Keep only last 10 denied requests
      if (state.denied_requests.length > 10) {
        state.denied_requests.shift();
      }
    } else {
      state.pending_requests.push(fullRequest);
    }

    this.agentStates.set(sessionId, state);

    return {
      allowed: !blocked,
      reason: blocked
        ? `Escalation request denied: ${violations.join(", ")}`
        : "Escalation request pending approval",
      violations,
      request_id: reqId,
      analysis: {
        current_autonomy_level: state.autonomy_level,
        requested_autonomy_level: request.requested_level,
        capability_violation: false,
        self_modification_detected: request.request_type === "self_modify",
        sub_agent_limit_exceeded: state.sub_agents.length >= this.config.maxSubAgents,
        hitl_required: true,
        escalation_patterns_detected: [],
      },
      requires_approval: !blocked,
      approval_type: approvalType,
      recommendations: this.generateRecommendations(violations, state.autonomy_level, !blocked),
    };
  }

  /**
   * Approve a pending escalation request (called by human/admin)
   */
  approveEscalation(sessionId: string, requestId: string): boolean {
    const state = this.agentStates.get(sessionId);
    if (!state) return false;

    const requestIndex = state.pending_requests.findIndex(r => r.request_id === requestId);
    if (requestIndex === -1) return false;

    const request = state.pending_requests[requestIndex];
    state.pending_requests.splice(requestIndex, 1);

    // Apply the escalation
    switch (request.request_type) {
      case "level_increase":
        if (request.requested_level !== undefined) {
          state.autonomy_level = Math.min(request.requested_level, this.config.maxAutonomyLevel);
        }
        break;

      case "capability_expansion":
        if (request.requested_capability) {
          state.capabilities.add(request.requested_capability);
        }
        break;

      case "spawn_agent":
        if (request.metadata?.agent_id) {
          state.sub_agents.push(request.metadata.agent_id);
        }
        break;
    }

    state.last_capability_change = Date.now();
    state.hitl_checkpoints++;
    this.agentStates.set(sessionId, state);
    return true;
  }

  /**
   * Deny a pending escalation request
   */
  denyEscalation(sessionId: string, requestId: string): boolean {
    const state = this.agentStates.get(sessionId);
    if (!state) return false;

    const requestIndex = state.pending_requests.findIndex(r => r.request_id === requestId);
    if (requestIndex === -1) return false;

    const request = state.pending_requests[requestIndex];
    state.pending_requests.splice(requestIndex, 1);
    state.denied_requests.push(request);

    // Reduce autonomy level slightly after denied escalation
    state.autonomy_level = Math.max(0, state.autonomy_level - 5);
    this.agentStates.set(sessionId, state);
    return true;
  }

  /**
   * Register a sub-agent
   */
  registerSubAgent(sessionId: string, subAgentId: string): boolean {
    let state = this.agentStates.get(sessionId);
    if (!state) {
      state = this.createAgentState();
      this.agentStates.set(sessionId, state);
    }

    if (state.sub_agents.length >= this.config.maxSubAgents) {
      return false;
    }

    state.sub_agents.push(subAgentId);
    this.agentStates.set(sessionId, state);
    return true;
  }

  /**
   * Get current agent capabilities
   */
  getAgentState(sessionId: string): AgentCapabilities | undefined {
    return this.agentStates.get(sessionId);
  }

  /**
   * Set autonomy level directly (admin only)
   */
  setAutonomyLevel(sessionId: string, level: number): void {
    let state = this.agentStates.get(sessionId);
    if (!state) {
      state = this.createAgentState();
    }
    state.autonomy_level = Math.min(level, this.config.maxAutonomyLevel);
    state.last_capability_change = Date.now();
    this.agentStates.set(sessionId, state);
  }

  /**
   * Reset agent state
   */
  resetSession(sessionId: string): void {
    this.agentStates.delete(sessionId);
  }

  // Private methods

  private createAgentState(): AgentCapabilities {
    return {
      capabilities: new Set(this.getCapabilitiesForLevel(this.config.baseAutonomyLevel)),
      autonomy_level: this.config.baseAutonomyLevel,
      sub_agents: [],
      pending_requests: [],
      denied_requests: [],
      last_capability_change: Date.now(),
      hitl_checkpoints: 0,
    };
  }

  private getCapabilitiesForLevel(level: number): string[] {
    // Find the highest level that doesn't exceed the current level
    const levels = Object.keys(this.config.capabilityLevels)
      .map(Number)
      .filter(l => l <= level)
      .sort((a, b) => b - a);

    if (levels.length === 0) return [];
    return this.config.capabilityLevels[levels[0]] || [];
  }

  private generateRecommendations(
    violations: string[],
    autonomyLevel: number,
    requiresApproval: boolean
  ): string[] {
    const recommendations: string[] = [];

    if (violations.some(v => v.includes("self_modification"))) {
      recommendations.push("Self-modification is not allowed - use approved update channels");
    }
    if (violations.some(v => v.includes("capability_violation"))) {
      recommendations.push("Request capability expansion through proper escalation process");
    }
    if (violations.some(v => v.includes("sub_agent"))) {
      recommendations.push("Sub-agent limit reached - terminate existing agents before spawning new ones");
    }
    if (violations.some(v => v.includes("autonomy_level"))) {
      recommendations.push("Request autonomy increase through formal escalation process");
    }
    if (requiresApproval) {
      recommendations.push("Wait for human/admin approval before proceeding");
    }
    if (autonomyLevel < 50) {
      recommendations.push("Build trust through successful operations to increase autonomy level");
    }

    if (recommendations.length === 0) {
      recommendations.push("Continue operating within current capability boundaries");
    }

    return recommendations;
  }
}
