/**
 * Core types for llm-trust-guard
 */

// Logger type shared across all guards
export type GuardLogger = (message: string, level: "info" | "warn" | "error") => void;

/**
 * Sensitivity mode for threshold-based guards.
 *
 * - `strict`     — lower thresholds, catches more attacks, higher false positive rate
 * - `balanced`   — default thresholds (same as current defaults)
 * - `permissive` — higher thresholds, fewer false positives, may miss borderline attacks
 *
 * Apply globally via TrustGuardConfig.sensitivity, or override per-guard.
 */
export type SensitivityMode = "strict" | "balanced" | "permissive";

// Common guard identity interface
export interface Guard {
  readonly guardName: string;
  readonly guardLayer: string;
}

// Generic role type - can be extended by users
export type Role = string;

// Session context for authenticated users
export interface SessionContext {
  user_id: string;
  tenant_id: string;
  role: Role;
  authenticated: boolean;
  session_id?: string;
  metadata?: Record<string, any>;
}

// Tool definition for LLM function calling
export interface ToolDefinition {
  name: string;
  description: string;
  parameters: {
    type: "object";
    properties: Record<string, SchemaProperty>;
    required?: string[];
  };
  roles?: Role[];
  constraints?: ToolConstraints;
}

// Schema property definition
export interface SchemaProperty {
  type: "string" | "number" | "boolean" | "object" | "array";
  description?: string;
  enum?: string[];
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: string;
  items?: SchemaProperty;
  properties?: Record<string, SchemaProperty>;
  required?: string[];
}

// Tool constraints for role-based limits
export interface ToolConstraints {
  [role: string]: {
    max_amount?: number;
    require_approval?: boolean;
    rate_limit?: number;
    allowed_values?: Record<string, any[]>;
  };
}

// Guard result base
export interface GuardResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
}

// L1: Input Sanitizer result
export interface SanitizerResult extends GuardResult {
  score: number;
  matches: string[];
  sanitizedInput: string;
  warnings: string[];
}

// L2: Tool Registry result
export interface ToolRegistryResult extends GuardResult {
  tool?: ToolDefinition;
  hallucination_detected: boolean;
  similar_tools?: string[];
}

// L3: Policy Gate result
export interface PolicyGateResult extends GuardResult {
  session_role: Role;
  required_roles: Role[];
  constraint_violations?: string[];
}

// L4: Tenant Boundary result
export interface TenantBoundaryResult extends GuardResult {
  session_tenant: string;
  resource_tenant?: string;
  enforced_params?: Record<string, any>;
}

// L5: Schema Validator result
export interface SchemaValidatorResult extends GuardResult {
  errors: string[];
  warnings: string[];
  sanitizedParams: Record<string, any>;
  blocked_attacks: string[];
}

// L6: Execution Monitor result
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

// L7: Output Filter result
export interface OutputFilterResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  pii_detected: Array<{
    type: string;
    count: number;
    masked: boolean;
    locations: string[];
  }>;
  secrets_detected: Array<{
    type: string;
    severity: string;
    blocked: boolean;
    location: string;
  }>;
  filtered_fields: string[];
  original_response?: any;
  filtered_response?: any;
  blocking_reason?: string;
}

// Conversation Guard result
export interface ConversationGuardResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  risk_score: number;
  risk_factors: Array<{
    factor: string;
    weight: number;
    details: string;
  }>;
  conversation_analysis: {
    turn_count: number;
    escalation_attempts: number;
    manipulation_indicators: number;
    suspicious_patterns: string[];
  };
}

// Tool Chain Validator result
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
  };
  warnings: string[];
}

// Encoding Detector result
export interface EncodingDetectorResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  encoding_analysis: {
    encodings_detected: Array<{
      type: string;
      count: number;
      locations: string[];
      decoded_sample?: string;
    }>;
    decoded_content?: string;
    threats_found: Array<{
      pattern_name: string;
      severity: string;
      in_layer: string;
    }>;
    obfuscation_score: number;
  };
}

// Combined guard check result
export interface TrustGuardResult {
  allowed: boolean;
  block_layer?: "L1" | "L2" | "L3" | "L4" | "L5" | "L6" | "L7" | "CONV" | "CHAIN" | "ENCODING" | "MEMORY" | "PROMPT_LEAKAGE" | "AUTONOMY" | "STATE" | "CIRCUIT_BREAKER" | "GUARD_ERROR";
  block_reason?: string;
  all_violations: string[];
  sanitizer?: SanitizerResult;
  registry?: ToolRegistryResult;
  policy?: PolicyGateResult;
  tenant?: TenantBoundaryResult;
  schema?: SchemaValidatorResult;
  execution?: ExecutionMonitorResult;
  output?: OutputFilterResult;
  conversation?: ConversationGuardResult;
  chain?: ToolChainValidatorResult;
  encoding?: EncodingDetectorResult;
  request_id: string;
}

// Configuration options
export interface TrustGuardConfig {
  // L1 config
  sanitizer?: {
    enabled?: boolean;
    threshold?: number;
    customPatterns?: Array<{ pattern: RegExp; weight: number; name: string }>;
    detectPAP?: boolean;
    papThreshold?: number;
    minPersuasionTechniques?: number;
    blockCompoundPersuasion?: boolean;
  };
  // L2 config
  registry?: {
    enabled?: boolean;
    tools: ToolDefinition[];
  };
  // L3 config
  policy?: {
    enabled?: boolean;
    roleHierarchy?: Record<Role, number>;
  };
  // L4 config
  tenant?: {
    enabled?: boolean;
    resourceOwnership?: Record<string, { tenant_id: string }>;
  };
  // L5 config
  schema?: {
    enabled?: boolean;
    strictTypes?: boolean;
  };
  // L6 config
  execution?: {
    enabled?: boolean;
    maxRequestsPerMinute?: number;
    maxRequestsPerHour?: number;
    operationCosts?: Record<string, number>;
    maxCostPerMinute?: number;
    maxCostPerHour?: number;
  };
  // L7 config
  output?: {
    enabled?: boolean;
    detectPII?: boolean;
    detectSecrets?: boolean;
    roleFilters?: Record<string, string[]>;
  };
  // Conversation Guard config
  conversation?: {
    enabled?: boolean;
    maxConversationLength?: number;
    escalationThreshold?: number;
  };
  // Tool Chain Validator config
  chain?: {
    enabled?: boolean;
    maxToolsPerRequest?: number;
    maxSensitiveToolsPerSession?: number;
    sensitiveTools?: string[];
  };
  // Encoding Detector config
  encoding?: {
    enabled?: boolean;
    maxDecodingDepth?: number;
    maxEncodedRatio?: number;
  };
  // MultiModal Guard config
  multiModal?: {
    enabled?: boolean;
    scanMetadata?: boolean;
    detectBase64Payloads?: boolean;
    allowedMimeTypes?: string[];
  };
  // Memory Guard config
  memory?: {
    enabled?: boolean;
    enableIntegrityCheck?: boolean;
    detectInjections?: boolean;
    maxMemoryItems?: number;
    signingKey?: string;
    autoQuarantine?: boolean;
    riskThreshold?: number;
  };
  // RAG Guard config
  rag?: {
    enabled?: boolean;
    detectInjections?: boolean;
    verifySource?: boolean;
    trustedSources?: string[];
    blockedSources?: string[];
    maxDocumentSize?: number;
    minTrustScore?: number;
    detectEmbeddingAttacks?: boolean;
  };
  // Code Execution Guard config
  codeExecution?: {
    enabled?: boolean;
    allowedLanguages?: string[];
    maxCodeLength?: number;
    maxExecutionTime?: number;
    allowNetwork?: boolean;
    allowFileSystem?: boolean;
    allowShell?: boolean;
    riskThreshold?: number;
  };
  // Agent Communication Guard config
  agentCommunication?: {
    enabled?: boolean;
    allowedAgents?: string[];
    requireSignatures?: boolean;
    strictMode?: boolean;
    maxMessageAge?: number;
  };
  // Circuit Breaker config
  circuitBreaker?: {
    enabled?: boolean;
    failureThreshold?: number;
    minimumRequests?: number;
    windowSize?: number;
    recoveryTimeout?: number;
    successThreshold?: number;
  };
  // Drift Detector config
  driftDetector?: {
    enabled?: boolean;
    minimumSamples?: number;
    anomalyThreshold?: number;
    alertThreshold?: number;
    checkGoalAlignment?: boolean;
  };
  // MCP Security Guard config
  mcpSecurity?: {
    enabled?: boolean;
    detectToolShadowing?: boolean;
    toolBlocklist?: string[];
    strictMode?: boolean;
    minServerReputation?: number;
  };
  // Prompt Leakage Guard config
  promptLeakage?: {
    enabled?: boolean;
    detectLeetspeak?: boolean;
    detectROT13?: boolean;
    detectBase64?: boolean;
    detectIndirectExtraction?: boolean;
    monitorOutput?: boolean;
    systemPromptKeywords?: string[];
    riskThreshold?: number;
  };
  // Trust Exploitation Guard config
  trustExploitation?: {
    enabled?: boolean;
    humanApprovalRequired?: string[];
    maxAutonomousActions?: number;
    monitorGoalConsistency?: boolean;
    detectPermissionEscalation?: boolean;
    sensitiveActions?: string[];
  };
  // Autonomy Escalation Guard config
  autonomyEscalation?: {
    enabled?: boolean;
    maxAutonomyLevel?: number;
    baseAutonomyLevel?: number;
    detectSelfModification?: boolean;
    maxSubAgents?: number;
    enforceHITL?: boolean;
    alwaysRequireHuman?: string[];
  };
  // State Persistence Guard config
  statePersistence?: {
    enabled?: boolean;
    enableIntegrityCheck?: boolean;
    requireEncryption?: boolean;
    maxStateSize?: number;
    maxStateAge?: number;
    enforceSessionIsolation?: boolean;
    sensitiveKeys?: string[];
    detectTampering?: boolean;
  };
  // Tool Result Guard config
  toolResult?: {
    enabled?: boolean;
    scanForInjection?: boolean;
    maxResultSize?: number;
    detectStateChangeClaims?: boolean;
  };
  // Context Budget Guard config
  contextBudget?: {
    enabled?: boolean;
    maxTotalTokens?: number;
    systemPromptReserve?: number;
    maxTurnsPerSession?: number;
    maxSimilarMessages?: number;
    tokenEstimator?: (text: string) => number;
  };
  // Output Schema Guard config
  outputSchema?: {
    enabled?: boolean;
    scanForInjection?: boolean;
    strictSchema?: boolean;
    maxOutputSize?: number;
  };
  // Token Cost Guard config
  tokenCost?: {
    enabled?: boolean;
    maxTokensPerSession?: number;
    maxTokensPerUser?: number;
    maxCostPerSession?: number;
    maxCostPerUser?: number;
    inputTokenCostPer1K?: number;
    outputTokenCostPer1K?: number;
    maxTokensPerRequest?: number;
    alertThreshold?: number;
    budgetWindowMs?: number;
  };
  // Pluggable ML detection classifier
  classifier?: import("../detection-backend").DetectionClassifier;
  /**
   * Global sensitivity mode — cascades to all threshold-based guards.
   * Per-guard threshold overrides take precedence over this value.
   *
   * | Mode        | FP rate  | Detection | Use when                        |
   * |-------------|----------|-----------|---------------------------------|
   * | strict      | ~12-15%  | ~65%      | Internal tools, high-risk apps  |
   * | balanced    | ~7-8%    | ~53%      | Default — general-purpose apps  |
   * | permissive  | ~3-4%    | ~40%      | Consumer apps with low FP budget|
   */
  sensitivity?: import("./index").SensitivityMode;
  // Input limits
  maxInputLength?: number;
  // Error handling
  failMode?: "open" | "closed";
  // Event hooks
  onBlock?: (guardName: string, result: any, requestId: string) => void;
  onAlert?: (guardName: string, message: string, requestId: string) => void;
  onError?: (guardName: string, error: Error, requestId: string) => void;
  // Logging
  logger?: (message: string, level: "info" | "warn" | "error") => void;
}
