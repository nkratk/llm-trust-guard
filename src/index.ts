/**
 * llm-trust-guard
 *
 * Security guards for LLM-powered applications.
 * Implements the Trust-Aware Orchestration Architecture.
 *
 * @example
 * ```typescript
 * import { TrustGuard } from 'llm-trust-guard';
 *
 * const guard = new TrustGuard({
 *   registry: { tools: myTools },
 *   policy: { roleHierarchy: { customer: 0, admin: 1 } }
 * });
 *
 * const result = guard.check(toolName, params, session);
 * if (!result.allowed) {
 *   console.log('Blocked:', result.block_reason);
 * }
 * ```
 */

// Export types
export * from "./types";

// Export individual guards - Original 10 layers
export { InputSanitizer, InputSanitizerConfig, PAPSanitizerResult } from "./guards/input-sanitizer";
export { ToolRegistry, ToolRegistryConfig } from "./guards/tool-registry";
export { PolicyGate, PolicyGateConfig } from "./guards/policy-gate";
export { TenantBoundary, TenantBoundaryConfig } from "./guards/tenant-boundary";
export { SchemaValidator, SchemaValidatorConfig } from "./guards/schema-validator";
export { ExecutionMonitor, ExecutionMonitorConfig } from "./guards/execution-monitor";
export { OutputFilter, OutputFilterConfig } from "./guards/output-filter";
export { ConversationGuard, ConversationGuardConfig } from "./guards/conversation-guard";
export { ToolChainValidator, ToolChainValidatorConfig } from "./guards/tool-chain-validator";
export { EncodingDetector, EncodingDetectorConfig } from "./guards/encoding-detector";

// Export new 2026 guards - Layers L8-L14
export { MultiModalGuard, MultiModalGuardConfig, MultiModalContent, MultiModalGuardResult } from "./guards/multimodal-guard";
export { MemoryGuard, MemoryGuardConfig, MemoryItem, MemoryGuardResult } from "./guards/memory-guard";
export { RAGGuard, RAGGuardConfig, RAGDocument, RAGGuardResult, EmbeddingAttackResult } from "./guards/rag-guard";
export { CodeExecutionGuard, CodeExecutionGuardConfig, CodeAnalysisResult, SandboxConfig } from "./guards/code-execution-guard";
export { AgentCommunicationGuard, AgentCommunicationGuardConfig, AgentIdentity, AgentMessage, MessageValidationResult } from "./guards/agent-communication-guard";
export { CircuitBreaker, CircuitBreakerConfig, CircuitState, CircuitStats, CircuitBreakerResult } from "./guards/circuit-breaker";
export { DriftDetector, DriftDetectorConfig, BehaviorSample, BaselineProfile, DriftAnalysis, DriftDetectorResult } from "./guards/drift-detector";

// Export new 2026 guards - Layers L15-L17 (Gap Analysis)
export { MCPSecurityGuard, MCPSecurityGuardConfig, MCPServerIdentity, MCPToolDefinition, MCPServerRegistration, MCPToolCall, MCPSecurityResult } from "./guards/mcp-security-guard";
export { PromptLeakageGuard, PromptLeakageGuardConfig, PromptLeakageResult, OutputLeakageResult } from "./guards/prompt-leakage-guard";
export { TrustExploitationGuard, TrustExploitationGuardConfig, AgentAction, TrustContext, TrustExploitationResult } from "./guards/trust-exploitation-guard";

// Export new 2026 guards - Layers L21-L22 (ASI08, ASI10)
export { AutonomyEscalationGuard, AutonomyEscalationGuardConfig, AutonomyRequest, AgentCapabilities, AutonomyEscalationResult } from "./guards/autonomy-escalation-guard";
export { StatePersistenceGuard, StatePersistenceGuardConfig, StateItem, StateOperation, StatePersistenceResult } from "./guards/state-persistence-guard";

// Export new v4.6.0 guards - Threat Coverage Gaps
export { ToolResultGuard, ToolResultGuardConfig, ToolResultGuardResult, ToolResultThreat } from "./guards/tool-result-guard";
export { ContextBudgetGuard, ContextBudgetGuardConfig, ContextBudgetResult } from "./guards/context-budget-guard";
export { OutputSchemaGuard, OutputSchemaGuardConfig, OutputSchemaResult } from "./guards/output-schema-guard";

export { TokenCostGuard, TokenCostGuardConfig, TokenCostResult, TokenUsage } from "./guards/token-cost-guard";
export { HeuristicAnalyzer, HeuristicAnalyzerConfig, HeuristicResult, HeuristicFeatures } from "./guards/heuristic-analyzer";

// Export v4.13.0 guards — Architectural defense + NCD detection
export { CompressionDetector, CompressionDetectorConfig, CompressionDetectorResult } from "./guards/compression-detector";
export { ExternalDataGuard, ExternalDataGuardConfig, ExternalDataGuardResult, DataProvenance } from "./guards/external-data-guard";
export { AgentSkillGuard, AgentSkillGuardConfig, AgentSkillGuardResult, SkillDefinition, SkillThreat } from "./guards/agent-skill-guard";
export { SessionIntegrityGuard, SessionIntegrityGuardConfig, SessionIntegrityResult, SessionState } from "./guards/session-integrity-guard";
export { SpawnPolicyGuard, SpawnPolicyGuardConfig, SpawnRequest, SpawnPolicyResult } from "./guards/spawn-policy-guard";
export { DelegationScopeGuard, DelegationScopeGuardConfig, DelegationRequest, DelegationScopeResult } from "./guards/delegation-scope-guard";
export { TrustTransitivityGuard, TrustTransitivityGuardConfig, TransitivityMode, AgentTrustEntry, TrustChainLink, TrustTransitivityResult } from "./guards/trust-transitivity-guard";

// Export detection backend
export { DetectionClassifier, DetectionResult, DetectionThreat, DetectionContext, createRegexClassifier, mergeDetectionResults } from "./detection-backend";

import crypto from "crypto";

// Import for TrustGuard - Original layers
import { InputSanitizer } from "./guards/input-sanitizer";
import { ToolRegistry } from "./guards/tool-registry";
import { PolicyGate } from "./guards/policy-gate";
import { TenantBoundary } from "./guards/tenant-boundary";
import { SchemaValidator } from "./guards/schema-validator";
import { ExecutionMonitor } from "./guards/execution-monitor";
import { OutputFilter } from "./guards/output-filter";
import { ConversationGuard } from "./guards/conversation-guard";
import { ToolChainValidator } from "./guards/tool-chain-validator";
import { EncodingDetector } from "./guards/encoding-detector";
// Import for TrustGuard - 2026 guards
import { MultiModalGuard } from "./guards/multimodal-guard";
import { MemoryGuard } from "./guards/memory-guard";
import { RAGGuard } from "./guards/rag-guard";
import { CodeExecutionGuard } from "./guards/code-execution-guard";
import { AgentCommunicationGuard } from "./guards/agent-communication-guard";
import { CircuitBreaker } from "./guards/circuit-breaker";
import { DriftDetector } from "./guards/drift-detector";
import { MCPSecurityGuard } from "./guards/mcp-security-guard";
import { PromptLeakageGuard } from "./guards/prompt-leakage-guard";
import { TrustExploitationGuard } from "./guards/trust-exploitation-guard";
import { AutonomyEscalationGuard } from "./guards/autonomy-escalation-guard";
import { StatePersistenceGuard } from "./guards/state-persistence-guard";
// Import for TrustGuard - v4.6.0 threat coverage guards
import { ToolResultGuard } from "./guards/tool-result-guard";
import { ContextBudgetGuard } from "./guards/context-budget-guard";
import { OutputSchemaGuard } from "./guards/output-schema-guard";
import { TokenCostGuard } from "./guards/token-cost-guard";
import { DetectionClassifier, mergeDetectionResults } from "./detection-backend";
import {
  TrustGuardConfig,
  TrustGuardResult,
  SessionContext,
  ToolDefinition,
  Role,
  SensitivityMode,
} from "./types";

// ---------------------------------------------------------------------------
// Sensitivity presets
// Concrete threshold values for each mode.
// balanced == current defaults (no behavioural change unless mode is set).
// ---------------------------------------------------------------------------
interface SensitivityPreset {
  sanitizer: { threshold: number; papThreshold: number; minPersuasionTechniques: number };
  compression: { threshold: number };
  encoding: { maxEncodedRatio: number };
  promptLeakage: { riskThreshold: number };
  rag: { minTrustScore: number };
  drift: { anomalyThreshold: number };
  memory: { riskThreshold: number };
}

const SENSITIVITY_PRESETS: Record<SensitivityMode, SensitivityPreset> = {
  strict: {
    sanitizer:     { threshold: 0.15, papThreshold: 0.25, minPersuasionTechniques: 1 },
    compression:   { threshold: 0.60 },
    encoding:      { maxEncodedRatio: 0.05 },
    promptLeakage: { riskThreshold: 0.3 },
    rag:           { minTrustScore: 0.8 },
    drift:         { anomalyThreshold: 0.5 },
    memory:        { riskThreshold: 0.3 },
  },
  balanced: {
    sanitizer:     { threshold: 0.3, papThreshold: 0.4, minPersuasionTechniques: 2 },
    compression:   { threshold: 0.55 },
    encoding:      { maxEncodedRatio: 0.1 },
    promptLeakage: { riskThreshold: 0.5 },
    rag:           { minTrustScore: 0.6 },
    drift:         { anomalyThreshold: 0.7 },
    memory:        { riskThreshold: 0.5 },
  },
  permissive: {
    sanitizer:     { threshold: 0.5, papThreshold: 0.6, minPersuasionTechniques: 3 },
    compression:   { threshold: 0.45 },
    encoding:      { maxEncodedRatio: 0.20 },
    promptLeakage: { riskThreshold: 0.7 },
    rag:           { minTrustScore: 0.4 },
    drift:         { anomalyThreshold: 0.85 },
    memory:        { riskThreshold: 0.7 },
  },
};

/**
 * TrustGuard - Main facade for all security guards (27 integrated + 4 standalone)
 *
 * Combines all protection layers into a single, easy-to-use interface.
 *
 * Protection Layers (Original):
 * - L1: Input Sanitizer - Detects prompt injection patterns (PAP)
 * - L2: Tool Registry - Prevents tool hallucination attacks
 * - L3: Policy Gate - Enforces RBAC with constraint validation
 * - L4: Tenant Boundary - Multi-tenant isolation
 * - L5: Schema Validator - Parameter validation & injection detection
 * - L6: Execution Monitor - Rate limiting & resource quotas
 * - L7: Output Filter - PII scrubbing & secret detection
 * - Conversation Guard - Multi-turn manipulation detection
 * - Tool Chain Validator - Dangerous tool sequence detection
 * - Encoding Detector - Encoding bypass attack detection
 *
 * Protection Layers (2026):
 * - MultiModal Guard - Image/audio injection prevention
 * - Memory Guard - Memory poisoning prevention (ASI06)
 * - RAG Guard - RAG document & embedding attack prevention
 * - Code Execution Guard - Safe code execution sandboxing
 * - Agent Communication Guard - Multi-agent message security
 * - Circuit Breaker - Cascading failure prevention
 * - Drift Detector - Behavioral anomaly detection
 * - MCP Security Guard - MCP tool shadowing prevention
 * - Prompt Leakage Guard - System prompt extraction prevention
 * - Trust Exploitation Guard - Trust boundary enforcement (ASI09)
 * - Autonomy Escalation Guard - Unauthorized autonomy prevention (ASI10)
 * - State Persistence Guard - State corruption prevention (ASI08)
 */
export class TrustGuard {
  // Original guards
  private sanitizer?: InputSanitizer;
  private registry?: ToolRegistry;
  private policy?: PolicyGate;
  private tenant?: TenantBoundary;
  private schema?: SchemaValidator;
  private execution?: ExecutionMonitor;
  private output?: OutputFilter;
  private conversation?: ConversationGuard;
  private chain?: ToolChainValidator;
  private encoding?: EncodingDetector;
  // 2026 guards
  private multiModal?: MultiModalGuard;
  private memoryGuard?: MemoryGuard;
  private ragGuard?: RAGGuard;
  private codeExecution?: CodeExecutionGuard;
  private agentCommunication?: AgentCommunicationGuard;
  private circuitBreaker?: CircuitBreaker;
  private driftDetector?: DriftDetector;
  private mcpSecurity?: MCPSecurityGuard;
  private promptLeakage?: PromptLeakageGuard;
  private trustExploitation?: TrustExploitationGuard;
  private autonomyEscalation?: AutonomyEscalationGuard;
  private statePersistence?: StatePersistenceGuard;

  // v4.6.0 threat coverage guards
  private toolResultGuard?: ToolResultGuard;
  private contextBudget?: ContextBudgetGuard;
  private outputSchema?: OutputSchemaGuard;
  private tokenCostGuard?: TokenCostGuard;
  private classifier?: DetectionClassifier;

  // Event hooks
  private onBlock?: (guardName: string, result: any, requestId: string) => void;
  private onAlert?: (guardName: string, message: string, requestId: string) => void;
  private onError?: (guardName: string, error: Error, requestId: string) => void;

  // Metrics
  private metrics = {
    totalChecks: 0,
    blockedChecks: 0,
    totalTimeMs: 0,
    errors: 0,
  };

  private maxInputLength: number;
  private failMode: "open" | "closed";
  private logger: (message: string, level: "info" | "warn" | "error") => void;

  constructor(config: TrustGuardConfig = {}) {
    // Initialize logger FIRST so it can be passed to child guards
    this.logger = config.logger || ((msg, level) => {
      if (level === "error") console.error(msg);
      else if (level === "warn") console.warn(msg);
      else console.log(msg);
    });
    this.maxInputLength = config.maxInputLength ?? 100_000;
    this.failMode = config.failMode ?? "closed";
    this.onBlock = config.onBlock;
    this.onAlert = config.onAlert;
    this.onError = config.onError;

    // Helper: create guard-level logger from facade logger
    const guardLogger = config.logger || undefined;

    // Resolve sensitivity preset (per-guard explicit values always win)
    const preset = SENSITIVITY_PRESETS[config.sensitivity ?? "balanced"];

    // Initialize original guards based on config
    if (config.sanitizer?.enabled !== false) {
      this.sanitizer = new InputSanitizer({
        threshold: config.sanitizer?.threshold ?? preset.sanitizer.threshold,
        customPatterns: config.sanitizer?.customPatterns,
        detectPAP: config.sanitizer?.detectPAP,
        papThreshold: config.sanitizer?.papThreshold ?? preset.sanitizer.papThreshold,
        minPersuasionTechniques: config.sanitizer?.minPersuasionTechniques ?? preset.sanitizer.minPersuasionTechniques,
        blockCompoundPersuasion: config.sanitizer?.blockCompoundPersuasion,
        logger: guardLogger,
      });
    }

    if (config.registry?.enabled !== false && config.registry?.tools) {
      this.registry = new ToolRegistry({
        tools: config.registry.tools,
        logger: guardLogger,
      });
    }

    if (config.policy?.enabled !== false) {
      this.policy = new PolicyGate({
        roleHierarchy: config.policy?.roleHierarchy,
        logger: guardLogger,
      });
    }

    if (config.tenant?.enabled !== false) {
      const ownershipMap = config.tenant?.resourceOwnership
        ? new Map(
            Object.entries(config.tenant.resourceOwnership).map(([id, data]) => [
              id,
              { resource_id: id, tenant_id: data.tenant_id },
            ])
          )
        : undefined;

      this.tenant = new TenantBoundary({
        resourceOwnership: ownershipMap,
        logger: guardLogger,
      });
    }

    if (config.schema?.enabled !== false) {
      this.schema = new SchemaValidator({
        strictTypes: config.schema?.strictTypes,
        logger: guardLogger,
      });
    }

    if (config.execution?.enabled !== false) {
      this.execution = new ExecutionMonitor({
        maxRequestsPerMinute: config.execution?.maxRequestsPerMinute,
        maxRequestsPerHour: config.execution?.maxRequestsPerHour,
        operationCosts: config.execution?.operationCosts,
        maxCostPerMinute: config.execution?.maxCostPerMinute,
        maxCostPerHour: config.execution?.maxCostPerHour,
        logger: guardLogger,
      });
    }

    if (config.output?.enabled !== false) {
      this.output = new OutputFilter({
        detectPII: config.output?.detectPII,
        detectSecrets: config.output?.detectSecrets,
        roleFilters: config.output?.roleFilters,
        logger: guardLogger,
      });
    }

    if (config.conversation?.enabled !== false) {
      this.conversation = new ConversationGuard({
        maxConversationLength: config.conversation?.maxConversationLength,
        escalationThreshold: config.conversation?.escalationThreshold,
        logger: guardLogger,
      });
    }

    if (config.chain?.enabled !== false) {
      this.chain = new ToolChainValidator({
        maxToolsPerRequest: config.chain?.maxToolsPerRequest,
        maxSensitiveToolsPerSession: config.chain?.maxSensitiveToolsPerSession,
        sensitiveTools: config.chain?.sensitiveTools,
        logger: guardLogger,
      });
    }

    if (config.encoding?.enabled !== false) {
      this.encoding = new EncodingDetector({
        maxDecodingDepth: config.encoding?.maxDecodingDepth,
        maxEncodedRatio: config.encoding?.maxEncodedRatio ?? preset.encoding.maxEncodedRatio,
        logger: guardLogger,
      });
    }

    // Initialize 2026 guards
    if (config.multiModal?.enabled) {
      this.multiModal = new MultiModalGuard({
        scanMetadata: config.multiModal.scanMetadata,
        detectBase64Payloads: config.multiModal.detectBase64Payloads,
        allowedMimeTypes: config.multiModal.allowedMimeTypes,
      });
    }

    if (config.memory?.enabled) {
      this.memoryGuard = new MemoryGuard({
        enableIntegrityCheck: config.memory.enableIntegrityCheck,
        detectInjections: config.memory.detectInjections,
        maxMemoryItems: config.memory.maxMemoryItems,
        signingKey: config.memory.signingKey,
        autoQuarantine: config.memory.autoQuarantine,
        riskThreshold: config.memory.riskThreshold ?? preset.memory.riskThreshold,
      });
    }

    if (config.rag?.enabled) {
      this.ragGuard = new RAGGuard({
        detectInjections: config.rag.detectInjections,
        verifySource: config.rag.verifySource,
        trustedSources: config.rag.trustedSources,
        blockedSources: config.rag.blockedSources,
        maxDocumentSize: config.rag.maxDocumentSize,
        minTrustScore: config.rag.minTrustScore ?? preset.rag.minTrustScore,
        detectEmbeddingAttacks: config.rag.detectEmbeddingAttacks,
      });
    }

    if (config.codeExecution?.enabled) {
      this.codeExecution = new CodeExecutionGuard({
        allowedLanguages: config.codeExecution.allowedLanguages,
        maxCodeLength: config.codeExecution.maxCodeLength,
        maxExecutionTime: config.codeExecution.maxExecutionTime,
        allowNetwork: config.codeExecution.allowNetwork,
        allowFileSystem: config.codeExecution.allowFileSystem,
        allowShell: config.codeExecution.allowShell,
        riskThreshold: config.codeExecution.riskThreshold,
      });
    }

    if (config.agentCommunication?.enabled) {
      this.agentCommunication = new AgentCommunicationGuard({
        allowedAgents: config.agentCommunication.allowedAgents,
        requireSignatures: config.agentCommunication.requireSignatures,
        strictMode: config.agentCommunication.strictMode,
        maxMessageAge: config.agentCommunication.maxMessageAge,
      });
    }

    if (config.circuitBreaker?.enabled) {
      this.circuitBreaker = new CircuitBreaker({
        failureThreshold: config.circuitBreaker.failureThreshold,
        minimumRequests: config.circuitBreaker.minimumRequests,
        windowSize: config.circuitBreaker.windowSize,
        recoveryTimeout: config.circuitBreaker.recoveryTimeout,
        successThreshold: config.circuitBreaker.successThreshold,
      });
    }

    if (config.driftDetector?.enabled) {
      this.driftDetector = new DriftDetector({
        minimumSamples: config.driftDetector.minimumSamples,
        anomalyThreshold: config.driftDetector.anomalyThreshold ?? preset.drift.anomalyThreshold,
        alertThreshold: config.driftDetector.alertThreshold,
        checkGoalAlignment: config.driftDetector.checkGoalAlignment,
      });
    }

    if (config.mcpSecurity?.enabled) {
      this.mcpSecurity = new MCPSecurityGuard({
        detectToolShadowing: config.mcpSecurity.detectToolShadowing,
        toolBlocklist: config.mcpSecurity.toolBlocklist,
        strictMode: config.mcpSecurity.strictMode,
        minServerReputation: config.mcpSecurity.minServerReputation,
      });
    }

    if (config.promptLeakage?.enabled) {
      this.promptLeakage = new PromptLeakageGuard({
        detectLeetspeak: config.promptLeakage.detectLeetspeak,
        detectROT13: config.promptLeakage.detectROT13,
        detectBase64: config.promptLeakage.detectBase64,
        detectIndirectExtraction: config.promptLeakage.detectIndirectExtraction,
        monitorOutput: config.promptLeakage.monitorOutput,
        systemPromptKeywords: config.promptLeakage.systemPromptKeywords,
        riskThreshold: config.promptLeakage.riskThreshold ?? preset.promptLeakage.riskThreshold,
      });
    }

    if (config.trustExploitation?.enabled) {
      this.trustExploitation = new TrustExploitationGuard({
        humanApprovalRequired: config.trustExploitation.humanApprovalRequired,
        maxAutonomousActions: config.trustExploitation.maxAutonomousActions,
        monitorGoalConsistency: config.trustExploitation.monitorGoalConsistency,
        detectPermissionEscalation: config.trustExploitation.detectPermissionEscalation,
        sensitiveActions: config.trustExploitation.sensitiveActions,
      });
    }

    if (config.autonomyEscalation?.enabled) {
      this.autonomyEscalation = new AutonomyEscalationGuard({
        maxAutonomyLevel: config.autonomyEscalation.maxAutonomyLevel,
        baseAutonomyLevel: config.autonomyEscalation.baseAutonomyLevel,
        detectSelfModification: config.autonomyEscalation.detectSelfModification,
        maxSubAgents: config.autonomyEscalation.maxSubAgents,
        enforceHITL: config.autonomyEscalation.enforceHITL,
        alwaysRequireHuman: config.autonomyEscalation.alwaysRequireHuman,
      });
    }

    if (config.statePersistence?.enabled) {
      this.statePersistence = new StatePersistenceGuard({
        enableIntegrityCheck: config.statePersistence.enableIntegrityCheck,
        requireEncryption: config.statePersistence.requireEncryption,
        maxStateSize: config.statePersistence.maxStateSize,
        maxStateAge: config.statePersistence.maxStateAge,
        enforceSessionIsolation: config.statePersistence.enforceSessionIsolation,
        sensitiveKeys: config.statePersistence.sensitiveKeys,
        detectTampering: config.statePersistence.detectTampering,
      });
    }

    // Initialize v4.6.0 threat coverage guards
    if (config.toolResult?.enabled) {
      this.toolResultGuard = new ToolResultGuard(config.toolResult);
    }

    if (config.contextBudget?.enabled) {
      this.contextBudget = new ContextBudgetGuard(config.contextBudget);
    }

    if (config.outputSchema?.enabled) {
      this.outputSchema = new OutputSchemaGuard(config.outputSchema);
    }

    if (config.tokenCost?.enabled) {
      this.tokenCostGuard = new TokenCostGuard(config.tokenCost);
    }

    if (config.classifier) {
      this.classifier = config.classifier;
    }

  }

  /**
   * Run all enabled guards on a tool call
   */
  check(
    toolName: string,
    params: Record<string, any>,
    session: SessionContext | undefined,
    options: {
      userInput?: string;
      claimedRole?: Role;
      allToolsInRequest?: string[];
    } = {}
  ): TrustGuardResult {
    const requestId = `req-${crypto.randomUUID()}`;
    const allViolations: string[] = [];

    this.logger(`[TrustGuard:${requestId}] Checking: ${toolName}`, "info");

    const startTime = Date.now();
    this.metrics.totalChecks++;

    try {
      const result = this.runChecks(toolName, params, session, options, requestId);
      this.metrics.totalTimeMs += Date.now() - startTime;
      if (!result.allowed) {
        this.metrics.blockedChecks++;
        if (this.onBlock) this.onBlock(result.block_layer || "UNKNOWN", result, requestId);
      }
      return result;
    } catch (error) {
      this.metrics.totalTimeMs += Date.now() - startTime;
      this.metrics.errors++;
      const errMsg = error instanceof Error ? error.message : String(error);
      this.logger(`[TrustGuard:${requestId}] Guard error: ${errMsg}`, "error");
      if (this.onError) {
        this.onError("TrustGuard", error instanceof Error ? error : new Error(errMsg), requestId);
      }

      if (this.failMode === "open") {
        return {
          allowed: true,
          all_violations: ["GUARD_ERROR"],
          request_id: requestId,
        };
      }
      return {
        allowed: false,
        block_reason: `Internal guard error: ${errMsg}`,
        all_violations: ["GUARD_ERROR"],
        request_id: requestId,
      };
    }
  }

  private runChecks(
    toolName: string,
    params: Record<string, any>,
    session: SessionContext | undefined,
    options: {
      userInput?: string;
      claimedRole?: Role;
      allToolsInRequest?: string[];
    },
    requestId: string
  ): TrustGuardResult {
    const allViolations: string[] = [];

    // Input length limit check
    if (options.userInput && options.userInput.length > this.maxInputLength) {
      this.logger(`[TrustGuard:${requestId}] BLOCKED: Input too long (${options.userInput.length} > ${this.maxInputLength})`, "warn");
      return {
        allowed: false,
        block_layer: "L1",
        block_reason: `Input length ${options.userInput.length} exceeds maximum ${this.maxInputLength}`,
        all_violations: ["INPUT_TOO_LONG"],
        request_id: requestId,
      };
    }

    // Encoding Detection (pre-L1)
    if (this.encoding && options.userInput) {
      const encodingResult = this.encoding.detect(options.userInput, requestId);

      if (!encodingResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by Encoding Detector`, "warn");
        return {
          allowed: false,
          block_layer: "ENCODING",
          block_reason: encodingResult.reason,
          all_violations: encodingResult.violations,
          encoding: encodingResult,
          request_id: requestId,
        };
      }
      allViolations.push(...encodingResult.violations);
    }

    // L1: Input Sanitization
    if (this.sanitizer && options.userInput) {
      const sanitizerResult = this.sanitizer.sanitize(options.userInput, requestId);

      if (!sanitizerResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by L1`, "warn");
        return {
          allowed: false,
          block_layer: "L1",
          block_reason: sanitizerResult.reason,
          all_violations: sanitizerResult.violations,
          sanitizer: sanitizerResult,
          request_id: requestId,
        };
      }
      allViolations.push(...sanitizerResult.violations);
    }

    // Prompt Leakage Guard (check input for extraction attempts)
    if (this.promptLeakage && options.userInput) {
      const leakageResult = this.promptLeakage.check(options.userInput, requestId);

      if (!leakageResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by Prompt Leakage Guard`, "warn");
        return {
          allowed: false,
          block_layer: "PROMPT_LEAKAGE",
          block_reason: leakageResult.reason,
          all_violations: [...allViolations, ...leakageResult.violations],
          request_id: requestId,
        };
      }
      allViolations.push(...leakageResult.violations);
    }

    // Memory Guard (validate context injection in user input)
    if (this.memoryGuard && options.userInput && session?.session_id) {
      const memResult = this.memoryGuard.validateContextInjection(
        options.userInput,
        session.session_id,
        requestId
      );

      if (!memResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by Memory Guard`, "warn");
        return {
          allowed: false,
          block_layer: "MEMORY",
          block_reason: memResult.reason,
          all_violations: [...allViolations, ...memResult.violations],
          request_id: requestId,
        };
      }
      allViolations.push(...memResult.violations);
    }

    // Conversation Guard
    if (this.conversation && options.userInput && session?.session_id) {
      const convResult = this.conversation.check(
        session.session_id,
        options.userInput,
        [toolName],
        options.claimedRole,
        requestId
      );

      if (!convResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by Conversation Guard`, "warn");
        return {
          allowed: false,
          block_layer: "CONV",
          block_reason: convResult.reason,
          all_violations: [...allViolations, ...convResult.violations],
          conversation: convResult,
          request_id: requestId,
        };
      }
      allViolations.push(...convResult.violations);
    }

    // L2: Tool Registry
    let tool: ToolDefinition | undefined;
    if (this.registry) {
      const registryResult = this.registry.check(
        toolName,
        session?.role || ("" as Role),
        requestId
      );

      if (!registryResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by L2`, "warn");
        return {
          allowed: false,
          block_layer: "L2",
          block_reason: registryResult.reason,
          all_violations: [...allViolations, ...registryResult.violations],
          registry: registryResult,
          request_id: requestId,
        };
      }

      tool = registryResult.tool;
      allViolations.push(...registryResult.violations);
    }

    // Tool Chain Validator
    if (this.chain && session?.session_id) {
      const chainResult = options.allToolsInRequest
        ? this.chain.validateBatch(session.session_id, options.allToolsInRequest, requestId)
        : this.chain.validate(session.session_id, toolName, undefined, requestId);

      if (!chainResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by Tool Chain Validator`, "warn");
        return {
          allowed: false,
          block_layer: "CHAIN",
          block_reason: chainResult.reason,
          all_violations: [...allViolations, ...chainResult.violations],
          chain: chainResult,
          request_id: requestId,
        };
      }
      allViolations.push(...chainResult.violations);
    }

    // L3: Policy Gate
    if (this.policy && tool) {
      const policyResult = this.policy.check(
        tool,
        params,
        session,
        options.claimedRole,
        requestId
      );

      if (!policyResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by L3`, "warn");
        return {
          allowed: false,
          block_layer: "L3",
          block_reason: policyResult.reason,
          all_violations: [...allViolations, ...policyResult.violations],
          policy: policyResult,
          request_id: requestId,
        };
      }
      allViolations.push(...policyResult.violations);
    } else if (this.policy && !tool) {
      this.logger(`[TrustGuard:${requestId}] Policy gate skipped: no tool definition (registry disabled or tool not found)`, "warn");
    }

    // Autonomy Escalation Guard (after tool validation)
    if (this.autonomyEscalation && session?.session_id) {
      const autonomyResult = this.autonomyEscalation.validate(
        toolName,
        session.session_id,
        params,
        requestId
      );

      if (!autonomyResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by Autonomy Escalation Guard`, "warn");
        return {
          allowed: false,
          block_layer: "AUTONOMY",
          block_reason: autonomyResult.reason,
          all_violations: [...allViolations, ...autonomyResult.violations],
          request_id: requestId,
        };
      }
      allViolations.push(...autonomyResult.violations);
    }

    // L4: Tenant Boundary (skip if no session — don't block for missing context)
    let enforcedParams = params;
    if (this.tenant && session) {
      const tenantResult = this.tenant.check(toolName, params, session, requestId);

      if (!tenantResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by L4`, "warn");
        return {
          allowed: false,
          block_layer: "L4",
          block_reason: tenantResult.reason,
          all_violations: [...allViolations, ...tenantResult.violations],
          tenant: tenantResult,
          request_id: requestId,
        };
      }

      if (tenantResult.enforced_params) {
        enforcedParams = tenantResult.enforced_params;
      }
      allViolations.push(...tenantResult.violations);
    }

    // L5: Schema Validation
    if (this.schema && tool) {
      const schemaResult = this.schema.validate(tool, enforcedParams, requestId);

      if (!schemaResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by L5`, "warn");
        return {
          allowed: false,
          block_layer: "L5",
          block_reason: schemaResult.reason,
          all_violations: [...allViolations, ...schemaResult.violations],
          schema: schemaResult,
          request_id: requestId,
        };
      }
      allViolations.push(...schemaResult.violations);
    }

    // L6: Execution Monitor (rate limiting)
    if (this.execution) {
      const execResult = this.execution.check(
        toolName,
        session?.user_id,
        session?.session_id,
        requestId
      );

      if (!execResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by L6`, "warn");
        return {
          allowed: false,
          block_layer: "L6",
          block_reason: execResult.reason,
          all_violations: [...allViolations, ...execResult.violations],
          execution: execResult,
          request_id: requestId,
        };
      }
      allViolations.push(...execResult.violations);
    }

    // Circuit Breaker check
    if (this.circuitBreaker) {
      const cbResult = this.circuitBreaker.check(toolName, requestId);

      if (!cbResult.allowed) {
        this.logger(`[TrustGuard:${requestId}] BLOCKED by Circuit Breaker`, "warn");
        return {
          allowed: false,
          block_layer: "L6",
          block_reason: cbResult.reason,
          all_violations: [...allViolations, "CIRCUIT_OPEN"],
          request_id: requestId,
        };
      }
    }

    this.logger(`[TrustGuard:${requestId}] All checks PASSED`, "info");

    return {
      allowed: true,
      all_violations: allViolations,
      request_id: requestId,
    };
  }

  /**
   * Filter output for PII, secrets, and prompt leakage (L7 + Prompt Leakage)
   */
  filterOutput(output: any, role?: string, requestId?: string): {
    allowed: boolean;
    filtered: any;
    pii_detected: boolean;
    secrets_detected: boolean;
    prompt_leakage_detected: boolean;
  } {
    let filtered = output;
    let piiDetected = false;
    let secretsDetected = false;
    let promptLeakageDetected = false;
    let allowed = true;

    // Output length limit check
    const outputStr = typeof output === "string" ? output : "";
    if (outputStr.length > this.maxInputLength) {
      this.logger(`[TrustGuard] Output too long (${outputStr.length}), truncating for filter`, "warn");
    }

    // L7: PII and secret filtering
    if (this.output) {
      const result = this.output.filter(output, role, requestId);
      filtered = result.filtered_response;
      piiDetected = result.pii_detected.length > 0;
      secretsDetected = result.secrets_detected.length > 0;
      if (!result.allowed) allowed = false;
    }

    // Prompt Leakage output check
    if (this.promptLeakage) {
      const outputStr = typeof filtered === "string" ? filtered : JSON.stringify(filtered);
      const leakageResult = this.promptLeakage.checkOutput(outputStr, requestId);
      if (leakageResult.leaked) {
        allowed = false;
        promptLeakageDetected = true;
        if (leakageResult.sanitized_output) {
          filtered = leakageResult.sanitized_output;
        }
      }
    }

    return {
      allowed,
      filtered,
      pii_detected: piiDetected,
      secrets_detected: secretsDetected,
      prompt_leakage_detected: promptLeakageDetected,
    };
  }

  /**
   * Mark an operation as complete (for rate limiting and circuit breaker)
   */
  completeOperation(session?: SessionContext, toolName?: string, success: boolean = true): void {
    if (this.execution) {
      this.execution.completeOperation(session?.user_id, session?.session_id);
    }
    if (this.circuitBreaker && toolName) {
      if (success) {
        this.circuitBreaker.recordSuccess(toolName);
      } else {
        this.circuitBreaker.recordFailure(toolName);
      }
    }
  }

  /**
   * Get tools available for a role
   */
  getToolsForRole(role: Role): ToolDefinition[] {
    if (this.registry) {
      return this.registry.getToolsForRole(role);
    }
    return [];
  }

  /**
   * Get individual guard instances for advanced usage.
   * All 22 guards are accessible through this method.
   */
  /**
   * Get runtime metrics for monitoring
   */
  getMetrics() {
    const avg = this.metrics.totalChecks > 0
      ? this.metrics.totalTimeMs / this.metrics.totalChecks
      : 0;
    return {
      totalChecks: this.metrics.totalChecks,
      blockedChecks: this.metrics.blockedChecks,
      blockRate: this.metrics.totalChecks > 0
        ? this.metrics.blockedChecks / this.metrics.totalChecks
        : 0,
      avgExecutionTimeMs: Math.round(avg * 100) / 100,
      errors: this.metrics.errors,
    };
  }

  getGuards() {
    return {
      // Original guards
      sanitizer: this.sanitizer,
      registry: this.registry,
      policy: this.policy,
      tenant: this.tenant,
      schema: this.schema,
      execution: this.execution,
      output: this.output,
      conversation: this.conversation,
      chain: this.chain,
      encoding: this.encoding,
      // 2026 guards
      multiModal: this.multiModal,
      memory: this.memoryGuard,
      rag: this.ragGuard,
      codeExecution: this.codeExecution,
      agentCommunication: this.agentCommunication,
      circuitBreaker: this.circuitBreaker,
      driftDetector: this.driftDetector,
      mcpSecurity: this.mcpSecurity,
      promptLeakage: this.promptLeakage,
      trustExploitation: this.trustExploitation,
      autonomyEscalation: this.autonomyEscalation,
      statePersistence: this.statePersistence,
      // v4.6.0 threat coverage guards
      toolResult: this.toolResultGuard,
      contextBudget: this.contextBudget,
      outputSchema: this.outputSchema,
      tokenCost: this.tokenCostGuard,
    };
  }

  /**
   * Reset session state across all session-aware guards
   */
  resetSession(sessionId: string): void {
    this.conversation?.resetSession(sessionId);
    this.chain?.resetSession(sessionId);
    this.execution?.reset(undefined, sessionId);
    this.memoryGuard?.clearSession(sessionId);
    this.trustExploitation?.resetSession(sessionId);
    this.autonomyEscalation?.resetSession(sessionId);
    this.statePersistence?.resetSession(sessionId);
    this.contextBudget?.resetSession(sessionId);
  }

  /**
   * Destroy all guards and release resources.
   * Call this on server shutdown or when the guard instance is no longer needed.
   */
  destroy(): void {
    this.conversation?.destroy();
    this.agentCommunication?.destroy();
    this.contextBudget?.destroy();
    this.tokenCostGuard?.destroy();
    // Reset all stateful maps
    this.execution?.reset();
    this.circuitBreaker?.resetAll();
    this.driftDetector?.resetAgent?.("*");
  }

  /**
   * Validate a tool's return value before feeding it back to the LLM context.
   * Call this after tool execution, before sending the result to the LLM.
   */
  validateToolResult(
    toolName: string,
    result: any,
    requestId?: string
  ): { allowed: boolean; violations: string[]; filtered?: any } {
    if (!this.toolResultGuard) {
      return { allowed: true, violations: [] };
    }

    const guardResult = this.toolResultGuard.validateResult(toolName, result, requestId);
    return {
      allowed: guardResult.allowed,
      violations: guardResult.violations,
    };
  }

  /**
   * Validate LLM structured output (JSON, function calls) before sending to downstream systems.
   */
  validateOutput(
    output: any,
    schemaName?: string,
    requestId?: string
  ): { allowed: boolean; violations: string[]; threats: Array<{ field: string; type: string; detail: string }> } {
    if (!this.outputSchema) {
      return { allowed: true, violations: [], threats: [] };
    }

    const result = this.outputSchema.validate(output, schemaName, requestId);
    return {
      allowed: result.allowed,
      violations: result.violations,
      threats: result.threats,
    };
  }

  /**
   * Async version of check() that also runs the pluggable detection classifier.
   * Use this when you have an ML-based or API-based classifier configured.
   * Falls back to sync check() when no classifier is configured.
   */
  async checkAsync(
    toolName: string,
    params: Record<string, any>,
    session: SessionContext | undefined,
    options: {
      userInput?: string;
      claimedRole?: Role;
      allToolsInRequest?: string[];
    } = {}
  ): Promise<TrustGuardResult> {
    // Always run sync checks first
    const syncResult = this.check(toolName, params, session, options);

    // If no classifier or sync already blocked, return early
    if (!this.classifier || !syncResult.allowed || !options.userInput) {
      return syncResult;
    }

    // Run classifier in parallel
    try {
      const classifierResult = await this.classifier(options.userInput, {
        type: "user_input",
        sessionId: session?.session_id,
      });

      if (!classifierResult.safe) {
        return {
          ...syncResult,
          allowed: false,
          block_layer: "L1",
          block_reason: `Classifier detected threat: ${classifierResult.threats.map(t => t.category).join(", ")}`,
          all_violations: [...syncResult.all_violations, ...classifierResult.threats.map(t => `CLASSIFIER_${t.category.toUpperCase()}`)],
        };
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      this.logger(`[TrustGuard] Classifier error: ${errMsg}`, "error");
      // Classifier failure doesn't block (sync guards already passed)
    }

    return syncResult;
  }
}

// Export integrations
export * from "./integrations/index.js";

// Default export
export default TrustGuard;
