/**
 * LangChain Integration for llm-trust-guard
 *
 * Provides callbacks, wrappers, and utilities for securing
 * LangChain-based applications.
 */

import {
  InputSanitizer,
  EncodingDetector,
  MemoryGuard,
  ToolChainValidator,
  OutputFilter,
} from "../index.js";
import type { PAPSanitizerResult } from "../guards/input-sanitizer.js";

export interface TrustGuardCallbackConfig {
  /** Enable input validation */
  validateInput?: boolean;
  /** Enable output filtering */
  filterOutput?: boolean;
  /** Enable tool chain validation */
  validateTools?: boolean;
  /** Throw error on violation (otherwise just log) */
  throwOnViolation?: boolean;
  /** Custom violation handler */
  onViolation?: (type: string, details: any) => void;
  /** InputSanitizer configuration */
  sanitizerConfig?: ConstructorParameters<typeof InputSanitizer>[0];
  /** OutputFilter configuration */
  outputConfig?: ConstructorParameters<typeof OutputFilter>[0];
}

/**
 * Security result from guard checks
 */
export interface SecurityCheckResult {
  allowed: boolean;
  guard: string;
  violations: string[];
  sanitizedInput?: string;
  details?: any;
}

/**
 * TrustGuard wrapper for LangChain
 *
 * @example
 * ```typescript
 * import { ChatOpenAI } from '@langchain/openai';
 * import { TrustGuardLangChain } from 'llm-trust-guard/integrations/langchain';
 *
 * const guard = new TrustGuardLangChain({
 *   validateInput: true,
 *   filterOutput: true,
 *   throwOnViolation: true
 * });
 *
 * // Validate before sending to LLM
 * const result = guard.validateInput(userMessage);
 * if (!result.allowed) {
 *   throw new Error(`Blocked: ${result.violations.join(', ')}`);
 * }
 *
 * // Use with LangChain
 * const llm = new ChatOpenAI();
 * const response = await llm.invoke(result.sanitizedInput || userMessage);
 *
 * // Filter output before returning to user
 * const filtered = guard.filterOutput(response.content);
 * ```
 */
export class TrustGuardLangChain {
  private inputSanitizer: InputSanitizer;
  private encodingDetector: EncodingDetector;
  private memoryGuard: MemoryGuard;
  private toolChainValidator: ToolChainValidator;
  private outputFilter: OutputFilter;
  private config: TrustGuardCallbackConfig;

  constructor(config: TrustGuardCallbackConfig = {}) {
    this.config = {
      validateInput: true,
      filterOutput: true,
      validateTools: true,
      throwOnViolation: false,
      ...config,
    };

    this.inputSanitizer = new InputSanitizer(config.sanitizerConfig);
    this.encodingDetector = new EncodingDetector();
    this.memoryGuard = new MemoryGuard();
    this.toolChainValidator = new ToolChainValidator();
    this.outputFilter = new OutputFilter(config.outputConfig);
  }

  /**
   * Validate user input before sending to LLM
   */
  validateInput(input: string, requestId?: string): SecurityCheckResult {
    const reqId = requestId || `lc-${Date.now()}`;

    // Check input sanitization
    const sanitizeResult = this.inputSanitizer.sanitize(input, reqId);
    if (!sanitizeResult.allowed) {
      this.handleViolation("input_sanitization", sanitizeResult);
      return {
        allowed: false,
        guard: "InputSanitizer",
        violations: sanitizeResult.violations,
        sanitizedInput: sanitizeResult.sanitizedInput,
        details: sanitizeResult,
      };
    }

    // Check encoding attacks
    const encodingResult = this.encodingDetector.detect(input, reqId);
    if (!encodingResult.allowed) {
      this.handleViolation("encoding_attack", encodingResult);
      return {
        allowed: false,
        guard: "EncodingDetector",
        violations: encodingResult.violations,
        details: encodingResult,
      };
    }

    return {
      allowed: true,
      guard: "all",
      violations: [],
      sanitizedInput: sanitizeResult.sanitizedInput,
    };
  }

  /**
   * Validate context/memory before injection
   */
  validateContext(context: string | string[], sessionId: string, requestId?: string): SecurityCheckResult {
    const reqId = requestId || `lc-ctx-${Date.now()}`;
    const result = this.memoryGuard.validateContextInjection(context, sessionId, reqId);

    if (!result.allowed) {
      this.handleViolation("context_injection", result);
      return {
        allowed: false,
        guard: "MemoryGuard",
        violations: result.violations,
        details: result,
      };
    }

    return {
      allowed: true,
      guard: "MemoryGuard",
      violations: [],
    };
  }

  /**
   * Validate RAG documents before context injection
   */
  validateDocuments(
    documents: Array<{ content: string; metadata?: any }>,
    sessionId: string
  ): SecurityCheckResult {
    const violations: string[] = [];

    for (let i = 0; i < documents.length; i++) {
      const doc = documents[i];

      // Check content for injections
      const contentResult = this.memoryGuard.validateContextInjection(doc.content, sessionId);
      if (!contentResult.allowed) {
        violations.push(`doc[${i}]: ${contentResult.violations.join(", ")}`);
      }

      // Check for encoded threats
      const encodingResult = this.encodingDetector.detect(doc.content);
      if (!encodingResult.allowed) {
        violations.push(`doc[${i}]: encoded threat detected`);
      }
    }

    if (violations.length > 0) {
      this.handleViolation("document_validation", { violations });
      return {
        allowed: false,
        guard: "DocumentValidator",
        violations,
      };
    }

    return {
      allowed: true,
      guard: "DocumentValidator",
      violations: [],
    };
  }

  /**
   * Validate tool calls before execution
   */
  validateToolCall(
    toolName: string,
    toolArgs: Record<string, any>,
    sessionId: string
  ): SecurityCheckResult {
    // Register the tool call
    const result = this.toolChainValidator.validate(sessionId, toolName);

    if (!result.allowed) {
      this.handleViolation("tool_call", result);
      return {
        allowed: false,
        guard: "ToolChainValidator",
        violations: result.violations,
        details: result,
      };
    }

    return {
      allowed: true,
      guard: "ToolChainValidator",
      violations: [],
    };
  }

  /**
   * Filter LLM output before returning to user
   */
  filterOutput(output: string, requestId?: string): string {
    if (!this.config.filterOutput) {
      return output;
    }

    const reqId = requestId || `lc-out-${Date.now()}`;
    const result = this.outputFilter.filter(output, reqId);

    if (result.filtered_response !== output) {
      this.handleViolation("output_filtered", {
        original: output.substring(0, 100),
        pii_detected: result.pii_detected.length,
        secrets_detected: result.secrets_detected.length,
      });
    }

    return typeof result.filtered_response === 'string' ? result.filtered_response : output;
  }

  /**
   * Create a secure message processor
   */
  createSecureProcessor(sessionId: string) {
    return {
      /**
       * Process user message with full validation
       */
      processUserMessage: (message: string): { allowed: boolean; message: string; violations: string[] } => {
        const result = this.validateInput(message);
        return {
          allowed: result.allowed,
          message: result.sanitizedInput || message,
          violations: result.violations,
        };
      },

      /**
       * Process context/RAG content
       */
      processContext: (context: string[]): { allowed: boolean; violations: string[] } => {
        const result = this.validateContext(context, sessionId);
        return {
          allowed: result.allowed,
          violations: result.violations,
        };
      },

      /**
       * Process tool call
       */
      processToolCall: (tool: string, args: any): { allowed: boolean; violations: string[] } => {
        const result = this.validateToolCall(tool, args, sessionId);
        return {
          allowed: result.allowed,
          violations: result.violations,
        };
      },

      /**
       * Process LLM output
       */
      processOutput: (output: string): string => {
        return this.filterOutput(output);
      },
    };
  }

  private handleViolation(type: string, details: any): void {
    if (this.config.onViolation) {
      this.config.onViolation(type, details);
    }

    if (this.config.throwOnViolation) {
      throw new TrustGuardViolationError(type, details);
    }
  }
}

/**
 * Error thrown when throwOnViolation is true
 */
export class TrustGuardViolationError extends Error {
  public type: string;
  public details: any;

  constructor(type: string, details: any) {
    super(`Trust guard violation: ${type}`);
    this.name = "TrustGuardViolationError";
    this.type = type;
    this.details = details;
  }
}

/**
 * Create a simple input validator function for use with LangChain
 *
 * @example
 * ```typescript
 * const validateInput = createInputValidator();
 *
 * // In your chain
 * const chain = RunnableSequence.from([
 *   new RunnableLambda({ func: (input) => {
 *     const result = validateInput(input.message);
 *     if (!result.allowed) throw new Error('Blocked');
 *     return { ...input, message: result.sanitized };
 *   }}),
 *   prompt,
 *   llm,
 *   outputParser
 * ]);
 * ```
 */
export function createInputValidator(config?: ConstructorParameters<typeof InputSanitizer>[0]) {
  const sanitizer = new InputSanitizer(config);
  const encoder = new EncodingDetector();

  return function validateInput(input: string): {
    allowed: boolean;
    sanitized: string;
    violations: string[];
    pap?: PAPSanitizerResult["pap"];
  } {
    const sanitizeResult = sanitizer.sanitize(input);
    if (!sanitizeResult.allowed) {
      return {
        allowed: false,
        sanitized: sanitizeResult.sanitizedInput,
        violations: sanitizeResult.violations,
        pap: sanitizeResult.pap,
      };
    }

    const encodingResult = encoder.detect(input);
    if (!encodingResult.allowed) {
      return {
        allowed: false,
        sanitized: input,
        violations: encodingResult.violations,
      };
    }

    return {
      allowed: true,
      sanitized: sanitizeResult.sanitizedInput,
      violations: [],
      pap: sanitizeResult.pap,
    };
  };
}

/**
 * Create an output filter function for use with LangChain
 */
export function createOutputFilter(config?: ConstructorParameters<typeof OutputFilter>[0]) {
  const filter = new OutputFilter(config);

  return function filterOutput(output: string): string {
    const result = filter.filter(output);
    return typeof result.filtered_response === 'string' ? result.filtered_response : output;
  };
}
