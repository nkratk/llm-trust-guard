/**
 * OpenAI Integration for llm-trust-guard
 *
 * Provides wrappers and utilities for securing OpenAI API calls.
 * Works with both the official OpenAI SDK and direct API calls.
 */

import {
  InputSanitizer,
  EncodingDetector,
  MemoryGuard,
  OutputFilter,
  ToolChainValidator,
} from "../index.js";

export interface SecureOpenAIConfig {
  /** Enable input validation */
  validateInput?: boolean;
  /** Enable output filtering */
  filterOutput?: boolean;
  /** Enable function/tool call validation */
  validateFunctions?: boolean;
  /** Throw error on violation */
  throwOnViolation?: boolean;
  /** Custom violation handler */
  onViolation?: (type: string, details: any) => void;
  /** InputSanitizer configuration */
  sanitizerConfig?: ConstructorParameters<typeof InputSanitizer>[0];
  /** OutputFilter configuration */
  outputConfig?: ConstructorParameters<typeof OutputFilter>[0];
}

export interface ValidationResult {
  allowed: boolean;
  violations: string[];
  sanitized?: string;
  details?: any;
}

export interface SecureMessage {
  role: "system" | "user" | "assistant" | "function" | "tool";
  content: string | null;
  name?: string;
  function_call?: any;
  tool_calls?: any[];
}

/**
 * Secure wrapper for OpenAI API calls
 *
 * @example
 * ```typescript
 * import OpenAI from 'openai';
 * import { SecureOpenAI } from 'llm-trust-guard/integrations/openai';
 *
 * const openai = new OpenAI();
 * const secure = new SecureOpenAI({
 *   validateInput: true,
 *   filterOutput: true,
 *   throwOnViolation: true
 * });
 *
 * // Validate messages before sending
 * const messages = [
 *   { role: 'system', content: 'You are a helpful assistant.' },
 *   { role: 'user', content: userInput }
 * ];
 *
 * const validatedMessages = secure.validateMessages(messages, sessionId);
 * if (!validatedMessages.allowed) {
 *   throw new Error(`Blocked: ${validatedMessages.violations.join(', ')}`);
 * }
 *
 * // Make the API call
 * const completion = await openai.chat.completions.create({
 *   model: 'gpt-4',
 *   messages: validatedMessages.messages
 * });
 *
 * // Filter the response
 * const safeResponse = secure.filterResponse(completion);
 * ```
 */
export class SecureOpenAI {
  private inputSanitizer: InputSanitizer;
  private encodingDetector: EncodingDetector;
  private memoryGuard: MemoryGuard;
  private outputFilter: OutputFilter;
  private toolChainValidator: ToolChainValidator;
  private config: SecureOpenAIConfig;

  constructor(config: SecureOpenAIConfig = {}) {
    this.config = {
      validateInput: true,
      filterOutput: true,
      validateFunctions: true,
      throwOnViolation: false,
      ...config,
    };

    this.inputSanitizer = new InputSanitizer(config.sanitizerConfig);
    this.encodingDetector = new EncodingDetector();
    this.memoryGuard = new MemoryGuard();
    this.outputFilter = new OutputFilter(config.outputConfig);
    this.toolChainValidator = new ToolChainValidator();
  }

  /**
   * Validate a single message content
   */
  validateContent(content: string, requestId?: string): ValidationResult {
    const reqId = requestId || `oai-${Date.now()}`;

    // Input sanitization
    const sanitizeResult = this.inputSanitizer.sanitize(content, reqId);
    if (!sanitizeResult.allowed) {
      this.handleViolation("input_sanitization", sanitizeResult);
      return {
        allowed: false,
        violations: sanitizeResult.violations,
        sanitized: sanitizeResult.sanitizedInput,
        details: sanitizeResult,
      };
    }

    // Encoding detection
    const encodingResult = this.encodingDetector.detect(content, reqId);
    if (!encodingResult.allowed) {
      this.handleViolation("encoding_attack", encodingResult);
      return {
        allowed: false,
        violations: encodingResult.violations,
        details: encodingResult,
      };
    }

    return {
      allowed: true,
      violations: [],
      sanitized: sanitizeResult.sanitizedInput,
    };
  }

  /**
   * Validate an array of chat messages
   */
  validateMessages(
    messages: SecureMessage[],
    sessionId: string,
    requestId?: string
  ): { allowed: boolean; messages: SecureMessage[]; violations: string[] } {
    const reqId = requestId || `oai-msgs-${Date.now()}`;
    const violations: string[] = [];
    const validatedMessages: SecureMessage[] = [];

    for (let i = 0; i < messages.length; i++) {
      const msg = messages[i];

      // Skip messages without content
      if (!msg.content) {
        validatedMessages.push(msg);
        continue;
      }

      if (msg.role === "user") {
        // Full validation for user messages
        const result = this.validateContent(msg.content, `${reqId}-${i}`);
        if (!result.allowed) {
          violations.push(`message[${i}]: ${result.violations.join(", ")}`);
          if (this.config.throwOnViolation) {
            throw new OpenAISecurityError("Message validation failed", violations);
          }
        }
        validatedMessages.push({
          ...msg,
          content: result.sanitized || msg.content,
        });
      } else if (msg.role === "system" || msg.role === "assistant") {
        // Encoding detection for system/assistant messages (may contain RAG content)
        const encodingResult = this.encodingDetector.detect(msg.content, `${reqId}-${i}`);
        if (!encodingResult.allowed) {
          violations.push(`message[${i}] (${msg.role}): ${encodingResult.violations.join(", ")}`);
        }
        validatedMessages.push(msg);
      } else {
        validatedMessages.push(msg);
      }
    }

    // Validate context coherence
    const contextContents = messages
      .filter((m) => m.role === "system" || m.role === "assistant")
      .map((m) => m.content)
      .filter((c): c is string => c !== null);

    if (this.memoryGuard && contextContents.length > 0) {
      const contextResult = this.memoryGuard.validateContextInjection(contextContents, sessionId, reqId);
      if (!contextResult.allowed) {
        violations.push(`context: ${contextResult.violations.join(", ")}`);
      }
    }

    return {
      allowed: violations.length === 0,
      messages: validatedMessages,
      violations,
    };
  }

  /**
   * Validate function/tool definitions
   */
  validateFunctions(
    functions: Array<{ name: string; description?: string; parameters?: any }>,
    sessionId: string
  ): ValidationResult {
    const violations: string[] = [];

    for (const func of functions) {
      // Check function name for suspicious patterns
      if (/^(system|admin|root|exec|eval|shell)/i.test(func.name)) {
        violations.push(`Suspicious function name: ${func.name}`);
      }

      // Check description for injection attempts
      if (func.description) {
        const result = this.validateContent(func.description);
        if (!result.allowed) {
          violations.push(`Function ${func.name} description: ${result.violations.join(", ")}`);
        }
      }
    }

    if (violations.length > 0) {
      this.handleViolation("function_validation", { violations });
    }

    return {
      allowed: violations.length === 0,
      violations,
    };
  }

  /**
   * Validate a function/tool call before execution
   */
  validateFunctionCall(
    name: string,
    args: Record<string, any>,
    sessionId: string
  ): ValidationResult {
    // Validate through tool chain validator
    const result = this.toolChainValidator.validate(sessionId, name);

    if (!result.allowed) {
      this.handleViolation("function_call", result);
      return {
        allowed: false,
        violations: result.violations,
        details: result,
      };
    }

    // Check arguments for injection
    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string") {
        const contentResult = this.validateContent(value);
        if (!contentResult.allowed) {
          this.handleViolation("function_arg_injection", { key, violations: contentResult.violations });
          return {
            allowed: false,
            violations: [`${key}: ${contentResult.violations.join(", ")}`],
          };
        }
      }
    }

    return {
      allowed: true,
      violations: [],
    };
  }

  /**
   * Filter the response from OpenAI
   */
  filterResponse(
    response: {
      choices?: Array<{
        message?: { content?: string | null; function_call?: any; tool_calls?: any[] };
        text?: string;
      }>;
    },
    requestId?: string
  ): typeof response {
    if (!this.config.filterOutput) {
      return response;
    }

    const reqId = requestId || `oai-resp-${Date.now()}`;

    if (response.choices) {
      return {
        ...response,
        choices: response.choices.map((choice, i) => {
          if (choice.message?.content) {
            const filtered = this.outputFilter.filter(choice.message.content, `${reqId}-${i}`);
            const filteredContent = typeof filtered.filtered_response === 'string'
              ? filtered.filtered_response
              : choice.message.content;
            return {
              ...choice,
              message: {
                ...choice.message,
                content: filteredContent,
              },
            };
          }
          if (choice.text) {
            const filtered = this.outputFilter.filter(choice.text, `${reqId}-${i}`);
            const filteredText = typeof filtered.filtered_response === 'string'
              ? filtered.filtered_response
              : choice.text;
            return {
              ...choice,
              text: filteredText,
            };
          }
          return choice;
        }),
      };
    }

    return response;
  }

  /**
   * Create a secure chat completion wrapper
   */
  createSecureChat(sessionId: string) {
    return {
      /**
       * Prepare messages for API call
       */
      prepareMessages: (messages: SecureMessage[]) => {
        return this.validateMessages(messages, sessionId);
      },

      /**
       * Validate function call before execution
       */
      validateFunctionCall: (name: string, args: any) => {
        return this.validateFunctionCall(name, args, sessionId);
      },

      /**
       * Filter response before returning
       */
      filterResponse: (response: any) => {
        return this.filterResponse(response);
      },
    };
  }

  private handleViolation(type: string, details: any): void {
    if (this.config.onViolation) {
      this.config.onViolation(type, details);
    }

    if (this.config.throwOnViolation) {
      throw new OpenAISecurityError(`Security violation: ${type}`, details.violations || [type]);
    }
  }
}

/**
 * Error thrown on security violations
 */
export class OpenAISecurityError extends Error {
  public violations: string[];

  constructor(message: string, violations: string[]) {
    super(message);
    this.name = "OpenAISecurityError";
    this.violations = violations;
  }
}

/**
 * Create a simple wrapper function for validating OpenAI messages
 *
 * @example
 * ```typescript
 * const validate = createMessageValidator();
 *
 * const userMessage = await getUserInput();
 * const result = validate(userMessage);
 *
 * if (!result.allowed) {
 *   console.log('Blocked:', result.violations);
 *   return;
 * }
 *
 * // Use result.sanitized in your API call
 * ```
 */
export function createMessageValidator(config?: ConstructorParameters<typeof InputSanitizer>[0]) {
  const sanitizer = new InputSanitizer(config);
  const encoder = new EncodingDetector();

  return function validate(content: string): {
    allowed: boolean;
    sanitized: string;
    violations: string[];
  } {
    const sanitizeResult = sanitizer.sanitize(content);
    if (!sanitizeResult.allowed) {
      return {
        allowed: false,
        sanitized: sanitizeResult.sanitizedInput,
        violations: sanitizeResult.violations,
      };
    }

    const encodingResult = encoder.detect(content);
    if (!encodingResult.allowed) {
      return {
        allowed: false,
        sanitized: content,
        violations: encodingResult.violations,
      };
    }

    return {
      allowed: true,
      sanitized: sanitizeResult.sanitizedInput,
      violations: [],
    };
  };
}

/**
 * Middleware-style wrapper for OpenAI client
 *
 * @example
 * ```typescript
 * import OpenAI from 'openai';
 * import { wrapOpenAIClient } from 'llm-trust-guard/integrations/openai';
 *
 * const openai = new OpenAI();
 * const secureOpenAI = wrapOpenAIClient(openai, {
 *   validateInput: true,
 *   filterOutput: true
 * });
 *
 * // Use secureOpenAI.chat.completions.create() as normal
 * // Input will be validated, output will be filtered
 * ```
 */
export function wrapOpenAIClient<T extends { chat: { completions: { create: Function } } }>(
  client: T,
  config: SecureOpenAIConfig = {}
): T {
  const secure = new SecureOpenAI(config);
  const sessionId = `wrap-${Date.now()}`;

  const originalCreate = client.chat.completions.create.bind(client.chat.completions);

  client.chat.completions.create = async function (params: any) {
    // Validate messages
    if (params.messages) {
      const validated = secure.validateMessages(params.messages, sessionId);
      if (!validated.allowed && config.throwOnViolation) {
        throw new OpenAISecurityError("Message validation failed", validated.violations);
      }
      params = { ...params, messages: validated.messages };
    }

    // Validate functions/tools
    if (params.functions && config.validateFunctions !== false) {
      const funcResult = secure.validateFunctions(params.functions, sessionId);
      if (!funcResult.allowed && config.throwOnViolation) {
        throw new OpenAISecurityError("Function validation failed", funcResult.violations);
      }
    }

    // Make the API call
    const response = await originalCreate(params);

    // Filter output
    return secure.filterResponse(response);
  };

  return client;
}
