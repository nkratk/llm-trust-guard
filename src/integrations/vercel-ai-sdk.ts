/**
 * Vercel AI SDK Integration for llm-trust-guard
 *
 * Provides middleware and wrappers for securing applications built with the
 * Vercel AI SDK (@vercel/ai / ai package). Works with any provider (OpenAI,
 * Anthropic, Google, Mistral, etc.) through the language model middleware API.
 *
 * Zero extra dependencies — `ai` is never imported directly.
 *
 * @example
 * ```typescript
 * import { openai } from '@ai-sdk/openai';
 * import { generateText, streamText } from 'ai';
 * import { wrapWithTrustGuard } from 'llm-trust-guard/integrations/vercel-ai-sdk';
 *
 * const model = wrapWithTrustGuard(openai('gpt-4o'));
 *
 * // Input is validated, output is filtered — automatic
 * const { text } = await generateText({
 *   model,
 *   messages: [{ role: 'user', content: userMessage }],
 * });
 * ```
 */

import {
  InputSanitizer,
  EncodingDetector,
  OutputFilter,
  MemoryGuard,
  ToolChainValidator,
} from "../index.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TrustGuardAIConfig {
  /** Enable InputSanitizer + EncodingDetector on user messages (default: true) */
  validateInput?: boolean;
  /** Enable OutputFilter on model responses (default: true) */
  filterOutput?: boolean;
  /** Enable ToolChainValidator on tool calls (default: true) */
  validateTools?: boolean;
  /** Throw error instead of returning blocked status (default: false) */
  throwOnViolation?: boolean;
  /** Custom violation handler: (type, details) => void */
  onViolation?: (type: string, details: unknown) => void;
  /** Forwarded to InputSanitizer constructor */
  sanitizerConfig?: ConstructorParameters<typeof InputSanitizer>[0];
  /** Forwarded to OutputFilter constructor */
  outputConfig?: ConstructorParameters<typeof OutputFilter>[0];
}

export interface InputValidationResult {
  allowed: boolean;
  violations: string[];
  sanitizedText?: string;
}

export interface AIOutputFilterResult {
  allowed: boolean;
  filteredText: string;
  piiDetected: number;
  secretsDetected: number;
}

// ---------------------------------------------------------------------------
// Core validator (framework-agnostic)
// ---------------------------------------------------------------------------

export class TrustGuardAI {
  readonly inputSanitizer: InputSanitizer;
  readonly encodingDetector: EncodingDetector;
  readonly outputFilter: OutputFilter;
  readonly memoryGuard: MemoryGuard;
  readonly toolChainValidator: ToolChainValidator;

  private readonly config: Required<
    Pick<
      TrustGuardAIConfig,
      "validateInput" | "filterOutput" | "validateTools" | "throwOnViolation"
    >
  > & TrustGuardAIConfig;

  constructor(config: TrustGuardAIConfig = {}) {
    this.config = {
      validateInput: config.validateInput ?? true,
      filterOutput: config.filterOutput ?? true,
      validateTools: config.validateTools ?? true,
      throwOnViolation: config.throwOnViolation ?? false,
      ...config,
    };

    this.inputSanitizer = new InputSanitizer(config.sanitizerConfig);
    this.encodingDetector = new EncodingDetector();
    this.outputFilter = new OutputFilter(config.outputConfig);
    this.memoryGuard = new MemoryGuard();
    this.toolChainValidator = new ToolChainValidator();
  }

  /**
   * Validate user input text. Returns the sanitized text if allowed.
   */
  validateInput(text: string, requestId?: string): InputValidationResult {
    const reqId = requestId ?? `vai-${Date.now()}`;

    if (!this.config.validateInput) {
      return { allowed: true, violations: [], sanitizedText: text };
    }

    const sanitizeResult = this.inputSanitizer.sanitize(text, reqId);
    if (!sanitizeResult.allowed) {
      this._handleViolation("input_sanitization", sanitizeResult);
      return {
        allowed: false,
        violations: sanitizeResult.violations,
        sanitizedText: sanitizeResult.sanitizedInput,
      };
    }

    const encodingResult = this.encodingDetector.detect(text, reqId);
    if (!encodingResult.allowed) {
      this._handleViolation("encoding_attack", encodingResult);
      return {
        allowed: false,
        violations: encodingResult.violations,
        sanitizedText: text,
      };
    }

    return {
      allowed: true,
      violations: [],
      sanitizedText: sanitizeResult.sanitizedInput,
    };
  }

  /**
   * Filter LLM output. Always returns a (possibly masked) string.
   */
  filterOutput(text: string, requestId?: string): AIOutputFilterResult {
    if (!this.config.filterOutput) {
      return {
        allowed: true,
        filteredText: text,
        piiDetected: 0,
        secretsDetected: 0,
      };
    }

    const reqId = requestId ?? `vai-out-${Date.now()}`;
    const result = this.outputFilter.filter(text, undefined, reqId);

    if (!result.allowed || result.filtered_response !== text) {
      this._handleViolation("output_filtered", {
        pii_detected: result.pii_detected.length,
        secrets_detected: result.secrets_detected.length,
        blocked: !result.allowed,
      });
    }

    return {
      allowed: result.allowed,
      filteredText:
        typeof result.filtered_response === "string"
          ? result.filtered_response
          : text,
      piiDetected: result.pii_detected.length,
      secretsDetected: result.secrets_detected.length,
    };
  }

  /**
   * Validate all user messages in an AI SDK message array in place.
   * Returns { allowed, messages, violations }.
   */
  validateMessages(
    messages: Array<{ role: string; content: string | unknown }>,
    requestId?: string
  ): { allowed: boolean; messages: typeof messages; violations: string[] } {
    const violations: string[] = [];
    const validated = messages.map((msg, i) => {
      if (msg.role !== "user" || typeof msg.content !== "string") {
        return msg;
      }
      const result = this.validateInput(msg.content, `${requestId ?? "vai"}-${i}`);
      if (!result.allowed) {
        violations.push(`message[${i}]: ${result.violations.join(", ")}`);
        return { ...msg, content: result.sanitizedText ?? msg.content };
      }
      return { ...msg, content: result.sanitizedText ?? msg.content };
    });

    return { allowed: violations.length === 0, messages: validated, violations };
  }

  /**
   * Validate a tool call before execution.
   */
  validateToolCall(
    toolName: string,
    args: Record<string, unknown>,
    sessionId: string
  ): { allowed: boolean; violations: string[] } {
    if (!this.config.validateTools) {
      return { allowed: true, violations: [] };
    }

    const result = this.toolChainValidator.validate(sessionId, toolName);
    if (!result.allowed) {
      this._handleViolation("tool_call", result);
      return { allowed: false, violations: result.violations };
    }

    // Scan string arguments for injection
    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string") {
        const argResult = this.validateInput(value);
        if (!argResult.allowed) {
          this._handleViolation("tool_arg_injection", {
            key,
            violations: argResult.violations,
          });
          return {
            allowed: false,
            violations: [`${toolName}.${key}: ${argResult.violations.join(", ")}`],
          };
        }
      }
    }

    return { allowed: true, violations: [] };
  }

  private _handleViolation(type: string, details: unknown): void {
    if (this.config.onViolation) {
      this.config.onViolation(type, details);
    }
    if (this.config.throwOnViolation) {
      throw new TrustGuardAIViolationError(type, details);
    }
  }
}

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

export class TrustGuardAIViolationError extends Error {
  public readonly violationType: string;
  public readonly details: unknown;

  constructor(type: string, details: unknown) {
    super(`llm-trust-guard: ${type}`);
    this.name = "TrustGuardAIViolationError";
    this.violationType = type;
    this.details = details;
  }
}

// ---------------------------------------------------------------------------
// Language model middleware (experimental_wrapLanguageModel API)
// ---------------------------------------------------------------------------

/**
 * Build a Vercel AI SDK LanguageModelV1Middleware object.
 *
 * Pass the returned object to `wrapLanguageModel` (or
 * `experimental_wrapLanguageModel` in older SDK versions):
 *
 * ```typescript
 * import { wrapLanguageModel } from 'ai';
 * import { openai } from '@ai-sdk/openai';
 * import { createTrustGuardMiddleware } from 'llm-trust-guard/integrations/vercel-ai-sdk';
 *
 * const model = wrapLanguageModel({
 *   model: openai('gpt-4o'),
 *   middleware: createTrustGuardMiddleware({ throwOnViolation: true }),
 * });
 * ```
 */
export function createTrustGuardMiddleware(
  config: TrustGuardAIConfig = {}
): {
  wrapGenerate: (options: {
    doGenerate: () => Promise<unknown>;
    params: { messages?: Array<{ role: string; content: unknown }> };
  }) => Promise<unknown>;
  wrapStream: (options: {
    doStream: () => Promise<{ stream: AsyncIterable<unknown> } & Record<string, unknown>>;
    params: { messages?: Array<{ role: string; content: unknown }> };
  }) => Promise<{ stream: AsyncIterable<unknown> } & Record<string, unknown>>;
} {
  const guard = new TrustGuardAI(config);

  function validateParams(params: {
    messages?: Array<{ role: string; content: unknown }>;
  }): void {
    if (!params.messages) return;
    const messages = params.messages as Array<{
      role: string;
      content: string | unknown;
    }>;
    const { allowed, violations } = guard.validateMessages(messages);
    if (!allowed) {
      const err = new TrustGuardAIViolationError(
        "input_sanitization",
        violations
      );
      if (config.throwOnViolation) throw err;
      if (config.onViolation) config.onViolation("input_sanitization", violations);
    }
  }

  return {
    async wrapGenerate({ doGenerate, params }) {
      validateParams(params);
      const result = await doGenerate();

      // Filter text output
      const typedResult = result as Record<string, unknown>;
      if (typeof typedResult["text"] === "string") {
        const { filteredText } = guard.filterOutput(typedResult["text"]);
        typedResult["text"] = filteredText;
      }
      return typedResult;
    },

    async wrapStream({ doStream, params }) {
      validateParams(params);
      const { stream, ...rest } = await doStream();

      // Wrap the stream to filter text-delta chunks
      async function* filteredStream(): AsyncGenerator<unknown> {
        for await (const chunk of stream) {
          const typedChunk = chunk as Record<string, unknown>;
          if (
            typedChunk["type"] === "text-delta" &&
            typeof typedChunk["textDelta"] === "string"
          ) {
            const { filteredText } = guard.filterOutput(typedChunk["textDelta"]);
            yield { ...typedChunk, textDelta: filteredText };
          } else {
            yield chunk;
          }
        }
      }

      return { stream: filteredStream(), ...rest };
    },
  };
}

// ---------------------------------------------------------------------------
// Convenience: wrap a model directly (one-liner API)
// ---------------------------------------------------------------------------

/**
 * Wrap a Vercel AI SDK language model with trust guard middleware.
 *
 * This is a convenience wrapper for `wrapLanguageModel` from the `ai` package.
 * It requires `ai` >= 3.1 to be installed in the host project.
 *
 * ```typescript
 * import { openai } from '@ai-sdk/openai';
 * import { wrapWithTrustGuard } from 'llm-trust-guard/integrations/vercel-ai-sdk';
 *
 * // Drop-in replacement for openai('gpt-4o')
 * const model = wrapWithTrustGuard(openai('gpt-4o'), {
 *   validateInput: true,
 *   filterOutput: true,
 *   throwOnViolation: true,
 * });
 *
 * const { text } = await generateText({ model, prompt: userMessage });
 * ```
 */
export function wrapWithTrustGuard<T extends object>(
  model: T,
  config: TrustGuardAIConfig = {}
): T {
  // Dynamically import ai to avoid a hard dependency
  let wrapFn: ((opts: { model: T; middleware: unknown }) => T) | undefined;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const ai = require("ai") as {
      wrapLanguageModel?: (opts: { model: T; middleware: unknown }) => T;
      experimental_wrapLanguageModel?: (opts: { model: T; middleware: unknown }) => T;
    };
    wrapFn = ai.wrapLanguageModel ?? ai.experimental_wrapLanguageModel;
  } catch {
    throw new Error(
      "llm-trust-guard: `wrapWithTrustGuard` requires the `ai` package. " +
        "Run: npm install ai"
    );
  }

  if (!wrapFn) {
    throw new Error(
      "llm-trust-guard: `wrapLanguageModel` not found in the `ai` package. " +
        "Upgrade to ai >= 3.1 or use `createTrustGuardMiddleware` directly."
    );
  }

  const middleware = createTrustGuardMiddleware(config);
  return wrapFn({ model, middleware });
}

// ---------------------------------------------------------------------------
// Standalone helpers (non-middleware usage)
// ---------------------------------------------------------------------------

/**
 * Create a simple validate-then-generate helper.
 *
 * ```typescript
 * import { generateText } from 'ai';
 * import { openai } from '@ai-sdk/openai';
 * import { createSecureGenerate } from 'llm-trust-guard/integrations/vercel-ai-sdk';
 *
 * const secureGenerate = createSecureGenerate(generateText, {
 *   throwOnViolation: true,
 * });
 *
 * const { text } = await secureGenerate({
 *   model: openai('gpt-4o'),
 *   messages: [{ role: 'user', content: userInput }],
 * });
 * ```
 */
export function createSecureGenerate<T extends (...args: unknown[]) => Promise<{ text?: string }>>(
  generateFn: T,
  config: TrustGuardAIConfig = {}
): T {
  const guard = new TrustGuardAI(config);

  return (async (params: Record<string, unknown>) => {
    const messages = params["messages"] as
      | Array<{ role: string; content: unknown }>
      | undefined;

    if (messages) {
      const { allowed, violations } = guard.validateMessages(messages as Array<{
        role: string;
        content: string | unknown;
      }>);
      if (!allowed) {
        if (config.throwOnViolation) {
          throw new TrustGuardAIViolationError("input_sanitization", violations);
        }
        if (config.onViolation) {
          config.onViolation("input_sanitization", violations);
        }
      }
    }

    const result = await generateFn(params as Parameters<T>[0]);

    if (typeof result.text === "string") {
      const { filteredText } = guard.filterOutput(result.text);
      return { ...result, text: filteredText };
    }

    return result;
  }) as T;
}
