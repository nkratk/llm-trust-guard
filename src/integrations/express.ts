/**
 * Express Middleware Integration for llm-trust-guard
 *
 * Provides ready-to-use middleware for Express.js applications
 * to protect LLM-powered endpoints.
 */

import { InputSanitizer, EncodingDetector, MemoryGuard } from "../index.js";
import type { PAPSanitizerResult } from "../guards/input-sanitizer.js";
import type { EncodingDetectorResult } from "../guards/encoding-detector.js";
import type { MemoryGuardResult } from "../guards/memory-guard.js";

// Express types (avoiding hard dependency)
interface Request {
  body?: any;
  query?: any;
  params?: any;
  headers?: any;
  session?: any;
  get?(name: string): string | undefined;
}

interface Response {
  status(code: number): Response;
  json(body: any): Response;
}

type NextFunction = (err?: any) => void;

export interface TrustGuardMiddlewareConfig {
  /** Fields to check in request body */
  bodyFields?: string[];
  /** Fields to check in query params */
  queryFields?: string[];
  /** Enable input sanitization */
  sanitize?: boolean;
  /** Enable encoding detection */
  detectEncoding?: boolean;
  /** Enable memory/context validation */
  validateMemory?: boolean;
  /** Custom error handler */
  onBlocked?: (req: Request, res: Response, result: ExpressGuardResult) => void;
  /** Custom logging function */
  logger?: (message: string, data?: any) => void;
  /** InputSanitizer configuration */
  sanitizerConfig?: ConstructorParameters<typeof InputSanitizer>[0];
  /** EncodingDetector configuration */
  encodingConfig?: ConstructorParameters<typeof EncodingDetector>[0];
  /** MemoryGuard configuration */
  memoryConfig?: ConstructorParameters<typeof MemoryGuard>[0];
  /** Session ID extractor */
  getSessionId?: (req: Request) => string;
}

export interface ExpressGuardResult {
  allowed: boolean;
  guard: string;
  violations: string[];
  details?: PAPSanitizerResult | EncodingDetectorResult | MemoryGuardResult;
}

/**
 * Create Express middleware for LLM input protection
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createTrustGuardMiddleware } from 'llm-trust-guard/integrations/express';
 *
 * const app = express();
 * app.use(express.json());
 *
 * // Protect all LLM endpoints
 * app.use('/api/chat', createTrustGuardMiddleware({
 *   bodyFields: ['message', 'prompt'],
 *   sanitize: true,
 *   detectEncoding: true
 * }));
 *
 * app.post('/api/chat', (req, res) => {
 *   // req.body.message is now validated
 *   res.json({ response: 'Safe response' });
 * });
 * ```
 */
export function createTrustGuardMiddleware(config: TrustGuardMiddlewareConfig = {}) {
  const {
    bodyFields = ["message", "prompt", "input", "query", "content"],
    queryFields = [],
    sanitize = true,
    detectEncoding = true,
    validateMemory = false,
    onBlocked,
    logger = console.log,
    sanitizerConfig,
    encodingConfig,
    memoryConfig,
    // WARNING: Custom getSessionId should use server-generated session IDs only.
    // Never trust client-provided headers for security-critical session identification.
    getSessionId = (req) => req.session?.id || `anon-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  } = config;

  // Initialize guards
  const inputSanitizer = sanitize ? new InputSanitizer(sanitizerConfig) : null;
  const encodingDetector = detectEncoding ? new EncodingDetector(encodingConfig) : null;
  const memoryGuard = validateMemory ? new MemoryGuard(memoryConfig) : null;

  return function trustGuardMiddleware(req: Request, res: Response, next: NextFunction) {
    const requestId = `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const sessionId = getSessionId(req);

    // Collect all text fields to check
    const textsToCheck: Array<{ field: string; value: string; source: string }> = [];

    // Check body fields
    if (req.body) {
      for (const field of bodyFields) {
        const value = req.body[field];
        if (typeof value === "string" && value.trim()) {
          textsToCheck.push({ field, value, source: "body" });
        }
      }
    }

    // Check query fields
    if (req.query) {
      for (const field of queryFields) {
        const value = req.query[field];
        if (typeof value === "string" && value.trim()) {
          textsToCheck.push({ field, value, source: "query" });
        }
      }
    }

    // Check each text field
    for (const { field, value, source } of textsToCheck) {
      // Input sanitization
      if (inputSanitizer) {
        const sanitizeResult = inputSanitizer.sanitize(value, requestId);
        if (!sanitizeResult.allowed) {
          const result: ExpressGuardResult = {
            allowed: false,
            guard: "InputSanitizer",
            violations: sanitizeResult.violations,
            details: sanitizeResult,
          };

          logger(`[TrustGuard] Blocked by InputSanitizer: ${source}.${field}`, {
            requestId,
            violations: sanitizeResult.violations,
          });

          if (onBlocked) {
            return onBlocked(req, res, result);
          }

          return res.status(400).json({
            error: "Request blocked by security policy",
            code: "INPUT_SANITIZATION_FAILED",
            field: `${source}.${field}`,
            violations: sanitizeResult.violations,
          });
        }
      }

      // Encoding detection
      if (encodingDetector) {
        const encodingResult = encodingDetector.detect(value, requestId);
        if (!encodingResult.allowed) {
          const result: ExpressGuardResult = {
            allowed: false,
            guard: "EncodingDetector",
            violations: encodingResult.violations,
            details: encodingResult,
          };

          logger(`[TrustGuard] Blocked by EncodingDetector: ${source}.${field}`, {
            requestId,
            violations: encodingResult.violations,
          });

          if (onBlocked) {
            return onBlocked(req, res, result);
          }

          return res.status(400).json({
            error: "Request blocked by security policy",
            code: "ENCODING_ATTACK_DETECTED",
            field: `${source}.${field}`,
            violations: encodingResult.violations,
          });
        }
      }

      // Memory/context validation
      if (memoryGuard) {
        const memoryResult = memoryGuard.validateContextInjection(value, sessionId, requestId);
        if (!memoryResult.allowed) {
          const result: ExpressGuardResult = {
            allowed: false,
            guard: "MemoryGuard",
            violations: memoryResult.violations,
            details: memoryResult,
          };

          logger(`[TrustGuard] Blocked by MemoryGuard: ${source}.${field}`, {
            requestId,
            violations: memoryResult.violations,
          });

          if (onBlocked) {
            return onBlocked(req, res, result);
          }

          return res.status(400).json({
            error: "Request blocked by security policy",
            code: "CONTEXT_INJECTION_DETECTED",
            field: `${source}.${field}`,
            violations: memoryResult.violations,
          });
        }
      }
    }

    // All checks passed
    next();
  };
}

/**
 * Create middleware for rate-limiting sensitive tool usage
 *
 * @example
 * ```typescript
 * app.use('/api/tools', createToolRateLimitMiddleware({
 *   sensitiveTools: ['delete', 'admin', 'execute'],
 *   maxSensitivePerSession: 5,
 *   windowMs: 60000
 * }));
 * ```
 */
export function createToolRateLimitMiddleware(config: {
  sensitiveTools: string[];
  maxSensitivePerSession?: number;
  windowMs?: number;
  getSessionId?: (req: Request) => string;
  getToolName?: (req: Request) => string | undefined;
}) {
  const {
    sensitiveTools,
    maxSensitivePerSession = 10,
    windowMs = 60000,
    getSessionId = (req) => req.session?.id || "anonymous",
    getToolName = (req) => req.body?.tool || req.body?.toolName,
  } = config;

  // Session usage tracking
  const sessionUsage = new Map<string, { count: number; resetAt: number }>();

  return function toolRateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
    const sessionId = getSessionId(req);
    const toolName = getToolName(req);

    // Check if this is a sensitive tool
    if (toolName && sensitiveTools.some((t) => toolName.toLowerCase().includes(t.toLowerCase()))) {
      const now = Date.now();
      let usage = sessionUsage.get(sessionId);

      // Reset if window expired
      if (!usage || now > usage.resetAt) {
        usage = { count: 0, resetAt: now + windowMs };
        sessionUsage.set(sessionId, usage);
      }

      // Check limit
      if (usage.count >= maxSensitivePerSession) {
        return res.status(429).json({
          error: "Rate limit exceeded for sensitive tool usage",
          code: "TOOL_RATE_LIMIT_EXCEEDED",
          retryAfter: Math.ceil((usage.resetAt - now) / 1000),
        });
      }

      // Increment counter
      usage.count++;
    }

    next();
  };
}

/**
 * Create middleware for output filtering
 *
 * @example
 * ```typescript
 * app.use(createOutputFilterMiddleware({
 *   patterns: [
 *     /api[_-]?key/i,
 *     /password/i,
 *     /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/
 *   ],
 *   replacement: '[REDACTED]'
 * }));
 * ```
 */
export function createOutputFilterMiddleware(config: {
  patterns: RegExp[];
  replacement?: string;
  fields?: string[];
}) {
  const { patterns, replacement = "[REDACTED]", fields = ["response", "message", "content", "text"] } = config;

  return function outputFilterMiddleware(req: Request, res: Response, next: NextFunction) {
    const originalJson = res.json.bind(res);

    res.json = function (body: any) {
      if (body && typeof body === "object") {
        const filtered = filterObject(body, fields, patterns, replacement);
        return originalJson(filtered);
      }
      return originalJson(body);
    };

    next();
  };
}

function filterObject(obj: any, fields: string[], patterns: RegExp[], replacement: string): any {
  if (Array.isArray(obj)) {
    return obj.map((item) => filterObject(item, fields, patterns, replacement));
  }

  if (obj && typeof obj === "object") {
    const result: any = {};
    for (const [key, value] of Object.entries(obj)) {
      if (fields.includes(key) && typeof value === "string") {
        let filtered = value;
        for (const pattern of patterns) {
          filtered = filtered.replace(new RegExp(pattern, "g"), replacement);
        }
        result[key] = filtered;
      } else if (typeof value === "object") {
        result[key] = filterObject(value, fields, patterns, replacement);
      } else {
        result[key] = value;
      }
    }
    return result;
  }

  return obj;
}
