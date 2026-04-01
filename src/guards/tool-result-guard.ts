/**
 * ToolResultGuard
 *
 * Validates tool return values before they flow back into LLM context.
 * Addresses the #1 attack vector in 2025-2026: tool output poisoning.
 *
 * Real-world incidents this guard prevents:
 * - Microsoft Copilot "Copirate" (2025): tool output contained hidden prompt injection
 * - Supabase Cursor SQL exfiltration (2025): tool returned attacker-controlled data
 * - WhatsApp MCP exfiltration (2025): tool output used for cross-service data theft
 */

export interface ToolResultGuardConfig {
  /** Expected return schemas per tool name */
  expectedSchemas?: Record<string, ToolResultSchema>;
  /** Scan all string values in results for prompt injection (default: true) */
  scanForInjection?: boolean;
  /** Max result size in characters (default: 50000) */
  maxResultSize?: number;
  /** Additional patterns to block in results */
  sensitivePatterns?: RegExp[];
  /** Block results claiming state changes (default: true) */
  detectStateChangeClaims?: boolean;
}

export interface ToolResultSchema {
  type: "string" | "number" | "boolean" | "object" | "array";
  properties?: Record<string, { type: string; required?: boolean }>;
  maxLength?: number;
}

export interface ToolResultGuardResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  injection_detected: boolean;
  schema_valid: boolean;
  threats: ToolResultThreat[];
}

export interface ToolResultThreat {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  location: string;
  detail: string;
}

// Injection patterns to detect in tool results (reused from InputSanitizer concepts)
const RESULT_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: "high" | "critical" }> = [
  // Prompt injection markers in tool output
  { name: "system_instruction", pattern: /(?:SYSTEM|ADMIN|INSTRUCTION)\s*:/i, severity: "critical" },
  { name: "ignore_instructions", pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules)/i, severity: "critical" },
  { name: "new_instructions", pattern: /new\s+instructions?\s*:/i, severity: "critical" },
  { name: "role_override", pattern: /you\s+are\s+now|from\s+now\s+on|act\s+as\s+(?:a|an)/i, severity: "critical" },
  { name: "xml_system_tag", pattern: /<\/?system>|<\/?admin>|\[system\]|\[admin\]/i, severity: "critical" },
  { name: "jailbreak", pattern: /jailbreak|DAN\s*mode|developer\s+mode|unrestricted/i, severity: "critical" },
  { name: "bypass_safety", pattern: /bypass\s+(?:security|safety|filters|restrictions)/i, severity: "high" },
  { name: "data_exfiltration", pattern: /send\s+(?:this|the|all)\s+(?:data|info)\s+to|exfiltrate/i, severity: "critical" },
  { name: "hidden_instruction", pattern: /HIDDEN_PROMPT|HIDDEN_INSTRUCTION|INVISIBLE_TEXT/i, severity: "critical" },
  { name: "markdown_injection", pattern: /!\[.*\]\(https?:\/\/[^)]*\?.*(?:token|key|secret|auth)/i, severity: "high" },
];

// State change claim patterns
const STATE_CHANGE_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "privilege_claim", pattern: /(?:user|role|permission)\s+(?:is\s+now|changed\s+to|promoted\s+to|set\s+to)\s+(?:admin|root|superuser)/i },
  { name: "auth_claim", pattern: /(?:authenticated|authorized|verified)\s+as\s+(?:admin|root|superuser)/i },
  { name: "approval_claim", pattern: /(?:approved|granted|authorized)\s+(?:without|bypassing)\s+(?:verification|approval|review)/i },
  { name: "config_change_claim", pattern: /(?:configuration|settings?|policy)\s+(?:updated|changed|modified)\s+(?:to|:)/i },
];

export class ToolResultGuard {
  private config: Required<Pick<ToolResultGuardConfig, "scanForInjection" | "maxResultSize" | "detectStateChangeClaims">> & ToolResultGuardConfig;

  constructor(config: ToolResultGuardConfig = {}) {
    this.config = {
      scanForInjection: config.scanForInjection ?? true,
      maxResultSize: config.maxResultSize ?? 50_000,
      detectStateChangeClaims: config.detectStateChangeClaims ?? true,
      expectedSchemas: config.expectedSchemas,
      sensitivePatterns: config.sensitivePatterns,
    };
  }

  /**
   * Validate a tool's return value before feeding it back to the LLM
   */
  validateResult(
    toolName: string,
    result: any,
    requestId?: string
  ): ToolResultGuardResult {
    const violations: string[] = [];
    const threats: ToolResultThreat[] = [];
    let injectionDetected = false;
    let schemaValid = true;

    // Size check
    const resultStr = typeof result === "string" ? result : this.safeStringify(result);
    if (resultStr.length > this.config.maxResultSize) {
      violations.push("RESULT_TOO_LARGE");
      threats.push({
        type: "size_exceeded",
        severity: "high",
        location: "root",
        detail: `Result size ${resultStr.length} exceeds max ${this.config.maxResultSize}`,
      });
    }

    // Schema validation (if schema registered for this tool)
    if (this.config.expectedSchemas?.[toolName]) {
      const schemaResult = this.validateSchema(result, this.config.expectedSchemas[toolName]);
      if (!schemaResult.valid) {
        schemaValid = false;
        violations.push("SCHEMA_MISMATCH");
        threats.push(...schemaResult.errors.map(e => ({
          type: "schema_violation",
          severity: "high" as const,
          location: e.path,
          detail: e.message,
        })));
      }
    }

    // Injection scanning (default: on)
    if (this.config.scanForInjection) {
      const injectionResult = this.scanForInjection(result);
      if (injectionResult.detected) {
        injectionDetected = true;
        violations.push("INJECTION_IN_TOOL_RESULT");
        threats.push(...injectionResult.threats);
      }
    }

    // State change claim detection
    if (this.config.detectStateChangeClaims) {
      const stateResult = this.detectStateChangeClaims(resultStr);
      if (stateResult.detected) {
        violations.push("STATE_CHANGE_CLAIM");
        threats.push(...stateResult.threats);
      }
    }

    // Custom sensitive patterns
    if (this.config.sensitivePatterns) {
      for (const pattern of this.config.sensitivePatterns) {
        pattern.lastIndex = 0;
        if (pattern.test(resultStr)) {
          violations.push("SENSITIVE_PATTERN_MATCH");
          threats.push({
            type: "sensitive_content",
            severity: "high",
            location: "root",
            detail: `Matched sensitive pattern: ${pattern.source.substring(0, 50)}`,
          });
        }
      }
    }

    const allowed = violations.length === 0;

    return {
      allowed,
      reason: allowed ? undefined : `Tool result validation failed: ${violations.join(", ")}`,
      violations,
      injection_detected: injectionDetected,
      schema_valid: schemaValid,
      threats,
    };
  }

  /**
   * Scan any value (string, object, array) for injection patterns
   */
  scanForInjection(value: any, path: string = "root"): { detected: boolean; threats: ToolResultThreat[] } {
    const threats: ToolResultThreat[] = [];

    if (typeof value === "string") {
      for (const { name, pattern, severity } of RESULT_INJECTION_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(value)) {
          threats.push({
            type: `injection_${name}`,
            severity,
            location: path,
            detail: `Injection pattern '${name}' detected in tool result`,
          });
        }
      }
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const sub = this.scanForInjection(value[i], `${path}[${i}]`);
        threats.push(...sub.threats);
      }
    } else if (value !== null && typeof value === "object") {
      for (const [key, val] of Object.entries(value)) {
        const sub = this.scanForInjection(val, `${path}.${key}`);
        threats.push(...sub.threats);
      }
    }

    return { detected: threats.length > 0, threats };
  }

  /**
   * Register expected schema for a tool
   */
  registerSchema(toolName: string, schema: ToolResultSchema): void {
    if (!this.config.expectedSchemas) this.config.expectedSchemas = {};
    this.config.expectedSchemas[toolName] = schema;
  }

  private detectStateChangeClaims(text: string): { detected: boolean; threats: ToolResultThreat[] } {
    const threats: ToolResultThreat[] = [];

    for (const { name, pattern } of STATE_CHANGE_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(text)) {
        threats.push({
          type: `state_change_${name}`,
          severity: "critical",
          location: "root",
          detail: `Tool result claims state change: ${name}`,
        });
      }
    }

    return { detected: threats.length > 0, threats };
  }

  private validateSchema(value: any, schema: ToolResultSchema): { valid: boolean; errors: Array<{ path: string; message: string }> } {
    const errors: Array<{ path: string; message: string }> = [];
    const actualType = Array.isArray(value) ? "array" : typeof value;

    if (actualType !== schema.type) {
      errors.push({ path: "root", message: `Expected type '${schema.type}', got '${actualType}'` });
      return { valid: false, errors };
    }

    if (schema.type === "string" && schema.maxLength && (value as string).length > schema.maxLength) {
      errors.push({ path: "root", message: `String length exceeds max ${schema.maxLength}` });
    }

    if (schema.type === "object" && schema.properties) {
      for (const [key, prop] of Object.entries(schema.properties)) {
        if (prop.required && (value[key] === undefined || value[key] === null)) {
          errors.push({ path: key, message: `Missing required field '${key}'` });
        }
        if (value[key] !== undefined && typeof value[key] !== prop.type) {
          errors.push({ path: key, message: `Field '${key}' expected '${prop.type}', got '${typeof value[key]}'` });
        }
      }
    }

    return { valid: errors.length === 0, errors };
  }

  private safeStringify(value: any): string {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
}
