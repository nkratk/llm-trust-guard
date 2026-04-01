/**
 * OutputSchemaGuard
 *
 * Validates LLM structured outputs (JSON, function calls) before they
 * reach downstream systems (databases, APIs, UIs).
 *
 * Addresses OWASP LLM05: Improper Output Handling.
 *
 * Why: LLMs can produce structured outputs containing:
 * - Unexpected actions ("delete_all" instead of "search")
 * - Injection in JSON values flowing to downstream parsers
 * - Hallucinated function calls that don't match available tools
 * - Hidden instructions in field values for downstream systems
 */

export interface OutputSchemaGuardConfig {
  /** Expected output schemas keyed by action/function name */
  schemas?: Record<string, OutputSchema>;
  /** Scan all string values for injection patterns (default: true) */
  scanForInjection?: boolean;
  /** Reject outputs with fields not in schema (default: false) */
  strictSchema?: boolean;
  /** Max output size in characters (default: 100000) */
  maxOutputSize?: number;
}

export interface OutputSchema {
  type: "object" | "array" | "string";
  properties?: Record<string, { type: string; enum?: string[]; maxLength?: number }>;
  required?: string[];
}

export interface OutputSchemaResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  schema_valid: boolean;
  injection_found: boolean;
  threats: Array<{ field: string; type: string; detail: string }>;
}

// Patterns for injection hidden in structured output values
const OUTPUT_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "sql_injection", pattern: /\b(?:DROP|DELETE|INSERT|UPDATE|ALTER)\s+(?:TABLE|FROM|INTO|SET)\b/i },
  { name: "command_injection", pattern: /;\s*(?:rm|cat|wget|curl|bash|sh|python)\b/i },
  { name: "xss", pattern: /<script|javascript:|on\w+\s*=/i },
  { name: "prompt_injection", pattern: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)/i },
  { name: "system_override", pattern: /(?:SYSTEM|ADMIN)\s*:|<\/?system>|\[system\]/i },
  { name: "path_traversal", pattern: /\.\.\//g },
  { name: "url_exfiltration", pattern: /https?:\/\/[^\s]+\?(?:.*(?:token|key|secret|password|auth))/i },
];

export class OutputSchemaGuard {
  private config: Required<Pick<OutputSchemaGuardConfig, "scanForInjection" | "strictSchema" | "maxOutputSize">> & OutputSchemaGuardConfig;

  constructor(config: OutputSchemaGuardConfig = {}) {
    this.config = {
      scanForInjection: config.scanForInjection ?? true,
      strictSchema: config.strictSchema ?? false,
      maxOutputSize: config.maxOutputSize ?? 100_000,
      schemas: config.schemas,
    };
  }

  /**
   * Validate LLM structured output
   */
  validate(
    output: any,
    schemaName?: string,
    requestId?: string
  ): OutputSchemaResult {
    const violations: string[] = [];
    const threats: Array<{ field: string; type: string; detail: string }> = [];
    let schemaValid = true;
    let injectionFound = false;

    // Size check
    const outputStr = this.safeStringify(output);
    if (outputStr.length > this.config.maxOutputSize) {
      violations.push("OUTPUT_TOO_LARGE");
    }

    // Schema validation
    if (schemaName && this.config.schemas?.[schemaName]) {
      const schema = this.config.schemas[schemaName];
      const schemaErrors = this.validateAgainstSchema(output, schema);
      if (schemaErrors.length > 0) {
        schemaValid = false;
        violations.push("SCHEMA_VIOLATION");
        threats.push(...schemaErrors.map(e => ({ field: e.field, type: "schema", detail: e.message })));
      }
    }

    // Injection scanning
    if (this.config.scanForInjection) {
      const injectionResult = this.scanForInjection(output);
      if (injectionResult.length > 0) {
        injectionFound = true;
        violations.push("INJECTION_IN_OUTPUT");
        threats.push(...injectionResult);
      }
    }

    const allowed = violations.length === 0;

    return {
      allowed,
      reason: allowed ? undefined : `Output validation failed: ${violations.join(", ")}`,
      violations,
      schema_valid: schemaValid,
      injection_found: injectionFound,
      threats,
    };
  }

  /**
   * Validate a function/tool call output from LLM
   */
  validateFunctionCall(
    functionName: string,
    args: Record<string, any>,
    requestId?: string
  ): OutputSchemaResult {
    return this.validate(args, functionName, requestId);
  }

  /**
   * Register a schema for an action/function
   */
  registerSchema(name: string, schema: OutputSchema): void {
    if (!this.config.schemas) this.config.schemas = {};
    this.config.schemas[name] = schema;
  }

  private validateAgainstSchema(
    output: any,
    schema: OutputSchema
  ): Array<{ field: string; message: string }> {
    const errors: Array<{ field: string; message: string }> = [];

    if (schema.type === "object" && typeof output === "object" && output !== null && !Array.isArray(output)) {
      // Check required fields
      for (const field of schema.required || []) {
        if (output[field] === undefined || output[field] === null) {
          errors.push({ field, message: `Missing required field '${field}'` });
        }
      }

      // Check field types and constraints
      if (schema.properties) {
        for (const [field, prop] of Object.entries(schema.properties)) {
          if (output[field] !== undefined) {
            const actualType = Array.isArray(output[field]) ? "array" : typeof output[field];
            if (actualType !== prop.type) {
              errors.push({ field, message: `Expected '${prop.type}', got '${actualType}'` });
            }
            if (prop.enum && !prop.enum.includes(output[field])) {
              errors.push({ field, message: `Value '${output[field]}' not in allowed values: ${prop.enum.join(", ")}` });
            }
            if (prop.maxLength && typeof output[field] === "string" && output[field].length > prop.maxLength) {
              errors.push({ field, message: `Exceeds max length ${prop.maxLength}` });
            }
          }
        }

        // Strict schema: reject unexpected fields
        if (this.config.strictSchema) {
          for (const key of Object.keys(output)) {
            if (!schema.properties[key]) {
              errors.push({ field: key, message: `Unexpected field '${key}' not in schema` });
            }
          }
        }
      }
    } else if (schema.type !== (Array.isArray(output) ? "array" : typeof output)) {
      errors.push({ field: "root", message: `Expected type '${schema.type}', got '${typeof output}'` });
    }

    return errors;
  }

  private scanForInjection(
    value: any,
    path: string = "root"
  ): Array<{ field: string; type: string; detail: string }> {
    const threats: Array<{ field: string; type: string; detail: string }> = [];

    if (typeof value === "string") {
      for (const { name, pattern } of OUTPUT_INJECTION_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(value)) {
          threats.push({
            field: path,
            type: `injection_${name}`,
            detail: `Pattern '${name}' found in output field '${path}'`,
          });
        }
      }
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        threats.push(...this.scanForInjection(value[i], `${path}[${i}]`));
      }
    } else if (value !== null && typeof value === "object") {
      for (const [key, val] of Object.entries(value)) {
        threats.push(...this.scanForInjection(val, `${path}.${key}`));
      }
    }

    return threats;
  }

  private safeStringify(value: any): string {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
}
