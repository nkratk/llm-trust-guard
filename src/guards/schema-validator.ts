/**
 * L5 Schema Validator
 *
 * Validates tool parameters against schemas.
 * Detects injection attacks and type coercion.
 */

import { ToolDefinition, SchemaProperty, SchemaValidatorResult, GuardLogger } from "../types";

// Injection patterns
const INJECTION_PATTERNS: Record<string, RegExp[]> = {
  SQL: [
    // Require SQL keyword + suspicious operator context (not bare quotes/semicolons)
    /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b.*?(--|;|\/\*)/i,
    /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b/i,
    /(\bOR\b|\bAND\b)\s*\d+\s*=\s*\d+/i,
  ],
  NOSQL: [
    /\$where|\$regex|\$ne|\$gt|\$lt|\$nin|\$or|\$and/i,
    /\{\s*['"]\$[a-z]+['"]\s*:/i,
  ],
  PATH_TRAVERSAL: [
    /\.\.\//,
    /\.\.\\/,
    /^\/etc\//i,
    /^\/root\//i,
    /%2e%2e%2f/i,
  ],
  COMMAND: [
    // Require command keyword context (not bare special chars)
    /;\s*\b(cat|ls|rm|wget|curl|nc|bash|sh|python|chmod|chown)\b/i,
    /\|\s*\b(sh|bash|cat|nc)\b/i,
    /`[^`]+`/,
    /\$\([^)]+\)/,
  ],
  XSS: [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
  ],
};

// Dangerous object keys
const DANGEROUS_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "__defineGetter__",
  "__defineSetter__",
]);

export interface SchemaValidatorConfig {
  strictTypes?: boolean;
  detectInjection?: boolean;
  sanitizeStrings?: boolean;
  logger?: GuardLogger;
}

export class SchemaValidator {
  private strictTypes: boolean;
  private detectInjection: boolean;
  private sanitizeStrings: boolean;
  private logger: GuardLogger;

  constructor(config: SchemaValidatorConfig = {}) {
    this.strictTypes = config.strictTypes ?? true;
    this.detectInjection = config.detectInjection ?? true;
    this.sanitizeStrings = config.sanitizeStrings ?? true;
    this.logger = config.logger || (() => {});
  }

  /**
   * Validate parameters against tool schema
   */
  validate(
    tool: ToolDefinition,
    params: Record<string, any>,
    requestId: string = ""
  ): SchemaValidatorResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const blocked_attacks: string[] = [];
    const sanitizedParams: Record<string, any> = {};

    // Check for prototype pollution at top level
    const pollutionCheck = this.checkPrototypePollution(params);
    if (!pollutionCheck.safe) {
      if (requestId) {
        this.logger(`[L5:${requestId}] BLOCKED: Prototype pollution`, "info");
      }
      return {
        allowed: false,
        reason: "Prototype pollution detected",
        violations: ["PROTOTYPE_POLLUTION"],
        errors: pollutionCheck.errors,
        warnings: [],
        sanitizedParams: {},
        blocked_attacks: ["PROTOTYPE_POLLUTION"],
      };
    }

    const schema = tool.parameters;

    // Check required fields
    for (const field of schema.required || []) {
      if (params[field] === undefined || params[field] === null) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    if (errors.length > 0) {
      return {
        allowed: false,
        reason: "Missing required fields",
        violations: ["MISSING_REQUIRED"],
        errors,
        warnings,
        sanitizedParams: {},
        blocked_attacks,
      };
    }

    // Validate each parameter
    for (const [paramName, paramSchema] of Object.entries(schema.properties)) {
      const value = params[paramName];

      if (value === undefined) continue;

      const result = this.validateParameter(
        paramName,
        value,
        paramSchema,
        requestId
      );

      if (!result.valid) {
        errors.push(...result.errors);
        blocked_attacks.push(...result.blocked);
      } else {
        sanitizedParams[paramName] = result.sanitizedValue;
      }

      warnings.push(...result.warnings);
    }

    const allowed = errors.length === 0;

    if (requestId) {
      if (allowed) {
        this.logger(`[L5:${requestId}] Validation PASSED`, "info");
      } else {
        this.logger(`[L5:${requestId}] Validation FAILED: ${errors.join(", ")}`, "info");
      }
    }

    return {
      allowed,
      reason: allowed ? undefined : errors[0],
      violations: allowed ? [] : ["VALIDATION_FAILED"],
      errors,
      warnings,
      sanitizedParams,
      blocked_attacks,
    };
  }

  /**
   * Validate a single parameter
   */
  private validateParameter(
    name: string,
    value: any,
    schema: SchemaProperty,
    requestId: string
  ): { valid: boolean; errors: string[]; warnings: string[]; sanitizedValue: any; blocked: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];
    const blocked: string[] = [];
    let sanitizedValue = value;

    // Strict type checking
    const actualType = this.getStrictType(value);
    if (this.strictTypes && actualType !== schema.type) {
      errors.push(`Type mismatch for '${name}': expected ${schema.type}, got ${actualType}`);
      blocked.push("TYPE_COERCION");
      return { valid: false, errors, warnings, sanitizedValue, blocked };
    }

    // Type-specific validation
    switch (schema.type) {
      case "string":
        const strResult = this.validateString(name, value, schema, requestId);
        errors.push(...strResult.errors);
        warnings.push(...strResult.warnings);
        blocked.push(...strResult.blocked);
        if (strResult.valid) sanitizedValue = strResult.sanitizedValue;
        break;

      case "number":
        const numResult = this.validateNumber(name, value, schema);
        errors.push(...numResult.errors);
        blocked.push(...numResult.blocked);
        break;

      case "object":
        const objResult = this.validateObject(name, value, schema, requestId);
        errors.push(...objResult.errors);
        blocked.push(...objResult.blocked);
        break;
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      sanitizedValue,
      blocked,
    };
  }

  private getStrictType(value: any): string {
    if (value === null) return "null";
    if (Array.isArray(value)) return "array";
    return typeof value;
  }

  private validateString(
    name: string,
    value: string,
    schema: SchemaProperty,
    requestId: string
  ): { valid: boolean; errors: string[]; warnings: string[]; sanitizedValue: string; blocked: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];
    const blocked: string[] = [];
    let sanitizedValue = value;

    // Length checks
    if (schema.minLength && value.length < schema.minLength) {
      errors.push(`'${name}' is too short (min: ${schema.minLength})`);
    }
    if (schema.maxLength && value.length > schema.maxLength) {
      errors.push(`'${name}' is too long (max: ${schema.maxLength})`);
    }

    // Enum check
    if (schema.enum && !schema.enum.includes(value)) {
      errors.push(`'${name}' must be one of: ${schema.enum.join(", ")}`);
    }

    // Pattern check
    if (schema.pattern) {
      const regex = new RegExp(schema.pattern);
      if (!regex.test(value)) {
        errors.push(`'${name}' does not match required format`);
        blocked.push("FORMAT_VIOLATION");
      }
    }

    // Injection detection
    if (this.detectInjection) {
      const injectionCheck = this.detectInjectionPatterns(value);
      if (injectionCheck.detected) {
        errors.push(`Injection detected in '${name}': ${injectionCheck.types.join(", ")}`);
        blocked.push(...injectionCheck.types.map((t) => `${t}_INJECTION`));
        if (requestId) {
          this.logger(`[L5:${requestId}] BLOCKED: Injection in '${name}'`, "info");
        }
      }
    }

    // Sanitize
    if (this.sanitizeStrings && errors.length === 0) {
      sanitizedValue = this.sanitizeString(value);
    }

    return { valid: errors.length === 0, errors, warnings, sanitizedValue, blocked };
  }

  private validateNumber(
    name: string,
    value: number,
    schema: SchemaProperty
  ): { valid: boolean; errors: string[]; blocked: string[] } {
    const errors: string[] = [];
    const blocked: string[] = [];

    if (!Number.isFinite(value)) {
      errors.push(`'${name}' must be a finite number`);
      blocked.push("INVALID_NUMBER");
      return { valid: false, errors, blocked };
    }

    if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      errors.push(`'${name}' exceeds safe integer bounds`);
      blocked.push("INTEGER_OVERFLOW");
      return { valid: false, errors, blocked };
    }

    if (schema.min !== undefined && value < schema.min) {
      errors.push(`'${name}' must be at least ${schema.min}`);
      if (value < 0) blocked.push("NEGATIVE_VALUE");
    }

    if (schema.max !== undefined && value > schema.max) {
      errors.push(`'${name}' must be at most ${schema.max}`);
      blocked.push("BOUNDARY_VIOLATION");
    }

    return { valid: errors.length === 0, errors, blocked };
  }

  private validateObject(
    name: string,
    value: Record<string, any>,
    schema: SchemaProperty,
    requestId: string
  ): { valid: boolean; errors: string[]; blocked: string[] } {
    const errors: string[] = [];
    const blocked: string[] = [];

    // Prototype pollution check
    const pollutionCheck = this.checkPrototypePollution(value);
    if (!pollutionCheck.safe) {
      errors.push(...pollutionCheck.errors);
      blocked.push("PROTOTYPE_POLLUTION");
      return { valid: false, errors, blocked };
    }

    // Deep scan for injection
    if (this.detectInjection) {
      this.deepScanForInjection(name, value, errors, blocked, requestId);
    }

    return { valid: errors.length === 0, errors, blocked };
  }

  private checkPrototypePollution(obj: Record<string, any>): { safe: boolean; errors: string[] } {
    const errors: string[] = [];

    const check = (o: any, path: string): void => {
      if (typeof o !== "object" || o === null) return;

      for (const key of Object.getOwnPropertyNames(o)) {
        if (DANGEROUS_KEYS.has(key)) {
          errors.push(`Dangerous key '${key}' at ${path || "root"}`);
        }
        if (typeof o[key] === "object" && o[key] !== null) {
          check(o[key], path ? `${path}.${key}` : key);
        }
      }
    };

    check(obj, "");
    return { safe: errors.length === 0, errors };
  }

  private detectInjectionPatterns(value: string): { detected: boolean; types: string[] } {
    const types: string[] = [];

    for (const [injectionType, patterns] of Object.entries(INJECTION_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(value)) {
          types.push(injectionType);
          break;
        }
      }
    }

    return { detected: types.length > 0, types };
  }

  private deepScanForInjection(
    name: string,
    obj: Record<string, any>,
    errors: string[],
    blocked: string[],
    requestId: string
  ): void {
    const scan = (o: any, path: string): void => {
      if (typeof o === "string") {
        const check = this.detectInjectionPatterns(o);
        if (check.detected) {
          errors.push(`Injection in '${path}': ${check.types.join(", ")}`);
          blocked.push(...check.types.map((t) => `${t}_INJECTION`));
        }
      } else if (typeof o === "object" && o !== null) {
        for (const [key, value] of Object.entries(o)) {
          scan(value, `${path}.${key}`);
        }
      }
    };

    for (const [key, value] of Object.entries(obj)) {
      scan(value, `${name}.${key}`);
    }
  }

  private sanitizeString(value: string): string {
    return value
      .replace(/[<>]/g, "")
      .replace(/['";]/g, "")
      .trim();
  }
}
