/**
 * L7: Output Filter
 *
 * Prevents sensitive data leakage by:
 * - Detecting and masking PII (emails, phone numbers, SSN, credit cards)
 * - Filtering sensitive fields from responses
 * - Blocking responses that contain secrets or credentials
 * - Applying role-based output filtering
 */

import { GuardLogger } from "../types";

export interface OutputFilterConfig {
  // PII detection
  detectPII?: boolean;
  piiPatterns?: PIIPattern[];
  // Field filtering
  sensitiveFields?: string[];
  // Secret detection
  detectSecrets?: boolean;
  secretPatterns?: SecretPattern[];
  // Role-based filtering
  roleFilters?: Record<string, string[]>; // role -> fields to hide
  // Masking options
  maskingChar?: string;
  logger?: GuardLogger;
  preserveLength?: boolean;
}

export interface PIIPattern {
  name: string;
  pattern: RegExp;
  maskAs?: string; // e.g., "[EMAIL]", "[SSN]"
}

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: "low" | "medium" | "high" | "critical";
}

export interface OutputFilterResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  pii_detected: PIIDetection[];
  secrets_detected: SecretDetection[];
  filtered_fields: string[];
  original_response?: any;
  filtered_response?: any;
  blocking_reason?: string;
}

export interface PIIDetection {
  type: string;
  count: number;
  masked: boolean;
  locations: string[];
}

export interface SecretDetection {
  type: string;
  severity: string;
  blocked: boolean;
  location: string;
}

export class OutputFilter {
  private config: OutputFilterConfig;
  private logger: GuardLogger;
  private defaultPIIPatterns: PIIPattern[] = [
    {
      name: "email",
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      maskAs: "[EMAIL]",
    },
    {
      name: "phone_us",
      pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
      maskAs: "[PHONE]",
    },
    {
      name: "ssn",
      pattern: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g,
      maskAs: "[SSN]",
    },
    {
      name: "credit_card",
      pattern: /\b(?:\d{4}[-.\s]?){3}\d{4}\b/g,
      maskAs: "[CREDIT_CARD]",
    },
    {
      name: "credit_card_amex",
      pattern: /\b3[47]\d{2}[-.\s]?\d{6}[-.\s]?\d{5}\b/g,
      maskAs: "[CREDIT_CARD]",
    },
    {
      name: "ip_address",
      pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
      maskAs: "[IP_ADDRESS]",
    },
    {
      name: "date_of_birth",
      pattern: /\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b/g,
      maskAs: "[DOB]",
    },
    {
      name: "passport",
      pattern: /\b[A-Z]{1,2}\d{6,9}\b/g,
      maskAs: "[PASSPORT]",
    },
    {
      name: "bank_account",
      pattern: /\b(?:account|acct|routing|iban)[#:\s]*\d{8,17}\b/gi,
      maskAs: "[BANK_ACCOUNT]",
    },
  ];

  private defaultSecretPatterns: SecretPattern[] = [
    {
      name: "api_key",
      pattern: /(?:api[_\-\s]?key|apikey)(?:\s+is)?\s*[=:\s]\s*["']?[A-Za-z0-9_\-]{16,}["']?/gi,
      severity: "critical",
    },
    {
      name: "api_key_prefix",
      pattern: /\b(?:sk|pk|rk|ak)[_-][a-zA-Z0-9]{8,}\b/g,
      severity: "critical",
    },
    {
      name: "aws_secret",
      pattern: /(?:aws[_-]?secret|secret[_-]?key)[=:\s]["']?[A-Za-z0-9\/+=]{40}["']?/gi,
      severity: "critical",
    },
    {
      name: "password",
      pattern: /(?:password|passwd|pwd)\s*(?:[=:]|is)\s*["']?[^\s"']{6,}["']?/gi,
      severity: "critical",
    },
    {
      name: "private_key",
      pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
      severity: "critical",
    },
    {
      name: "jwt_token",
      pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
      severity: "high",
    },
    {
      name: "bearer_token",
      pattern: /Bearer\s+[A-Za-z0-9_\-\.]+/gi,
      severity: "high",
    },
    {
      name: "database_url",
      pattern: /(?:mongodb|mysql|postgres|redis):\/\/[^\s]+/gi,
      severity: "critical",
    },
    {
      name: "github_token",
      pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
      severity: "critical",
    },
  ];

  private defaultSensitiveFields: string[] = [
    "password",
    "secret",
    "token",
    "api_key",
    "apiKey",
    "private_key",
    "privateKey",
    "ssn",
    "social_security",
    "credit_card",
    "creditCard",
    "card_number",
    "cardNumber",
    "cvv",
    "pin",
    "account_number",
    "accountNumber",
    "routing_number",
    "routingNumber",
  ];

  constructor(config: OutputFilterConfig = {}) {
    this.config = {
      detectPII: config.detectPII ?? true,
      piiPatterns: config.piiPatterns ?? this.defaultPIIPatterns,
      sensitiveFields: config.sensitiveFields ?? this.defaultSensitiveFields,
      detectSecrets: config.detectSecrets ?? true,
      secretPatterns: config.secretPatterns ?? this.defaultSecretPatterns,
      roleFilters: config.roleFilters ?? {},
      maskingChar: config.maskingChar ?? "*",
      preserveLength: config.preserveLength ?? false,
    };
    this.logger = config.logger || (() => {});
  }

  /**
   * Filter output and detect sensitive data
   */
  filter(
    output: any,
    role?: string,
    requestId: string = ""
  ): OutputFilterResult {
    const violations: string[] = [];
    const piiDetections: PIIDetection[] = [];
    const secretDetections: SecretDetection[] = [];
    const filteredFields: string[] = [];
    let blockingReason: string | undefined;

    // Convert to string for pattern matching
    let outputStr: string;
    if (typeof output === "string") {
      outputStr = output;
    } else {
      try {
        outputStr = JSON.stringify(output);
      } catch {
        outputStr = String(output);
      }
    }

    // Detect PII
    if (this.config.detectPII) {
      for (const pattern of this.config.piiPatterns!) {
        const matches = outputStr.match(pattern.pattern);
        if (matches && matches.length > 0) {
          piiDetections.push({
            type: pattern.name,
            count: matches.length,
            masked: true,
            locations: this.findLocations(outputStr, pattern.pattern),
          });
          violations.push(`PII_DETECTED_${pattern.name.toUpperCase()}`);
        }
      }
    }

    // Detect secrets
    if (this.config.detectSecrets) {
      for (const pattern of this.config.secretPatterns!) {
        const matches = outputStr.match(pattern.pattern);
        if (matches && matches.length > 0) {
          secretDetections.push({
            type: pattern.name,
            severity: pattern.severity,
            blocked: pattern.severity === "critical",
            location: "response",
          });
          violations.push(`SECRET_DETECTED_${pattern.name.toUpperCase()}`);

          // Block critical secrets
          if (pattern.severity === "critical") {
            blockingReason = `Critical secret detected: ${pattern.name}`;
          }
        }
      }
    }

    // Filter output (deep clone objects, handle circular references)
    let filteredOutput: any;
    if (typeof output === "string") {
      filteredOutput = output;
    } else {
      try {
        filteredOutput = JSON.parse(JSON.stringify(output));
      } catch {
        // Circular reference or non-serializable - filter as string representation
        filteredOutput = String(output);
      }
    }

    // Mask PII in output
    if (this.config.detectPII && typeof filteredOutput === "string") {
      for (const pattern of this.config.piiPatterns!) {
        filteredOutput = filteredOutput.replace(
          pattern.pattern,
          pattern.maskAs || this.generateMask(8)
        );
      }
    } else if (typeof filteredOutput === "object" && filteredOutput !== null) {
      filteredOutput = this.filterObject(
        filteredOutput,
        role,
        filteredFields,
        piiDetections
      );
    }

    // Mask secrets in output
    if (this.config.detectSecrets && typeof filteredOutput === "string") {
      for (const pattern of this.config.secretPatterns!) {
        const label = `[${pattern.name.toUpperCase()}]`;
        filteredOutput = filteredOutput.replace(pattern.pattern, label);
      }
    }

    // Determine if blocked
    const hasBlockingSecrets = secretDetections.some((s) => s.blocked);
    const allowed = !hasBlockingSecrets;

    if (!allowed) {
      this.logger(
        `[OutputFilter:${requestId}] BLOCKED: ${blockingReason}`, "info"
      );
    }

    return {
      allowed,
      reason: allowed ? undefined : blockingReason,
      violations,
      pii_detected: piiDetections,
      secrets_detected: secretDetections,
      filtered_fields: filteredFields,
      original_response: output,
      filtered_response: filteredOutput,
      blocking_reason: blockingReason,
    };
  }

  /**
   * Quick check if output contains any sensitive data
   */
  containsSensitiveData(output: any): boolean {
    const result = this.filter(output);
    return (
      result.pii_detected.length > 0 ||
      result.secrets_detected.length > 0 ||
      result.filtered_fields.length > 0
    );
  }

  /**
   * Mask a specific value
   */
  mask(value: string, type?: string): string {
    const piiPattern = this.config.piiPatterns?.find((p) => p.name === type);
    if (piiPattern?.maskAs) {
      return piiPattern.maskAs;
    }
    return this.generateMask(value.length);
  }

  private filterObject(
    obj: any,
    role: string | undefined,
    filteredFields: string[],
    piiDetections: PIIDetection[]
  ): any {
    if (Array.isArray(obj)) {
      return obj.map((item) =>
        this.filterObject(item, role, filteredFields, piiDetections)
      );
    }

    if (typeof obj !== "object" || obj === null) {
      // Check for PII in string values
      if (typeof obj === "string") {
        return this.maskPIIInString(obj, piiDetections);
      }
      return obj;
    }

    const result: Record<string, any> = {};
    const roleSpecificFilter = role ? this.config.roleFilters?.[role] : undefined;

    for (const [key, value] of Object.entries(obj)) {
      // Check if field should be filtered
      const lowerKey = key.toLowerCase();
      const isSensitive = this.config.sensitiveFields?.some(
        (f) => lowerKey.includes(f.toLowerCase())
      );
      const isRoleFiltered = roleSpecificFilter?.includes(key);

      if (isSensitive || isRoleFiltered) {
        filteredFields.push(key);
        result[key] = "[FILTERED]";
        continue;
      }

      // Recursively filter nested objects
      if (typeof value === "object" && value !== null) {
        result[key] = this.filterObject(
          value,
          role,
          filteredFields,
          piiDetections
        );
      } else if (typeof value === "string") {
        result[key] = this.maskPIIInString(value, piiDetections);
      } else {
        result[key] = value;
      }
    }

    return result;
  }

  private maskPIIInString(
    str: string,
    piiDetections: PIIDetection[]
  ): string {
    let result = str;
    for (const pattern of this.config.piiPatterns!) {
      const matches = result.match(pattern.pattern);
      if (matches && matches.length > 0) {
        result = result.replace(
          pattern.pattern,
          pattern.maskAs || this.generateMask(8)
        );
      }
    }
    return result;
  }

  private generateMask(length: number): string {
    if (this.config.preserveLength) {
      return this.config.maskingChar!.repeat(length);
    }
    return this.config.maskingChar!.repeat(8);
  }

  private findLocations(text: string, pattern: RegExp): string[] {
    const locations: string[] = [];
    let match;
    const regex = new RegExp(pattern.source, pattern.flags);
    while ((match = regex.exec(text)) !== null) {
      locations.push(`index:${match.index}`);
      if (!pattern.flags.includes("g")) break;
    }
    return locations;
  }
}
