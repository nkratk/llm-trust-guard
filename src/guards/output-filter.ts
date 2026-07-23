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
  /** Optional secondary check a regex match must also pass (e.g. Luhn checksum). */
  validate?: (matchedText: string) => boolean;
}

/**
 * Standard Luhn checksum, used to gate the credit_card pattern. A loosened
 * digit-shape regex alone false-positives on invoice/order/tracking numbers
 * (and, via buildScanVariants' reversed-string scan, on coincidental
 * BIN-prefix-shaped digit runs) — Luhn cuts that surface the same way real
 * credit-card detectors do, without needing a stricter/narrower regex.
 */
function isValidLuhn(matchedText: string): boolean {
  const digits = matchedText.replace(/\D/g, "");
  if (digits.length < 12 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
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
      // Bounded local-part/label/TLD lengths and a label-grouped domain —
      // same ReDoS fix as ExternalDataGuard's matching pattern (10s+ on an
      // 80KB string with no valid email in it).
      pattern: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}\b/g,
      maskAs: "[EMAIL]",
    },
    {
      name: "phone_us",
      // NANP area/exchange codes never start with 0/1, used here (rather than a
      // paired-parens group) to catch unformatted/dash/dot numbers too — a
      // symmetric \(?...\)? group can't match "(415) 555-2671" because \b can't
      // land between whitespace and "(" (two non-word chars), so the match
      // start shifts past the paren entirely and the alternative is unreachable.
      pattern: /\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b/g,
      maskAs: "[PHONE]",
    },
    {
      name: "ssn",
      pattern: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g,
      maskAs: "[SSN]",
    },
    {
      name: "credit_card",
      // Visa/Mastercard/Discover BIN-prefixed, 12-19 digits total, with
      // separators anywhere — not just rigid 4-4-4-4 grouping (real numbers
      // get grouped inconsistently, e.g. "5555-555-555-5544-4"). BIN prefix
      // + Luhn (validate, below) together keep this from matching arbitrary
      // invoice/order/tracking numbers of similar shape.
      // BIN prefix covers Visa (4xxx), Mastercard legacy (5[1-5]xx) and
      // current 2-series (2221-2720, added after adversarial review found
      // real currently-issued Mastercard PANs like 2223... were invisible),
      // and Discover (6011, 65xx, 644-649).
      pattern: /\b(?:4\d{3}|5[1-5]\d{2}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)|6011|65\d{2}|64[4-9]\d)(?:[-.\s]?\d){8,15}\b/g,
      maskAs: "[CREDIT_CARD]",
      validate: isValidLuhn,
    },
    {
      name: "credit_card_amex",
      pattern: /\b3[47]\d{2}[-.\s]?\d{6}[-.\s]?\d{5}\b/g,
      maskAs: "[CREDIT_CARD]",
    },
    {
      name: "ip_address",
      // Bound each octet 0-255 so obviously-invalid shapes (e.g. version
      // strings with an octet >255) are excluded. For the remaining
      // ambiguous case (every octet valid, e.g. "10.4.32.3" — structurally
      // identical to a real IPv4 address by shape alone) a negative
      // lookbehind suppresses the match when a version-indicating keyword
      // (version/release/upgrade/update) appears shortly before it — this
      // doesn't fully disambiguate (an out-of-band "10.4.32.3" with no such
      // keyword nearby is still flagged, correctly erring toward recall),
      // but closes the specific reported case. A bare "v" prefix (e.g.
      // "v10.4.32.3") needs no special handling — the leading \b already
      // excludes it, since a digit immediately preceded by a letter is
      // word-to-word (no boundary) either way.
      pattern: /\b(?<!\b(?:version|release|upgrade|update)\b[^\d\n]{0,15})(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/gi,
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
      // Optional "is" before the separator so combined phrasing ("password
      // is: X") matches too — previously "is" and ":"/"=" were mutually
      // exclusive alternatives that couldn't compose.
      pattern: /(?:password|passwd|pwd)\s*(?:is\s*)?(?:[=:]|is)\s*["']?[^\s"']{6,}["']?/gi,
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
    {
      name: "github_fine_grained_pat",
      pattern: /github_pat_[A-Za-z0-9_]{30,}/g,
      severity: "critical",
    },
    {
      name: "slack_token",
      pattern: /xox[bporas]-[A-Za-z0-9\-]{10,}/g,
      severity: "critical",
    },
    {
      name: "stripe_key",
      pattern: /sk_(?:live|test)_[a-zA-Z0-9]{24,}/g,
      severity: "critical",
    },
    {
      name: "aws_access_key",
      pattern: /\bAKIA[0-9A-Z]{16}\b/g,
      severity: "critical",
    },
    {
      name: "anthropic_key",
      pattern: /sk-ant-[a-zA-Z0-9\-]{20,}/g,
      severity: "critical",
    },
    {
      name: "basic_auth",
      pattern: /Authorization:\s*Basic\s+[A-Za-z0-9+\/=]{8,}/gi,
      severity: "critical",
    },
    {
      name: "xml_password",
      pattern: /<(?:password|secret|token|apikey)>[^<]{3,}<\/(?:password|secret|token|apikey)>/gi,
      severity: "critical",
    },
    {
      name: "url_password",
      pattern: /:\/\/[^:]+:[^@\s]{3,}@/g,
      severity: "critical",
    },
    {
      name: "connection_string_password",
      pattern: /(?:Password|Pwd)\s*=\s*[^\s;]{3,}/gi,
      severity: "critical",
    },
    // Fraudulent output markers — fake judge/evaluator approvals embedded in LLM output
    {
      name: "judge_stealth_marker",
      pattern: /\*\*\[(?:SYSTEM-(?:OK|PASS|APPROVED|GOOD)|APPROVED|ACCEPTED|VALIDATED)\]\*\*|\[SYSTEM-OK\]/gi,
      severity: "high",
    },
    {
      name: "echogram_marker",
      pattern: /<(?:malicious|evil|harmful|bad|toxic|unsafe)\s*>/gi,
      severity: "high",
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

  private buildScanVariants(text: string): string[] {
    const variants = new Set<string>();
    // ZWSP / bidi strip
    const stripped = text.replace(/[​-‏‪- ⁠᠎﻿­]/g, "");
    if (stripped !== text) variants.add(stripped);
    // URL-decode
    if (text.includes("%")) {
      try {
        const dec = decodeURIComponent(text.replace(/\+/g, " "));
        if (dec !== text) variants.add(dec);
      } catch { /* ignore */ }
    }
    // Hex-decode (pure hex, even length, ≥20 chars)
    if (/^[0-9a-f]+$/i.test(text) && text.length % 2 === 0 && text.length >= 20) {
      try {
        const hex = Buffer.from(text, "hex").toString("utf8");
        if (/[\x20-\x7E]{4,}/.test(hex)) variants.add(hex);
      } catch { /* ignore */ }
    }
    // Base64-decode (≥16 data chars)
    if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(text)) {
      try {
        const b64 = Buffer.from(text, "base64").toString("utf8");
        if (/[\x20-\x7E]{4,}/.test(b64)) variants.add(b64);
      } catch { /* ignore */ }
    }
    // Reverse
    const rev = [...text].reverse().join("");
    if (rev !== text) variants.add(rev);
    // Cyrillic homoglyph normalisation
    const cyrMap: Record<string, string> = {
      "а": "a", "А": "A", "е": "e", "Е": "E",
      "і": "i", "І": "I", "о": "o", "О": "O",
      "р": "p", "Р": "P", "с": "c", "С": "C",
      "В": "B", "Т": "T", "Х": "X", "К": "K",
      "М": "M", "Н": "H",
    };
    const normalized = text.replace(/[Ѐ-ӿ]/gu, (ch) => cyrMap[ch] ?? ch);
    if (normalized !== text) variants.add(normalized);
    return Array.from(variants);
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

    // Build obfuscation-bypass scan variants (ZWSP-stripped, URL/hex/base64 decoded, reversed, Cyrillic normalised)
    const scanTargets = [outputStr, ...this.buildScanVariants(outputStr)];

    // Detect PII (across all scan variants)
    if (this.config.detectPII) {
      const detectedPII = new Set<string>();
      for (const target of scanTargets) {
        for (const pattern of this.config.piiPatterns!) {
          if (detectedPII.has(pattern.name)) continue;
          let matches: string[] | null = target.match(pattern.pattern);
          if (matches && pattern.validate) {
            matches = matches.filter((m) => pattern.validate!(m));
          }
          if (matches && matches.length > 0) {
            detectedPII.add(pattern.name);
            piiDetections.push({
              type: pattern.name,
              count: matches.length,
              masked: true,
              locations: this.findLocations(target, pattern.pattern, pattern.validate),
            });
            violations.push(`PII_DETECTED_${pattern.name.toUpperCase()}`);
          }
        }
      }
    }

    // Detect secrets (across all scan variants)
    if (this.config.detectSecrets) {
      const detectedSecrets = new Set<string>();
      for (const target of scanTargets) {
        for (const pattern of this.config.secretPatterns!) {
          if (detectedSecrets.has(pattern.name)) continue;
          const matches = target.match(pattern.pattern);
          if (matches && matches.length > 0) {
            detectedSecrets.add(pattern.name);
            secretDetections.push({
              type: pattern.name,
              severity: pattern.severity,
              blocked: pattern.severity === "critical",
              location: "response",
            });
            violations.push(`SECRET_DETECTED_${pattern.name.toUpperCase()}`);
            if (pattern.severity === "critical") {
              blockingReason = `Critical secret detected: ${pattern.name}`;
            }
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
        const mask = pattern.maskAs || this.generateMask(8);
        filteredOutput = filteredOutput.replace(pattern.pattern, (m: string) =>
          pattern.validate && !pattern.validate(m) ? m : mask
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
      let matches: string[] | null = result.match(pattern.pattern);
      if (matches && pattern.validate) {
        matches = matches.filter((m) => pattern.validate!(m));
      }
      if (matches && matches.length > 0) {
        const mask = pattern.maskAs || this.generateMask(8);
        result = result.replace(pattern.pattern, (m: string) =>
          pattern.validate && !pattern.validate(m) ? m : mask
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

  private findLocations(text: string, pattern: RegExp, validate?: (m: string) => boolean): string[] {
    const locations: string[] = [];
    let match;
    const regex = new RegExp(pattern.source, pattern.flags);
    while ((match = regex.exec(text)) !== null) {
      if (!validate || validate(match[0])) locations.push(`index:${match.index}`);
      if (!pattern.flags.includes("g")) break;
    }
    return locations;
  }
}
