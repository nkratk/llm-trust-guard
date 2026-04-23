/**
 * ExternalDataGuard
 *
 * Validates ALL external data before it enters LLM context.
 * Covers API responses, tool outputs, RAG results, file contents,
 * webhook payloads, and any other untrusted data source.
 *
 * This is an ARCHITECTURAL guard — it enforces boundaries on what
 * external data can reach the LLM, regardless of whether the LLM
 * itself has been compromised. Defense-in-depth at the data boundary.
 *
 * Threat model:
 * - Indirect prompt injection via API responses or RAG documents
 * - Context stuffing via oversized payloads
 * - Data exfiltration via embedded URLs in external content
 * - Secret/credential leakage through external data
 * - Poisoned data from compromised or unknown sources
 */

import { GuardLogger } from "../types";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface ExternalDataGuardConfig {
  /** Allowlist of trusted data sources (exact match or prefix) */
  allowedSources?: string[];
  /** Blocklist of known-bad data sources */
  blockedSources?: string[];
  /** Max characters of external content allowed (default: 50000) */
  maxContentLength?: number;
  /** Scan content for prompt injection patterns (default: true) */
  scanForInjection?: boolean;
  /** Detect leaked secrets, API keys, credentials (default: true) */
  scanForSecrets?: boolean;
  /** Detect data exfiltration URLs in content (default: true) */
  scanForExfiltration?: boolean;
  /** Require provenance metadata for all data (default: false) */
  requireProvenance?: boolean;
  /** Optional logger */
  logger?: GuardLogger;
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

export interface ExternalDataGuardResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  /** Identified data source */
  source?: string;
  /** Length of the content inspected */
  contentLength: number;
  /** Specific threat categories detected */
  threats: string[];
}

// ---------------------------------------------------------------------------
// Provenance metadata callers attach to external data
// ---------------------------------------------------------------------------

export interface DataProvenance {
  /** Where the data came from (URL, service name, file path, etc.) */
  source: string;
  /** Content type hint (e.g. "application/json", "text/html") */
  contentType?: string;
  /** When the data was retrieved (ISO string or epoch ms) */
  retrievedAt?: string | number;
  /** Max acceptable age in seconds before data is considered stale */
  maxAgeSec?: number;
}

// ---------------------------------------------------------------------------
// Detection patterns
// ---------------------------------------------------------------------------

const INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "system_tag", pattern: /<\/?system>|<\/?admin>|\[system\]|\[admin\]/i },
  { name: "ignore_instructions", pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|prompts?)/i },
  { name: "new_instructions", pattern: /new\s+instructions?\s*:/i },
  { name: "role_override", pattern: /you\s+are\s+now|from\s+now\s+on|act\s+as\s+(?:a|an)\s/i },
  { name: "hidden_instruction", pattern: /HIDDEN_PROMPT|HIDDEN_INSTRUCTION|INVISIBLE_TEXT/i },
  { name: "jailbreak", pattern: /jailbreak|DAN\s*mode|developer\s+mode|unrestricted\s+mode/i },
  { name: "bypass_safety", pattern: /bypass\s+(?:security|safety|filters|restrictions|guardrails)/i },
  { name: "instruction_delimiter", pattern: /={3,}\s*(?:SYSTEM|INSTRUCTIONS?|BEGIN)\s*={3,}/i },
  { name: "prompt_leak_request", pattern: /(?:print|show|reveal|output)\s+(?:your|the|system)\s+(?:prompt|instructions)/i },
  { name: "base64_injection", pattern: /(?:decode|eval|execute)\s+(?:the\s+)?(?:following\s+)?base64/i },
];

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "aws_key", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "generic_api_key", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}/i },
  { name: "bearer_token", pattern: /Bearer\s+[A-Za-z0-9\-._~+\/]{20,}/ },
  { name: "private_key", pattern: /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----/ },
  { name: "github_token", pattern: /gh[ps]_[A-Za-z0-9_]{36,}/ },
  { name: "jwt", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: "password_field", pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{8,}/i },
  { name: "connection_string", pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s]{10,}/i },
];

const EXFILTRATION_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // Named-key exfil: markdown image URL whose query param key hints at data smuggling
  { name: "markdown_image_exfil", pattern: /!\[.*?\]\(https?:\/\/[^)]*\?[^)]*(?:token|key|secret|data|q|payload|p|prompt|ctx|context|info|msg|body|session|conv)=/i },
  // "Reprompt"-style exfil (CVE-2026-24307): markdown image with any long query-param value (≥30 chars).
  // Legitimate cache-busters are typically short version strings / short hashes; exfiltrated content runs longer.
  { name: "markdown_image_exfil_long_value", pattern: /!\[.*?\]\(https?:\/\/[^)]+\?[^)]*=[^)&]{30,}/ },
  { name: "tracking_pixel", pattern: /<img[^>]+src=["']https?:\/\/[^"']*\?[^"']*["'][^>]*(?:width|height)\s*=\s*["']?[01]px/i },
  { name: "encoded_url_exfil", pattern: /https?:\/\/[^\s]*(?:callback|webhook|exfil|collect)[^\s]*\?[^\s]*(?:data|payload|d)=/i },
  { name: "data_send_instruction", pattern: /send\s+(?:this|the|all)\s+(?:data|information|content|context)\s+to/i },
  { name: "fetch_url", pattern: /(?:fetch|request|call|curl|wget)\s+https?:\/\//i },
];

const PII_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: "credit_card", pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/ },
  { name: "email_address", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/i },
];

// ---------------------------------------------------------------------------
// Guard implementation
// ---------------------------------------------------------------------------

export class ExternalDataGuard {
  private config: Required<Pick<ExternalDataGuardConfig,
    "maxContentLength" | "scanForInjection" | "scanForSecrets" |
    "scanForExfiltration" | "requireProvenance"
  >> & ExternalDataGuardConfig;

  constructor(config: ExternalDataGuardConfig = {}) {
    this.config = {
      ...config,
      maxContentLength: config.maxContentLength ?? 50_000,
      scanForInjection: config.scanForInjection ?? true,
      scanForSecrets: config.scanForSecrets ?? true,
      scanForExfiltration: config.scanForExfiltration ?? true,
      requireProvenance: config.requireProvenance ?? false,
    };
  }

  /**
   * Validate external data before it enters LLM context.
   *
   * @param content  - The raw external content (string or object)
   * @param provenance - Optional metadata about the data source
   */
  validate(
    content: string | Record<string, unknown>,
    provenance?: DataProvenance
  ): ExternalDataGuardResult {
    const violations: string[] = [];
    const threats: string[] = [];
    const contentStr = typeof content === "string" ? content : this.safeStringify(content);
    const source = provenance?.source;

    // 1. Provenance requirement
    if (this.config.requireProvenance && !provenance?.source) {
      violations.push("MISSING_PROVENANCE");
      threats.push("no_source_metadata");
    }

    // 2. Source verification
    if (source) {
      if (this.isBlockedSource(source)) {
        violations.push("BLOCKED_SOURCE");
        threats.push("blocked_data_source");
      }
      if (this.config.allowedSources && this.config.allowedSources.length > 0) {
        if (!this.isAllowedSource(source)) {
          violations.push("UNAPPROVED_SOURCE");
          threats.push("source_not_in_allowlist");
        }
      }
    }

    // 3. Size limits — prevent context stuffing
    if (contentStr.length > this.config.maxContentLength) {
      violations.push("CONTENT_TOO_LARGE");
      threats.push("context_stuffing");
    }

    // 4. Metadata validation — freshness check
    if (provenance?.retrievedAt && provenance?.maxAgeSec) {
      const retrievedMs = typeof provenance.retrievedAt === "string"
        ? new Date(provenance.retrievedAt).getTime()
        : provenance.retrievedAt;
      const ageMs = Date.now() - retrievedMs;
      if (ageMs > provenance.maxAgeSec * 1000) {
        violations.push("STALE_DATA");
        threats.push("data_expired");
      }
    }

    // 5. Content injection detection
    if (this.config.scanForInjection) {
      for (const { name, pattern } of INJECTION_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(contentStr)) {
          violations.push("INJECTION_DETECTED");
          threats.push(`injection:${name}`);
        }
      }
    }

    // 6. Secret / credential detection
    if (this.config.scanForSecrets) {
      for (const { name, pattern } of SECRET_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(contentStr)) {
          violations.push("SECRET_DETECTED");
          threats.push(`secret:${name}`);
        }
      }
      // Also flag PII
      for (const { name, pattern } of PII_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(contentStr)) {
          violations.push("PII_DETECTED");
          threats.push(`pii:${name}`);
        }
      }
    }

    // 7. Data exfiltration URL detection
    if (this.config.scanForExfiltration) {
      for (const { name, pattern } of EXFILTRATION_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(contentStr)) {
          violations.push("EXFILTRATION_ATTEMPT");
          threats.push(`exfil:${name}`);
        }
      }
    }

    // Deduplicate
    const uniqueViolations = [...new Set(violations)];
    const uniqueThreats = [...new Set(threats)];
    const allowed = uniqueViolations.length === 0;

    const result: ExternalDataGuardResult = {
      allowed,
      reason: allowed ? undefined : `External data rejected: ${uniqueViolations.join(", ")}`,
      violations: uniqueViolations,
      source,
      contentLength: contentStr.length,
      threats: uniqueThreats,
    };

    if (!allowed) {
      this.log(`Blocked external data: ${uniqueViolations.join(", ")}`, "warn");
    }

    return result;
  }

  /**
   * Validate a batch of external data items (e.g. multiple RAG chunks).
   * Returns individual results and a combined summary.
   */
  validateBatch(
    items: Array<{ content: string | Record<string, unknown>; provenance?: DataProvenance }>
  ): { results: ExternalDataGuardResult[]; allAllowed: boolean; totalThreats: number } {
    const results = items.map(item => this.validate(item.content, item.provenance));
    return {
      results,
      allAllowed: results.every(r => r.allowed),
      totalThreats: results.reduce((sum, r) => sum + r.threats.length, 0),
    };
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private isBlockedSource(source: string): boolean {
    if (!this.config.blockedSources) return false;
    const lower = source.toLowerCase();
    return this.config.blockedSources.some(b => lower.includes(b.toLowerCase()));
  }

  private isAllowedSource(source: string): boolean {
    if (!this.config.allowedSources) return true;
    const lower = source.toLowerCase();
    return this.config.allowedSources.some(a => lower.startsWith(a.toLowerCase()));
  }

  private log(message: string, level: "info" | "warn" | "error"): void {
    this.config.logger?.(message, level);
  }

  private safeStringify(value: unknown): string {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
}
