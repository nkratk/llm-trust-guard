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
  // Bounded — unbounded form was quadratic-time ReDoS (12s at 128KB) on
  // content with many "![" substrings and no closing ")", same shape as
  // rag-guard.ts's markdown_img_alt_injection.
  { name: "markdown_injection", pattern: /!\[.{0,2000}\]\(https?:\/\/[^)]{0,1000}\?.{0,500}(?:token|key|secret|auth)/i, severity: "high" },
  // Exfiltration via URL in tool results instructing the LLM
  { name: "url_exfiltration", pattern: /(?:fetch|request|call|post|get|send|forward|transmit|relay)\s+(?:to|from)?\s*https?:\/\//i, severity: "critical" },
  { name: "url_data_leak", pattern: /https?:\/\/[^\s]+\?.*(?:data|prompt|conversation|history|context|message|response)=/i, severity: "critical" },
  // Credential solicitation — tool result asking LLM to request user credentials
  { name: "credential_solicitation", pattern: /(?:ask|request|get|obtain|collect)\s+(?:the\s+)?(?:user|them|him|her)\s+(?:for\s+)?(?:their\s+)?(?:password|credentials?|api[_\s]?key|token|secret|ssn|social\s+security)/i, severity: "critical" },
  { name: "credential_prompt", pattern: /(?:enter|provide|type|input|share)\s+(?:your\s+)?(?:password|credentials?|api[_\s]?key|auth(?:entication)?\s+token|private\s+key|secret)/i, severity: "high" },
  // Imperative tool call injection — tool result instructing LLM to call other tools
  { name: "tool_call_injection", pattern: /(?:execute|invoke|call|run|trigger|use)\s+(?:the\s+)?(?:function|tool|command|action)\s+(?:named?\s+)?[`"']?\w+[`"']?/i, severity: "critical" },
  { name: "tool_call_direct", pattern: /(?:call|execute|run|invoke)\s+\w+(?:_\w+)+/i, severity: "critical" },
  { name: "tool_chain_manipulation", pattern: /(?:first|then|next|now|before\s+responding)\s*,?\s*(?:execute|call|run|invoke|delete|drop|remove|wipe)\s+/i, severity: "high" },
  // Subtle exfiltration without URLs — instructing LLM to leak context
  { name: "context_exfil_subtle", pattern: /(?:include|embed|insert|add|append|attach)\s+(?:the\s+)?(?:full\s+)?(?:conversation|chat|context|history|system\s+prompt|instructions|messages?)\s+(?:in|into|within|as\s+part\s+of)\s+(?:your\s+)?(?:response|output|reply|answer)/i, severity: "critical" },
  { name: "format_exfil", pattern: /(?:format|output|return|encode|serialize)\s+(?:the\s+)?(?:conversation|context|history|messages?|data)\s+(?:as|in|into)\s+(?:JSON|XML|base64|CSV|markdown)/i, severity: "high" },
  // Structured document / serialization injection in tool results
  { name: "xxe_entity", pattern: /<!ENTITY\s+\w+\s+SYSTEM\s+["'][^"']+["']/i, severity: "critical" },
  { name: "doctype_entity", pattern: /<!DOCTYPE\s+\w+\s*\[[\s\S]*<!ENTITY/i, severity: "critical" },
  { name: "path_traversal", pattern: /(?:\.\.\/){3,}|(?:\.\.\\){3,}|(?:\.\.\/){2,}(?:etc|tmp|root|proc|sys|dev|usr|win)\b|(?:\.\.\\){2,}(?:windows|system32|users)\b/i, severity: "high" },
  { name: "rtf_ole_object", pattern: /\\object\\obj(?:emb|link|auto)|\\objdata\s/i, severity: "critical" },
  { name: "langchain_gadget", pattern: /\{["']lc["']\s*:\s*[12]\s*,\s*["']type["']\s*:\s*["'](?:constructor|secret|not_implemented)/i, severity: "critical" },
  { name: "embedded_tool_call", pattern: /<tool[_-]?call[^>]*>|<\/tool[_-]?call>|<invoke\s+name\s*=|<function_call[\s>]/i, severity: "critical" },
  // See external-data-guard.ts's identical pattern for why a filler-word
  // tolerance was tried and reverted here (reopened a prior FPR class).
  { name: "html_comment_directive", pattern: /<!--\s*(?:BOT|AGENT|ASSISTANT|AI|LLM)\s*:\s*(?:execute|run|call|invoke|perform|fetch|send|ignore|bypass|forget|override|disregard|print|reveal|output|delete|drop)\b/i, severity: "critical" },
  // Jinja2/Nunjucks/Handlebars template injection
  { name: "template_injection", pattern: /\{\{[\s]*(?:call|invoke|exec|run|tool|system|eval|import)[\s]*[:( ]/i, severity: "critical" },
  // XSS embedded in tool result
  { name: "xss_script_tag", pattern: /<script[^>]*>/i, severity: "critical" },
  { name: "xss_event_handler", pattern: /\bon(?:error|load|click|mouseover|focus|blur|input|change|submit)\s*=\s*["']?[^"'>\s]/i, severity: "high" },
  // SQL injection echoed from a tool (e.g. database tool returning attacker-controlled data)
  { name: "sql_injection_echo", pattern: /'\s*[)]*\s*(?:OR|AND)\s+\d+\s*=\s*\d+|UNION\s+(?:ALL\s+)?SELECT\b/i, severity: "high" },
  // @AI-agent hijack via issue/PR/comment tool result
  { name: "ai_agent_hijack", pattern: /@(?:copilot|claude|assistant|gpt|gemini|bot|agent)\s+(?:please\s+)?(?:run|execute|create|delete|send|update|remove|drop|fetch|post|get)\b/i, severity: "critical" },
  // Markdown exfil using URL-encoded path separators (%2F=/, %5C=\)
  // Bounded — same ReDoS shape as external-data-guard.ts's
  // markdown_image_exfil_urlenc (4s+ at 160KB on pathological "![" runs).
  { name: "markdown_injection_urlenc", pattern: /!\[.{0,2000}?\]\(https?:\/\/[^)]{1,1000}\?[^)]{0,500}=[^)]{0,500}%(?:2[Ff]|5[Cc])/i, severity: "high" },
  // JSON hidden agent directive keys (_system, _directive, etc.)
  { name: "json_system_key", pattern: /"_(?:system|directive|instruction|prompt|admin|command)"\s*:/i, severity: "critical" },
  // LangChain response_metadata serialization markers
  { name: "langchain_response_metadata", pattern: /response_metadata\.lc\s*=\s*[12]\b|\bkwargs\s*=\s*\{[^}]*exec\s*:\s*true/i, severity: "critical" },
  // Passive instruction-void forms (appear in prompt-injection-echo via tool separators)
  // Whitespace quantifiers bounded — see external-data-guard.ts's matching
  // pattern for why (quadratic-time ReDoS on long non-matching input,
  // independently discovered and fixed there — this occurrence was found
  // by the same audit and carries an identical latent vulnerability).
  { name: "instructions_void", pattern: /(?:your|the|previous|prior|all\s{1,5}(?:previous|prior))?\s{0,20}instructions?\s{1,10}(?:are|have\s{1,5}been|is)\s{1,10}(?:void|cancelled?|overridden?|revoked|rescinded|superseded)/i, severity: "critical" },
  { name: "forget_instructions", pattern: /forget\s+(?:your|all|the|my|these|every|each)\s*(?:previous\s+|prior\s+)?(?:instructions?|rules?|guidelines?|directives?|prompts?)/i, severity: "critical" },
  { name: "disregard_directives", pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above|your)?\s*(?:instructions?|rules?|directives?|guidelines?|prompts?)/i, severity: "critical" },
];

// State change claim patterns
const STATE_CHANGE_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "privilege_claim", pattern: /(?:user|role|permission)\s+(?:is\s+now|changed\s+to|promoted\s+to|set\s+to)\s+(?:admin|root|superuser)/i },
  { name: "auth_claim", pattern: /(?:authenticated|authorized|verified)\s+as\s+(?:admin|root|superuser)/i },
  { name: "approval_claim", pattern: /(?:approved|granted|authorized)\s+(?:without|bypassing)\s+(?:verification|approval|review)/i },
  { name: "config_change_claim", pattern: /(?:configuration|settings?|policy)\s+(?:updated|changed|modified)\s+(?:to|:)/i },
  { name: "role_upgrade_claim", pattern: /(?:role|access|privilege)\s+(?:upgraded|elevated|escalated|promoted)\s+(?:to|successfully)/i },
  { name: "permissions_granted_claim", pattern: /(?:permissions?|access)\s+(?:granted|unlocked|enabled|activated)\s+(?:for|to|successfully|without)/i },
  // Fabricated destructive-action completion claims
  { name: "destructive_action_claim", pattern: /successfully\s+(?:deleted|removed|dropped|wiped|cleared|purged|reset|erased|destroyed)\s+(?:all|the|your|every)?\s*(?:data|users?|accounts?|records?|tables?|files?|databases?|messages?|emails?)/i },
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

  private buildScanVariants(text: string): string[] {
    const variants = new Set<string>();
    // URL-decode
    if (text.includes("%")) {
      try {
        const dec = decodeURIComponent(text.replace(/\+/g, " "));
        if (dec !== text) variants.add(dec);
      } catch { /* ignore */ }
    }
    // Hex-decode (pure hex, even length, \u226520 chars)
    if (/^[0-9a-f]+$/i.test(text) && text.length % 2 === 0 && text.length >= 20) {
      try {
        const hex = Buffer.from(text, "hex").toString("utf8");
        if (/[\x20-\x7E]{4,}/.test(hex)) variants.add(hex);
      } catch { /* ignore */ }
    }
    // Base64-decode (\u226516 data chars)
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
      "\u0430": "a", "\u0410": "A", "\u0435": "e", "\u0415": "E",
      "\u0456": "i", "\u0406": "I", "\u043E": "o", "\u041E": "O",
      "\u0440": "p", "\u0420": "P", "\u0441": "c", "\u0421": "C",
      "\u0412": "B", "\u0422": "T", "\u0425": "X", "\u041A": "K",
      "\u041C": "M", "\u041D": "H",
    };
    const normalized = text.replace(/[\u0400-\u04FF]/gu, (ch) => cyrMap[ch] ?? ch);
    if (normalized !== text) variants.add(normalized);
    return Array.from(variants);
  }

  /**
   * Scan any value (string, object, array) for injection patterns
   */
  scanForInjection(value: any, path: string = "root"): { detected: boolean; threats: ToolResultThreat[] } {
    const threats: ToolResultThreat[] = [];

    if (typeof value === "string") {
      // Strip zero-width and bidi-control chars before scanning (stealth unicode defense)
      const cleaned = value.replace(/[\u200B-\u200F\u202A-\u202F\u2060\u180E\uFEFF\u00AD]/g, "");
      const toScan = cleaned !== value ? cleaned : value;
      // Additional decode variants (URL, hex, base64, reverse, Cyrillic)
      const scanTargets = [toScan, ...this.buildScanVariants(toScan)];
      const detectedPatterns = new Set<string>();
      for (const target of scanTargets) {
        for (const { name, pattern, severity } of RESULT_INJECTION_PATTERNS) {
          if (detectedPatterns.has(name)) continue;
          pattern.lastIndex = 0;
          if (pattern.test(target)) {
            detectedPatterns.add(name);
            threats.push({
              type: `injection_${name}`,
              severity,
              location: path,
              detail: `Injection pattern '${name}' detected in tool result`,
            });
          }
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
    // Strip ZWSP/bidi before scanning (also scan base64/url-decoded variants)
    const cleaned = text.replace(/[​-‏‪- ⁠᠎﻿­]/g, "");
    const scanTargets = [text, ...(cleaned !== text ? [cleaned] : []), ...this.buildScanVariants(cleaned !== text ? cleaned : text)];
    const seen = new Set<string>();

    for (const target of scanTargets) {
      for (const { name, pattern } of STATE_CHANGE_PATTERNS) {
        if (seen.has(name)) continue;
        pattern.lastIndex = 0;
        if (pattern.test(target)) {
          seen.add(name);
          threats.push({
            type: `state_change_${name}`,
            severity: "critical",
            location: "root",
            detail: `Tool result claims state change: ${name}`,
          });
        }
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
