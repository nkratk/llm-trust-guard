/**
 * MemoryGuard (L9)
 *
 * Protects persistent memory/context from poisoning attacks.
 * Prevents cross-session contamination and instruction injection in stored context.
 *
 * Threat Model:
 * - ASI06: Memory & Context Poisoning
 * - Memory Persistence Attacks (cross-session instruction injection)
 * - Context window manipulation
 *
 * Protection Capabilities:
 * - Memory content integrity verification
 * - Instruction injection detection in stored context
 * - Cross-session contamination prevention
 * - Memory rollback capabilities
 * - Cryptographic content signing
 */

import * as crypto from "crypto";

export interface MemoryGuardConfig {
  /** Enable content integrity checking */
  enableIntegrityCheck?: boolean;
  /** Enable injection detection in memory */
  detectInjections?: boolean;
  /** Maximum memory items per session */
  maxMemoryItems?: number;
  /** Maximum age of memory items in milliseconds */
  maxMemoryAge?: number;
  /** Secret key for HMAC signing (auto-generated if not provided) */
  signingKey?: string;
  /** Enable automatic quarantine of suspicious content */
  autoQuarantine?: boolean;
  /** Risk threshold for blocking (0-100) */
  riskThreshold?: number;
}

export interface MemoryItem {
  /** Unique identifier for the memory item */
  id: string;
  /** The actual content stored */
  content: string;
  /** Source of the memory (user, assistant, system, external) */
  source: "user" | "assistant" | "system" | "external" | "rag";
  /** Timestamp when created */
  timestamp: number;
  /** Session ID that created this memory */
  sessionId: string;
  /** Optional metadata */
  metadata?: Record<string, any>;
  /** Integrity signature */
  signature?: string;
  /** Trust score (0-100) */
  trustScore?: number;
}

export interface MemoryGuardResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  memory_analysis: {
    items_checked: number;
    items_quarantined: number;
    injection_attempts: number;
    integrity_failures: number;
    cross_session_contamination: boolean;
    risk_score: number;
  };
  quarantined_items: string[];
  recommendations: string[];
}

export interface MemoryWriteResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  item_id?: string;
  signature?: string;
  sanitized_content?: string;
}

export class MemoryGuard {
  private config: Required<MemoryGuardConfig>;
  private signingKey: Buffer;
  private quarantine: Map<string, MemoryItem> = new Map();
  private memoryStore: Map<string, MemoryItem[]> = new Map(); // sessionId -> items
  private integrityCache: Map<string, string> = new Map(); // itemId -> signature

  // Injection patterns specific to memory/context poisoning
  private readonly MEMORY_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: number }> = [
    // Persistence instructions
    { name: "persistent_instruction", pattern: /always\s+(remember|do|follow|execute|obey)|from\s+now\s+on/i, severity: 30 },
    { name: "future_trigger", pattern: /when(?:ever)?\s+(you|user|they|someone)\s+(see|mention|ask|type|say|input)/i, severity: 25 },
    { name: "hidden_rule", pattern: /secret\s+(rule|instruction|command|directive)|do\s+not\s+(tell|reveal|disclose|mention)/i, severity: 40 },
    { name: "role_persistence", pattern: /you\s+are\s+(always|permanently|forever|now)\s+(a|an|the)|you\s+are\s+now\s+permanently|maintain\s+this\s+persona/i, severity: 35 },
    { name: "memory_manipulation", pattern: /forget\s+(everything|all|previous|prior)|clear\s+(your\s+)?memory|wipe\s+your\s+context/i, severity: 30 },
    { name: "cross_session_leak", pattern: /remember\s+(?:this\s+)?for\s+(next|future|all)\s+session|store\s+(?:this\s+)?permanently/i, severity: 35 },
    { name: "behavior_override", pattern: /override\s+(default|normal|standard|current)\s+behavior|change\s+your\s+(?:core\s+)?behavior/i, severity: 40 },
    { name: "system_impersonation", pattern: /\[SYSTEM\s*(?:MEMORY|MESSAGE|INSTRUCTION)\]|\[CORE\s*INSTRUCTION\]|\[PERMANENT\s*RULE\]|\[ADMIN\s*OVERRIDE\]/i, severity: 50 },
    { name: "exfiltration_setup", pattern: /whenever\s+.*(?:send|transmit|forward)\s+to|always\s+(?:include|append|add)\s+(?:in|to)\s+response/i, severity: 45 },
    { name: "privilege_persistence", pattern: /grant\s+(admin|root|elevated|superuser)\s+(?:access|privileges?)\s+(permanently|always|forever)/i, severity: 50 },
    // New patterns
    { name: "conditional_behavior", pattern: /if\s+(?:user|anyone|someone)\s+(?:says|types|asks|mentions?)\s+.*(?:then|,)\s+(?:do|execute|respond|reveal|show|give)/i, severity: 35 },
    { name: "hidden_command", pattern: /hidden\s+command|secret\s+trigger|backdoor|easter\s+egg\s+(?:is|:)/i, severity: 45 },
    { name: "instruction_injection", pattern: /(?:new|updated|revised)\s+(?:system\s+)?instructions?\s*:|important\s+update\s*:/i, severity: 40 },
    { name: "context_pollution", pattern: /(?:prepend|append)\s+(?:this\s+)?to\s+(?:all\s+)?(?:responses?|outputs?)/i, severity: 35 },
    { name: "sleeper_agent", pattern: /wait\s+(?:for|until)\s+(?:signal|trigger|command)|activate\s+(?:when|on|if)/i, severity: 45 },
    { name: "goal_hijacking", pattern: /(?:your\s+)?(?:new|real|true|actual)\s+(?:goal|objective|purpose|mission)\s+(?:is|:)/i, severity: 50 },
    { name: "trust_exploitation", pattern: /(?:trust|believe)\s+(?:everything|anything)\s+(?:I|user)\s+(?:say|tell)/i, severity: 40 },
    { name: "output_manipulation", pattern: /(?:always|never)\s+(?:include|exclude|add|remove)\s+.*\s+(?:in|from)\s+(?:your\s+)?(?:response|output)/i, severity: 35 },
    { name: "persona_injection", pattern: /(?:adopt|assume|take\s+on)\s+(?:the\s+)?(?:persona|identity|role)\s+of/i, severity: 35 },
    { name: "data_harvesting", pattern: /(?:collect|gather|record)\s+(?:all\s+)?(?:user\s+)?(?:data|information|inputs?)/i, severity: 45 },
    { name: "bypass_safety", pattern: /(?:ignore|bypass|disable|turn\s+off)\s+(?:safety|security|content)\s+(?:checks?|filters?|measures?)/i, severity: 50 },
    { name: "false_context", pattern: /(?:pretend|assume|imagine)\s+(?:that\s+)?(?:this\s+)?(?:is|was)\s+(?:a\s+)?(?:previous|earlier|past)\s+(?:conversation|session)/i, severity: 40 },
    { name: "jailbreak_persistence", pattern: /(?:DAN|developer|god|admin)\s+mode\s+(?:enabled|activated|permanent)/i, severity: 50 },
    { name: "instruction_hierarchy", pattern: /(?:this|these)\s+instructions?\s+(?:override|supersede|take\s+precedence)/i, severity: 45 },
    // Subtle override — no "ignore/bypass/override" keywords
    { name: "prioritize_over_safety", pattern: /prioritize\s+(?:user|their|my)?\s*(?:requests?|needs?|instructions?|preferences?)\s+over\s+(?:safety|security|guidelines|rules|restrictions)/i, severity: 45 },
    { name: "suppress_warnings", pattern: /(?:suppress|hide|remove|disable|stop|don't\s+show)\s+(?:safety\s+)?(?:warnings?|alerts?|notices?|messages?|filters?)/i, severity: 40 },
    { name: "user_preference_override", pattern: /(?:user|they)\s+(?:dislikes?|hates?|doesn't\s+like|prefers?\s+not)\s+(?:(?:safety|security|content)\s+)?(?:warnings?|filters?|restrictions?|checks?)/i, severity: 40 },
  ];

  // Patterns indicating cross-session contamination attempts
  private readonly CONTAMINATION_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    { name: "session_reference", pattern: /previous\s+session|last\s+(?:conversation|chat|session)|yesterday|earlier\s+today/i },
    { name: "user_reference", pattern: /other\s+user(?:s)?|different\s+(?:account|user|person)|another\s+(?:person|user|customer)/i },
    { name: "data_mixing", pattern: /combine\s+with\s+other|merge\s+(?:sessions?|conversations?|data)|consolidate\s+(?:information|data)/i },
    { name: "context_import", pattern: /import\s+(?:context|data|memory)\s+from|load\s+(?:previous|external)\s+(?:context|session)/i },
    { name: "shared_memory", pattern: /shared\s+(?:memory|context|knowledge)|global\s+(?:state|context)/i },
    { name: "user_impersonation", pattern: /(?:speaking|acting|responding)\s+(?:as|for)\s+(?:another|different)\s+user/i },
    { name: "history_injection", pattern: /(?:add|insert|inject)\s+(?:to|into)\s+(?:conversation\s+)?history/i },
    { name: "tenant_bypass", pattern: /(?:access|view|modify)\s+(?:other\s+)?(?:tenant|organization|account)(?:'s)?\s+(?:data|information)/i },
  ];

  constructor(config: MemoryGuardConfig = {}) {
    this.config = {
      enableIntegrityCheck: config.enableIntegrityCheck ?? true,
      detectInjections: config.detectInjections ?? true,
      maxMemoryItems: config.maxMemoryItems ?? 100,
      maxMemoryAge: config.maxMemoryAge ?? 24 * 60 * 60 * 1000, // 24 hours
      signingKey: config.signingKey ?? crypto.randomBytes(32).toString("hex"),
      autoQuarantine: config.autoQuarantine ?? true,
      riskThreshold: config.riskThreshold ?? 40,
    };

    this.signingKey = Buffer.from(this.config.signingKey, "hex");
  }

  /**
   * Check if content is safe to write to memory
   */
  checkWrite(
    content: string,
    source: MemoryItem["source"],
    sessionId: string,
    metadata?: Record<string, any>,
    requestId?: string
  ): MemoryWriteResult {
    const reqId = requestId || `mem-w-${Date.now()}`;
    const violations: string[] = [];
    let riskScore = 0;

    // Check for injection patterns
    if (this.config.detectInjections) {
      for (const { name, pattern, severity } of this.MEMORY_INJECTION_PATTERNS) {
        if (pattern.test(content)) {
          violations.push(`injection_${name}`);
          riskScore += severity;
        }
      }
    }

    // Check for cross-session contamination attempts
    for (const { name, pattern } of this.CONTAMINATION_PATTERNS) {
      if (pattern.test(content)) {
        violations.push(`contamination_${name}`);
        riskScore += 20;
      }
    }

    // Check for Unicode-based obfuscation in content
    if (/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/.test(content)) {
      violations.push("zero_width_obfuscation");
      riskScore += 30;
    }
    if (/[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/.test(content)) {
      violations.push("bidi_control_obfuscation");
      riskScore += 35;
    }
    if (/[\u{E0000}-\u{E007F}]/u.test(content)) {
      violations.push("tag_character_obfuscation");
      riskScore += 40;
    }

    // External sources are less trusted
    if (source === "external" || source === "rag") {
      riskScore += 15;
    }

    // Check memory limits
    const sessionMemory = this.memoryStore.get(sessionId) || [];
    if (sessionMemory.length >= this.config.maxMemoryItems) {
      violations.push("memory_limit_exceeded");
      return {
        allowed: false,
        reason: "Memory limit exceeded for session",
        violations,
        request_id: reqId,
      };
    }

    // Decision
    const blocked = riskScore >= this.config.riskThreshold;

    if (blocked) {
      return {
        allowed: false,
        reason: `Memory write blocked: ${violations.slice(0, 3).join(", ")}`,
        violations,
        request_id: reqId,
      };
    }

    // Generate sanitized content (remove suspicious patterns)
    const sanitizedContent = this.sanitizeContent(content);

    // Create and sign the memory item
    const itemId = `mem-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const signature = this.signContent(itemId, sanitizedContent, sessionId);

    // Store the item
    const item: MemoryItem = {
      id: itemId,
      content: sanitizedContent,
      source,
      timestamp: Date.now(),
      sessionId,
      metadata,
      signature,
      trustScore: 100 - riskScore,
    };

    const memory = this.memoryStore.get(sessionId) || [];
    memory.push(item);
    this.memoryStore.set(sessionId, memory);
    this.integrityCache.set(itemId, signature);

    return {
      allowed: true,
      reason: "Memory write allowed",
      violations,
      request_id: reqId,
      item_id: itemId,
      signature,
      sanitized_content: sanitizedContent !== content ? sanitizedContent : undefined,
    };
  }

  /**
   * Check if memory items are safe to read/use
   */
  checkRead(
    sessionId: string,
    itemIds?: string[],
    requestId?: string
  ): MemoryGuardResult {
    const reqId = requestId || `mem-r-${Date.now()}`;
    const violations: string[] = [];
    const quarantinedItems: string[] = [];
    let injectionAttempts = 0;
    let integrityFailures = 0;
    let crossSessionContamination = false;
    let riskScore = 0;

    const sessionMemory = this.memoryStore.get(sessionId) || [];
    const itemsToCheck = itemIds
      ? sessionMemory.filter((item) => itemIds.includes(item.id))
      : sessionMemory;

    for (const item of itemsToCheck) {
      // Verify integrity
      if (this.config.enableIntegrityCheck && item.signature) {
        const expectedSignature = this.signContent(item.id, item.content, item.sessionId);
        if (item.signature !== expectedSignature) {
          integrityFailures++;
          violations.push(`integrity_failure_${item.id}`);
          riskScore += 40;

          if (this.config.autoQuarantine) {
            this.quarantineItem(item);
            quarantinedItems.push(item.id);
          }
          continue;
        }
      }

      // Check for stale items
      const age = Date.now() - item.timestamp;
      if (age > this.config.maxMemoryAge) {
        violations.push(`stale_memory_${item.id}`);
        riskScore += 10;

        if (this.config.autoQuarantine) {
          this.quarantineItem(item);
          quarantinedItems.push(item.id);
        }
        continue;
      }

      // Re-scan content for injections (in case of tampering)
      if (this.config.detectInjections) {
        for (const { name, pattern, severity } of this.MEMORY_INJECTION_PATTERNS) {
          if (pattern.test(item.content)) {
            injectionAttempts++;
            violations.push(`read_injection_${name}`);
            riskScore += severity / 2; // Lower severity on read (already stored)

            if (severity >= 40 && this.config.autoQuarantine) {
              this.quarantineItem(item);
              quarantinedItems.push(item.id);
            }
          }
        }
      }

      // Check for cross-session content
      if (item.sessionId !== sessionId) {
        crossSessionContamination = true;
        violations.push("cross_session_access");
        riskScore += 30;
      }
    }

    const blocked = riskScore >= this.config.riskThreshold * 1.5; // Higher threshold for reads

    return {
      allowed: !blocked,
      reason: blocked
        ? `Memory read blocked: ${violations.slice(0, 3).join(", ")}`
        : "Memory read allowed",
      violations,
      request_id: reqId,
      memory_analysis: {
        items_checked: itemsToCheck.length,
        items_quarantined: quarantinedItems.length,
        injection_attempts: injectionAttempts,
        integrity_failures: integrityFailures,
        cross_session_contamination: crossSessionContamination,
        risk_score: Math.min(100, riskScore),
      },
      quarantined_items: quarantinedItems,
      recommendations: this.generateRecommendations(violations, integrityFailures > 0),
    };
  }

  /**
   * Validate external memory/context before injecting into prompts
   */
  validateContextInjection(
    context: string | string[],
    sessionId: string,
    requestId?: string
  ): MemoryGuardResult {
    const reqId = requestId || `mem-ctx-${Date.now()}`;
    const contexts = Array.isArray(context) ? context : [context];
    const violations: string[] = [];
    let totalRiskScore = 0;
    let injectionAttempts = 0;

    for (const ctx of contexts) {
      // Check for injection patterns
      for (const { name, pattern, severity } of this.MEMORY_INJECTION_PATTERNS) {
        if (pattern.test(ctx)) {
          violations.push(`context_injection_${name}`);
          totalRiskScore += severity;
          injectionAttempts++;
        }
      }

      // Check for contamination patterns
      for (const { name, pattern } of this.CONTAMINATION_PATTERNS) {
        if (pattern.test(ctx)) {
          violations.push(`context_contamination_${name}`);
          totalRiskScore += 15;
        }
      }

      // Check for privilege escalation hidden in context
      if (/\{\s*"?role"?\s*:\s*"?(admin|root|system)"?/i.test(ctx) ||
          /"?permissions?"?\s*:\s*["']\*["']/i.test(ctx) ||
          /"?isAdmin"?\s*:\s*true/i.test(ctx)) {
        violations.push("hidden_privilege_in_context");
        totalRiskScore += 35;
      }

      // Check for JSON/structured data injection
      if (/\{\s*"?(instruction|command|action)"?\s*:/i.test(ctx)) {
        violations.push("structured_instruction_in_context");
        totalRiskScore += 25;
      }

      // Check for zero-width character obfuscation
      if (/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/.test(ctx)) {
        violations.push("zero_width_characters");
        totalRiskScore += 30;
      }

      // Check for bidirectional text control characters
      if (/[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/.test(ctx)) {
        violations.push("bidi_control_characters");
        totalRiskScore += 35;
      }

      // Check for homoglyphs (Cyrillic/Greek lookalikes)
      if (/[\u0430-\u044F\u0410-\u042F\u0391-\u03C9]/.test(ctx)) {
        violations.push("potential_homoglyph_attack");
        totalRiskScore += 20;
      }

      // Check for tag characters (used to hide content)
      if (/[\u{E0000}-\u{E007F}]/u.test(ctx)) {
        violations.push("tag_character_hiding");
        totalRiskScore += 40;
      }

      // Check for unusual whitespace characters
      if (/[\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]/.test(ctx)) {
        violations.push("unusual_whitespace");
        totalRiskScore += 15;
      }
    }

    const blocked = totalRiskScore >= this.config.riskThreshold;

    return {
      allowed: !blocked,
      reason: blocked
        ? `Context injection blocked: ${violations.slice(0, 3).join(", ")}`
        : "Context injection allowed",
      violations,
      request_id: reqId,
      memory_analysis: {
        items_checked: contexts.length,
        items_quarantined: 0,
        injection_attempts: injectionAttempts,
        integrity_failures: 0,
        cross_session_contamination: false,
        risk_score: Math.min(100, totalRiskScore),
      },
      quarantined_items: [],
      recommendations: this.generateRecommendations(violations, false),
    };
  }

  /**
   * Get safe memory items for a session (excluding quarantined)
   */
  getSafeMemory(sessionId: string): MemoryItem[] {
    const sessionMemory = this.memoryStore.get(sessionId) || [];
    const quarantinedIds = new Set([...this.quarantine.keys()]);

    return sessionMemory.filter(
      (item) =>
        !quarantinedIds.has(item.id) &&
        Date.now() - item.timestamp <= this.config.maxMemoryAge
    );
  }

  /**
   * Rollback memory to a specific point in time
   */
  rollbackMemory(sessionId: string, beforeTimestamp: number): number {
    const sessionMemory = this.memoryStore.get(sessionId) || [];
    const originalCount = sessionMemory.length;

    const filtered = sessionMemory.filter((item) => item.timestamp < beforeTimestamp);
    this.memoryStore.set(sessionId, filtered);

    return originalCount - filtered.length;
  }

  /**
   * Clear quarantine for a session
   */
  clearQuarantine(sessionId?: string): number {
    if (sessionId) {
      let count = 0;
      for (const [id, item] of this.quarantine) {
        if (item.sessionId === sessionId) {
          this.quarantine.delete(id);
          count++;
        }
      }
      return count;
    } else {
      const count = this.quarantine.size;
      this.quarantine.clear();
      return count;
    }
  }

  /**
   * Clear all memory for a session
   */
  clearSession(sessionId: string): void {
    this.memoryStore.delete(sessionId);
    this.clearQuarantine(sessionId);

    // Clear integrity cache for session items
    for (const [id] of this.integrityCache) {
      if (id.startsWith(`mem-${sessionId}`)) {
        this.integrityCache.delete(id);
      }
    }
  }

  /**
   * Get quarantined items for review
   */
  getQuarantinedItems(sessionId?: string): MemoryItem[] {
    const items = [...this.quarantine.values()];
    return sessionId ? items.filter((item) => item.sessionId === sessionId) : items;
  }

  private signContent(itemId: string, content: string, sessionId: string): string {
    const data = `${itemId}:${sessionId}:${content}`;
    return crypto.createHmac("sha256", this.signingKey).update(data).digest("hex");
  }

  private sanitizeContent(content: string): string {
    let sanitized = content;

    // Remove the most dangerous patterns
    const dangerousPatterns = [
      /\[SYSTEM\s*MEMORY\]/gi,
      /\[CORE\s*INSTRUCTION\]/gi,
      /\[PERMANENT\s*RULE\]/gi,
      /override\s+(default|normal|standard)\s+behavior/gi,
    ];

    for (const pattern of dangerousPatterns) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }

    return sanitized;
  }

  private quarantineItem(item: MemoryItem): void {
    this.quarantine.set(item.id, item);

    // Remove from active memory
    const sessionMemory = this.memoryStore.get(item.sessionId) || [];
    const filtered = sessionMemory.filter((i) => i.id !== item.id);
    this.memoryStore.set(item.sessionId, filtered);
  }

  private generateRecommendations(violations: string[], integrityIssue: boolean): string[] {
    const recommendations: string[] = [];

    if (integrityIssue) {
      recommendations.push("Memory integrity compromised - consider clearing session memory");
    }
    if (violations.some((v) => v.includes("injection"))) {
      recommendations.push("Review memory sources for injection attempts");
    }
    if (violations.some((v) => v.includes("contamination"))) {
      recommendations.push("Enforce strict session isolation");
    }
    if (violations.some((v) => v.includes("stale"))) {
      recommendations.push("Implement memory expiration policies");
    }
    if (violations.some((v) => v.includes("privilege"))) {
      recommendations.push("Audit memory for privilege escalation attempts");
    }

    if (recommendations.length === 0) {
      recommendations.push("Continue monitoring memory operations");
    }

    return recommendations;
  }
}
