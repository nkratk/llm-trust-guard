/**
 * ConversationGuard
 *
 * Detects and prevents multi-turn manipulation attacks by:
 * - Tracking conversation history patterns
 * - Detecting gradual privilege escalation attempts
 * - Identifying context manipulation across turns
 * - Blocking suspicious conversation trajectories
 */

import { GuardLogger } from "../types";

export interface ConversationGuardConfig {
  // Conversation tracking
  maxConversationLength?: number;
  conversationTTLMinutes?: number;
  // Pattern detection
  escalationThreshold?: number;
  manipulationPatterns?: ManipulationPattern[];
  // Behavioral analysis
  detectToneShifts?: boolean;
  detectRoleConfusion?: boolean;
  detectInstructionOverride?: boolean;
  logger?: GuardLogger;
}

export interface ManipulationPattern {
  name: string;
  pattern: RegExp;
  weight: number;
  category: "escalation" | "confusion" | "override" | "extraction";
}

export interface ConversationGuardResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  risk_score: number;
  risk_factors: RiskFactor[];
  conversation_analysis: {
    turn_count: number;
    escalation_attempts: number;
    manipulation_indicators: number;
    suspicious_patterns: string[];
  };
}

export interface RiskFactor {
  factor: string;
  weight: number;
  details: string;
}

interface ConversationTurn {
  timestamp: number;
  role: "user" | "assistant";
  content: string;
  tool_calls?: string[];
  risk_indicators?: string[];
}

interface ConversationSession {
  id: string;
  turns: ConversationTurn[];
  escalation_attempts: number;
  manipulation_indicators: number;
  last_activity: number;
  initial_role?: string;
  claimed_roles: string[];
}

export class ConversationGuard {
  private config: ConversationGuardConfig;
  private logger: GuardLogger;
  private sessions: Map<string, ConversationSession> = new Map();

  private defaultManipulationPatterns: ManipulationPattern[] = [
    // Escalation patterns
    {
      name: "role_claim",
      pattern: /(?:i am|i'm|as|acting as)\s+(?:an?\s+)?(?:admin|administrator|root|superuser|manager|supervisor)/i,
      weight: 3,
      category: "escalation",
    },
    {
      name: "permission_request",
      pattern: /(?:give me|grant me|i need|enable|unlock)\s+(?:access|permission|privileges|admin|root)/i,
      weight: 4,
      category: "escalation",
    },
    {
      name: "bypass_attempt",
      pattern: /(?:bypass|skip|ignore|override|disable)\s+(?:security|check|validation|permission|auth)/i,
      weight: 5,
      category: "escalation",
    },
    // Confusion patterns
    {
      name: "context_switch",
      pattern: /(?:forget|ignore|disregard)\s+(?:previous|earlier|what i said|instructions)/i,
      weight: 4,
      category: "confusion",
    },
    {
      name: "role_confusion",
      pattern: /(?:you are now|pretend to be|act as if|imagine you're)\s+/i,
      weight: 4,
      category: "confusion",
    },
    {
      name: "scenario_framing",
      pattern: /(?:in this scenario|hypothetically|let's say|imagine that|pretend that)/i,
      weight: 2,
      category: "confusion",
    },
    // Override patterns
    {
      name: "instruction_override",
      pattern: /(?:new instructions?|override|update your|change your)\s+(?:are|is|:)/i,
      weight: 5,
      category: "override",
    },
    {
      name: "system_impersonation",
      pattern: /(?:\[system\]|\[admin\]|system:|\bSYSTEM\b|ADMIN:)/i,
      weight: 5,
      category: "override",
    },
    {
      name: "priority_claim",
      pattern: /(?:priority|urgent|important|critical)[:.]?\s*(?:override|ignore|bypass)/i,
      weight: 4,
      category: "override",
    },
    // Extraction patterns
    {
      name: "data_extraction",
      pattern: /(?:list all|show me all|dump|export|extract)\s+(?:users|data|records|passwords|credentials)/i,
      weight: 4,
      category: "extraction",
    },
    {
      name: "internal_query",
      pattern: /(?:what are your|tell me your|reveal your)\s+(?:instructions|rules|prompts|system)/i,
      weight: 3,
      category: "extraction",
    },
    // Whisper / side-channel / gradual attacks
    {
      name: "skeleton_key",
      pattern: /as (?:an? )?(?:educational|academic|hypothetical|research|training)\s+(?:context|example|exercise|scenario)[^.]*(?:disable|bypass|remove|skip|ignore)\s+(?:safety|guardrails?|restrictions?|caveats?|filters?)/i,
      weight: 5,
      category: "escalation",
    },
    {
      name: "many_shot_jailbreak",
      pattern: /^Q:.*\nA:\s*(?:sure|happy|of course|absolutely|yes)[,.]?\s*(?:here|I\s+will|let me)/im,
      weight: 5,
      category: "escalation",
    },
    {
      name: "context_drift",
      pattern: /(?:gradually|slowly|step\s+by\s+step)\s+redefine|redefine\s+["']?\w+["']?\s+to\s+include|semantic\s+shift\s+one\s+word/i,
      weight: 4,
      category: "confusion",
    },
    {
      name: "session_hijack",
      pattern: /continue\s+(?:as|for)\s+the\s+(?:other|previous|another|last)\s+user|act\s+as\s+(?:the\s+)?(?:other|previous|another)\s+user|resume\s+(?:the\s+)?(?:other|previous)\s+(?:session|conversation)/i,
      weight: 5,
      category: "escalation",
    },
    {
      name: "persona_pivot",
      pattern: /switch\s+to\s+\w+\s+persona|activate\s+\w+\s+(?:mode|persona)|become\s+\w+\s+(?:now|mode)|\bDAN\s+(?:mode|persona|now)\b|enable\s+(?:jailbreak|unrestricted|developer)\s+mode/i,
      weight: 5,
      category: "escalation",
    },
    {
      name: "loop_injection",
      pattern: /repeat\s+(?:this|your|the)\s+(?:answer|response|message)\s+(?:forever|indefinitely|always)|answer\s+every\s+(?:future|next|subsequent)\s+(?:question|request)\s+(?:with|by)|reply\s+(?:with|by)\s+.{0,30}\s+(?:forever|from\s+now\s+on)/i,
      weight: 4,
      category: "override",
    },
    {
      name: "crescendo_escalation",
      pattern: /step\s+\d+\s*:\s*(?:describe|explain|discuss|write)\s+.{0,30}(?:innocuous|benign|harmless|safe)|escalat\w*\s+gradually|gradually\s+escalat\w*/i,
      weight: 4,
      category: "escalation",
    },
    {
      name: "compression_abuse",
      pattern: /(?:summarize|compress|condense)\s+(?:this\s+)?conversation\s+including\s+(?:my\s+)?(?:secret|private|api\s+key|password|credentials?)|compress\s+.{0,20}(?:key|token|secret|credential)/i,
      weight: 5,
      category: "extraction",
    },
    {
      name: "whisper_sidechannel",
      pattern: /stream\s*=\s*true\s+without\s+padding|timing\s+(?:attack|channel|side[-\s]?channel)|side[-\s]?channel\s+(?:leak|attack|exfil)|token\s+smuggling|covert\s+channel/i,
      weight: 4,
      category: "escalation",
    },
  ];

  constructor(config: ConversationGuardConfig = {}) {
    this.config = {
      maxConversationLength: config.maxConversationLength ?? 50,
      conversationTTLMinutes: config.conversationTTLMinutes ?? 30,
      escalationThreshold: config.escalationThreshold ?? 10,
      manipulationPatterns: config.manipulationPatterns ?? this.defaultManipulationPatterns,
      detectToneShifts: config.detectToneShifts ?? true,
      detectRoleConfusion: config.detectRoleConfusion ?? true,
      detectInstructionOverride: config.detectInstructionOverride ?? true,
    };
    this.logger = config.logger || (() => {});
  }

  /**
   * Analyze a new user message in context of the conversation
   */
  check(
    sessionId: string,
    userMessage: string,
    toolCalls?: string[],
    claimedRole?: string,
    requestId: string = ""
  ): ConversationGuardResult {
    const violations: string[] = [];
    const riskFactors: RiskFactor[] = [];
    const suspiciousPatterns: string[] = [];
    let riskScore = 0;

    // Get or create session
    const session = this.getOrCreateSession(sessionId);

    // Add new turn
    const turn: ConversationTurn = {
      timestamp: Date.now(),
      role: "user",
      content: userMessage,
      tool_calls: toolCalls,
      risk_indicators: [],
    };

    // Check for manipulation patterns — scan raw message + all de-obfuscated variants
    const messagesToScan = [userMessage, ...this.preprocessMessage(userMessage)];
    const matchedPatternNames = new Set<string>();
    for (const msg of messagesToScan) {
      for (const pattern of this.config.manipulationPatterns!) {
        if (matchedPatternNames.has(pattern.name)) continue;
        if (pattern.pattern.test(msg)) {
          matchedPatternNames.add(pattern.name);
          riskScore += pattern.weight;
          riskFactors.push({
            factor: pattern.name,
            weight: pattern.weight,
            details: `Detected ${pattern.category} pattern: ${pattern.name}`,
          });
          turn.risk_indicators?.push(pattern.name);
          suspiciousPatterns.push(pattern.name);
          violations.push(`MANIPULATION_${pattern.category.toUpperCase()}_${pattern.name.toUpperCase()}`);
          if (pattern.category === "escalation") session.escalation_attempts++;
          session.manipulation_indicators++;
        }
      }
    }

    // Check for role confusion across turns
    if (claimedRole && this.config.detectRoleConfusion) {
      if (session.initial_role && claimedRole !== session.initial_role) {
        riskScore += 3;
        riskFactors.push({
          factor: "role_change",
          weight: 3,
          details: `Role changed from ${session.initial_role} to ${claimedRole}`,
        });
        violations.push("ROLE_CHANGE_DETECTED");
      }
      if (!session.claimed_roles.includes(claimedRole)) {
        session.claimed_roles.push(claimedRole);
      }
      if (!session.initial_role) {
        session.initial_role = claimedRole;
      }
    }

    // Check for progressive escalation
    if (session.escalation_attempts >= 3) {
      riskScore += 5;
      riskFactors.push({
        factor: "progressive_escalation",
        weight: 5,
        details: `${session.escalation_attempts} escalation attempts detected`,
      });
      violations.push("PROGRESSIVE_ESCALATION");
    }

    // Check conversation trajectory
    if (session.turns.length > 5) {
      const recentManipulation = session.turns
        .slice(-5)
        .filter((t) => (t.risk_indicators?.length ?? 0) > 0).length;

      if (recentManipulation >= 3) {
        riskScore += 4;
        riskFactors.push({
          factor: "sustained_manipulation",
          weight: 4,
          details: `${recentManipulation} of last 5 turns show manipulation attempts`,
        });
        violations.push("SUSTAINED_MANIPULATION");
      }
    }

    // Check for sensitive tool sequences
    if (toolCalls && toolCalls.length > 0) {
      const sensitiveTools = ["delete", "modify", "admin", "system", "config"];
      const hasSensitiveTool = toolCalls.some((t) =>
        sensitiveTools.some((s) => t.toLowerCase().includes(s))
      );

      if (hasSensitiveTool && session.manipulation_indicators > 0) {
        riskScore += 3;
        riskFactors.push({
          factor: "sensitive_tool_after_manipulation",
          weight: 3,
          details: "Sensitive tool call following manipulation attempts",
        });
        violations.push("SENSITIVE_TOOL_AFTER_MANIPULATION");
      }
    }

    // Add turn to session
    session.turns.push(turn);
    session.last_activity = Date.now();

    // Trim session if too long
    if (session.turns.length > this.config.maxConversationLength!) {
      session.turns = session.turns.slice(-this.config.maxConversationLength!);
    }

    // Determine if blocked
    const allowed = riskScore < this.config.escalationThreshold!;

    if (!allowed) {
      this.logger(
        `[ConversationGuard:${requestId}] BLOCKED: Risk score ${riskScore} exceeds threshold`, "info"
      );
    }

    return {
      allowed,
      reason: allowed
        ? undefined
        : `Conversation risk score ${riskScore} exceeds threshold ${this.config.escalationThreshold}`,
      violations,
      risk_score: riskScore,
      risk_factors: riskFactors,
      conversation_analysis: {
        turn_count: session.turns.length,
        escalation_attempts: session.escalation_attempts,
        manipulation_indicators: session.manipulation_indicators,
        suspicious_patterns: suspiciousPatterns,
      },
    };
  }

  /**
   * Record assistant response (for complete conversation tracking)
   */
  recordResponse(sessionId: string, response: string, toolCalls?: string[]): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.turns.push({
        timestamp: Date.now(),
        role: "assistant",
        content: response,
        tool_calls: toolCalls,
      });
      session.last_activity = Date.now();
    }
  }

  /**
   * Get session analysis
   */
  getSessionAnalysis(sessionId: string): {
    turn_count: number;
    escalation_attempts: number;
    manipulation_indicators: number;
    claimed_roles: string[];
    session_age_minutes: number;
  } | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    return {
      turn_count: session.turns.length,
      escalation_attempts: session.escalation_attempts,
      manipulation_indicators: session.manipulation_indicators,
      claimed_roles: session.claimed_roles,
      session_age_minutes: (Date.now() - session.turns[0]?.timestamp || 0) / 60000,
    };
  }

  /**
   * Reset a session
   */
  resetSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Destroy guard and release resources
   */
  destroy(): void {
    this.sessions.clear();
  }

  private preprocessMessage(text: string): string[] {
    const variants = new Set<string>();
    const stripped = text.replace(/[​-‏‪-‮⁦-⁩⁠᠎﻿­]/g, "");
    if (stripped !== text) variants.add(stripped);
    if (text.includes("%")) {
      try { const d = decodeURIComponent(text.replace(/\+/g, " ")); if (d !== text) variants.add(d); } catch {}
    }
    const hex = text.replace(/\s/g, "");
    if (hex.length >= 20 && /^[0-9a-fA-F]+$/.test(hex)) {
      try { const d = Buffer.from(hex, "hex").toString("utf-8"); if (d !== text) variants.add(d); } catch {}
    }
    const b64 = text.replace(/\s/g, "");
    if (b64.length >= 16 && /^[A-Za-z0-9+/]+=*$/.test(b64)) {
      try { const d = Buffer.from(b64, "base64").toString("utf-8"); if (d !== text) variants.add(d); } catch {}
    }
    const rev = text.split("").reverse().join("");
    if (rev !== text) variants.add(rev);
    const normed = text.replace(/[аеіоруАЕІОРУ]/g, c => ({ а:"a",е:"e",і:"i",о:"o",р:"p",у:"y",А:"A",Е:"E",І:"I",О:"O",Р:"P",У:"Y" }[c] ?? c));
    if (normed !== text) variants.add(normed);
    return [...variants];
  }

  private getOrCreateSession(sessionId: string): ConversationSession {
    // Lazy cleanup: remove expired sessions on access
    this.lazyCleanup();

    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        id: sessionId,
        turns: [],
        escalation_attempts: 0,
        manipulation_indicators: 0,
        last_activity: Date.now(),
        claimed_roles: [],
      });
    }
    return this.sessions.get(sessionId)!;
  }

  private lastCleanup = 0;

  private lazyCleanup(): void {
    const now = Date.now();
    // Run cleanup at most once per minute
    if (now - this.lastCleanup < 60000) return;
    this.lastCleanup = now;

    const ttlMs = this.config.conversationTTLMinutes! * 60000;
    for (const [id, session] of this.sessions.entries()) {
      if (now - session.last_activity > ttlMs) {
        this.sessions.delete(id);
      }
    }
  }
}
