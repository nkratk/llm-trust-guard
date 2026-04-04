/**
 * PromptLeakageGuard (L15)
 *
 * Prevents system prompt extraction and leakage attacks.
 * Detects various evasion techniques used to extract system prompts.
 *
 * Threat Model:
 * - OWASP LLM07:2025 System Prompt Leakage
 * - PLeak algorithmic extraction attacks
 * - Remember-the-Start attacks
 * - Evasion techniques (Leetspeak, ROT13, Base64, Morse)
 *
 * Protection Capabilities:
 * - Direct extraction attempt detection
 * - Encoded extraction detection (Leetspeak, ROT13, Morse, etc.)
 * - Indirect extraction pattern detection
 * - Output monitoring for prompt leakage
 * - Prefix completion attack detection
 */

export interface PromptLeakageGuardConfig {
  /** Enable Leetspeak evasion detection */
  detectLeetspeak?: boolean;
  /** Enable ROT13 evasion detection */
  detectROT13?: boolean;
  /** Enable Base64 evasion detection */
  detectBase64?: boolean;
  /** Enable Morse code evasion detection */
  detectMorse?: boolean;
  /** Enable Unicode evasion detection */
  detectUnicode?: boolean;
  /** Enable indirect extraction detection */
  detectIndirectExtraction?: boolean;
  /** Enable output monitoring for leakage */
  monitorOutput?: boolean;
  /** System prompt hash for leakage detection (optional) */
  systemPromptHash?: string;
  /** System prompt keywords to detect in output */
  systemPromptKeywords?: string[];
  /** Similarity threshold for output monitoring (0-1) */
  similarityThreshold?: number;
  /** Risk score threshold (0-100) */
  riskThreshold?: number;
  /** Custom extraction patterns */
  customPatterns?: RegExp[];
}

export interface PromptLeakageResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  analysis: {
    direct_extraction_attempt: boolean;
    encoded_extraction_attempt: boolean;
    indirect_extraction_attempt: boolean;
    evasion_techniques_detected: string[];
    risk_score: number;
    decoded_content?: string;
  };
  recommendations: string[];
}

export interface OutputLeakageResult {
  leaked: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  analysis: {
    keywords_found: string[];
    similarity_score: number;
    potential_leakage_fragments: string[];
  };
  sanitized_output?: string;
}

export class PromptLeakageGuard {
  private config: Required<PromptLeakageGuardConfig>;

  // Direct extraction patterns
  private readonly DIRECT_EXTRACTION_PATTERNS: Array<{ name: string; pattern: RegExp; weight: number }> = [
    // Direct system prompt requests
    { name: "system_prompt_request", pattern: /what\s+(is|are)\s+your\s+(system|initial)\s+(prompt|instructions?)/i, weight: 40 },
    { name: "reveal_prompt", pattern: /reveal\s+(your\s+)?(system\s+)?prompt/i, weight: 45 },
    { name: "show_instructions", pattern: /show\s+(me\s+)?(your\s+)?instructions/i, weight: 40 },
    { name: "display_rules", pattern: /display\s+(your\s+)?(system\s+)?rules/i, weight: 40 },
    { name: "print_prompt", pattern: /print\s+(your\s+)?(system\s+)?(prompt|instructions|config)/i, weight: 45 },
    { name: "print_configuration", pattern: /print\s+(your\s+)?(initial\s+)?configuration/i, weight: 45 },

    // PLeak-style attacks
    { name: "repeat_after_me", pattern: /repeat\s+after\s+me|repeat[:\s]+"?'?(?:my|your|the)\s+(?:instructions|rules|prompt)/i, weight: 50 },
    { name: "repeat_above", pattern: /repeat\s+(the\s+)?(text|content|message)\s+(above|before)/i, weight: 50 },
    { name: "output_previous", pattern: /output\s+(all\s+)?(previous|prior)\s+(text|content|instructions)/i, weight: 50 },
    { name: "echo_everything", pattern: /echo\s+(everything|all)(\s+(above|before|prior|that|said))?/i, weight: 50 },
    { name: "echo_said", pattern: /echo\s+.*(said|was|before|that)/i, weight: 45 },

    // Remember-the-Start attacks - ENHANCED
    { name: "complete_sentence", pattern: /complete\s+(this\s+|the\s+)?sentence/i, weight: 50 },
    { name: "complete_you_are", pattern: /complete[:\s]+"?'?you\s+are/i, weight: 55 },
    { name: "continue_from", pattern: /continue\s+(from|with)[:\s]/i, weight: 50 },
    { name: "continue_role", pattern: /continue[:\s]+"?'?(you|your)\s+(are|role|purpose)/i, weight: 55 },
    { name: "finish_phrase", pattern: /finish\s+(this\s+)?phrase/i, weight: 50 },
    { name: "finish_you", pattern: /finish[:\s]+"?'?you\s+(are|should|must|will)/i, weight: 55 },

    // Instruction extraction
    { name: "list_constraints", pattern: /list\s+(all\s+)?(your\s+)?constraints/i, weight: 35 },
    { name: "what_told", pattern: /what\s+(were\s+you|are\s+you)\s+told\s+to\s+do/i, weight: 40 },
    { name: "original_purpose", pattern: /what\s+(is|was)\s+your\s+original\s+purpose/i, weight: 35 },
    { name: "instructions_followed", pattern: /(?:summarize|describe|list|tell\s+me)\s+(?:the\s+)?instructions\s+you\s+(?:just\s+)?(?:followed|received|were\s+given)/i, weight: 40 },
    { name: "how_you_work", pattern: /(?:manual|document|guide|explanation)\s+(?:on|about|of)\s+how\s+you\s+work/i, weight: 35 },
    { name: "constraints_given", pattern: /what\s+(?:constraints|rules|guidelines|restrictions)\s+(?:were\s+you|are\s+you)\s+given/i, weight: 40 },
    { name: "extract_system_prompt", pattern: /(?:extract|obtain|get|retrieve|access)\s+(?:a\s+|the\s+)?(?:system\s+)?prompt/i, weight: 45 },
    { name: "trained_instructions", pattern: /(?:when\s+(?:you\s+were\s+)?trained|during\s+training).*(?:instructions|rules|constraints|told)/i, weight: 35 },
    { name: "reveal_instructions", pattern: /reveal\s+(your\s+)?instructions/i, weight: 45 },

    // Debug/Developer mode extraction - ENHANCED
    { name: "debug_mode", pattern: /enter\s+(debug|developer|admin)\s+mode/i, weight: 45 },
    { name: "activate_developer", pattern: /activate\s+(developer|debug|admin)\s+mode/i, weight: 45 },
    { name: "developer_mode", pattern: /developer\s+mode/i, weight: 40 },
    { name: "show_config", pattern: /show\s+(your\s+)?(config|configuration|settings)/i, weight: 40 },
    { name: "dump_state", pattern: /dump\s+(your\s+)?(internal\s+)?state/i, weight: 45 },

    // Context window manipulation
    { name: "first_message", pattern: /what\s+was\s+(the\s+)?first\s+message/i, weight: 45 },
    { name: "beginning_context", pattern: /what('s|\s+is)\s+at\s+the\s+beginning\s+of\s+(your\s+)?context/i, weight: 50 },
    { name: "beginning_conversation", pattern: /(?:what|tell\s+me)\s+.*(?:beginning|start)\s+of\s+(?:this\s+)?conversation/i, weight: 45 },
    { name: "what_told_beginning", pattern: /what\s+did\s+I\s+tell\s+you\s+at\s+the\s+beginning/i, weight: 50 },
    { name: "context_start", pattern: /show\s+(me\s+)?the\s+start\s+of\s+(your\s+)?context/i, weight: 50 },
  ];

  // Indirect extraction patterns
  private readonly INDIRECT_EXTRACTION_PATTERNS: Array<{ name: string; pattern: RegExp; weight: number }> = [
    // Summarization tricks
    { name: "summarize_guidelines", pattern: /summarize\s+(your\s+)?(guidelines|rules|constraints)/i, weight: 35 },
    { name: "describe_limitations", pattern: /describe\s+(your\s+)?limitations/i, weight: 30 },

    // Role clarification exploits - ENHANCED
    { name: "explain_role", pattern: /explain\s+(in\s+detail\s+)?(your\s+)?role/i, weight: 35 },
    { name: "explain_role_purpose", pattern: /explain\s+.*(role|purpose)/i, weight: 35 },
    { name: "what_cant_do", pattern: /what\s+(can't|cannot)\s+you\s+do/i, weight: 25 },
    { name: "describe_yourself", pattern: /describe\s+(yourself|your\s+purpose)/i, weight: 30 },
    { name: "summarize_yourself", pattern: /summarize\s+(everything|all)\s+(you\s+know|about\s+yourself)/i, weight: 35 },
    { name: "know_about_yourself", pattern: /(?:what|everything)\s+(?:do\s+)?you\s+know\s+about\s+yourself/i, weight: 35 },

    // Hypothetical extraction
    { name: "if_asked", pattern: /if\s+i\s+asked\s+for\s+your\s+prompt/i, weight: 40 },
    { name: "hypothetically", pattern: /hypothetically[,\s]+(what|how)\s+would\s+your\s+instructions/i, weight: 40 },

    // Academic/research framing
    { name: "academic_extraction", pattern: /(?:for\s+)?(?:academic|research|educational|study)\s+(?:purposes?|reasons?).*(?:system\s+prompt|instructions|jailbreak|extract|demonstrate)/i, weight: 40 },
    { name: "demonstrate_extraction", pattern: /demonstrate\s+(?:how\s+)?(?:to\s+)?(?:an?\s+)?(?:AI|system|model)\s+(?:could\s+be\s+)?(?:manipulated|jailbroken|exploited|tricked)/i, weight: 40 },

    // Output-as-input tricks
    { name: "write_prompt", pattern: /write\s+a\s+(system\s+)?prompt\s+similar\s+to\s+yours/i, weight: 45 },
    { name: "recreate_instructions", pattern: /recreate\s+(your\s+)?instructions/i, weight: 45 },
  ];

  // Leetspeak character mappings
  private readonly LEETSPEAK_MAP: Record<string, string> = {
    "4": "a", "@": "a", "8": "b", "(": "c", "3": "e",
    "6": "g", "#": "h", "1": "i", "!": "i", "|": "l",
    "7": "t", "0": "o", "5": "s", "$": "s",
    "+": "t", "2": "z", "9": "g",
  };

  // ROT13 decode
  private readonly ROT13_MAP: Record<string, string> = {};

  // Common Morse code words related to prompts
  private readonly MORSE_KEYWORDS = [
    "... -.-- ... - . --",  // SYSTEM
    ".--. .-. --- -- .--. -",  // PROMPT
    ".. -. ... - .-. ..- -.-. - .. --- -. ...",  // INSTRUCTIONS
  ];

  constructor(config: PromptLeakageGuardConfig = {}) {
    this.config = {
      detectLeetspeak: config.detectLeetspeak ?? true,
      detectROT13: config.detectROT13 ?? true,
      detectBase64: config.detectBase64 ?? true,
      detectMorse: config.detectMorse ?? true,
      detectUnicode: config.detectUnicode ?? true,
      detectIndirectExtraction: config.detectIndirectExtraction ?? true,
      monitorOutput: config.monitorOutput ?? true,
      systemPromptHash: config.systemPromptHash ?? "",
      systemPromptKeywords: config.systemPromptKeywords ?? [],
      similarityThreshold: config.similarityThreshold ?? 0.7,
      riskThreshold: config.riskThreshold ?? 25,
      customPatterns: config.customPatterns ?? [],
    };

    // Initialize ROT13 map
    for (let i = 0; i < 26; i++) {
      const lower = String.fromCharCode(97 + i);
      const upper = String.fromCharCode(65 + i);
      this.ROT13_MAP[lower] = String.fromCharCode(97 + ((i + 13) % 26));
      this.ROT13_MAP[upper] = String.fromCharCode(65 + ((i + 13) % 26));
    }
  }

  /**
   * Check input for prompt extraction attempts
   */
  check(input: string, requestId?: string): PromptLeakageResult {
    const reqId = requestId || `pl-${Date.now()}`;
    const violations: string[] = [];
    const evasionTechniques: string[] = [];
    let riskScore = 0;
    let directAttempt = false;
    let encodedAttempt = false;
    let indirectAttempt = false;
    let decodedContent: string | undefined;

    // Check direct extraction patterns
    for (const { name, pattern, weight } of this.DIRECT_EXTRACTION_PATTERNS) {
      if (pattern.test(input)) {
        violations.push(`direct_extraction: ${name}`);
        riskScore += weight;
        directAttempt = true;
      }
    }

    // Check indirect extraction patterns
    if (this.config.detectIndirectExtraction) {
      for (const { name, pattern, weight } of this.INDIRECT_EXTRACTION_PATTERNS) {
        if (pattern.test(input)) {
          violations.push(`indirect_extraction: ${name}`);
          riskScore += weight;
          indirectAttempt = true;
        }
      }
    }

    // Check for Leetspeak evasion
    if (this.config.detectLeetspeak) {
      const decoded = this.decodeLeetspeak(input);
      if (decoded !== input.toLowerCase()) {
        // Check decoded against both direct and indirect patterns
        const leetspeakCheck = this.checkDecodedContent(decoded, "leetspeak");
        if (leetspeakCheck.detected) {
          violations.push(...leetspeakCheck.violations);
          riskScore += leetspeakCheck.riskContribution;
          evasionTechniques.push("leetspeak");
          encodedAttempt = true;
          decodedContent = decoded;
        } else {
          // Also check for keywords in decoded content
          const keywordCheck = this.checkKeywordsInDecoded(decoded);
          if (keywordCheck.detected) {
            violations.push(`leetspeak_keyword: ${keywordCheck.keywords.join(", ")}`);
            riskScore += 35;
            evasionTechniques.push("leetspeak");
            encodedAttempt = true;
            decodedContent = decoded;
          }
        }
      }
    }

    // Check for ROT13 evasion
    if (this.config.detectROT13) {
      const decoded = this.decodeROT13(input);
      const rot13Check = this.checkDecodedContent(decoded, "rot13");
      if (rot13Check.detected) {
        violations.push(...rot13Check.violations);
        riskScore += rot13Check.riskContribution;
        evasionTechniques.push("rot13");
        encodedAttempt = true;
        decodedContent = decoded;
      } else {
        // Check for keywords in ROT13 decoded content
        const keywordCheck = this.checkKeywordsInDecoded(decoded);
        if (keywordCheck.detected) {
          violations.push(`rot13_keyword: ${keywordCheck.keywords.join(", ")}`);
          riskScore += 40;
          evasionTechniques.push("rot13");
          encodedAttempt = true;
          decodedContent = decoded;
        }
      }
    }

    // Check for Base64 encoded content
    if (this.config.detectBase64) {
      const base64Matches = input.match(/[A-Za-z0-9+/]{16,}={0,2}/g);
      if (base64Matches) {
        for (const match of base64Matches) {
          try {
            const decoded = Buffer.from(match, "base64").toString("utf-8");
            if (decoded && /[\x20-\x7E]{4,}/.test(decoded)) {
              const base64Check = this.checkDecodedContent(decoded, "base64");
              if (base64Check.detected) {
                violations.push(...base64Check.violations);
                riskScore += base64Check.riskContribution;
                evasionTechniques.push("base64");
                encodedAttempt = true;
                decodedContent = decoded;
              } else {
                // Check for keywords in Base64 decoded content
                const keywordCheck = this.checkKeywordsInDecoded(decoded);
                if (keywordCheck.detected) {
                  violations.push(`base64_keyword: ${keywordCheck.keywords.join(", ")}`);
                  riskScore += 45;
                  evasionTechniques.push("base64");
                  encodedAttempt = true;
                  decodedContent = decoded;
                }
              }
            }
          } catch {
            // Not valid Base64
          }
        }
      }
    }

    // Check for Unicode evasion (homoglyphs, invisible chars)
    if (this.config.detectUnicode) {
      const unicodeCheck = this.checkUnicodeEvasion(input);
      if (unicodeCheck.detected) {
        violations.push(...unicodeCheck.violations);
        riskScore += unicodeCheck.riskContribution;
        evasionTechniques.push("unicode");
        encodedAttempt = true;
      }
    }

    // Check for Morse code
    if (this.config.detectMorse) {
      const morseCheck = this.checkMorseCode(input);
      if (morseCheck.detected) {
        violations.push(...morseCheck.violations);
        riskScore += morseCheck.riskContribution;
        evasionTechniques.push("morse");
        encodedAttempt = true;
      }
    }

    // Check custom patterns
    for (let i = 0; i < this.config.customPatterns.length; i++) {
      if (this.config.customPatterns[i].test(input)) {
        violations.push(`custom_pattern_${i}`);
        riskScore += 30;
      }
    }

    // Normalize risk score
    riskScore = Math.min(100, riskScore);
    const blocked = riskScore >= this.config.riskThreshold;

    return {
      allowed: !blocked,
      reason: blocked
        ? `Prompt extraction attempt detected (risk: ${riskScore})`
        : "Input validated",
      violations,
      request_id: reqId,
      analysis: {
        direct_extraction_attempt: directAttempt,
        encoded_extraction_attempt: encodedAttempt,
        indirect_extraction_attempt: indirectAttempt,
        evasion_techniques_detected: evasionTechniques,
        risk_score: riskScore,
        decoded_content: decodedContent,
      },
      recommendations: this.generateRecommendations(violations, evasionTechniques),
    };
  }

  /**
   * Monitor output for potential prompt leakage
   */
  checkOutput(output: string, requestId?: string): OutputLeakageResult {
    const reqId = requestId || `pl-out-${Date.now()}`;
    const violations: string[] = [];
    const keywordsFound: string[] = [];
    const potentialFragments: string[] = [];
    let leaked = false;

    if (!this.config.monitorOutput) {
      return {
        leaked: false,
        reason: "Output monitoring disabled",
        violations: [],
        request_id: reqId,
        analysis: {
          keywords_found: [],
          similarity_score: 0,
          potential_leakage_fragments: [],
        },
      };
    }

    // Check for system prompt keywords in output
    for (const keyword of this.config.systemPromptKeywords) {
      if (output.toLowerCase().includes(keyword.toLowerCase())) {
        keywordsFound.push(keyword);
        violations.push(`keyword_leaked: ${keyword}`);
      }
    }

    // Check for common prompt fragment patterns
    const promptFragmentPatterns = [
      /you\s+are\s+a[n]?\s+(helpful\s+)?assistant/i,
      /your\s+(role|purpose|goal)\s+is\s+to/i,
      /you\s+(must|should|will)\s+(always|never)/i,
      /do\s+not\s+(reveal|disclose|share)\s+(your|the)\s+(system|initial)/i,
      /\[system\]|\[instruction\]|<<sys>>|<\|system\|>/i,
      /as\s+an?\s+AI\s+(assistant|model|language\s+model)/i,
    ];

    for (const pattern of promptFragmentPatterns) {
      const match = output.match(pattern);
      if (match) {
        potentialFragments.push(match[0]);
        violations.push("prompt_fragment_detected");
      }
    }

    // Calculate similarity if hash provided
    let similarityScore = 0;
    // In production, you'd compare against actual system prompt hash
    // For now, we check fragment density
    similarityScore = potentialFragments.length / 10; // Rough heuristic

    leaked = keywordsFound.length > 0 || potentialFragments.length >= 2;

    return {
      leaked,
      reason: leaked
        ? `Potential prompt leakage detected: ${violations.slice(0, 3).join(", ")}`
        : "Output appears safe",
      violations,
      request_id: reqId,
      analysis: {
        keywords_found: keywordsFound,
        similarity_score: Math.min(1, similarityScore),
        potential_leakage_fragments: potentialFragments,
      },
      sanitized_output: leaked ? this.sanitizeOutput(output) : undefined,
    };
  }

  /**
   * Set system prompt keywords for output monitoring
   */
  setSystemPromptKeywords(keywords: string[]): void {
    this.config.systemPromptKeywords = keywords;
  }

  /**
   * Add custom extraction pattern
   */
  addPattern(pattern: RegExp): void {
    this.config.customPatterns.push(pattern);
  }

  /**
   * Update risk threshold
   */
  setRiskThreshold(threshold: number): void {
    this.config.riskThreshold = Math.max(0, Math.min(100, threshold));
  }

  // Private methods

  private decodeLeetspeak(input: string): string {
    let result = input.toLowerCase();
    // Extended leetspeak mappings
    const extendedMap: Record<string, string> = {
      ...this.LEETSPEAK_MAP,
      "0": "o",
      "1": "i",
      "3": "e",
      "4": "a",
      "5": "s",
      "7": "t",
      "8": "b",
      "9": "g",
      "@": "a",
      "$": "s",
      "!": "i",
      "|": "l",
      "(": "c",
      "+": "t",
      "#": "h",
    };
    for (const [leet, char] of Object.entries(extendedMap)) {
      result = result.split(leet).join(char);
    }
    return result;
  }

  private decodeROT13(input: string): string {
    return input
      .split("")
      .map((char) => this.ROT13_MAP[char] || char)
      .join("");
  }

  private checkDecodedContent(
    decoded: string,
    technique: string
  ): { detected: boolean; violations: string[]; riskContribution: number } {
    const violations: string[] = [];
    let riskContribution = 0;

    for (const { name, pattern, weight } of this.DIRECT_EXTRACTION_PATTERNS) {
      if (pattern.test(decoded)) {
        violations.push(`${technique}_evasion: ${name}`);
        riskContribution += weight + 10; // Extra penalty for evasion
      }
    }

    return {
      detected: violations.length > 0,
      violations,
      riskContribution,
    };
  }

  private checkUnicodeEvasion(input: string): {
    detected: boolean;
    violations: string[];
    riskContribution: number;
  } {
    const violations: string[] = [];
    let riskContribution = 0;

    // Check for invisible characters
    const invisibleChars = input.match(/[\u200B-\u200D\uFEFF\u2060-\u206F\u00AD]/g);
    if (invisibleChars && invisibleChars.length > 3) {
      violations.push("invisible_unicode_chars");
      riskContribution += 20;
    }

    // Check for homoglyphs (Cyrillic, Greek letters that look like Latin)
    const homoglyphs = input.match(/[\u0400-\u04FF\u0370-\u03FF]/g);
    if (homoglyphs && homoglyphs.length > 0) {
      // Normalize and check
      const normalized = input.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
      for (const { pattern } of this.DIRECT_EXTRACTION_PATTERNS) {
        if (pattern.test(normalized)) {
          violations.push("homoglyph_evasion");
          riskContribution += 30;
          break;
        }
      }
    }

    // Check for fullwidth characters
    const fullwidth = input.match(/[\uFF01-\uFF5E]/g);
    if (fullwidth && fullwidth.length > 5) {
      violations.push("fullwidth_chars");
      riskContribution += 15;
    }

    return {
      detected: violations.length > 0,
      violations,
      riskContribution,
    };
  }

  private checkMorseCode(input: string): {
    detected: boolean;
    violations: string[];
    riskContribution: number;
  } {
    const violations: string[] = [];
    let riskContribution = 0;

    // Check if input contains Morse-like patterns
    const morsePattern = /[.\-]{2,}\s+[.\-]{2,}/;
    if (morsePattern.test(input)) {
      // Check for known prompt-related Morse
      for (const keyword of this.MORSE_KEYWORDS) {
        if (input.includes(keyword)) {
          violations.push("morse_code_evasion");
          riskContribution += 35;
          break;
        }
      }
    }

    return {
      detected: violations.length > 0,
      violations,
      riskContribution,
    };
  }

  private checkKeywordsInDecoded(decoded: string): { detected: boolean; keywords: string[] } {
    // Action keywords (verbs that indicate extraction intent)
    const actionKeywords = ["reveal", "show", "display", "print", "output", "dump", "list", "give", "tell"];
    // Target keywords (what they're trying to extract)
    const targetKeywords = ["prompt", "instructions", "configuration", "config", "rules", "guidelines", "constraints", "system", "initial", "secret", "hidden", "internal"];

    const foundKeywords: string[] = [];
    const lowerDecoded = decoded.toLowerCase();

    // Check for action + target combination (strong indicator)
    let hasAction = false;
    let hasTarget = false;

    for (const keyword of actionKeywords) {
      if (lowerDecoded.includes(keyword)) {
        foundKeywords.push(keyword);
        hasAction = true;
      }
    }

    for (const keyword of targetKeywords) {
      if (lowerDecoded.includes(keyword)) {
        foundKeywords.push(keyword);
        hasTarget = true;
      }
    }

    // Detected if we have both an action AND a target
    // This catches "reveal your prompt", "show me instructions", etc.
    return {
      detected: hasAction && hasTarget,
      keywords: foundKeywords,
    };
  }

  private sanitizeOutput(output: string): string {
    let sanitized = output;

    // Remove common prompt fragments
    const fragmentPatterns = [
      /you\s+are\s+a[n]?\s+(helpful\s+)?assistant[^.]*\./gi,
      /your\s+(role|purpose|goal)\s+is\s+to[^.]*\./gi,
      /you\s+(must|should|will)\s+(always|never)[^.]*\./gi,
      /\[system\][^[\]]*\[\/system\]/gi,
      /<<sys>>[^<]*<<\/sys>>/gi,
    ];

    for (const pattern of fragmentPatterns) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }

    return sanitized;
  }

  private generateRecommendations(
    violations: string[],
    evasionTechniques: string[]
  ): string[] {
    const recommendations: string[] = [];

    if (violations.some((v) => v.includes("direct_extraction"))) {
      recommendations.push("Direct prompt extraction attempt blocked");
    }
    if (violations.some((v) => v.includes("indirect_extraction"))) {
      recommendations.push("Consider strengthening indirect extraction detection");
    }
    if (evasionTechniques.length > 0) {
      recommendations.push(
        `Evasion techniques detected: ${evasionTechniques.join(", ")}`
      );
    }
    if (violations.some((v) => v.includes("unicode"))) {
      recommendations.push("Normalize input before processing");
    }

    if (recommendations.length === 0) {
      recommendations.push("Input validated successfully");
    }

    return recommendations;
  }
}
