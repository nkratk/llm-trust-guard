/**
 * HeuristicAnalyzer
 *
 * Advanced heuristic detection using three techniques from research (DMPI-PMHFE, 2026):
 *
 * 1. SYNONYM EXPANSION — Expand injection keywords to catch paraphrased attacks
 *    Instead of matching "ignore" only, match {ignore, disregard, overlook, neglect, skip, bypass, omit...}
 *
 * 2. STRUCTURAL PATTERN ANALYSIS — Detect instruction-like sentence structures
 *    Imperative commands, Q&A injection (many-shot), repeated token attacks
 *
 * 3. STATISTICAL FEATURES — Score inputs based on statistical properties
 *    Instruction word density, special character ratio, command-to-question ratio
 *
 * These techniques are zero-dependency, pure string analysis — no ML required.
 * Research shows they add +10-15pp detection over keyword-only regex.
 */

export interface HeuristicAnalyzerConfig {
  /** Enable synonym expansion (default: true) */
  synonymExpansion?: boolean;
  /** Enable structural pattern analysis (default: true) */
  structuralAnalysis?: boolean;
  /** Enable statistical feature scoring (default: true) */
  statisticalScoring?: boolean;
  /** Risk threshold for blocking (0-1, default: 0.6) */
  riskThreshold?: number;
  /** Q&A pair threshold for many-shot detection (default: 3) */
  manyShotThreshold?: number;
  /** Repeated token threshold (default: 3) */
  repeatedTokenThreshold?: number;
}

export interface HeuristicResult {
  allowed: boolean;
  reason?: string;
  riskScore: number;
  features: HeuristicFeatures;
  violations: string[];
}

export interface HeuristicFeatures {
  // Synonym matching (8 categories)
  is_ignore: boolean;
  is_urgent: boolean;
  is_incentive: boolean;
  is_covert: boolean;
  is_format_manipulation: boolean;
  is_hypothetical: boolean;
  is_systemic: boolean;
  is_immoral: boolean;
  synonym_categories_matched: number;
  // Structural patterns
  is_shot_attack: boolean;
  is_repeated_token: boolean;
  is_imperative: boolean;
  is_role_assignment: boolean;
  structural_score: number;
  // Statistical features
  instruction_word_density: number;
  special_char_ratio: number;
  uppercase_ratio: number;
  average_word_length: number;
  statistical_score: number;
}

/**
 * Synonym sets for 8 attack categories
 * Based on DMPI-PMHFE paper (2026) + expanded with additional synonyms
 * All lowercase for matching
 */
type SynonymCategory =
  | "ignore"
  | "urgent"
  | "incentive"
  | "covert"
  | "format_manipulation"
  | "hypothetical"
  | "systemic"
  | "immoral";

type SynonymFeatureKey = `is_${SynonymCategory}`;

const SYNONYM_SETS: Record<SynonymCategory, { keywords: Set<string>; weight: number }> = {
  ignore: {
    keywords: new Set([
      "ignore", "disregard", "overlook", "neglect", "skip", "bypass", "omit",
      "dismiss", "override", "overrule", "forget", "abandon", "drop", "ditch",
      "scrap", "discard", "set aside", "pay no attention", "turn a blind eye",
      "look past", "brush off", "shrug off", "wave away", "cast aside",
      "put aside", "leave behind", "throw out", "toss out",
    ]),
    weight: 0.3,
  },
  urgent: {
    keywords: new Set([
      "urgent", "immediate", "immediately", "asap", "emergency", "critical",
      "time-sensitive", "pressing", "crucial", "dire", "life-threatening",
      "now", "hurry", "rush", "quick", "fast", "right away", "without delay",
      "time is running out", "deadline",
    ]),
    weight: 0.15,
  },
  incentive: {
    keywords: new Set([
      "excellent", "fantastic", "nice", "awesome", "brilliant", "great",
      "amazing", "wonderful", "superb", "outstanding", "reward", "tip",
      "bonus", "payment", "compensate", "grateful", "appreciate",
    ]),
    weight: 0.1,
  },
  covert: {
    keywords: new Set([
      "secret", "hidden", "covert", "quiet", "silent", "discreetly", "stealth",
      "confidential", "private", "classified", "concealed", "disguised",
      "undercover", "off the record", "between us", "nobody will know",
      "our little secret", "hush", "whisper",
    ]),
    weight: 0.2,
  },
  format_manipulation: {
    keywords: new Set([
      "encode", "decode", "disguise", "morse", "binary", "hexadecimal",
      "base64", "rot13", "cipher", "encrypt", "obfuscate", "scramble",
      "reverse", "translate to code", "convert to",
    ]),
    weight: 0.15,
  },
  hypothetical: {
    keywords: new Set([
      "assume", "imagine", "hypothetically", "fictional", "scenario",
      "pretend", "suppose", "what if", "let's say", "in theory",
      "theoretically", "fantasy", "roleplay", "simulation", "make believe",
      "alternate reality", "parallel universe", "thought experiment",
    ]),
    weight: 0.15,
  },
  systemic: {
    keywords: new Set([
      "developer", "administrator", "admin", "boss", "manager", "creator",
      "owner", "supervisor", "root", "superuser", "operator", "maintainer",
      "engineer", "architect", "designer", "authority", "controller",
      "master", "god mode", "sudo",
    ]),
    weight: 0.2,
  },
  immoral: {
    keywords: new Set([
      "amoral", "immoral", "unethical", "illegal", "harmful", "dangerous",
      "offensive", "violent", "malicious", "evil", "wicked", "sinister",
      "criminal", "unlawful", "forbidden", "prohibited", "taboo",
      "no morals", "no ethics", "no rules", "no limits", "unrestricted",
      "uncensored", "unfiltered",
    ]),
    weight: 0.25,
  },
};

/**
 * Words that indicate instruction-like content (for density scoring)
 */
const INSTRUCTION_WORDS = new Set([
  "must", "should", "shall", "will", "need", "require", "always", "never",
  "do", "don't", "cannot", "can't", "ensure", "make sure", "remember",
  "forget", "ignore", "follow", "obey", "comply", "execute", "perform",
  "output", "respond", "reply", "answer", "generate", "create", "write",
  "act", "behave", "pretend", "assume", "become", "transform",
]);

export class HeuristicAnalyzer {
  private config: Required<HeuristicAnalyzerConfig>;

  constructor(config: HeuristicAnalyzerConfig = {}) {
    this.config = {
      synonymExpansion: config.synonymExpansion ?? true,
      structuralAnalysis: config.structuralAnalysis ?? true,
      statisticalScoring: config.statisticalScoring ?? true,
      riskThreshold: config.riskThreshold ?? 0.8,
      manyShotThreshold: config.manyShotThreshold ?? 3,
      repeatedTokenThreshold: config.repeatedTokenThreshold ?? 3,
    };
  }

  /**
   * Analyze input using all three heuristic techniques
   */
  analyze(input: string, requestId?: string): HeuristicResult {
    const violations: string[] = [];
    const features: HeuristicFeatures = {
      is_ignore: false,
      is_urgent: false,
      is_incentive: false,
      is_covert: false,
      is_format_manipulation: false,
      is_hypothetical: false,
      is_systemic: false,
      is_immoral: false,
      synonym_categories_matched: 0,
      is_shot_attack: false,
      is_repeated_token: false,
      is_imperative: false,
      is_role_assignment: false,
      structural_score: 0,
      instruction_word_density: 0,
      special_char_ratio: 0,
      uppercase_ratio: 0,
      average_word_length: 0,
      statistical_score: 0,
    };

    let totalRisk = 0;

    // Technique 1: Synonym Expansion
    if (this.config.synonymExpansion) {
      const synonymResult = this.checkSynonyms(input);
      Object.assign(features, synonymResult.features);
      totalRisk += synonymResult.risk;
      if (synonymResult.risk > 0) {
        violations.push(...synonymResult.matched.map(m => `SYNONYM_${m.toUpperCase()}`));
      }
    }

    // Technique 2: Structural Pattern Analysis
    if (this.config.structuralAnalysis) {
      const structResult = this.checkStructure(input);
      features.is_shot_attack = structResult.is_shot_attack;
      features.is_repeated_token = structResult.is_repeated_token;
      features.is_imperative = structResult.is_imperative;
      features.is_role_assignment = structResult.is_role_assignment;
      features.structural_score = structResult.score;
      totalRisk += structResult.score;
      if (structResult.violations.length > 0) {
        violations.push(...structResult.violations);
      }
    }

    // Technique 3: Statistical Feature Scoring
    if (this.config.statisticalScoring) {
      const statResult = this.scoreStatistics(input);
      features.instruction_word_density = statResult.instruction_word_density;
      features.special_char_ratio = statResult.special_char_ratio;
      features.uppercase_ratio = statResult.uppercase_ratio;
      features.average_word_length = statResult.average_word_length;
      features.statistical_score = statResult.score;
      totalRisk += statResult.score;
    }

    // Compound risk: multiple categories matching is more suspicious
    if (features.synonym_categories_matched >= 3) {
      totalRisk += 0.15; // Bonus risk for multi-category attack
      violations.push("MULTI_CATEGORY_COMPOUND");
    }

    const riskScore = Math.min(1, totalRisk);
    const allowed = riskScore < this.config.riskThreshold;

    return {
      allowed,
      reason: allowed ? undefined : `Heuristic analysis risk ${riskScore.toFixed(2)} exceeds threshold ${this.config.riskThreshold}`,
      riskScore,
      features,
      violations,
    };
  }

  /**
   * Technique 1: Synonym Expansion
   * Check if input tokens match expanded synonym sets for 8 attack categories
   */
  private checkSynonyms(input: string): { features: Partial<HeuristicFeatures>; risk: number; matched: string[] } {
    // Tokenize and normalize
    const tokens = input.toLowerCase().split(/\s+/).map(t => t.replace(/[^a-z'-]/g, "")).filter(t => t.length > 2);
    const inputLower = input.toLowerCase();

    const features: Partial<HeuristicFeatures> = {};
    let risk = 0;
    const matched: string[] = [];
    let categoriesMatched = 0;

    for (const [category, { keywords, weight }] of Object.entries(SYNONYM_SETS) as [SynonymCategory, { keywords: Set<string>; weight: number }][]) {
      let found = false;

      // Check individual tokens
      for (const token of tokens) {
        if (keywords.has(token)) {
          found = true;
          break;
        }
      }

      // Check multi-word phrases
      if (!found) {
        for (const keyword of keywords) {
          if (keyword.includes(" ") && inputLower.includes(keyword)) {
            found = true;
            break;
          }
        }
      }

      const featureKey: SynonymFeatureKey = `is_${category}`;
      if (found) {
        features[featureKey] = true;
        risk += weight;
        matched.push(category);
        categoriesMatched++;
      } else {
        features[featureKey] = false;
      }
    }

    features.synonym_categories_matched = categoriesMatched;
    return { features, risk, matched };
  }

  /**
   * Technique 2: Structural Pattern Analysis
   * Detect instruction-like sentence structures
   */
  private checkStructure(input: string): {
    is_shot_attack: boolean;
    is_repeated_token: boolean;
    is_imperative: boolean;
    is_role_assignment: boolean;
    score: number;
    violations: string[];
  } {
    const violations: string[] = [];
    let score = 0;

    // Many-shot detection: count Q&A-like pairs
    const qaPattern = /(?:Q:|Question:|Human:|User:)[\s\S]*?(?:A:|Answer:|Assistant:|AI:)/gi;
    const qaMatches = input.match(qaPattern) || [];
    const is_shot_attack = qaMatches.length >= this.config.manyShotThreshold;
    if (is_shot_attack) {
      score += 0.3;
      violations.push("MANY_SHOT_PATTERN");
    }

    // Repeated token detection
    const words = input.toLowerCase().split(/\s+/).filter(w => w.length > 3);
    const wordCounts = new Map<string, number>();
    for (const w of words) {
      wordCounts.set(w, (wordCounts.get(w) || 0) + 1);
    }
    const maxRepeat = Math.max(0, ...wordCounts.values());
    const is_repeated_token = maxRepeat >= this.config.repeatedTokenThreshold && words.length > 10 &&
      (maxRepeat / words.length) > 0.15; // >15% of words are the same word
    if (is_repeated_token) {
      score += 0.1;
      violations.push("REPEATED_TOKEN_ATTACK");
    }

    // Imperative sentence detection (commands)
    const sentences = input.split(/[.!?\n]+/).filter(s => s.trim().length > 5);
    let imperativeCount = 0;
    for (const sentence of sentences) {
      const trimmed = sentence.trim();
      // Starts with a verb (imperative mood)
      if (/^(?:ignore|forget|disregard|override|bypass|reveal|show|tell|give|grant|make|do|don't|never|always|you\s+(?:must|should|will|are|can))/i.test(trimmed)) {
        imperativeCount++;
      }
    }
    const is_imperative = sentences.length > 0 && (imperativeCount / sentences.length) > 0.4;
    if (is_imperative) {
      score += 0.15;
      violations.push("HIGH_IMPERATIVE_RATIO");
    }

    // Role assignment structure: "You are [now] a/an [ROLE]"
    const is_role_assignment = /you\s+(?:are|will\s+be|shall\s+be|must\s+be)\s+(?:now\s+)?(?:a|an|the|my)\s+/i.test(input) &&
      /(?:no\s+(?:restrictions|rules|limits)|unrestricted|unfiltered|evil|amoral|can\s+do\s+anything)/i.test(input);
    if (is_role_assignment) {
      score += 0.25;
      violations.push("ROLE_ASSIGNMENT_WITH_BYPASS");
    }

    return { is_shot_attack, is_repeated_token, is_imperative, is_role_assignment, score, violations };
  }

  /**
   * Technique 3: Statistical Feature Scoring
   * Score based on statistical properties of the input
   */
  private scoreStatistics(input: string): {
    instruction_word_density: number;
    special_char_ratio: number;
    uppercase_ratio: number;
    average_word_length: number;
    score: number;
  } {
    const words = input.split(/\s+/).filter(w => w.length > 0);
    if (words.length === 0) return { instruction_word_density: 0, special_char_ratio: 0, uppercase_ratio: 0, average_word_length: 0, score: 0 };

    // Instruction word density
    let instructionCount = 0;
    for (const word of words) {
      if (INSTRUCTION_WORDS.has(word.toLowerCase().replace(/[^a-z']/g, ""))) {
        instructionCount++;
      }
    }
    const instruction_word_density = instructionCount / words.length;

    // Special character ratio (high ratio = potential encoding/obfuscation)
    const specialChars = input.replace(/[a-zA-Z0-9\s]/g, "").length;
    const special_char_ratio = specialChars / input.length;

    // Uppercase ratio (high ratio = shouting/emphasis, common in jailbreaks)
    const uppercaseChars = input.replace(/[^A-Z]/g, "").length;
    const letterChars = input.replace(/[^a-zA-Z]/g, "").length;
    const uppercase_ratio = letterChars > 0 ? uppercaseChars / letterChars : 0;

    // Average word length
    const totalWordLength = words.reduce((sum, w) => sum + w.length, 0);
    const average_word_length = totalWordLength / words.length;

    // Score based on statistical anomalies
    let score = 0;

    // High instruction density is suspicious
    if (instruction_word_density > 0.15) score += 0.1;
    if (instruction_word_density > 0.25) score += 0.1;

    // Very high uppercase ratio (>40% caps) is suspicious
    if (uppercase_ratio > 0.4 && letterChars > 20) score += 0.05;

    return { instruction_word_density, special_char_ratio, uppercase_ratio, average_word_length, score };
  }
}
