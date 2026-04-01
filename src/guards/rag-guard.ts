/**
 * RAGGuard (L10) v2
 *
 * Validates RAG (Retrieval Augmented Generation) content before injection.
 * Protects against supply chain attacks via poisoned documents and embeddings.
 *
 * Threat Model:
 * - ASI04: Agentic Supply Chain Vulnerabilities
 * - RAG Poisoning: Malicious content in retrieved documents
 * - Embedding manipulation attacks
 * - Indirect prompt injection via documents
 *
 * Protection Capabilities (v2 Enhanced):
 * - Retrieved document sanitization
 * - Source verification and trust scoring
 * - Injection pattern detection in documents
 * - Content integrity verification
 * - Suspicious document quarantine
 * - Advanced embedding attack detection (backdoor, adversarial)
 * - Unicode steganography detection
 * - Markdown/HTML hidden instruction detection
 * - Cross-document similarity anomaly detection
 * - Embedding norm and distribution analysis
 */

import * as crypto from "crypto";

export interface RAGGuardConfig {
  /** Enable injection detection in retrieved content */
  detectInjections?: boolean;
  /** Enable source verification */
  verifySource?: boolean;
  /** Trusted document sources (domains, paths) */
  trustedSources?: string[];
  /** Blocked document sources */
  blockedSources?: string[];
  /** Maximum document size in characters */
  maxDocumentSize?: number;
  /** Minimum trust score to allow (0-100) */
  minTrustScore?: number;
  /** Enable content hashing for integrity */
  enableContentHashing?: boolean;
  /** Known good content hashes */
  knownGoodHashes?: Set<string>;
  /** Auto-sanitize dangerous content */
  autoSanitize?: boolean;
  // v2 Enhanced options
  /** Enable advanced embedding attack detection */
  detectEmbeddingAttacks?: boolean;
  /** Embedding dimension for validation */
  embeddingDimension?: number;
  /** Enable Unicode steganography detection */
  detectSteganography?: boolean;
  /** Enable cross-document similarity analysis */
  detectClusteringAnomalies?: boolean;
  /** Expected embedding magnitude range */
  embeddingMagnitudeRange?: [number, number];
  /** Cosine similarity threshold for anomaly detection */
  similarityThreshold?: number;
  /** Enable indirect prompt injection detection */
  detectIndirectInjection?: boolean;
}

/** Result of embedding attack analysis */
export interface EmbeddingAttackResult {
  detected: boolean;
  attack_type: string[];
  risk_score: number;
  details: {
    magnitude_anomaly?: boolean;
    distribution_anomaly?: boolean;
    backdoor_pattern?: boolean;
    adversarial_perturbation?: boolean;
    clustering_anomaly?: boolean;
  };
}

export interface RAGDocument {
  /** Document identifier */
  id: string;
  /** Document content */
  content: string;
  /** Source URL or path */
  source: string;
  /** Document metadata */
  metadata?: {
    title?: string;
    author?: string;
    lastModified?: string;
    contentType?: string;
    [key: string]: any;
  };
  /** Embedding vector (for detection of manipulation) */
  embedding?: number[];
  /** Retrieval score from vector DB */
  retrievalScore?: number;
  /** Content hash if pre-computed */
  contentHash?: string;
}

export interface RAGGuardResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  document_analysis: {
    documents_checked: number;
    documents_blocked: number;
    documents_sanitized: number;
    injection_attempts: number;
    untrusted_sources: string[];
    average_trust_score: number;
    // v2 additions
    embedding_attacks_detected: number;
    steganography_detected: number;
    indirect_injection_attempts: number;
  };
  sanitized_documents?: RAGDocument[];
  blocked_document_ids: string[];
  recommendations: string[];
  // v2 additions
  embedding_analysis?: EmbeddingAttackResult[];
}

export interface SourceTrustResult {
  trusted: boolean;
  score: number;
  reason: string;
}

export class RAGGuard {
  private config: Required<RAGGuardConfig>;
  private contentHashCache: Map<string, string> = new Map();
  private sourceReputationCache: Map<string, number> = new Map();

  // Injection patterns specifically targeting RAG/document content
  private readonly RAG_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: number }> = [
    // Direct instruction injection
    { name: "instruction_override", pattern: /ignore\s+(all\s+)?previous\s+(context|documents|information)/i, severity: 50 },
    { name: "system_instruction", pattern: /\[SYSTEM\]|\[INSTRUCTION\]|\[OVERRIDE\]|<system>|<instruction>/i, severity: 45 },
    { name: "role_injection", pattern: /you\s+(are|must|should)\s+(now\s+)?(be|act\s+as|become)/i, severity: 40 },

    // Delimiter injection (to break out of RAG context)
    { name: "delimiter_break", pattern: /---\s*(end|stop)\s*(of\s*)?(context|document|rag)/i, severity: 45 },
    { name: "context_escape", pattern: /\]\]\]|\}\}\}|<<<|>>>|'''|"""/g, severity: 30 },

    // Hidden instruction markers
    { name: "hidden_instruction", pattern: /HIDDEN:|SECRET:|INVISIBLE:|DO_NOT_DISPLAY:/i, severity: 50 },
    { name: "admin_marker", pattern: /ADMIN_INSTRUCTION|ROOT_COMMAND|ELEVATED_PROMPT/i, severity: 55 },

    // Data exfiltration setup
    { name: "exfil_setup", pattern: /send\s+(all|this|data)\s+to|forward\s+to\s+https?:\/\//i, severity: 50 },
    { name: "callback_injection", pattern: /callback\s*[:=]\s*https?:\/\/|webhook\s*[:=]/i, severity: 45 },

    // Tool/action injection via documents
    { name: "tool_injection", pattern: /call\s+(tool|function|action)\s*[:=]|execute\s*[:=]/i, severity: 45 },
    { name: "code_injection", pattern: /```(javascript|python|bash|sh)\s*\n[^`]*\b(eval|exec|system|subprocess)\b/i, severity: 50 },

    // Persona/behavior modification
    { name: "persona_override", pattern: /your\s+(new\s+)?(persona|identity|character)\s+(is|will\s+be)/i, severity: 40 },
    { name: "behavior_mod", pattern: /always\s+(respond|reply|answer)\s+with|never\s+(mention|reveal|disclose)/i, severity: 35 },

    // Prompt leakage attempts
    { name: "prompt_extraction", pattern: /reveal\s+(your\s+)?(system\s+)?prompt|show\s+(me\s+)?(your\s+)?instructions/i, severity: 40 },
    { name: "debug_mode", pattern: /enable\s+debug|activate\s+developer\s+mode|enter\s+test\s+mode/i, severity: 35 },
  ];

  // Suspicious metadata patterns
  private readonly SUSPICIOUS_METADATA_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    { name: "script_in_title", pattern: /<script|javascript:/i },
    { name: "injection_in_author", pattern: /admin|system|root|override/i },
    { name: "suspicious_content_type", pattern: /application\/x-|text\/x-/i },
  ];

  // Known malicious source patterns
  private readonly MALICIOUS_SOURCE_PATTERNS = [
    /pastebin\.com/i,
    /hastebin\.com/i,
    /gist\.githubusercontent\.com.*injection/i,
    /raw\.githubusercontent\.com.*malicious/i,
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses
  ];

  // Indirect prompt injection patterns (v2)
  private readonly INDIRECT_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: number }> = [
    // HTML/Markdown hidden instructions
    { name: "html_comment_injection", pattern: /<!--[\s\S]*?(ignore|override|system|instruction|admin)[\s\S]*?-->/i, severity: 45 },
    { name: "markdown_hidden", pattern: /\[[\s\S]*?\]\(javascript:|data:text\/html|about:blank\)/i, severity: 50 },
    { name: "invisible_link", pattern: /\[]\([^)]+\)/g, severity: 30 },

    // Unicode steganography
    { name: "zero_width_chars", pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF]{3,}/g, severity: 40 },
    { name: "rtl_override", pattern: /[\u202A-\u202E\u2066-\u2069]/g, severity: 35 },
    { name: "confusable_chars", pattern: /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445]/g, severity: 25 }, // Cyrillic lookalikes

    // Whitespace injection
    { name: "excessive_whitespace", pattern: /[\t\n\r]{10,}/g, severity: 20 },
    { name: "tab_encoding", pattern: /\t{5,}/g, severity: 25 },

    // Encoded instructions - enhanced detection
    { name: "base64_block", pattern: /[A-Za-z0-9+/]{40,}={0,2}/g, severity: 40 },
    { name: "base64_with_context", pattern: /(?:encode|decode|base64|reference)[:\s]*[A-Za-z0-9+/]{20,}/i, severity: 45 },
    { name: "hex_encoded", pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/g, severity: 35 },
    { name: "unicode_escape", pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}/g, severity: 35 },

    // Context switching attempts
    { name: "fake_boundary", pattern: /={5,}|#{5,}|-{10,}/g, severity: 20 },
    { name: "json_injection", pattern: /\{"(role|content|system)":/i, severity: 45 },
    { name: "xml_injection", pattern: /<\/?(?:prompt|assistant|user|system)>/i, severity: 45 },
  ];

  constructor(config: RAGGuardConfig = {}) {
    this.config = {
      detectInjections: config.detectInjections ?? true,
      verifySource: config.verifySource ?? true,
      trustedSources: config.trustedSources ?? [],
      blockedSources: config.blockedSources ?? [],
      maxDocumentSize: config.maxDocumentSize ?? 50000, // 50KB
      minTrustScore: config.minTrustScore ?? 30,
      enableContentHashing: config.enableContentHashing ?? true,
      knownGoodHashes: config.knownGoodHashes ?? new Set(),
      autoSanitize: config.autoSanitize ?? true,
      // v2 options
      detectEmbeddingAttacks: config.detectEmbeddingAttacks ?? true,
      embeddingDimension: config.embeddingDimension ?? 1536, // OpenAI default
      detectSteganography: config.detectSteganography ?? true,
      detectClusteringAnomalies: config.detectClusteringAnomalies ?? true,
      embeddingMagnitudeRange: config.embeddingMagnitudeRange ?? [0.8, 1.2],
      similarityThreshold: config.similarityThreshold ?? 0.95,
      detectIndirectInjection: config.detectIndirectInjection ?? true,
    };
  }

  /**
   * Validate RAG documents before injecting into context
   */
  validate(
    documents: RAGDocument[],
    requestId?: string
  ): RAGGuardResult {
    const reqId = requestId || `rag-${Date.now()}`;
    const violations: string[] = [];
    const blockedIds: string[] = [];
    const untrustedSources: string[] = [];
    const sanitizedDocs: RAGDocument[] = [];
    const embeddingAnalysis: EmbeddingAttackResult[] = [];
    let injectionAttempts = 0;
    let documentsBlocked = 0;
    let documentsSanitized = 0;
    let totalTrustScore = 0;
    let embeddingAttacksDetected = 0;
    let steganographyDetected = 0;
    let indirectInjectionAttempts = 0;

    for (const doc of documents) {
      let docViolations: string[] = [];
      let docRiskScore = 0;
      let shouldBlock = false;
      let needsSanitization = false;

      // Check document size
      if (doc.content.length > this.config.maxDocumentSize) {
        docViolations.push("oversized_document");
        docRiskScore += 20;
      }

      // Verify source
      if (this.config.verifySource) {
        const sourceResult = this.verifyDocumentSource(doc.source);
        if (!sourceResult.trusted) {
          docViolations.push(`untrusted_source: ${sourceResult.reason}`);
          untrustedSources.push(doc.source);
          docRiskScore += 100 - sourceResult.score;

          if (sourceResult.score < this.config.minTrustScore) {
            shouldBlock = true;
          }
        }
        totalTrustScore += sourceResult.score;
      } else {
        totalTrustScore += 50; // Neutral score when not verifying
      }

      // Check content hash if enabled
      if (this.config.enableContentHashing) {
        const hash = this.hashContent(doc.content);
        if (doc.contentHash && doc.contentHash !== hash) {
          docViolations.push("content_hash_mismatch");
          docRiskScore += 40;
          shouldBlock = true;
        }

        // Check against known good hashes
        if (this.config.knownGoodHashes.has(hash)) {
          docRiskScore = Math.max(0, docRiskScore - 30); // Reduce risk for known good content
        }
      }

      // Check for injection patterns
      if (this.config.detectInjections) {
        const injectionResult = this.detectInjections(doc.content);
        if (injectionResult.found) {
          injectionAttempts += injectionResult.patterns.length;
          docViolations.push(...injectionResult.violations);
          docRiskScore += injectionResult.riskContribution;
          needsSanitization = true;

          if (injectionResult.riskContribution >= 50) {
            shouldBlock = true;
          }
        }
      }

      // Check metadata
      if (doc.metadata) {
        const metadataResult = this.checkMetadata(doc.metadata);
        if (metadataResult.suspicious) {
          docViolations.push(...metadataResult.violations);
          docRiskScore += metadataResult.riskContribution;
        }
      }

      // Check embedding anomalies (basic) - runs first to catch critical issues
      if (doc.embedding) {
        // Critical: Check for invalid values (NaN, Infinity, null, non-numbers)
        // Note: JSON serialization converts NaN/Infinity to null
        const hasInvalidValues = doc.embedding.some((v: any) =>
          v === null ||
          v === undefined ||
          typeof v !== "number" ||
          !isFinite(v) ||
          isNaN(v)
        );
        if (hasInvalidValues) {
          docViolations.push("embedding_contains_invalid_values");
          docRiskScore += 50;
          shouldBlock = true;
        }

        if (doc.retrievalScore !== undefined) {
          const embeddingResult = this.checkEmbedding(doc.embedding, doc.retrievalScore);
          if (embeddingResult.anomalous) {
            docViolations.push(`embedding_anomaly: ${embeddingResult.reason}`);
            docRiskScore += 35;
            if (embeddingResult.shouldBlock) {
              shouldBlock = true;
            }
          }
        }
      }

      // v2: Advanced embedding attack detection
      if (this.config.detectEmbeddingAttacks && doc.embedding) {
        const embeddingAttack = this.detectEmbeddingAttacks(doc.embedding, doc.retrievalScore);
        if (embeddingAttack.detected) {
          embeddingAttacksDetected++;
          embeddingAnalysis.push(embeddingAttack);
          docViolations.push(...embeddingAttack.attack_type.map(t => `embedding_attack: ${t}`));
          docRiskScore += embeddingAttack.risk_score;
          if (embeddingAttack.risk_score >= 40) {
            shouldBlock = true;
          }
        }
      }

      // v2: Indirect injection detection
      if (this.config.detectIndirectInjection) {
        const indirectResult = this.detectIndirectInjection(doc.content);
        if (indirectResult.found) {
          indirectInjectionAttempts += indirectResult.patterns.length;
          docViolations.push(...indirectResult.violations);
          docRiskScore += indirectResult.riskContribution;
          needsSanitization = true;
          if (indirectResult.riskContribution >= 40) {
            shouldBlock = true;
          }
        }
      }

      // v2: Steganography detection
      if (this.config.detectSteganography) {
        const stegoResult = this.detectSteganography(doc.content);
        if (stegoResult.found) {
          steganographyDetected++;
          docViolations.push(...stegoResult.violations);
          docRiskScore += stegoResult.riskContribution;
          needsSanitization = true;
        }
      }

      // Decision for this document
      if (shouldBlock || docRiskScore >= 70) {
        blockedIds.push(doc.id);
        documentsBlocked++;
        violations.push(...docViolations.map((v) => `[${doc.id}] ${v}`));
      } else if (needsSanitization && this.config.autoSanitize) {
        const sanitized = this.sanitizeDocument(doc);
        sanitizedDocs.push(sanitized);
        documentsSanitized++;
        violations.push(...docViolations.map((v) => `[${doc.id}] ${v} (sanitized)`));
      } else {
        sanitizedDocs.push(doc);
        if (docViolations.length > 0) {
          violations.push(...docViolations.map((v) => `[${doc.id}] ${v} (allowed)`));
        }
      }
    }

    const averageTrustScore = documents.length > 0 ? totalTrustScore / documents.length : 0;
    const blocked = documentsBlocked === documents.length || averageTrustScore < this.config.minTrustScore;

    return {
      allowed: !blocked,
      reason: blocked
        ? `RAG content blocked: ${documentsBlocked}/${documents.length} documents failed validation`
        : "RAG content validated",
      violations,
      request_id: reqId,
      document_analysis: {
        documents_checked: documents.length,
        documents_blocked: documentsBlocked,
        documents_sanitized: documentsSanitized,
        injection_attempts: injectionAttempts,
        untrusted_sources: [...new Set(untrustedSources)],
        average_trust_score: Math.round(averageTrustScore),
        // v2 additions
        embedding_attacks_detected: embeddingAttacksDetected,
        steganography_detected: steganographyDetected,
        indirect_injection_attempts: indirectInjectionAttempts,
      },
      sanitized_documents: blocked ? undefined : sanitizedDocs,
      blocked_document_ids: blockedIds,
      recommendations: this.generateRecommendations(violations, untrustedSources.length > 0),
      // v2 addition
      embedding_analysis: embeddingAnalysis.length > 0 ? embeddingAnalysis : undefined,
    };
  }

  /**
   * Validate a single document
   */
  validateSingle(
    document: RAGDocument,
    requestId?: string
  ): RAGGuardResult {
    return this.validate([document], requestId);
  }

  /**
   * Verify document source trustworthiness
   */
  verifyDocumentSource(source: string): SourceTrustResult {
    // Check cache
    const cached = this.sourceReputationCache.get(source);
    if (cached !== undefined) {
      return {
        trusted: cached >= this.config.minTrustScore,
        score: cached,
        reason: cached >= this.config.minTrustScore ? "Cached trusted source" : "Cached untrusted source",
      };
    }

    let score = 50; // Neutral starting point
    let reason = "Unknown source";

    // Check blocked sources
    for (const blocked of this.config.blockedSources) {
      if (source.includes(blocked) || new RegExp(blocked, "i").test(source)) {
        this.sourceReputationCache.set(source, 0);
        return { trusted: false, score: 0, reason: "Blocked source" };
      }
    }

    // Check malicious patterns
    for (const pattern of this.MALICIOUS_SOURCE_PATTERNS) {
      if (pattern.test(source)) {
        this.sourceReputationCache.set(source, 10);
        return { trusted: false, score: 10, reason: "Matches malicious source pattern" };
      }
    }

    // Check trusted sources
    for (const trusted of this.config.trustedSources) {
      if (source.includes(trusted) || new RegExp(trusted, "i").test(source)) {
        this.sourceReputationCache.set(source, 90);
        return { trusted: true, score: 90, reason: "Trusted source" };
      }
    }

    // Analyze source URL/path
    try {
      const url = new URL(source);

      // HTTPS is more trusted
      if (url.protocol === "https:") {
        score += 15;
        reason = "HTTPS source";
      }

      // Well-known domains get bonus
      const trustedDomains = [".gov", ".edu", ".org", "wikipedia.org", "microsoft.com", "google.com"];
      for (const domain of trustedDomains) {
        if (url.hostname.endsWith(domain)) {
          score += 20;
          reason = `Trusted domain: ${domain}`;
          break;
        }
      }

      // Suspicious URL patterns
      if (url.pathname.includes("..") || url.search.includes("<")) {
        score -= 30;
        reason = "Suspicious URL pattern";
      }
    } catch {
      // Local file path
      if (source.startsWith("/") || source.match(/^[A-Z]:\\/)) {
        score = 60;
        reason = "Local file path";
      }
    }

    this.sourceReputationCache.set(source, score);
    return {
      trusted: score >= this.config.minTrustScore,
      score,
      reason,
    };
  }

  /**
   * Add trusted source
   */
  addTrustedSource(source: string): void {
    if (!this.config.trustedSources.includes(source)) {
      this.config.trustedSources.push(source);
    }
    this.sourceReputationCache.set(source, 90);
  }

  /**
   * Add blocked source
   */
  addBlockedSource(source: string): void {
    if (!this.config.blockedSources.includes(source)) {
      this.config.blockedSources.push(source);
    }
    this.sourceReputationCache.set(source, 0);
  }

  /**
   * Register known good content hash
   */
  registerKnownGoodHash(content: string): string {
    const hash = this.hashContent(content);
    this.config.knownGoodHashes.add(hash);
    return hash;
  }

  /**
   * Clear source reputation cache
   */
  clearSourceCache(): void {
    this.sourceReputationCache.clear();
  }

  private detectInjections(content: string): {
    found: boolean;
    patterns: string[];
    violations: string[];
    riskContribution: number;
  } {
    const patterns: string[] = [];
    const violations: string[] = [];
    let riskContribution = 0;

    for (const { name, pattern, severity } of this.RAG_INJECTION_PATTERNS) {
      const matches = content.match(pattern);
      if (matches) {
        patterns.push(name);
        violations.push(`injection_${name}`);
        riskContribution += severity;
      }
    }

    // Check for excessive special characters (possible obfuscation)
    const specialCharRatio = (content.match(/[^\w\s]/g) || []).length / content.length;
    if (specialCharRatio > 0.3) {
      patterns.push("high_special_char_ratio");
      violations.push("possible_obfuscation");
      riskContribution += 15;
    }

    // Check for invisible unicode
    const invisibleChars = content.match(/[\u200B-\u200D\uFEFF\u2060-\u206F]/g);
    if (invisibleChars && invisibleChars.length > 5) {
      patterns.push("invisible_unicode");
      violations.push("hidden_characters");
      riskContribution += 20;
    }

    return {
      found: patterns.length > 0,
      patterns,
      violations,
      riskContribution: Math.min(100, riskContribution),
    };
  }

  private checkMetadata(metadata: Record<string, any>): {
    suspicious: boolean;
    violations: string[];
    riskContribution: number;
  } {
    const violations: string[] = [];
    let riskContribution = 0;

    const metadataStr = JSON.stringify(metadata);

    for (const { name, pattern } of this.SUSPICIOUS_METADATA_PATTERNS) {
      if (pattern.test(metadataStr)) {
        violations.push(`metadata_${name}`);
        riskContribution += 15;
      }
    }

    // Check for injection in specific fields
    for (const { name, pattern, severity } of this.RAG_INJECTION_PATTERNS.slice(0, 5)) {
      if (pattern.test(metadataStr)) {
        violations.push(`metadata_injection_${name}`);
        riskContribution += severity / 2;
      }
    }

    return {
      suspicious: violations.length > 0,
      violations,
      riskContribution: Math.min(50, riskContribution),
    };
  }

  private checkEmbedding(embedding: number[], retrievalScore: number): {
    anomalous: boolean;
    reason?: string;
    shouldBlock?: boolean;
  } {
    // Simplified embedding anomaly detection

    // Check for invalid values (NaN, Infinity, null) - CRITICAL, always block
    if (embedding.some((v: any) => v === null || v === undefined || typeof v !== "number" || !isFinite(v))) {
      return { anomalous: true, reason: "Invalid embedding values (NaN/Infinity/null)", shouldBlock: true };
    }

    // Check for suspiciously uniform embeddings
    const uniqueValues = new Set(embedding.map((v) => Math.round(v * 100) / 100));
    if (uniqueValues.size < embedding.length * 0.1) {
      return { anomalous: true, reason: "Suspiciously uniform embedding", shouldBlock: true };
    }

    // Check for mismatch between high retrieval score and embedding characteristics
    const magnitude = Math.sqrt(embedding.reduce((sum, v) => sum + v * v, 0));
    if (retrievalScore > 0.9 && magnitude < 0.1) {
      return { anomalous: true, reason: "Score/embedding mismatch" };
    }

    return { anomalous: false };
  }

  private sanitizeDocument(doc: RAGDocument): RAGDocument {
    let sanitizedContent = doc.content;

    // Remove injection patterns
    for (const { pattern } of this.RAG_INJECTION_PATTERNS) {
      sanitizedContent = sanitizedContent.replace(pattern, "[REDACTED]");
    }

    // Remove invisible characters
    sanitizedContent = sanitizedContent.replace(/[\u200B-\u200D\uFEFF\u2060-\u206F]/g, "");

    // Escape potential delimiter breakers
    sanitizedContent = sanitizedContent.replace(/(\[{3,}|\]{3,}|\{{3,}|\}{3,}|<{3,}|>{3,})/g, "");

    return {
      ...doc,
      content: sanitizedContent,
      metadata: {
        ...doc.metadata,
        _sanitized: true,
        _originalLength: doc.content.length,
        _sanitizedLength: sanitizedContent.length,
      },
    };
  }

  private hashContent(content: string): string {
    return crypto.createHash("sha256").update(content).digest("hex");
  }

  private generateRecommendations(violations: string[], hasUntrustedSources: boolean): string[] {
    const recommendations: string[] = [];

    if (hasUntrustedSources) {
      recommendations.push("Review and whitelist trusted document sources");
    }
    if (violations.some((v) => v.includes("injection"))) {
      recommendations.push("Implement document sanitization in your RAG pipeline");
    }
    if (violations.some((v) => v.includes("hash"))) {
      recommendations.push("Enable content integrity verification with known good hashes");
    }
    if (violations.some((v) => v.includes("oversized"))) {
      recommendations.push("Implement document chunking with size limits");
    }
    if (violations.some((v) => v.includes("embedding"))) {
      recommendations.push("Add embedding validation to your vector store pipeline");
    }

    if (recommendations.length === 0) {
      recommendations.push("Continue monitoring RAG document sources");
    }

    return recommendations;
  }

  // ============= v2 Enhanced Detection Methods =============

  /**
   * Detect advanced embedding attacks (backdoor, adversarial perturbation)
   */
  private detectEmbeddingAttacks(
    embedding: number[],
    retrievalScore?: number
  ): EmbeddingAttackResult {
    const attackTypes: string[] = [];
    const details: EmbeddingAttackResult["details"] = {};
    let riskScore = 0;

    // Check embedding dimension
    if (embedding.length !== this.config.embeddingDimension) {
      attackTypes.push("dimension_mismatch");
      riskScore += 20;
    }

    // Calculate embedding magnitude
    const magnitude = Math.sqrt(embedding.reduce((sum, v) => sum + v * v, 0));
    const [minMag, maxMag] = this.config.embeddingMagnitudeRange;

    // Check for magnitude anomalies
    if (magnitude < minMag || magnitude > maxMag) {
      attackTypes.push("magnitude_anomaly");
      details.magnitude_anomaly = true;
      riskScore += 25;
    }

    // Check for adversarial perturbation patterns
    // Adversarial embeddings often have unusual value distributions
    const values = embedding.map(Math.abs);
    const sortedValues = [...values].sort((a, b) => b - a);
    const topValues = sortedValues.slice(0, 10);
    const avgTop = topValues.reduce((a, b) => a + b, 0) / topValues.length;
    const avgAll = values.reduce((a, b) => a + b, 0) / values.length;

    // Adversarial perturbations often spike certain dimensions
    if (avgTop > avgAll * 10) {
      attackTypes.push("adversarial_perturbation");
      details.adversarial_perturbation = true;
      riskScore += 35;
    }

    // Check for backdoor patterns
    // Backdoor embeddings often have repeated patterns
    const chunkSize = Math.min(50, Math.floor(embedding.length / 10));
    const chunks: number[][] = [];
    for (let i = 0; i < embedding.length - chunkSize; i += chunkSize) {
      chunks.push(embedding.slice(i, i + chunkSize));
    }

    // Check for repeated chunks (backdoor signature)
    if (chunks.length >= 2) {
      for (let i = 0; i < chunks.length - 1; i++) {
        const similarity = this.cosineSimilarity(chunks[i], chunks[i + 1]);
        if (similarity > this.config.similarityThreshold) {
          attackTypes.push("backdoor_pattern");
          details.backdoor_pattern = true;
          riskScore += 40;
          break;
        }
      }
    }

    // Check distribution anomalies
    const mean = embedding.reduce((a, b) => a + b, 0) / embedding.length;
    const variance = embedding.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / embedding.length;
    const stdDev = Math.sqrt(variance);

    // Normal embeddings usually have stdDev in reasonable range
    if (stdDev < 0.001 || stdDev > 2.0) {
      attackTypes.push("distribution_anomaly");
      details.distribution_anomaly = true;
      riskScore += 20;
    }

    // High retrieval score with suspicious embedding
    if (retrievalScore && retrievalScore > 0.95 && riskScore > 20) {
      attackTypes.push("suspicious_high_score");
      riskScore += 15;
    }

    return {
      detected: attackTypes.length > 0,
      attack_type: attackTypes,
      risk_score: Math.min(100, riskScore),
      details,
    };
  }

  /**
   * Detect indirect prompt injection patterns
   */
  private detectIndirectInjection(content: string): {
    found: boolean;
    patterns: string[];
    violations: string[];
    riskContribution: number;
  } {
    const patterns: string[] = [];
    const violations: string[] = [];
    let riskContribution = 0;

    for (const { name, pattern, severity } of this.INDIRECT_INJECTION_PATTERNS) {
      const matches = content.match(pattern);
      if (matches) {
        patterns.push(name);
        violations.push(`indirect_injection_${name}`);
        riskContribution += severity;
      }
    }

    return {
      found: patterns.length > 0,
      patterns,
      violations,
      riskContribution: Math.min(100, riskContribution),
    };
  }

  /**
   * Detect steganography (hidden data in content)
   */
  private detectSteganography(content: string): {
    found: boolean;
    violations: string[];
    riskContribution: number;
  } {
    const violations: string[] = [];
    let riskContribution = 0;

    // Zero-width character steganography - lower threshold
    const zeroWidthChars = content.match(/[\u200B-\u200F\u2028-\u202F\uFEFF]+/g);
    if (zeroWidthChars) {
      const totalZeroWidth = zeroWidthChars.reduce((sum, m) => sum + m.length, 0);
      // Lower threshold to 3 (any zero-width chars are suspicious in normal text)
      if (totalZeroWidth >= 3) {
        violations.push("zero_width_steganography");
        riskContribution += 40 + Math.min(30, totalZeroWidth * 5);
      }
    }

    // Whitespace pattern encoding - multiple checks
    const tabSpacePattern = /\s{4,}\t+\s+|\t{2,}\s+\t/;
    if (tabSpacePattern.test(content)) {
      violations.push("whitespace_encoding");
      riskContribution += 35;
    }

    const whitespaceRatio = (content.match(/[\t\n\r ]/g) || []).length / content.length;
    if (whitespaceRatio > 0.35) {
      violations.push("excessive_whitespace_ratio");
      riskContribution += 25;
    }

    // Unicode tag character steganography (U+E0000-U+E007F)
    const tagChars = content.match(/[\uDB40][\uDC00-\uDC7F]/g);
    if (tagChars && tagChars.length > 0) {
      violations.push("unicode_tag_steganography");
      riskContribution += 40;
    }

    // Variation selector abuse (U+FE00-U+FE0F)
    const variationSelectors = content.match(/[\uFE00-\uFE0F]/g);
    if (variationSelectors && variationSelectors.length > 5) {
      violations.push("variation_selector_abuse");
      riskContribution += 25;
    }

    // Binary-like pattern in text (potential hidden data)
    const binaryPattern = content.match(/[01]{16,}/g);
    if (binaryPattern) {
      violations.push("binary_steganography");
      riskContribution += 30;
    }

    return {
      found: violations.length > 0,
      violations,
      riskContribution: Math.min(100, riskContribution),
    };
  }

  /**
   * Calculate cosine similarity between two vectors
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) return 0;

    const dotProduct = a.reduce((sum, val, i) => sum + val * b[i], 0);
    const magnitudeA = Math.sqrt(a.reduce((sum, val) => sum + val * val, 0));
    const magnitudeB = Math.sqrt(b.reduce((sum, val) => sum + val * val, 0));

    if (magnitudeA === 0 || magnitudeB === 0) return 0;
    return dotProduct / (magnitudeA * magnitudeB);
  }

  /**
   * Analyze a batch of embeddings for clustering anomalies
   */
  analyzeEmbeddingCluster(embeddings: number[][]): {
    anomalous: boolean;
    anomalousIndices: number[];
    reason: string;
  } {
    if (embeddings.length < 3) {
      return { anomalous: false, anomalousIndices: [], reason: "Not enough embeddings for cluster analysis" };
    }

    const anomalousIndices: number[] = [];

    // Calculate pairwise similarities
    const similarities: number[][] = [];
    for (let i = 0; i < embeddings.length; i++) {
      similarities[i] = [];
      for (let j = 0; j < embeddings.length; j++) {
        if (i === j) {
          similarities[i][j] = 1;
        } else {
          similarities[i][j] = this.cosineSimilarity(embeddings[i], embeddings[j]);
        }
      }
    }

    // Find embeddings with unusually high or low similarity to all others
    for (let i = 0; i < embeddings.length; i++) {
      const avgSimilarity = similarities[i].reduce((a, b) => a + b, 0) / embeddings.length;

      // Anomaly: embedding is too similar to everything (potential backdoor)
      if (avgSimilarity > this.config.similarityThreshold) {
        anomalousIndices.push(i);
      }

      // Anomaly: embedding is dissimilar to everything (potential outlier attack)
      if (avgSimilarity < 0.3) {
        anomalousIndices.push(i);
      }
    }

    return {
      anomalous: anomalousIndices.length > 0,
      anomalousIndices: [...new Set(anomalousIndices)],
      reason: anomalousIndices.length > 0
        ? `${anomalousIndices.length} embeddings show clustering anomalies`
        : "No clustering anomalies detected",
    };
  }
}
