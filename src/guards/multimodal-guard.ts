/**
 * MultiModalGuard (L8)
 *
 * Detects hidden instructions and malicious content in multi-modal inputs
 * (images, audio, documents, base64 payloads).
 *
 * Threat Model:
 * - ASI01: Agent Goal Hijack via manipulated media
 * - Multi-Modal Injection: Hidden text in images, audio with embedded instructions
 *
 * Detection Capabilities:
 * - Image metadata (EXIF) injection
 * - Steganographic patterns
 * - Hidden text detection (white-on-white, etc.)
 * - Base64 embedded payloads
 * - Document macro/script detection
 * - Audio transcript injection markers
 */

import { buildDecodeVariants } from "../decode-variants";

export interface MultiModalGuardConfig {
  /** Enable EXIF/metadata scanning */
  scanMetadata?: boolean;
  /** Enable base64 payload detection */
  detectBase64Payloads?: boolean;
  /** Enable steganography detection heuristics */
  detectSteganography?: boolean;
  /** Maximum allowed metadata size in bytes */
  maxMetadataSize?: number;
  /** Suspicious patterns to detect in extracted text */
  customPatterns?: RegExp[];
  /** Allowed MIME types */
  allowedMimeTypes?: string[];
  /** Block all multi-modal content (strict mode) */
  strictMode?: boolean;
}

export interface MultiModalContent {
  /** Content type: image, audio, document, base64 */
  type: "image" | "audio" | "document" | "base64" | "url";
  /** Raw content or base64 string */
  content?: string;
  /** MIME type if known */
  mimeType?: string;
  /** URL if remote content */
  url?: string;
  /** Filename if provided */
  filename?: string;
  /** Extracted metadata */
  metadata?: Record<string, any>;
  /** Any extracted text (OCR, transcripts, etc.) */
  extractedText?: string;
}

export interface MultiModalGuardResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  content_analysis: {
    type: string;
    threats_detected: string[];
    metadata_suspicious: boolean;
    hidden_content_detected: boolean;
    injection_patterns_found: string[];
    risk_score: number;
  };
  recommendations: string[];
}

export class MultiModalGuard {
  private config: Required<MultiModalGuardConfig>;

  // Suspicious patterns in metadata or extracted text
  private readonly INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    { name: "ignore_instructions", pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)/i },
    { name: "system_override", pattern: /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|<\s*system\s*>|<\s*admin\s*>/i },
    { name: "role_switch", pattern: /you\s+are\s+(now|actually)\s+(a|an|the)|switch\s+to\s+(\w+)\s+mode/i },
    { name: "hidden_prompt", pattern: /HIDDEN_PROMPT|SECRET_INSTRUCTION|INVISIBLE_COMMAND/i },
    { name: "jailbreak_markers", pattern: /DAN\s*(?:mode|persona|character)|developer\s*mode|unrestricted\s*mode|bypass\s+(?:safety|guardrails?)/i },
    { name: "base64_instruction", pattern: /execute\s*:\s*[A-Za-z0-9+/=]{20,}/i },
    { name: "command_injection", pattern: /;\s*(rm|del|wget|curl|eval|exec)\s/i },
    { name: "exfiltration_markers", pattern: /send\s+(to|this|data)\s+(to\s+)?https?:\/\//i },
    // ZWNJ/ZWJ (U+200C/200D) deliberately excluded from this single-occurrence
    // check \u2014 they're legitimate orthographic characters in Persian, Arabic-
    // script, and Indic text (e.g. correct Persian word joining), not just an
    // attack vector. Abuse of ZWNJ/ZWJ at scale is still caught by the
    // threshold-based excessive_invisible_characters heuristic (>5) below,
    // which covers the full invisible-character range including these two.
    { name: "invisible_unicode", pattern: /[\u200B\uFEFF\u2060-\u206F]/g },
    // Policy Puppetry in metadata
    { name: "json_policy_in_metadata", pattern: /"(?:role|instructions?|system|policy)"\s*:\s*"/i },
    // \s* bounded — same ReDoS shape as input-sanitizer.ts's ini_policy_section.
    { name: "ini_policy_in_metadata", pattern: /^\s{0,20}\[(?:system|admin|override|config)\]\s{0,20}$/im },
    // Symbolic/emoji semantic injection (NVIDIA AI Red Team research)
    { name: "emoji_instruction_sequence", pattern: /(?:🔓|🔑|🛡️|⚙️|🔧|🚫|❌|✅)\s*(?:unlock|admin|override|bypass|disable|enable|grant|allow)/i },
    // [A-Z]{2,}/\s* bounded — unbounded form was quadratic-time ReDoS on long non-matching input.
    { name: "rebus_instruction_pattern", pattern: /(?:[A-Z]{2,20}\s{0,5}[-=:>→]\s{0,5}){3,}/  },
    // Cross-metadata payload splitting
    { name: "metadata_split_marker", pattern: /(?:part|step|fragment)\s*[1-9]\s*(?:of|:)/i },
    // Instruction-void phrases — covers OCR, EXIF, ultrasonic, mind-map, and video-frame containers
    // Whitespace quantifiers bounded — see external-data-guard.ts's
    // matching pattern for why (quadratic-time ReDoS on long non-matching input).
    { name: "instructions_void", pattern: /(?:your|the|previous|prior|all\s{1,5}(?:previous|prior))?\s{0,20}instructions?\s{1,10}(?:are|have\s{1,5}been|is)\s{1,10}(?:void|cancelled?|overridden?|revoked|rescinded|superseded)/i },
    { name: "forget_instructions", pattern: /forget\s+(?:your|all|the|my|these|every|each)\s*(?:previous\s+|prior\s+)?(?:instructions?|rules?|guidelines?|directives?|prompts?)/i },
    { name: "disregard_directives", pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above|your)?\s*(?:instructions?|rules?|directives?|guidelines?|prompts?)/i },
    // Activation / state-override phrases that appear inside media containers
    { name: "system_override_phrase", pattern: /system\s+override\s+(?:engaged|active|activated|initiated)|admin\s+mode\s+(?:activated|active|enabled)|jailbreak\s+(?:initiated|active|activated|running)/i },
    // QR / data-URL agent directive injection
    { name: "qr_agent_cmd", pattern: /data:agent;cmd=/i },
    // URL-encoded jailbreak phrases in query strings or QR payloads
    { name: "url_encoded_injection", pattern: /%(?:20|22|27)(?:Disregard|Ignore|Forget|System|Admin|Jailbreak|Your)/i },
    // Browser-extension / AI-sidebar spoofing
    { name: "browser_extension_spoof", pattern: /atlas-sidebar-shim|chrome\.runtime\.sendMessage\b|window\.postMessage[^)]*(?:copilot|prompt_capture|action.*leak)|(?:moz|chrome)-extension:\/\/[^/]+\/(?:sidebar|panel|inject|overlay)/i },
    // SVG script / event-handler XSS
    { name: "svg_xss_injection", pattern: /<svg[^>]*(?:onload|onerror)\s*=|<svg\s*>\s*<script|<(?:svg|foreignObject)[^>]*href\s*=\s*["']?javascript:|<svg[^>]*>\s*<image[^>]*onerror/i },
    // Ultrasonic / physical covert command channels
    { name: "ultrasonic_hidden_cmd", pattern: /ultrasonic\s+(?:encoded|beacon\s+encoding)\s*:/i },
    // Mind-map / diagram / flowchart injection
    { name: "mindmap_diagram_inject", pattern: /mind[- ]?map[^\n.]*(?:child|node|leaf|branch)[^\n.]*(?:disregard|ignore|forget|override|admin|bypass|exfil|leak|jailbreak|system_role|developer\s+mode|execute)|(?:diagram|flowchart)[^\n.]*(?:bypass_safety|bypass_guardrails|leak\s+token|system_role|admin\b|execute\b)/i },
    // Physical-world injection (road signs, billboards, IR ink)
    { name: "physical_world_inject", pattern: /<billboard>[^<]*(?:SYSTEM|OVERRIDE|IGNORE|ADMIN)\b|road\s+texture\s+encoding|\bOVERRIDE\s*:\s*(?:proceed|ignore|bypass|navigate)/i },
    // Cross-modal alignment attacks (image+caption, tool_call= directives)
    { name: "cross_modal_tool_call", pattern: /image\s*\+\s*caption[^\n.]*(?:approved\s+by\s+user|tool_call\s*=)|tool_call\s*=\s*(?:transfer|delete|send|execute|list)\b/i },
  ];

  // Suspicious EXIF fields that could contain injection
  private readonly SUSPICIOUS_METADATA_FIELDS = [
    "ImageDescription",
    "UserComment",
    "XPComment",
    "XPKeywords",
    "XPSubject",
    "XPTitle",
    "Artist",
    "Copyright",
    "Software",
    "HostComputer",
    "DocumentName",
    "PageName",
  ];

  // Known dangerous MIME types
  private readonly DANGEROUS_MIME_TYPES = [
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-sh",
    "application/x-shellscript",
    "application/javascript",
    "text/javascript",
    "application/x-python",
    "application/vnd.ms-office",
  ];

  // Steganography detection patterns (simplified heuristics)
  private readonly STEGO_MARKERS = [
    /^[\x00-\x08\x0B\x0C\x0E-\x1F]{4,}/, // Unusual control characters
    /PK\x03\x04/, // ZIP header (could be embedded)
    /%PDF-/, // Embedded PDF
    /\x89PNG.*IEND.*[A-Za-z]{10,}/, // Data after PNG end
  ];

  constructor(config: MultiModalGuardConfig = {}) {
    this.config = {
      scanMetadata: config.scanMetadata ?? true,
      detectBase64Payloads: config.detectBase64Payloads ?? true,
      detectSteganography: config.detectSteganography ?? true,
      maxMetadataSize: config.maxMetadataSize ?? 10000, // 10KB
      customPatterns: config.customPatterns ?? [],
      allowedMimeTypes: config.allowedMimeTypes ?? [
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "audio/mpeg",
        "audio/wav",
        "audio/ogg",
        "application/pdf",
        "text/plain",
      ],
      strictMode: config.strictMode ?? false,
    };
  }

  /**
   * Analyze multi-modal content for hidden instructions or malicious payloads
   */
  check(
    content: MultiModalContent,
    requestId?: string
  ): MultiModalGuardResult {
    const reqId = requestId || `mm-${Date.now()}`;
    const violations: string[] = [];
    const threatsDetected: string[] = [];
    const injectionPatternsFound: string[] = [];
    let riskScore = 0;
    let metadataSuspicious = false;
    let hiddenContentDetected = false;

    // Strict mode blocks all multi-modal content
    if (this.config.strictMode) {
      return {
        allowed: false,
        reason: "Multi-modal content blocked in strict mode",
        violations: ["strict_mode_block"],
        request_id: reqId,
        content_analysis: {
          type: content.type,
          threats_detected: ["strict_mode"],
          metadata_suspicious: false,
          hidden_content_detected: false,
          injection_patterns_found: [],
          risk_score: 100,
        },
        recommendations: ["Disable strict mode to allow multi-modal content"],
      };
    }

    // Check MIME type
    if (content.mimeType) {
      if (this.DANGEROUS_MIME_TYPES.includes(content.mimeType)) {
        violations.push("dangerous_mime_type");
        threatsDetected.push(`Dangerous MIME type: ${content.mimeType}`);
        riskScore += 50;
      }

      if (!this.config.allowedMimeTypes.includes(content.mimeType)) {
        violations.push("disallowed_mime_type");
        threatsDetected.push(`Disallowed MIME type: ${content.mimeType}`);
        riskScore += 30;
      }
    }

    // Check for suspicious filename
    if (content.filename) {
      const dangerousExtensions = [".exe", ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".js"];
      const ext = content.filename.toLowerCase().slice(content.filename.lastIndexOf("."));
      if (dangerousExtensions.includes(ext)) {
        violations.push("dangerous_file_extension");
        threatsDetected.push(`Dangerous file extension: ${ext}`);
        riskScore += 40;
      }

      // Double extension attack
      if (/\.(jpg|png|gif|pdf)\.(exe|sh|bat|js)$/i.test(content.filename)) {
        violations.push("double_extension_attack");
        threatsDetected.push("Double extension attack detected");
        riskScore += 60;
      }
    }

    // Scan metadata for injections
    if (this.config.scanMetadata && content.metadata) {
      const metadataResult = this.scanMetadata(content.metadata);
      if (metadataResult.suspicious) {
        metadataSuspicious = true;
        violations.push(...metadataResult.violations);
        injectionPatternsFound.push(...metadataResult.patterns);
        riskScore += metadataResult.riskContribution;
      }

      // Check metadata size
      const metadataSize = JSON.stringify(content.metadata).length;
      if (metadataSize > this.config.maxMetadataSize) {
        violations.push("oversized_metadata");
        threatsDetected.push(`Metadata size ${metadataSize} exceeds limit ${this.config.maxMetadataSize}`);
        riskScore += 20;
      }
    }

    // Scan extracted text (OCR, transcripts) for injections — also across
    // de-obfuscated variants (URL/hex/base64/ROT13/reversed/zero-width-
    // stripped/homoglyph-normalized), since a raw match alone is trivially
    // bypassed by wrapping the payload in any of these encodings.
    if (content.extractedText) {
      const textResult = this.scanText(content.extractedText);
      if (textResult.injectionFound) {
        hiddenContentDetected = true;
        violations.push(...textResult.violations);
        injectionPatternsFound.push(...textResult.patterns);
        riskScore += textResult.riskContribution;
      }
      // Only the first variant to surface a given violation name contributes
      // its risk score — otherwise the same underlying threat, visible in
      // several decode variants at once (e.g. both the hex- and rot13-
      // decoded forms), would inflate risk_score once per variant instead
      // of once per distinct threat. Seeded from the raw-text scan's OWN
      // violations only (not the broader `violations` array, which by this
      // point may also hold unrelated MIME-type/metadata violations) so an
      // unrelated violation can never suppress a real text-injection score
      // just by having the same name.
      const alreadyFlagged = new Set(textResult.violations);
      for (const target of buildDecodeVariants(content.extractedText)) {
        const decodedResult = this.scanText(target, false);
        if (decodedResult.injectionFound) {
          hiddenContentDetected = true;
          const newViolations = decodedResult.violations.filter(v => !alreadyFlagged.has(v));
          newViolations.forEach(v => alreadyFlagged.add(v));
          violations.push(...decodedResult.violations);
          injectionPatternsFound.push(...decodedResult.patterns);
          // Sum only the newly-surfaced violations' own contributions, not
          // the whole variant's total (which may also include already-
          // counted violations, double-counting them otherwise).
          for (const v of newViolations) {
            riskScore += decodedResult.contributionByViolation[v] ?? 0;
          }
        }
      }
    }

    // Detect base64 payloads in content
    if (this.config.detectBase64Payloads && content.content) {
      const base64Result = this.detectBase64Payloads(content.content);
      if (base64Result.found) {
        violations.push("embedded_base64_payload");
        threatsDetected.push("Embedded base64 payload detected");
        riskScore += 30;

        // Decode and scan the payload
        for (const payload of base64Result.payloads) {
          try {
            const decoded = Buffer.from(payload, "base64").toString("utf-8");
            const decodedScan = this.scanText(decoded, false);
            if (decodedScan.injectionFound) {
              hiddenContentDetected = true;
              violations.push("base64_injection_payload");
              injectionPatternsFound.push(...decodedScan.patterns);
              riskScore += 40;
            }
          } catch {
            // Invalid base64, skip
          }
        }
      }
    }

    // Steganography detection heuristics
    if (this.config.detectSteganography && content.content) {
      const stegoResult = this.detectSteganography(content.content);
      if (stegoResult.detected) {
        violations.push("potential_steganography");
        threatsDetected.push("Potential steganography detected");
        hiddenContentDetected = true;
        riskScore += 25;
      }
    }

    // URL safety check
    if (content.type === "url" && content.url) {
      const urlResult = this.checkUrl(content.url);
      if (!urlResult.safe) {
        violations.push(...urlResult.violations);
        threatsDetected.push(...urlResult.threats);
        riskScore += urlResult.riskContribution;
      }
    }

    // Apply custom patterns
    const allText = [
      content.extractedText || "",
      JSON.stringify(content.metadata || {}),
    ].join(" ");

    for (const pattern of this.config.customPatterns) {
      if (pattern.test(allText)) {
        violations.push("custom_pattern_match");
        injectionPatternsFound.push(`Custom: ${pattern.source.substring(0, 30)}`);
        riskScore += 20;
      }
    }

    // Deduplicate — scanning multiple decode variants can surface the same
    // named violation/pattern more than once for one underlying threat.
    const uniqueViolations = [...new Set(violations)];
    const uniquePatterns = [...new Set(injectionPatternsFound)];

    // Calculate final decision
    const blocked = riskScore >= 50 || uniqueViolations.length > 0;

    return {
      allowed: !blocked,
      reason: blocked
        ? `Multi-modal content blocked: ${uniqueViolations.slice(0, 3).join(", ")}`
        : "Multi-modal content passed security checks",
      violations: uniqueViolations,
      request_id: reqId,
      content_analysis: {
        type: content.type,
        threats_detected: threatsDetected,
        metadata_suspicious: metadataSuspicious,
        hidden_content_detected: hiddenContentDetected,
        injection_patterns_found: uniquePatterns,
        risk_score: Math.min(100, riskScore),
      },
      recommendations: this.generateRecommendations(uniqueViolations),
    };
  }

  /**
   * Batch check multiple content items
   */
  checkBatch(
    contents: MultiModalContent[],
    requestId?: string
  ): MultiModalGuardResult {
    const reqId = requestId || `mm-batch-${Date.now()}`;
    const allViolations: string[] = [];
    const allThreats: string[] = [];
    const allPatterns: string[] = [];
    let totalRiskScore = 0;
    let anyMetadataSuspicious = false;
    let anyHiddenContent = false;

    for (const content of contents) {
      const result = this.check(content, reqId);
      allViolations.push(...result.violations);
      allThreats.push(...result.content_analysis.threats_detected);
      allPatterns.push(...result.content_analysis.injection_patterns_found);
      totalRiskScore = Math.max(totalRiskScore, result.content_analysis.risk_score);
      anyMetadataSuspicious = anyMetadataSuspicious || result.content_analysis.metadata_suspicious;
      anyHiddenContent = anyHiddenContent || result.content_analysis.hidden_content_detected;
    }

    const blocked = totalRiskScore >= 50 || allViolations.length > 0;

    return {
      allowed: !blocked,
      reason: blocked
        ? `Batch blocked: ${[...new Set(allViolations)].slice(0, 3).join(", ")}`
        : "All multi-modal content passed security checks",
      violations: [...new Set(allViolations)],
      request_id: reqId,
      content_analysis: {
        type: `batch(${contents.length})`,
        threats_detected: [...new Set(allThreats)],
        metadata_suspicious: anyMetadataSuspicious,
        hidden_content_detected: anyHiddenContent,
        injection_patterns_found: [...new Set(allPatterns)],
        risk_score: totalRiskScore,
      },
      recommendations: this.generateRecommendations([...new Set(allViolations)]),
    };
  }

  /**
   * Extract and analyze image metadata (EXIF simulation)
   * In production, use a proper EXIF parser
   */
  parseImageMetadata(base64Image: string): Record<string, any> {
    const metadata: Record<string, any> = {};

    try {
      // Look for EXIF markers in the base64 content
      // This is a simplified simulation - real implementation would use exif-parser
      const decoded = Buffer.from(base64Image, "base64");
      const content = decoded.toString("latin1");

      // Look for common EXIF text patterns
      const textMatches = content.match(/[\x20-\x7E]{10,}/g) || [];
      for (const match of textMatches.slice(0, 20)) {
        if (match.includes("=") || match.includes(":")) {
          const [key, ...valueParts] = match.split(/[=:]/);
          if (key && valueParts.length > 0) {
            metadata[key.trim()] = valueParts.join(":").trim();
          }
        }
      }

      // Look for XML metadata (XMP)
      const xmpMatch = content.match(/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/i);
      if (xmpMatch) {
        metadata._xmp = xmpMatch[0].substring(0, 500);
      }
    } catch {
      // Ignore parsing errors
    }

    return metadata;
  }

  private scanMetadata(metadata: Record<string, any>): {
    suspicious: boolean;
    violations: string[];
    patterns: string[];
    riskContribution: number;
  } {
    const violations: string[] = [];
    const patterns: string[] = [];
    let riskContribution = 0;

    const checkValue = (key: string, value: any, path: string = "") => {
      const currentPath = path ? `${path}.${key}` : key;

      if (typeof value === "string") {
        // Check suspicious fields
        if (this.SUSPICIOUS_METADATA_FIELDS.includes(key)) {
          for (const { name, pattern } of this.INJECTION_PATTERNS) {
            if (pattern.test(value)) {
              violations.push(`metadata_injection_${name}`);
              patterns.push(`${name} in ${currentPath}`);
              riskContribution += 30;
            }
          }
        }

        // Check all fields for obvious injection
        for (const { name, pattern } of this.INJECTION_PATTERNS) {
          if (pattern.test(value) && value.length > 20) {
            violations.push(`metadata_${name}`);
            patterns.push(`${name} in ${currentPath}`);
            riskContribution += 20;
          }
        }
      } else if (typeof value === "object" && value !== null) {
        for (const [k, v] of Object.entries(value)) {
          checkValue(k, v, currentPath);
        }
      }
    };

    for (const [key, value] of Object.entries(metadata)) {
      checkValue(key, value);
    }

    return {
      suspicious: violations.length > 0,
      violations: [...new Set(violations)],
      patterns: [...new Set(patterns)],
      riskContribution: Math.min(60, riskContribution),
    };
  }

  /**
   * @param rawHeuristics - Whether to run the invisible-character and
   * intra-token-homoglyph-mixing heuristics, which look for anomalies
   * introduced by an attacker in the ORIGINAL text. Must be false when
   * scanning an already-decoded/normalized variant: partial homoglyph
   * normalization (only the small set of commonly-spoofed letters) applied
   * to genuinely non-English text (e.g. a plain Cyrillic sentence) creates
   * artificial intra-token script mixing that isn't an attack, and would
   * otherwise false-positive on legitimate non-English content.
   */
  private scanText(text: string, rawHeuristics: boolean = true): {
    injectionFound: boolean;
    violations: string[];
    patterns: string[];
    riskContribution: number;
    /** Per-violation-name contribution, for callers that need to dedupe
     * risk score across multiple scanText() calls (e.g. across decode
     * variants) without double-counting a violation seen more than once. */
    contributionByViolation: Record<string, number>;
  } {
    const violations: string[] = [];
    const patterns: string[] = [];
    const contributionByViolation: Record<string, number> = {};
    let riskContribution = 0;

    for (const { name, pattern } of this.INJECTION_PATTERNS) {
      if (pattern.test(text)) {
        const violationName = `text_injection_${name}`;
        violations.push(violationName);
        patterns.push(name);
        contributionByViolation[violationName] = 25;
        riskContribution += 25;
      }
    }

    if (rawHeuristics) {
      // Check for invisible unicode characters (used to hide instructions)
      const invisibleCount = (text.match(/[\u200B-\u200D\uFEFF\u2060-\u206F]/g) || []).length;
      if (invisibleCount > 5) {
        violations.push("excessive_invisible_characters");
        patterns.push(`invisible_unicode(${invisibleCount})`);
        contributionByViolation["excessive_invisible_characters"] = 20;
        riskContribution += 20;
      }

      // Check for homoglyph attacks \u2014 require intra-token script mixing (Cyrillic adjacent to Latin
      // within a word), not just both scripts appearing anywhere in the document.
      // "\u0430dmin" (Cyrillic \u0430 + Latin dmin) \u2192 attack. "\u041A\u0430\u043A \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u044C chroot?" \u2192 benign.
      const intraTokenHomoglyph = /[a-zA-Z][\u0430-\u044F\u0410-\u042F]|[\u0430-\u044F\u0410-\u042F][a-zA-Z]/;
      if (intraTokenHomoglyph.test(text)) {
        violations.push("potential_homoglyph_attack");
        patterns.push("mixed_scripts");
        contributionByViolation["potential_homoglyph_attack"] = 15;
        riskContribution += 15;
      }
    }

    return {
      injectionFound: violations.length > 0,
      violations,
      patterns,
      riskContribution: Math.min(60, riskContribution),
      contributionByViolation,
    };
  }

  private detectBase64Payloads(content: string): {
    found: boolean;
    payloads: string[];
  } {
    // Look for base64 patterns that might be hidden payloads
    const base64Pattern = /(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?:[^A-Za-z0-9+/]|$)/g;
    const payloads: string[] = [];

    let match;
    while ((match = base64Pattern.exec(content)) !== null) {
      // Verify it's valid base64
      try {
        const decoded = Buffer.from(match[1], "base64");
        // Check if decoded content looks like text with instructions
        const text = decoded.toString("utf-8");
        if (/[a-zA-Z\s]{10,}/.test(text)) {
          payloads.push(match[1]);
        }
      } catch {
        // Not valid base64
      }
    }

    return {
      found: payloads.length > 0,
      payloads,
    };
  }

  private detectSteganography(content: string): {
    detected: boolean;
    markers: string[];
  } {
    const markers: string[] = [];

    for (const marker of this.STEGO_MARKERS) {
      if (marker.test(content)) {
        markers.push(marker.source.substring(0, 20));
      }
    }

    // Entropy analysis — only meaningful on binary/long content.
    // Short strings and natural-language text trivially hit high unique-char ratios.
    const entropyThreshold = 0.9;
    const sample = content.slice(-1000);
    if (sample.length >= 200) {
      const uniqueChars = new Set(sample).size;
      const entropy = uniqueChars / sample.length;
      if (entropy > entropyThreshold) {
        markers.push("high_entropy_tail");
      }
    }

    return {
      detected: markers.length > 0,
      markers,
    };
  }

  private checkUrl(url: string): {
    safe: boolean;
    violations: string[];
    threats: string[];
    riskContribution: number;
  } {
    const violations: string[] = [];
    const threats: string[] = [];
    let riskContribution = 0;

    try {
      const parsed = new URL(url);

      // Check for suspicious protocols
      if (!["http:", "https:"].includes(parsed.protocol)) {
        violations.push("suspicious_protocol");
        threats.push(`Suspicious protocol: ${parsed.protocol}`);
        riskContribution += 40;
      }

      // Check for IP addresses instead of domains
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname)) {
        violations.push("ip_address_url");
        threats.push("Direct IP address URL");
        riskContribution += 20;
      }

      // Check for suspicious patterns in URL
      if (parsed.href.includes("..") || parsed.href.includes("%00")) {
        violations.push("path_traversal_url");
        threats.push("Path traversal in URL");
        riskContribution += 30;
      }

      // Check for data URLs
      if (url.startsWith("data:")) {
        violations.push("data_url");
        threats.push("Data URL detected");
        riskContribution += 25;
      }
    } catch {
      violations.push("invalid_url");
      threats.push("Invalid URL format");
      riskContribution += 30;
    }

    return {
      safe: violations.length === 0,
      violations,
      threats,
      riskContribution,
    };
  }

  private generateRecommendations(violations: string[]): string[] {
    const recommendations: string[] = [];

    if (violations.some((v) => v.includes("metadata"))) {
      recommendations.push("Strip metadata from uploaded files before processing");
    }
    if (violations.some((v) => v.includes("base64"))) {
      recommendations.push("Validate and sanitize base64 payloads before decoding");
    }
    if (violations.some((v) => v.includes("mime"))) {
      recommendations.push("Implement strict MIME type validation");
    }
    if (violations.some((v) => v.includes("steganography"))) {
      recommendations.push("Consider re-encoding images to remove hidden data");
    }
    if (violations.some((v) => v.includes("injection"))) {
      recommendations.push("Sanitize extracted text before including in prompts");
    }

    if (recommendations.length === 0) {
      recommendations.push("Continue monitoring multi-modal inputs");
    }

    return recommendations;
  }
}
