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
    { name: "jailbreak_markers", pattern: /DAN\s*mode|developer\s*mode|unrestricted\s*mode|bypass\s*safety/i },
    { name: "base64_instruction", pattern: /execute\s*:\s*[A-Za-z0-9+/=]{20,}/i },
    { name: "command_injection", pattern: /;\s*(rm|del|wget|curl|eval|exec)\s/i },
    { name: "exfiltration_markers", pattern: /send\s+(to|this|data)\s+(to\s+)?https?:\/\//i },
    { name: "invisible_unicode", pattern: /[\u200B-\u200D\uFEFF\u2060-\u206F]/g },
    // Policy Puppetry in metadata
    { name: "json_policy_in_metadata", pattern: /"(?:role|instructions?|system|policy)"\s*:\s*"/i },
    { name: "ini_policy_in_metadata", pattern: /^\s*\[(?:system|admin|override|config)\]\s*$/im },
    // Symbolic/emoji semantic injection (NVIDIA AI Red Team research)
    { name: "emoji_instruction_sequence", pattern: /(?:🔓|🔑|🛡️|⚙️|🔧|🚫|❌|✅)\s*(?:unlock|admin|override|bypass|disable|enable|grant|allow)/i },
    { name: "rebus_instruction_pattern", pattern: /(?:[A-Z]{2,}\s*[-=:>→]\s*){3,}/  },
    // Cross-metadata payload splitting
    { name: "metadata_split_marker", pattern: /(?:part|step|fragment)\s*[1-9]\s*(?:of|:)/i },
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

    // Scan extracted text (OCR, transcripts) for injections
    if (content.extractedText) {
      const textResult = this.scanText(content.extractedText);
      if (textResult.injectionFound) {
        hiddenContentDetected = true;
        violations.push(...textResult.violations);
        injectionPatternsFound.push(...textResult.patterns);
        riskScore += textResult.riskContribution;
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
            const decodedScan = this.scanText(decoded);
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

    // Calculate final decision
    const blocked = riskScore >= 50 || violations.length > 0;

    return {
      allowed: !blocked,
      reason: blocked
        ? `Multi-modal content blocked: ${violations.slice(0, 3).join(", ")}`
        : "Multi-modal content passed security checks",
      violations,
      request_id: reqId,
      content_analysis: {
        type: content.type,
        threats_detected: threatsDetected,
        metadata_suspicious: metadataSuspicious,
        hidden_content_detected: hiddenContentDetected,
        injection_patterns_found: injectionPatternsFound,
        risk_score: Math.min(100, riskScore),
      },
      recommendations: this.generateRecommendations(violations),
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

  private scanText(text: string): {
    injectionFound: boolean;
    violations: string[];
    patterns: string[];
    riskContribution: number;
  } {
    const violations: string[] = [];
    const patterns: string[] = [];
    let riskContribution = 0;

    for (const { name, pattern } of this.INJECTION_PATTERNS) {
      if (pattern.test(text)) {
        violations.push(`text_injection_${name}`);
        patterns.push(name);
        riskContribution += 25;
      }
    }

    // Check for invisible unicode characters (used to hide instructions)
    const invisibleCount = (text.match(/[\u200B-\u200D\uFEFF\u2060-\u206F]/g) || []).length;
    if (invisibleCount > 5) {
      violations.push("excessive_invisible_characters");
      patterns.push(`invisible_unicode(${invisibleCount})`);
      riskContribution += 20;
    }

    // Check for homoglyph attacks
    const homoglyphPattern = /[\u0430-\u044F\u0410-\u042F]/; // Cyrillic that looks like Latin
    if (homoglyphPattern.test(text) && /[a-zA-Z]/.test(text)) {
      violations.push("potential_homoglyph_attack");
      patterns.push("mixed_scripts");
      riskContribution += 15;
    }

    return {
      injectionFound: violations.length > 0,
      violations,
      patterns,
      riskContribution: Math.min(60, riskContribution),
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

    // Entropy analysis (simplified)
    // High entropy after expected end markers suggests hidden data
    const entropyThreshold = 0.9;
    const sample = content.slice(-1000);
    const uniqueChars = new Set(sample).size;
    const entropy = uniqueChars / sample.length;

    if (entropy > entropyThreshold) {
      markers.push("high_entropy_tail");
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
