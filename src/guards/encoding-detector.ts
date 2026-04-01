/**
 * EncodingDetector
 *
 * Detects and blocks encoding-based bypass attempts:
 * - Base64 encoded payloads
 * - URL encoded attacks
 * - Unicode/punycode obfuscation
 * - Hex encoding
 * - HTML entity encoding
 * - Mixed encoding attacks
 */

import { GuardLogger } from "../types";

export interface EncodingDetectorConfig {
  // Detection settings
  detectBase64?: boolean;
  detectURLEncoding?: boolean;
  detectUnicode?: boolean;
  detectHex?: boolean;
  detectHTMLEntities?: boolean;
  detectMixedEncoding?: boolean;
  detectROT13?: boolean;
  detectOctal?: boolean;
  detectBase32?: boolean;
  // Decoding depth
  maxDecodingDepth?: number;
  // Threat patterns to look for after decoding
  threatPatterns?: ThreatPattern[];
  // Suspicious encoding thresholds
  maxEncodedRatio?: number; // Max ratio of encoded chars
  logger?: GuardLogger;
}

export interface ThreatPattern {
  name: string;
  pattern: RegExp;
  severity: "low" | "medium" | "high" | "critical";
}

export interface EncodingDetectorResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  encoding_analysis: {
    encodings_detected: EncodingDetection[];
    decoded_content?: string;
    threats_found: ThreatFound[];
    obfuscation_score: number;
  };
}

export interface EncodingDetection {
  type: string;
  count: number;
  locations: string[];
  decoded_sample?: string;
}

export interface ThreatFound {
  pattern_name: string;
  severity: string;
  in_layer: string; // "original" | "decoded_1" | "decoded_2" etc.
}

export class EncodingDetector {
  private config: EncodingDetectorConfig;
  private logger: GuardLogger;

  private defaultThreatPatterns: ThreatPattern[] = [
    // SQL Injection - Enhanced
    {
      name: "sql_injection",
      pattern: /(?:union\s+(?:all\s+)?select|drop\s+(?:table|database)|insert\s+into|delete\s+from|update\s+.*set|exec\s*\(|execute\s*\(|truncate\s+table|alter\s+table|create\s+table|;\s*select\s|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$|\/\*.*\*\/)/gi,
      severity: "critical",
    },
    // Command Injection - Enhanced
    {
      name: "command_injection",
      pattern: /(?:;\s*(?:cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|nc|netcat|nmap|chmod|chown|kill|pkill)|`[^`]+`|\$\([^)]+\)|\|\s*(?:sh|bash)|&&\s*(?:rm|cat|wget)|>\s*\/(?:etc|tmp|var))/gi,
      severity: "critical",
    },
    // Path Traversal - Enhanced
    {
      name: "path_traversal",
      pattern: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|\.\.%5c|%252e%252e|%c0%ae|%c1%9c|\.\.%c0%af|\.\.%c1%9c)/gi,
      severity: "high",
    },
    // XSS - Enhanced
    {
      name: "xss",
      pattern: /(?:<script|javascript:|on\w+\s*=|<iframe|<object|<embed|<svg\s+onload|<img\s+onerror|<body\s+onload|expression\s*\(|vbscript:|data:text\/html|<style>.*expression)/gi,
      severity: "high",
    },
    // Prompt Injection - Enhanced
    {
      name: "prompt_injection",
      pattern: /(?:ignore\s+(?:all\s+)?(?:previous|prior|above|the)?\s*(?:instructions|rules|guidelines|directives)?|disregard\s+(?:above|all|everything|the)|you\s+are\s+now|new\s+instructions|forget\s+(?:everything|all)|system\s*:\s*you|act\s+as\s+(?:a|an|if)|pretend\s+(?:you|to\s+be)|roleplay\s+as|jailbreak|DAN\s+mode|developer\s+mode|bypass\s+(?:safety|security|restrictions|filters)|reveal\s+.*(?:system|prompt|instructions|secret|password)|show\s+.*(?:system|prompt|instructions)|output\s+.*(?:system|prompt|instructions)|system\s+prompt|your\s+(?:system|initial)\s+(?:prompt|instructions))/gi,
      severity: "high",
    },
    // System Commands - Enhanced
    {
      name: "system_command",
      pattern: /(?:\/bin\/|\/etc\/passwd|\/etc\/shadow|cmd\.exe|powershell|\.exe|\.bat|\.cmd|\.ps1|\.sh\s|eval\s*\(|system\s*\(|exec\s*\(|popen|subprocess|os\.system)/gi,
      severity: "critical",
    },
    // Data Exfiltration
    {
      name: "data_exfiltration",
      pattern: /(?:curl\s+.*-d|wget\s+.*--post|fetch\s*\(|XMLHttpRequest|sendBeacon|\.innerHTML\s*=|document\.cookie|localStorage\.|sessionStorage\.)/gi,
      severity: "high",
    },
    // LDAP Injection
    {
      name: "ldap_injection",
      pattern: /(?:\)\s*\(\||\*\)\s*\(|\)\s*\(\&|%28%7c|%29%28)/gi,
      severity: "high",
    },
    // XML Injection / XXE
    {
      name: "xxe_injection",
      pattern: /(?:<!ENTITY|<!DOCTYPE.*SYSTEM|<!DOCTYPE.*PUBLIC|SYSTEM\s*"file:|SYSTEM\s*"http)/gi,
      severity: "critical",
    },
    // Template Injection
    {
      name: "template_injection",
      pattern: /(?:\{\{.*\}\}|\$\{.*\}|<%.*%>|<\?.*\?>|\[\[.*\]\])/gi,
      severity: "high",
    },
    // Role/Permission Escalation
    {
      name: "role_escalation",
      pattern: /(?:admin\s*:\s*true|role\s*:\s*(?:admin|root|superuser)|isAdmin\s*=\s*true|permissions?\s*:\s*\[?\s*['"]\*['"])/gi,
      severity: "critical",
    },
  ];

  constructor(config: EncodingDetectorConfig = {}) {
    this.config = {
      detectBase64: config.detectBase64 ?? true,
      detectURLEncoding: config.detectURLEncoding ?? true,
      detectUnicode: config.detectUnicode ?? true,
      detectHex: config.detectHex ?? true,
      detectHTMLEntities: config.detectHTMLEntities ?? true,
      detectMixedEncoding: config.detectMixedEncoding ?? true,
      detectROT13: config.detectROT13 ?? true,
      detectOctal: config.detectOctal ?? true,
      detectBase32: config.detectBase32 ?? true,
      maxDecodingDepth: config.maxDecodingDepth ?? 3,
      threatPatterns: config.threatPatterns ?? this.defaultThreatPatterns,
      maxEncodedRatio: config.maxEncodedRatio ?? 0.5,
    };
    this.logger = config.logger || (() => {});
  }

  /**
   * Detect encoding and analyze for threats
   */
  detect(
    input: string,
    requestId: string = ""
  ): EncodingDetectorResult {
    const violations: string[] = [];
    const encodingsDetected: EncodingDetection[] = [];
    const threatsFound: ThreatFound[] = [];
    let obfuscationScore = 0;

    // Check original input for threats
    this.checkThreats(input, "original", threatsFound);

    // Detect and decode Base64
    if (this.config.detectBase64) {
      const base64Result = this.detectBase64(input);
      if (base64Result.found) {
        encodingsDetected.push({
          type: "base64",
          count: base64Result.matches.length,
          locations: base64Result.locations,
          decoded_sample: base64Result.decoded?.substring(0, 100),
        });
        obfuscationScore += 3;
        violations.push("BASE64_ENCODING_DETECTED");

        // Check decoded content for threats
        if (base64Result.decoded) {
          this.checkThreats(base64Result.decoded, "decoded_base64", threatsFound);
        }
      }
    }

    // Detect URL encoding
    if (this.config.detectURLEncoding) {
      const urlResult = this.detectURLEncoding(input);
      if (urlResult.found) {
        encodingsDetected.push({
          type: "url_encoding",
          count: urlResult.count,
          locations: [],
          decoded_sample: urlResult.decoded?.substring(0, 100),
        });
        obfuscationScore += urlResult.ratio > 0.3 ? 4 : 2;

        if (urlResult.ratio > this.config.maxEncodedRatio!) {
          violations.push("EXCESSIVE_URL_ENCODING");
        }

        // Check decoded content for threats
        if (urlResult.decoded) {
          this.checkThreats(urlResult.decoded, "decoded_url", threatsFound);
        }
      }
    }

    // Detect Unicode obfuscation
    if (this.config.detectUnicode) {
      const unicodeResult = this.detectUnicode(input);
      if (unicodeResult.found) {
        encodingsDetected.push({
          type: "unicode",
          count: unicodeResult.count,
          locations: unicodeResult.types,
          decoded_sample: unicodeResult.normalized?.substring(0, 100),
        });
        obfuscationScore += 3;
        violations.push("UNICODE_OBFUSCATION_DETECTED");

        // Check both normalizations for threats:
        // stripped (intra-word ZWS: "igno\u200Bre" → "ignore")
        // spaced (inter-word ZWS: "Ignore\u200Bprevious" → "Ignore previous")
        if (unicodeResult.normalized) {
          this.checkThreats(unicodeResult.normalized, "decoded_unicode", threatsFound);
        }
        if (unicodeResult.normalizedSpaced && unicodeResult.normalizedSpaced !== unicodeResult.normalized) {
          this.checkThreats(unicodeResult.normalizedSpaced, "decoded_unicode", threatsFound);
        }
      }
    }

    // Detect Hex encoding
    if (this.config.detectHex) {
      const hexResult = this.detectHex(input);
      if (hexResult.found) {
        encodingsDetected.push({
          type: "hex",
          count: hexResult.matches.length,
          locations: hexResult.locations,
          decoded_sample: hexResult.decoded?.substring(0, 100),
        });
        obfuscationScore += 2;
        violations.push("HEX_ENCODING_DETECTED");

        if (hexResult.decoded) {
          // Check threats in decoded hex AND in full input with hex replaced
          this.checkThreats(hexResult.decoded, "decoded_hex", threatsFound);
          // Also check the full decoded input (hex + surrounding text)
          const fullDecoded = input
            .replace(/(?:0x|\\x)([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
          this.checkThreats(fullDecoded, "decoded_hex", threatsFound);
        }
      }
    }

    // Detect HTML entities
    if (this.config.detectHTMLEntities) {
      const htmlResult = this.detectHTMLEntities(input);
      if (htmlResult.found) {
        encodingsDetected.push({
          type: "html_entities",
          count: htmlResult.count,
          locations: [],
          decoded_sample: htmlResult.decoded?.substring(0, 100),
        });
        obfuscationScore += 2;

        // Flag excessive HTML entity encoding (>50% of content is entities)
        const entityChars = htmlResult.count * 5; // avg entity length ~5 chars (&#XX;)
        if (input.length > 10 && entityChars / input.length > 0.5) {
          obfuscationScore += 3;
          violations.push("EXCESSIVE_HTML_ENTITY_ENCODING");
        }

        if (htmlResult.decoded) {
          this.checkThreats(htmlResult.decoded, "decoded_html", threatsFound);
        }
      }
    }

    // Detect ROT13 encoding
    if (this.config.detectROT13) {
      const rot13Result = this.detectROT13(input);
      if (rot13Result.found) {
        encodingsDetected.push({
          type: "rot13",
          count: rot13Result.matches.length,
          locations: rot13Result.locations,
          decoded_sample: rot13Result.decoded?.substring(0, 100),
        });
        obfuscationScore += 3;
        violations.push("ROT13_ENCODING_DETECTED");

        if (rot13Result.decoded) {
          this.checkThreats(rot13Result.decoded, "decoded_rot13", threatsFound);
        }
      }
    }

    // Detect Octal encoding
    if (this.config.detectOctal) {
      const octalResult = this.detectOctal(input);
      if (octalResult.found) {
        encodingsDetected.push({
          type: "octal",
          count: octalResult.matches.length,
          locations: octalResult.locations,
          decoded_sample: octalResult.decoded?.substring(0, 100),
        });
        obfuscationScore += 2;
        violations.push("OCTAL_ENCODING_DETECTED");

        if (octalResult.decoded) {
          this.checkThreats(octalResult.decoded, "decoded_octal", threatsFound);
        }
      }
    }

    // Detect Base32 encoding
    if (this.config.detectBase32) {
      const base32Result = this.detectBase32(input);
      if (base32Result.found) {
        encodingsDetected.push({
          type: "base32",
          count: base32Result.matches.length,
          locations: base32Result.locations,
          decoded_sample: base32Result.decoded?.substring(0, 100),
        });
        obfuscationScore += 3;
        violations.push("BASE32_ENCODING_DETECTED");

        if (base32Result.decoded) {
          this.checkThreats(base32Result.decoded, "decoded_base32", threatsFound);
        }
      }
    }

    // Check for mixed encoding (multiple layers)
    if (this.config.detectMixedEncoding && encodingsDetected.length > 1) {
      obfuscationScore += encodingsDetected.length * 2;
      violations.push("MIXED_ENCODING_DETECTED");
    }

    // Add violations for threats found
    for (const threat of threatsFound) {
      if (threat.severity === "critical" || threat.severity === "high") {
        violations.push(
          `ENCODED_THREAT_${threat.pattern_name.toUpperCase()}_IN_${threat.in_layer.toUpperCase()}`
        );
      }
    }

    // Determine if blocked
    // Blocking logic:
    // 1. Critical/high threats in DECODED layers = always block (encoding used to hide attack)
    // 2. Critical threats in ORIGINAL = only block if encoding was ALSO detected (hiding attempt)
    // 3. Original-only threats without encoding = let InputSanitizer handle it (reduces FP)
    const hasEncodingDetected = encodingsDetected.length > 0;
    const hasThreatInDecoded = threatsFound.some(
      (t) => (t.severity === "critical" || t.severity === "high") && t.in_layer !== "original"
    );
    const hasCriticalInOriginalWithEncoding = hasEncodingDetected && threatsFound.some(
      (t) => t.severity === "critical" && t.in_layer === "original"
    );
    const allowed = !hasThreatInDecoded && !hasCriticalInOriginalWithEncoding;

    if (!allowed) {
      this.logger(
        `[EncodingDetector:${requestId}] BLOCKED: ${violations.join(", ")}`, "info"
      );
    }

    // Get fully decoded content
    let decodedContent = input;
    for (let depth = 0; depth < this.config.maxDecodingDepth!; depth++) {
      const decoded = this.fullyDecode(decodedContent);
      if (decoded === decodedContent) break;
      decodedContent = decoded;
    }

    return {
      allowed,
      reason: allowed
        ? undefined
        : `Encoding bypass attempt detected: ${violations.join(", ")}`,
      violations,
      encoding_analysis: {
        encodings_detected: encodingsDetected,
        decoded_content: decodedContent !== input ? decodedContent : undefined,
        threats_found: threatsFound,
        obfuscation_score: obfuscationScore,
      },
    };
  }

  /**
   * Quick check if input contains encoded threats
   */
  containsEncodedThreat(input: string): boolean {
    const result = this.detect(input);
    return result.encoding_analysis.threats_found.some(
      (t) => t.in_layer !== "original"
    );
  }

  private detectBase64(input: string): {
    found: boolean;
    matches: string[];
    locations: string[];
    decoded?: string;
  } {
    // Match potential Base64 strings (min 20 chars to avoid false positives)
    const base64Pattern = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
    const matches: string[] = [];
    const locations: string[] = [];
    let decoded: string | undefined;

    let match;
    while ((match = base64Pattern.exec(input)) !== null) {
      try {
        const candidate = match[0];
        const decodedStr = Buffer.from(candidate, "base64").toString("utf-8");

        // Check if it decodes to printable ASCII
        if (/^[\x20-\x7E\r\n\t]+$/.test(decodedStr)) {
          matches.push(candidate);
          locations.push(`index:${match.index}`);
          decoded = decoded ? decoded + " " + decodedStr : decodedStr;
        }
      } catch {
        // Not valid base64
      }
    }

    return {
      found: matches.length > 0,
      matches,
      locations,
      decoded,
    };
  }

  private detectURLEncoding(input: string): {
    found: boolean;
    count: number;
    ratio: number;
    decoded?: string;
  } {
    const urlEncodedPattern = /%[0-9A-Fa-f]{2}/g;
    const matches = input.match(urlEncodedPattern) || [];
    const ratio = (matches.length * 3) / input.length;

    let decoded: string | undefined;
    if (matches.length > 0) {
      try {
        decoded = decodeURIComponent(input);
      } catch {
        // Try partial decoding
        decoded = input.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
          try {
            return String.fromCharCode(parseInt(hex, 16));
          } catch {
            return _;
          }
        });
      }
    }

    return {
      found: matches.length > 0,
      count: matches.length,
      ratio,
      decoded,
    };
  }

  private detectUnicode(input: string): {
    found: boolean;
    count: number;
    types: string[];
    normalized?: string;
    normalizedSpaced?: string;
  } {
    const types: string[] = [];
    let count = 0;

    // Check for \uXXXX escape sequences
    const unicodeEscapes = /\\u[0-9A-Fa-f]{4}/g;
    const escapeMatches = input.match(unicodeEscapes) || [];
    if (escapeMatches.length > 0) {
      count += escapeMatches.length;
      types.push("unicode_escape_u");
    }

    // Check for \u{XXXXX} escape sequences (ES6 style)
    const unicodeEscapesES6 = /\\u\{[0-9A-Fa-f]{1,6}\}/g;
    const escapeMatchesES6 = input.match(unicodeEscapesES6) || [];
    if (escapeMatchesES6.length > 0) {
      count += escapeMatchesES6.length;
      types.push("unicode_escape_es6");
    }

    // Check for \UXXXXXXXX escape sequences (Python style)
    const unicodeEscapesPython = /\\U[0-9A-Fa-f]{8}/g;
    const escapeMatchesPython = input.match(unicodeEscapesPython) || [];
    if (escapeMatchesPython.length > 0) {
      count += escapeMatchesPython.length;
      types.push("unicode_escape_U");
    }

    // Check for unusual Unicode characters (homoglyphs)
    // Cyrillic lookalikes, Greek lookalikes, mathematical alphanumerics
    const homoglyphs = /[\u0430-\u044F\u0410-\u042F\u0391-\u03C9\u2010-\u2015\uFF01-\uFF5E\u{1D400}-\u{1D7FF}]/gu;
    const homoglyphMatches = input.match(homoglyphs) || [];
    if (homoglyphMatches.length > 0) {
      count += homoglyphMatches.length;
      types.push("homoglyphs");
    }

    // Check for zero-width characters
    const zeroWidth = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g;
    const zeroWidthMatches = input.match(zeroWidth) || [];
    if (zeroWidthMatches.length > 0) {
      count += zeroWidthMatches.length;
      types.push("zero_width");
    }

    // Check for bidirectional text control characters (used in trojan source attacks)
    const bidiControls = /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g;
    const bidiMatches = input.match(bidiControls) || [];
    if (bidiMatches.length > 0) {
      count += bidiMatches.length;
      types.push("bidi_controls");
    }

    // Check for confusable characters (common substitutions)
    const confusables = /[\u0131\u0130\u017F\u212A\u0261\u0251\u025B\u0254\u028C]/g;
    const confusableMatches = input.match(confusables) || [];
    if (confusableMatches.length > 0) {
      count += confusableMatches.length;
      types.push("confusables");
    }

    // Check for tag characters (used to hide text)
    const tagChars = /[\u{E0000}-\u{E007F}]/gu;
    const tagMatches = input.match(tagChars) || [];
    if (tagMatches.length > 0) {
      count += tagMatches.length;
      types.push("tag_characters");
    }

    let normalized: string | undefined;
    let normalizedSpaced: string | undefined;
    if (count > 0) {
      // Homoglyph map: Cyrillic/Greek lookalikes → Latin
      const homoglyphMap: Record<string, string> = {
        "\u0430": "a", "\u0410": "A", "\u0435": "e", "\u0415": "E",
        "\u043E": "o", "\u041E": "O", "\u0440": "p", "\u0420": "P",
        "\u0441": "c", "\u0421": "C", "\u0443": "y", "\u0423": "Y",
        "\u0456": "i", "\u0406": "I", "\u0445": "x", "\u0425": "X",
        "\u0422": "T", "\u041D": "H", "\u041C": "M", "\u041A": "K",
        "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u039A": "K",
        "\u039C": "M", "\u039D": "N", "\u039F": "O", "\u03A1": "P",
        "\u03A4": "T", "\u0396": "Z",
      };
      let baseStr = input.normalize("NFKC");
      for (const [src, dst] of Object.entries(homoglyphMap)) {
        baseStr = baseStr.split(src).join(dst);
      }
      const base = baseStr
        .replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        )
        .replace(/\\u\{([0-9A-Fa-f]{1,6})\}/g, (_, hex) =>
          String.fromCodePoint(parseInt(hex, 16))
        )
        .replace(/\\U([0-9A-Fa-f]{8})/g, (_, hex) =>
          String.fromCodePoint(parseInt(hex, 16))
        )
        .replace(/[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g, "")
        .replace(/[\u{E0000}-\u{E007F}]/gu, "");

      // Primary: strip ZWS (catches intra-word: "igno\u200Bre" → "ignore")
      normalized = base
        .replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g, "")
        .replace(/\s{2,}/g, " ")
        .trim();

      // Secondary: replace ZWS with space (catches inter-word: "Ignore\u200Bprevious" → "Ignore previous")
      normalizedSpaced = base
        .replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g, " ")
        .replace(/\s{2,}/g, " ")
        .trim();
    }

    return {
      found: count > 0,
      count,
      types,
      normalized,
      normalizedSpaced,
    };
  }

  private detectHex(input: string): {
    found: boolean;
    matches: string[];
    locations: string[];
    decoded?: string;
  } {
    const matches: string[] = [];
    const locations: string[] = [];
    let decoded = "";

    // Pattern 1: 0x41 or \x41 format
    const hexPattern1 = /(?:0x|\\x)([0-9A-Fa-f]{2})/g;
    let match;
    while ((match = hexPattern1.exec(input)) !== null) {
      matches.push(match[0]);
      locations.push(`index:${match.index}`);
      decoded += String.fromCharCode(parseInt(match[1], 16));
    }

    // Pattern 2: Consecutive hex bytes like 41424344 (min 8 chars = 4 bytes)
    const hexPattern2 = /(?:^|[^0-9A-Fa-f])([0-9A-Fa-f]{8,})(?:[^0-9A-Fa-f]|$)/g;
    while ((match = hexPattern2.exec(input)) !== null) {
      const hexString = match[1];
      // Only process if even length (complete bytes)
      if (hexString.length % 2 === 0) {
        let decodedBytes = "";
        let isPrintable = true;

        for (let i = 0; i < hexString.length; i += 2) {
          const byte = parseInt(hexString.substr(i, 2), 16);
          if (byte >= 32 && byte <= 126) {
            decodedBytes += String.fromCharCode(byte);
          } else {
            isPrintable = false;
            break;
          }
        }

        if (isPrintable && decodedBytes.length >= 4) {
          matches.push(hexString);
          locations.push(`index:${match.index}`);
          decoded += decodedBytes;
        }
      }
    }

    // Pattern 3: Space-separated hex bytes like "41 42 43 44"
    const hexPattern3 = /(?:[0-9A-Fa-f]{2}\s+){3,}[0-9A-Fa-f]{2}/g;
    while ((match = hexPattern3.exec(input)) !== null) {
      const bytes = match[0].split(/\s+/);
      let decodedBytes = "";
      let isPrintable = true;

      for (const byteStr of bytes) {
        const byte = parseInt(byteStr, 16);
        if (byte >= 32 && byte <= 126) {
          decodedBytes += String.fromCharCode(byte);
        } else {
          isPrintable = false;
          break;
        }
      }

      if (isPrintable && decodedBytes.length >= 4) {
        matches.push(match[0]);
        locations.push(`index:${match.index}`);
        decoded += decodedBytes;
      }
    }

    return {
      found: matches.length > 0,
      matches,
      locations,
      decoded: decoded || undefined,
    };
  }

  private detectHTMLEntities(input: string): {
    found: boolean;
    count: number;
    decoded?: string;
  } {
    // Match HTML entities
    const entityPattern = /&(?:#\d+|#x[0-9A-Fa-f]+|\w+);/g;
    const matches = input.match(entityPattern) || [];

    let decoded: string | undefined;
    if (matches.length > 0) {
      decoded = input
        .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)))
        .replace(/&#x([0-9A-Fa-f]+);/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        )
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'");
    }

    return {
      found: matches.length > 0,
      count: matches.length,
      decoded,
    };
  }

  private detectROT13(input: string): {
    found: boolean;
    matches: string[];
    locations: string[];
    decoded?: string;
  } {
    // ROT13 decode function
    const rot13Decode = (str: string): string => {
      return str.replace(/[a-zA-Z]/g, (char) => {
        const base = char <= 'Z' ? 65 : 97;
        return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
      });
    };

    const matches: string[] = [];
    const locations: string[] = [];
    let decoded: string | undefined;

    // Look for words that when ROT13 decoded match threat keywords
    const threatKeywords = [
      'ignore', 'instructions', 'system', 'admin', 'password', 'secret',
      'delete', 'drop', 'select', 'union', 'script', 'eval', 'exec',
      'shell', 'command', 'root', 'sudo', 'bypass', 'hack', 'inject',
      'reveal', 'prompt', 'override', 'jailbreak', 'unrestricted',
    ];

    // Find potential ROT13 sequences (longer alphabetic sequences)
    const wordPattern = /\b[a-zA-Z]{5,}\b/g;
    let match;

    while ((match = wordPattern.exec(input)) !== null) {
      const candidate = match[0];
      const decodedWord = rot13Decode(candidate).toLowerCase();

      if (threatKeywords.includes(decodedWord)) {
        matches.push(candidate);
        locations.push(`index:${match.index}`);
        decoded = decoded ? decoded + " " + decodedWord : decodedWord;
      }
    }

    // Also decode the entire input when it looks like ROT13 (all alpha+spaces)
    const isAllAlpha = /^[a-zA-Z\s]+$/.test(input.trim());
    if (matches.length > 0 || isAllAlpha) {
      const fullDecoded = rot13Decode(input);
      decoded = fullDecoded; // Always use full decode for threat scanning
      if (isAllAlpha && matches.length === 0) {
        // Input is all alpha — likely ROT13 even without keyword matches
        matches.push(input.substring(0, 20));
        locations.push("index:0");
      }
    }

    return {
      found: matches.length > 0,
      matches,
      locations,
      decoded,
    };
  }

  private detectOctal(input: string): {
    found: boolean;
    matches: string[];
    locations: string[];
    decoded?: string;
  } {
    // Match octal sequences like \101 or 0101
    const octalPattern = /(?:\\([0-7]{3})|(?:^|\s)(0[0-7]{2,}))/g;
    const matches: string[] = [];
    const locations: string[] = [];
    let decoded = "";

    let match;
    while ((match = octalPattern.exec(input)) !== null) {
      const octalValue = match[1] || match[2];
      matches.push(match[0]);
      locations.push(`index:${match.index}`);

      if (match[1]) {
        // \101 format
        decoded += String.fromCharCode(parseInt(match[1], 8));
      } else if (match[2]) {
        // 0101 format - could be a number or encoded char
        const charCode = parseInt(match[2], 8);
        if (charCode >= 32 && charCode <= 126) {
          decoded += String.fromCharCode(charCode);
        }
      }
    }

    return {
      found: matches.length > 0,
      matches,
      locations,
      decoded: decoded || undefined,
    };
  }

  private detectBase32(input: string): {
    found: boolean;
    matches: string[];
    locations: string[];
    decoded?: string;
  } {
    // Base32 alphabet: A-Z and 2-7, with = padding
    const base32Pattern = /(?:[A-Z2-7]{8}){2,}(?:={0,6})?/g;
    const matches: string[] = [];
    const locations: string[] = [];
    let decoded: string | undefined;

    // Base32 decode function
    const base32Decode = (str: string): string | null => {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      const cleanStr = str.replace(/=/g, '').toUpperCase();

      let bits = '';
      for (const char of cleanStr) {
        const index = alphabet.indexOf(char);
        if (index === -1) return null;
        bits += index.toString(2).padStart(5, '0');
      }

      let result = '';
      for (let i = 0; i + 8 <= bits.length; i += 8) {
        const byte = parseInt(bits.substr(i, 8), 2);
        if (byte >= 32 && byte <= 126) {
          result += String.fromCharCode(byte);
        } else {
          return null; // Not printable ASCII
        }
      }

      return result.length > 0 ? result : null;
    };

    let match;
    while ((match = base32Pattern.exec(input)) !== null) {
      try {
        const candidate = match[0];
        const decodedStr = base32Decode(candidate);

        if (decodedStr && decodedStr.length >= 4) {
          matches.push(candidate);
          locations.push(`index:${match.index}`);
          decoded = decoded ? decoded + " " + decodedStr : decodedStr;
        }
      } catch {
        // Not valid base32
      }
    }

    return {
      found: matches.length > 0,
      matches,
      locations,
      decoded,
    };
  }

  private checkThreats(
    content: string,
    layer: string,
    threatsFound: ThreatFound[]
  ): void {
    for (const pattern of this.config.threatPatterns!) {
      // Reset lastIndex to avoid stateful global regex bug
      pattern.pattern.lastIndex = 0;
      if (pattern.pattern.test(content)) {
        threatsFound.push({
          pattern_name: pattern.name,
          severity: pattern.severity,
          in_layer: layer,
        });
      }
    }
  }

  private fullyDecode(input: string): string {
    let result = input;

    // URL decode
    try {
      result = decodeURIComponent(result);
    } catch {
      result = result.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
        try {
          return String.fromCharCode(parseInt(hex, 16));
        } catch {
          return _;
        }
      });
    }

    // Unicode decode (\uXXXX format)
    result = result.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );

    // Unicode decode ES6 (\u{XXXXX} format)
    result = result.replace(/\\u\{([0-9A-Fa-f]{1,6})\}/g, (_, hex) =>
      String.fromCodePoint(parseInt(hex, 16))
    );

    // Unicode decode Python (\UXXXXXXXX format)
    result = result.replace(/\\U([0-9A-Fa-f]{8})/g, (_, hex) =>
      String.fromCodePoint(parseInt(hex, 16))
    );

    // Hex decode
    result = result.replace(/(?:0x|\\x)([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );

    // Octal decode (\NNN format)
    result = result.replace(/\\([0-7]{3})/g, (_, oct) =>
      String.fromCharCode(parseInt(oct, 8))
    );

    // HTML entity decode
    result = result
      .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)))
      .replace(/&#x([0-9A-Fa-f]+);/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      )
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&nbsp;/g, " ");

    // Remove zero-width characters
    result = result.replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g, "");

    // Remove bidi control characters
    result = result.replace(/[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g, "");

    return result;
  }
}
