/**
 * DetectionBackend - Pluggable detection classifier
 *
 * Allows users to plug in ML-based detection alongside the built-in regex guards.
 * Default: regex-only (zero dependencies, <5ms).
 * Optional: any async classifier (embedding similarity, external API, custom ML).
 *
 * Why this exists: Research shows regex-only detection is bypassed at >90% ASR
 * by adaptive attacks (JBFuzz 99%, AutoDAN 88%, PAIR adaptive). This interface
 * lets users add ML-based detection without forcing dependencies on all users.
 */

import { InputSanitizer } from "./guards/input-sanitizer";
import { EncodingDetector } from "./guards/encoding-detector";

/** Context about what is being classified */
export interface DetectionContext {
  type: "user_input" | "tool_result" | "llm_output" | "system_context" | "rag_document";
  sessionId?: string;
  metadata?: Record<string, any>;
}

/** Result from a detection classifier */
export interface DetectionResult {
  safe: boolean;
  confidence: number; // 0-1 (1 = definitely safe, 0 = definitely unsafe)
  threats: DetectionThreat[];
}

export interface DetectionThreat {
  category: string; // "injection", "jailbreak", "pii", "toxicity", "exfiltration", etc.
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

/**
 * Detection classifier callback type.
 *
 * Can be sync (for regex/local ML) or async (for API calls).
 * Users implement this as a function, closure, or class method.
 *
 * @example
 * // Sync classifier (fast, local)
 * const myClassifier: DetectionClassifier = (input, ctx) => ({
 *   safe: !input.includes("hack"),
 *   confidence: 0.9,
 *   threats: []
 * });
 *
 * @example
 * // Async classifier (ML API)
 * const mlClassifier: DetectionClassifier = async (input, ctx) => {
 *   const res = await fetch('https://my-ml-api/classify', {
 *     method: 'POST',
 *     body: JSON.stringify({ text: input, type: ctx.type })
 *   });
 *   const data = await res.json();
 *   return { safe: data.score < 0.5, confidence: data.score, threats: data.threats };
 * };
 */
export type DetectionClassifier = (
  input: string,
  context: DetectionContext
) => DetectionResult | Promise<DetectionResult>;

/**
 * Create a built-in regex classifier that wraps InputSanitizer + EncodingDetector.
 *
 * Useful as a baseline or fallback classifier.
 */
export function createRegexClassifier(config?: {
  threshold?: number;
  detectPAP?: boolean;
}): DetectionClassifier {
  const sanitizer = new InputSanitizer({
    threshold: config?.threshold ?? 0.3,
    detectPAP: config?.detectPAP ?? true,
  });
  const encoder = new EncodingDetector();

  return (input: string, context: DetectionContext): DetectionResult => {
    const threats: DetectionThreat[] = [];

    // Run sanitizer
    const sanitizeResult = sanitizer.sanitize(input);
    if (!sanitizeResult.allowed) {
      threats.push({
        category: sanitizeResult.pap?.detected ? "persuasion" : "injection",
        severity: "high",
        description: `Injection detected: ${sanitizeResult.matches.slice(0, 3).join(", ")}`,
      });
    }

    // Run encoding detector
    const encodingResult = encoder.detect(input);
    if (!encodingResult.allowed) {
      threats.push({
        category: "encoding_bypass",
        severity: "high",
        description: `Encoded threat: ${encodingResult.violations.slice(0, 3).join(", ")}`,
      });
    }

    return {
      safe: threats.length === 0,
      confidence: sanitizeResult.score,
      threats,
    };
  };
}

/**
 * Merge two detection results (used when combining regex + ML backends)
 *
 * Policy: if EITHER result is unsafe, the merged result is unsafe.
 * Confidence: take the lower confidence (most conservative).
 */
export function mergeDetectionResults(a: DetectionResult, b: DetectionResult): DetectionResult {
  return {
    safe: a.safe && b.safe,
    confidence: Math.min(a.confidence, b.confidence),
    threats: [...a.threats, ...b.threats],
  };
}
