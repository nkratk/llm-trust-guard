/**
 * Shared decode/normalize variant builder for content-inspecting guards.
 *
 * Several guards (InputSanitizer, ExternalDataGuard, MultiModalGuard) need
 * to re-scan content after undoing common obfuscation — URL-encoding, hex,
 * base64, ROT13, string-reversal, zero-width/bidi-control insertion, and
 * Cyrillic homoglyph substitution — since attackers can wrap a payload in
 * any of these (or layer them) to evade pattern matching against the raw
 * string alone. This module is the single place that logic lives, so a fix
 * to the decode chain applies to every guard that uses it instead of
 * drifting across separate copies.
 */

const HOMOGLYPH_MAP: Record<string, string> = {
  "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "у": "y",
  "А": "A", "Е": "E", "І": "I", "О": "O", "Р": "P", "У": "Y",
};
const HOMOGLYPH_RE = /[аеіоруАЕІОРУ]/g;

// Zero-width and bidi-control characters — ZWSP/ZWNJ/ZWJ/LRM/RLM (U+200B-200F),
// bidi embeddings/overrides (U+202A-202E), bidi isolates (U+2066-2069), word
// joiner (U+2060), Mongolian vowel separator (U+180E), BOM (U+FEFF), soft
// hyphen (U+00AD) — used to split a trigger word across invisible boundaries.
const INVISIBLE_CHARS_RE = /[​-‏‪-‮⁦-⁩⁠᠎﻿­]/g;

function rot13(text: string): string {
  return text.replace(/[a-zA-Z]/g, c => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/** Single-pass decode/normalize transforms — each returns [] if inapplicable. */
function applyOneStepTransforms(text: string): string[] {
  const out: string[] = [];
  const stripped = text.replace(INVISIBLE_CHARS_RE, "");
  if (stripped !== text) out.push(stripped);
  if (text.includes("%")) {
    try { const d = decodeURIComponent(text.replace(/\+/g, " ")); if (d !== text) out.push(d); } catch { /* not URL-encoded */ }
  }
  const hex = text.replace(/\s/g, "");
  if (hex.length >= 20 && /^[0-9a-fA-F]+$/.test(hex)) {
    try { const d = Buffer.from(hex, "hex").toString("utf-8"); if (d !== text) out.push(d); } catch { /* not hex */ }
  }
  const b64 = text.replace(/\s/g, "");
  if (b64.length >= 16 && /^[A-Za-z0-9+/]+=*$/.test(b64)) {
    try { const d = Buffer.from(b64, "base64").toString("utf-8"); if (d !== text) out.push(d); } catch { /* not base64 */ }
  }
  const rev = text.split("").reverse().join("");
  if (rev !== text) out.push(rev);
  const rotated = rot13(text);
  if (rotated !== text) out.push(rotated);
  const normed = text.replace(HOMOGLYPH_RE, c => HOMOGLYPH_MAP[c] ?? c);
  if (normed !== text) out.push(normed);
  return out;
}

// Some cap is still worth keeping as defense-in-depth against any
// not-yet-found catastrophic-backtracking regex elsewhere in the codebase
// (this function turns ONE pattern-scan into up to 40), but a cap below a
// guard's own maxContentLength is a silent detection bypass, not safety —
// content between the two thresholds is neither decoded nor rejected for
// size. Set well above every guard's default maxContentLength (largest is
// ExternalDataGuard's 50,000) with headroom, since every guard pattern in
// this codebase has been verified to scan linearly (not quadratically)
// even at 200,000+ characters — see CHANGELOG's ReDoS hardening entry.
const MAX_INPUT_LENGTH = 100_000;

/**
 * Build de-obfuscated variants of `text` for re-scanning, chaining
 * transforms up to a small depth so layered encodings (e.g. homograph
 * substitution that is then percent-encoded, or hex-of-base64) resolve to
 * readable text — a single independent pass per transform misses these
 * combinations. Does not include the original `text` in the result.
 */
export function buildDecodeVariants(rawText: string): string[] {
  const text = rawText.length > MAX_INPUT_LENGTH ? rawText.slice(0, MAX_INPUT_LENGTH) : rawText;
  const seen = new Set<string>([text]);
  let frontier = [text];
  const MAX_DEPTH = 3;
  const MAX_VARIANTS = 40; // guard against pathological branching
  for (let depth = 0; depth < MAX_DEPTH && seen.size < MAX_VARIANTS; depth++) {
    const next: string[] = [];
    for (const variant of frontier) {
      for (const t of applyOneStepTransforms(variant)) {
        if (!seen.has(t)) {
          seen.add(t);
          next.push(t);
          if (seen.size >= MAX_VARIANTS) break;
        }
      }
      if (seen.size >= MAX_VARIANTS) break;
    }
    frontier = next;
    if (frontier.length === 0) break;
  }
  seen.delete(text);
  return [...seen];
}
