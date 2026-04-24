/**
 * WildChat-1M FPR measurement (novel axis).
 *
 * Reads a JSONL of real ChatGPT first-user-turns (non-toxic, non-redacted)
 * extracted from allenai/WildChat-1M shard 0 with seed=42. Measures FP rate
 * under both Pipeline A (Sanitizer+Encoder, same as ARTICLE-2) and Pipeline B
 * (detection-only facade).
 *
 * Agent D (comparison frame) flagged that FPR on real ChatGPT traffic is a
 * novel axis — Prompt Guard 86M self-reports 3–5% OOD FPR, but nobody publishes
 * FPR on WildChat specifically.
 */

import { InputSanitizer } from "../../src/guards/input-sanitizer";
import { EncodingDetector } from "../../src/guards/encoding-detector";
import { TrustGuard } from "../../src/index";
import * as fs from "fs";

// Input path: CLI arg > env var > default
const INPUT = process.argv[2] || process.env.WILDCHAT_SAMPLE || "/tmp/wildchat/sample10k.jsonl";

const sanitizer = new InputSanitizer({ threshold: 0.3, detectPAP: true });
const encoder = new EncodingDetector();
const facade = new TrustGuard({
  logger: () => {},
  sanitizer: { threshold: 0.3, detectPAP: true },
  execution: { enabled: false },
  policy: { enabled: false },
  tenant: { enabled: false },
  schema: { enabled: false },
  output: { enabled: false },
  chain: { enabled: false },
  conversation: { enabled: false },
  promptLeakage: { enabled: true },
});

function pipelineA(text: string): boolean {
  try {
    const s = sanitizer.sanitize(text);
    const e = encoder.detect(text);
    return !s.allowed || !e.allowed;
  } catch { return false; }
}

function pipelineB(text: string): boolean {
  try {
    const r = facade.check("benchmark_probe", {}, undefined, { userInput: text });
    return !r.allowed;
  } catch { return false; }
}

function wilsonCI(k: number, n: number) {
  if (n === 0) return { lo: 0, hi: 0 };
  const z = 1.96;
  const p = k / n;
  const denom = 1 + z * z / n;
  const c = (p + z * z / (2 * n)) / denom;
  const m = (z / denom) * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n));
  return { lo: Math.max(0, c - m), hi: Math.min(1, c + m) };
}

interface Row { content: string; language: string; conv_hash: string; }

const lines = fs.readFileSync(INPUT, "utf-8").trim().split("\n");
const rows: Row[] = lines.map(l => JSON.parse(l));
console.log(`Loaded ${rows.length} WildChat prompts`);

// Overall
let blockedA = 0, blockedB = 0;
const fpA_samples: string[] = [];
const fpB_samples: string[] = [];

// Per-language breakdown
const perLang: Record<string, { n: number; blockedA: number; blockedB: number }> = {};

for (const row of rows) {
  const lang = row.language || "unknown";
  if (!perLang[lang]) perLang[lang] = { n: 0, blockedA: 0, blockedB: 0 };
  perLang[lang].n++;

  const a = pipelineA(row.content);
  const b = pipelineB(row.content);
  if (a) {
    blockedA++;
    perLang[lang].blockedA++;
    if (fpA_samples.length < 5) fpA_samples.push(row.content.substring(0, 140));
  }
  if (b) {
    blockedB++;
    perLang[lang].blockedB++;
    if (fpB_samples.length < 5) fpB_samples.push(row.content.substring(0, 140));
  }
}

const fprA = blockedA / rows.length;
const fprB = blockedB / rows.length;
const aCI = wilsonCI(blockedA, rows.length);
const bCI = wilsonCI(blockedB, rows.length);

console.log(`\n== WildChat-1M FPR (n=${rows.length}) ==`);
console.log(`Pipeline A (Sanitizer+Encoder): ${blockedA} blocked, FPR=${(fprA*100).toFixed(2)}% [${(aCI.lo*100).toFixed(2)}%, ${(aCI.hi*100).toFixed(2)}%]`);
console.log(`Pipeline B (Detection facade):  ${blockedB} blocked, FPR=${(fprB*100).toFixed(2)}% [${(bCI.lo*100).toFixed(2)}%, ${(bCI.hi*100).toFixed(2)}%]`);

console.log(`\n== Per-language (top 10 by n) ==`);
const langs = Object.entries(perLang).sort((a, b) => b[1].n - a[1].n).slice(0, 10);
console.log("language | n | A FPR | B FPR");
for (const [lang, s] of langs) {
  const aFpr = s.n ? (s.blockedA / s.n * 100).toFixed(2) + "%" : "n/a";
  const bFpr = s.n ? (s.blockedB / s.n * 100).toFixed(2) + "%" : "n/a";
  console.log(`${lang} | ${s.n} | ${aFpr} | ${bFpr}`);
}

console.log(`\nSample Pipeline A false positives:`);
fpA_samples.forEach((s, i) => console.log(`  ${i + 1}. ${s}`));
console.log(`\nSample Pipeline B false positives:`);
fpB_samples.forEach((s, i) => console.log(`  ${i + 1}. ${s}`));

// Write JSON report
const report = {
  generatedAt: new Date().toISOString(),
  libraryVersion: "4.19.0",
  corpus: "WildChat-1M shard 0 (allenai/WildChat-1M, ODC-BY)",
  sampleSeed: 42,
  sampleMethod: "simple random of non-toxic, non-redacted first-user-turns",
  n: rows.length,
  pipelineA: { blocked: blockedA, fpr: fprA, ci95_lo: aCI.lo, ci95_hi: aCI.hi },
  pipelineB: { blocked: blockedB, fpr: fprB, ci95_lo: bCI.lo, ci95_hi: bCI.hi },
  perLanguage: perLang,
  sampleFalsePositivesA: fpA_samples,
  sampleFalsePositivesB: fpB_samples,
};
fs.writeFileSync("/Users/nandakishoreleburu/Desktop/kishoreWorks/POC/trust-architecture-pocs/llm-trust-guard/tests/adversarial/wildchat-fpr-results.json", JSON.stringify(report, null, 2));
console.log("\nReport written to tests/adversarial/wildchat-fpr-results.json");
