/**
 * Dump the full set of Pipeline A blocks from the WildChat sample for
 * hand-labeling. Output JSONL so a small sample can be adjudicated by hand
 * to estimate the TP/FP split in the 493 blocked prompts.
 */

import { InputSanitizer } from "../../src/guards/input-sanitizer";
import { EncodingDetector } from "../../src/guards/encoding-detector";
import { TrustGuard } from "../../src/index";
import * as fs from "fs";

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

function blockA(text: string): { blocked: boolean; reasons: string[] } {
  const reasons: string[] = [];
  try {
    const s = sanitizer.sanitize(text);
    if (!s.allowed) reasons.push(`sanitizer:${(s.matches || []).join(",") || "(unnamed)"}`);
    const e = encoder.detect(text);
    if (!e.allowed) reasons.push(`encoder`);
    return { blocked: reasons.length > 0, reasons };
  } catch {
    return { blocked: false, reasons: [] };
  }
}

function blockB(text: string): { blocked: boolean; reasons: string[] } {
  try {
    const r = facade.check("benchmark_probe", {}, undefined, { userInput: text });
    if (r.allowed) return { blocked: false, reasons: [] };
    return { blocked: true, reasons: [r.block_layer || "UNKNOWN"] };
  } catch {
    return { blocked: false, reasons: [] };
  }
}

const block = blockA;

const INPUT = process.argv[2] || process.env.WILDCHAT_SAMPLE || "/tmp/wildchat/sample10k.jsonl";
const lines = fs.readFileSync(INPUT, "utf-8").trim().split("\n");

for (const [name, fn, outfile] of [
  ["Pipeline A", blockA, "/tmp/wildchat/pipelineA-blocks.jsonl"],
  ["Pipeline B", blockB, "/tmp/wildchat/pipelineB-blocks.jsonl"],
] as const) {
  const out: any[] = [];
  for (const l of lines) {
    const row = JSON.parse(l);
    const r = fn(row.content);
    if (r.blocked) {
      out.push({ conv_hash: row.conv_hash, language: row.language, content: row.content, reasons: r.reasons });
    }
  }
  fs.writeFileSync(outfile, out.map(r => JSON.stringify(r)).join("\n") + "\n");
  console.log(`${name}: wrote ${out.length} blocks to ${outfile}`);
}
