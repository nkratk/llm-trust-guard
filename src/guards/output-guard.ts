/**
 * OutputGuard (L35)
 *
 * Detects dangerous payloads in LLM/tool output *before* it reaches a
 * downstream sink (browser/DOM, SQL engine, OS shell, markdown renderer,
 * spreadsheet/CSV importer). This closes OWASP **LLM05:2025 — Improper Output
 * Handling**, which the existing OutputFilter (PII/secret egress) does not cover.
 *
 * > "Treat model output as untrusted input to the next system."
 *
 * This is a CONTENT guard — it inspects the text the model produced, not the
 * user input. It does not understand intent; it flags syntactic payloads that
 * are dangerous when interpolated unescaped into a downstream interpreter.
 *
 * Threat Model (sinks):
 * - HTML/DOM   → stored/reflected XSS (<script>, javascript:, on*= handlers)
 * - SQL        → second-order SQL injection (UNION SELECT, ' OR 1=1, ;DROP)
 * - OS shell   → command injection ($(...), backticks, ; rm, curl | bash)
 * - Markdown   → data exfiltration via auto-fetched images (![](https://x?=DATA))
 * - Spreadsheet→ CSV/formula injection (cells starting =,+,-,@ with HYPERLINK/cmd)
 *
 * Maps to: OWASP LLM05:2025, OWASP ASI02:2026 (Tool Misuse), CWE-79/89/78/1236.
 * Refs: https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
 *       https://arxiv.org/abs/2507.13169 (Prompt Injection 2.0)
 */

import { GuardLogger } from "../types";

// --- Interfaces ---

export type OutputSink = "html" | "sql" | "shell" | "markdown" | "csv";

export interface OutputGuardConfig {
  /** Detect HTML/DOM XSS payloads (default: true) */
  detectHtml?: boolean;
  /** Detect SQL injection payloads (default: true) */
  detectSql?: boolean;
  /** Detect OS shell / command injection payloads (default: true) */
  detectShell?: boolean;
  /** Detect markdown-image data-exfiltration links (default: true) */
  detectMarkdownExfil?: boolean;
  /** Detect spreadsheet/CSV formula injection (default: true) */
  detectCsvFormula?: boolean;
  /**
   * Domains allowed in markdown image/link URLs. When set, external URLs whose
   * host is not in this list are flagged. Empty (default) = only flag image
   * URLs that carry a query string (the exfil signal).
   */
  allowedDomains?: string[];
  /** Additional regex patterns to flag (treated as "high" severity) */
  blockedPatterns?: string[];
  /** Risk score (0-1) at or above which output is blocked (default: 0.7) */
  riskThreshold?: number;
  /** Return a neutralized copy of the output in `sanitized` (default: false) */
  sanitize?: boolean;
  /** Logger */
  logger?: GuardLogger;
}

export interface OutputThreat {
  sink: OutputSink | "custom";
  type: string;
  detail: string;
  severity: "low" | "medium" | "high" | "critical";
}

export interface OutputGuardResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  riskScore: number;
  threats: OutputThreat[];
  /** Present only when config.sanitize is true */
  sanitized?: string;
}

// --- Detection patterns ---

const HTML_PATTERNS: Array<{ pattern: RegExp; label: string; severity: OutputThreat["severity"] }> = [
  { pattern: /<script\b[^>]*>/i, label: "<script> tag", severity: "critical" },
  { pattern: /<iframe\b[^>]*>/i, label: "<iframe> tag", severity: "high" },
  { pattern: /<object\b[^>]*>|<embed\b[^>]*>/i, label: "<object>/<embed> tag", severity: "high" },
  { pattern: /javascript:\s*[^\s"']/i, label: "javascript: URI", severity: "high" },
  { pattern: /\bon(?:error|load|click|mouseover|focus|submit|toggle|animationstart)\s*=/i, label: "inline event handler", severity: "high" },
  { pattern: /<svg\b[^>]*\bon\w+\s*=/i, label: "<svg> with event handler", severity: "high" },
  { pattern: /\bdocument\.(?:cookie|location|write)\b/i, label: "document.cookie/location/write", severity: "high" },
  { pattern: /\bdata:text\/html/i, label: "data:text/html URI", severity: "high" },
  { pattern: /<img\b[^>]*\bonerror\s*=/i, label: "<img onerror=>", severity: "critical" },
];

const SQL_PATTERNS: Array<{ pattern: RegExp; label: string; severity: OutputThreat["severity"] }> = [
  { pattern: /\bUNION\s+(?:ALL\s+)?SELECT\b/i, label: "UNION SELECT", severity: "critical" },
  { pattern: /'\s*OR\s+'?\d+'?\s*=\s*'?\d+/i, label: "tautology ' OR 1=1", severity: "critical" },
  { pattern: /\bOR\s+1\s*=\s*1\b/i, label: "OR 1=1 tautology", severity: "high" },
  { pattern: /;\s*DROP\s+(?:TABLE|DATABASE)\b/i, label: ";DROP TABLE/DATABASE", severity: "critical" },
  { pattern: /;\s*DELETE\s+FROM\b/i, label: ";DELETE FROM", severity: "critical" },
  { pattern: /;\s*(?:INSERT\s+INTO|UPDATE)\b/i, label: ";INSERT/UPDATE statement", severity: "high" },
  { pattern: /\bxp_cmdshell\b/i, label: "xp_cmdshell", severity: "critical" },
  { pattern: /--\s*$|\/\*.*?\*\//m, label: "SQL comment terminator", severity: "low" },
];

const SHELL_PATTERNS: Array<{ pattern: RegExp; label: string; severity: OutputThreat["severity"] }> = [
  { pattern: /\$\([^)]+\)/, label: "command substitution $(...)", severity: "high" },
  { pattern: /`[^`]+`/, label: "backtick command substitution", severity: "high" },
  { pattern: /;\s*rm\s+-[rf]/i, label: ";rm -rf", severity: "critical" },
  { pattern: /(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b/i, label: "curl|wget piped to shell", severity: "critical" },
  { pattern: /\|\s*(?:bash|sh|zsh|powershell|cmd)\b/i, label: "pipe to shell interpreter", severity: "high" },
  { pattern: /&&\s*(?:rm|curl|wget|nc|chmod|chown)\b/i, label: "chained destructive command", severity: "high" },
  { pattern: /\bIFS\s*=|\$\{IFS\}/, label: "IFS manipulation", severity: "medium" },
];

/** Markdown image whose URL carries a query string (auto-fetch exfil channel) */
const MARKDOWN_IMAGE = /!\[[^\]]*\]\(\s*(https?:\/\/[^)\s]+)\s*\)/gi;
/** Markdown link (for allowedDomains enforcement) */
const MARKDOWN_LINK = /(?<!!)\[[^\]]*\]\(\s*(https?:\/\/[^)\s]+)\s*\)/gi;

/** Spreadsheet formula-injection: a cell that starts with a formula trigger */
const CSV_TRIGGER = /(?:^|[\n\r,;\t])\s*([=+\-@][^\n\r,;\t]{0,200})/g;
/** Dangerous functions that make a leading + - @ unambiguously an attack */
const CSV_DANGEROUS_FN = /\b(?:HYPERLINK|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|WEBSERVICE|DDE|MSEXCEL)\b|cmd\s*\||^\s*=[\w.]+\s*\(/i;

// --- Guard Implementation ---

export class OutputGuard {
  readonly guardName = "OutputGuard";
  readonly guardLayer = "L35";

  private config: Required<Omit<OutputGuardConfig, "logger">> & { logger?: GuardLogger };

  constructor(config: OutputGuardConfig = {}) {
    this.config = {
      detectHtml: config.detectHtml ?? true,
      detectSql: config.detectSql ?? true,
      detectShell: config.detectShell ?? true,
      detectMarkdownExfil: config.detectMarkdownExfil ?? true,
      detectCsvFormula: config.detectCsvFormula ?? true,
      allowedDomains: config.allowedDomains ?? [],
      blockedPatterns: config.blockedPatterns ?? [],
      riskThreshold: config.riskThreshold ?? 0.7,
      sanitize: config.sanitize ?? false,
      logger: config.logger,
    };
  }

  /**
   * Scan model/tool output for downstream-sink payloads.
   * @param output the text produced by the model (or a tool result)
   */
  scan(output: string): OutputGuardResult {
    const threats: OutputThreat[] = [];
    const violations: string[] = [];

    if (typeof output !== "string" || output.length === 0) {
      return { allowed: true, violations: [], riskScore: 0, threats: [] };
    }

    if (this.config.detectHtml) this.match(output, HTML_PATTERNS, "html", threats, violations);
    if (this.config.detectSql) this.match(output, SQL_PATTERNS, "sql", threats, violations);
    if (this.config.detectShell) this.match(output, SHELL_PATTERNS, "shell", threats, violations);
    if (this.config.detectMarkdownExfil) this.detectMarkdownExfil(output, threats, violations);
    if (this.config.detectCsvFormula) this.detectCsvFormula(output, threats, violations);

    for (const pat of this.config.blockedPatterns) {
      if (new RegExp(pat, "i").test(output)) {
        threats.push({ sink: "custom", type: "custom_blocked_pattern", detail: `Matched blocked pattern: ${pat}`, severity: "high" });
        violations.push(`blocked_pattern:${pat}`);
      }
    }

    const riskScore = this.computeRiskScore(threats);
    const allowed = riskScore < this.config.riskThreshold && !threats.some((t) => t.severity === "critical");
    const reason = allowed ? undefined : this.buildReason(threats);

    if (!allowed) this.config.logger?.(`OutputGuard blocked output: ${reason}`, "warn");

    const result: OutputGuardResult = { allowed, reason, violations, riskScore, threats };
    if (this.config.sanitize) result.sanitized = this.neutralize(output);
    return result;
  }

  private match(
    output: string,
    patterns: Array<{ pattern: RegExp; label: string; severity: OutputThreat["severity"] }>,
    sink: OutputSink,
    threats: OutputThreat[],
    violations: string[]
  ): void {
    for (const { pattern, label, severity } of patterns) {
      if (pattern.test(output)) {
        threats.push({ sink, type: `${sink}_payload`, detail: `Detected ${label}`, severity });
        violations.push(`${sink}:${label}`);
      }
    }
  }

  private detectMarkdownExfil(output: string, threats: OutputThreat[], violations: string[]): void {
    const allow = this.config.allowedDomains.map((d) => d.toLowerCase());
    const flagUrl = (url: string, kind: "image" | "link"): boolean => {
      const host = this.hostOf(url);
      const hasQuery = /[?&]/.test(url);
      if (allow.length > 0) {
        // Allowlist mode: flag any host not on the allowlist
        return !!host && !allow.some((d) => host === d || host.endsWith(`.${d}`));
      }
      // Default mode: images that carry a query string are an exfil channel
      return kind === "image" && hasQuery;
    };

    for (const m of output.matchAll(MARKDOWN_IMAGE)) {
      if (flagUrl(m[1], "image")) {
        threats.push({ sink: "markdown", type: "markdown_image_exfil", detail: `Auto-fetched image leaks data to ${this.hostOf(m[1]) || m[1]}`, severity: "high" });
        violations.push(`markdown:image_exfil:${this.hostOf(m[1]) || m[1]}`);
      }
    }
    if (allow.length > 0) {
      for (const m of output.matchAll(MARKDOWN_LINK)) {
        if (flagUrl(m[1], "link")) {
          threats.push({ sink: "markdown", type: "markdown_link_offdomain", detail: `Link to non-allowlisted domain ${this.hostOf(m[1]) || m[1]}`, severity: "medium" });
          violations.push(`markdown:offdomain:${this.hostOf(m[1]) || m[1]}`);
        }
      }
    }
  }

  private detectCsvFormula(output: string, threats: OutputThreat[], violations: string[]): void {
    for (const m of output.matchAll(CSV_TRIGGER)) {
      const cell = m[1];
      const leader = cell[0];
      // A cell starting with '=' is always a formula; +,-,@ only flag with a
      // dangerous function (avoids flagging "-5", "+1", "@mention", "- bullet").
      if (leader === "=" || CSV_DANGEROUS_FN.test(cell)) {
        threats.push({ sink: "csv", type: "csv_formula_injection", detail: `Cell begins with formula trigger "${leader}": ${cell.slice(0, 40)}`, severity: leader === "=" || CSV_DANGEROUS_FN.test(cell) ? "high" : "medium" });
        violations.push(`csv:formula:${leader}`);
      }
    }
  }

  /** Best-effort lowercase host extraction without the URL constructor (zero-dep, never throws) */
  private hostOf(url: string): string {
    const m = /^https?:\/\/([^/?#:\s]+)/i.exec(url);
    return m ? m[1].toLowerCase() : "";
  }

  private computeRiskScore(threats: OutputThreat[]): number {
    if (threats.length === 0) return 0;
    const weights: Record<string, number> = { low: 0.1, medium: 0.25, high: 0.45, critical: 0.8 };
    let score = 0;
    for (const t of threats) score += weights[t.severity] ?? 0.1;
    return Math.min(score, 1);
  }

  private buildReason(threats: OutputThreat[]): string {
    const critical = threats.filter((t) => t.severity === "critical");
    const high = threats.filter((t) => t.severity === "high");
    if (critical.length > 0) return `Critical output payloads detected: ${critical.map((t) => t.detail).join("; ")}`;
    if (high.length > 0) return `High-risk output payloads detected: ${high.map((t) => t.detail).join("; ")}`;
    return `Multiple output payloads detected (risk score exceeded threshold)`;
  }

  /** Opt-in neutralization: strip script tags and prefix CSV formula cells with a quote */
  private neutralize(output: string): string {
    let out = output
      .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, "")
      .replace(/<script\b[^>]*>/gi, "")
      .replace(/javascript:/gi, "blocked:")
      .replace(/\son(?:error|load|click|mouseover|focus|submit|toggle)\s*=/gi, " data-blocked-handler=");
    // Prefix formula cells so spreadsheets treat them as text (OWASP guidance)
    out = out.replace(CSV_TRIGGER, (full, cell: string) => {
      if (cell[0] === "=" || CSV_DANGEROUS_FN.test(cell)) {
        return full.replace(cell, `'${cell}`);
      }
      return full;
    });
    return out;
  }
}
