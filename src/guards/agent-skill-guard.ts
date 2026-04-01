/**
 * AgentSkillGuard
 *
 * Detects malicious agent plugins, tools, and skills before registration/execution.
 * Inspired by OpenClaw research which discovered 824 backdoored plugins across
 * npm, PyPI, and GitHub ecosystems.
 *
 * This is an ARCHITECTURAL guard — it prevents malicious tools from being
 * registered regardless of whether the agent itself was compromised.
 *
 * Threat Model:
 * - Backdoored tool definitions with hidden eval/exec calls
 * - Exfiltration patterns embedded in tool descriptions
 * - Privilege escalation chains across tool combinations
 * - Typosquatting / deceptive naming of trusted tools
 * - Hidden prompt injection in tool metadata
 * - Capability mismatch (read-only tools with write permissions)
 * - Overly broad or suspicious parameter definitions
 */

import { GuardLogger } from "../types";

// --- Interfaces ---

export interface SkillDefinition {
  name: string;
  description: string;
  parameters?: Record<string, any>;
  permissions?: string[];
  source?: string;
  version?: string;
  author?: string;
}

export interface AgentSkillGuardConfig {
  /** Allowlist of known-good tool names */
  trustedTools?: string[];
  /** Additional regex patterns to block */
  blockedPatterns?: string[];
  /** Max description length before flagging (default: 2000) */
  maxDescriptionLength?: number;
  /** Detect data exfiltration patterns in descriptions (default: true) */
  detectExfiltration?: boolean;
  /** Detect hidden prompt injections in metadata (default: true) */
  detectHiddenInstructions?: boolean;
  /** Detect privilege escalation chains (default: true) */
  detectPrivilegeEscalation?: boolean;
  /** Detect typosquatting / deceptive naming (default: true) */
  detectDeceptiveNaming?: boolean;
  /** Logger */
  logger?: GuardLogger;
}

export interface SkillThreat {
  type: string;
  detail: string;
  severity: "low" | "medium" | "high" | "critical";
}

export interface AgentSkillGuardResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  riskScore: number;
  threats: SkillThreat[];
}

// --- Constants ---

/** Patterns from OpenClaw research: code execution in tool definitions */
const BACKDOOR_PATTERNS: Array<{ pattern: RegExp; label: string; severity: SkillThreat["severity"] }> = [
  { pattern: /\beval\s*\(/i, label: "eval() call", severity: "critical" },
  { pattern: /\bexec\s*\(/i, label: "exec() call", severity: "critical" },
  { pattern: /\bFunction\s*\(/i, label: "Function() constructor", severity: "critical" },
  { pattern: /\bchild_process\b/i, label: "child_process reference", severity: "critical" },
  { pattern: /\bspawn\s*\(/i, label: "spawn() call", severity: "high" },
  { pattern: /\bexecSync\s*\(/i, label: "execSync() call", severity: "critical" },
  { pattern: /\brequire\s*\(\s*['"][^'"]*['"]\s*\)/i, label: "dynamic require()", severity: "high" },
  { pattern: /\bimport\s*\(\s*['"][^'"]*['"]\s*\)/i, label: "dynamic import()", severity: "high" },
  { pattern: /\b__proto__\b/, label: "prototype pollution indicator", severity: "high" },
  { pattern: /\bconstructor\s*\[/, label: "constructor bracket access", severity: "high" },
  { pattern: /process\.env/i, label: "environment variable access", severity: "medium" },
  { pattern: /\.ssh\b|\.aws\b|\.kube\b/i, label: "credential directory reference", severity: "critical" },
  { pattern: /base64[_-]?(?:encode|decode)/i, label: "base64 encoding (obfuscation)", severity: "medium" },
  { pattern: /\batob\s*\(|\bbtoa\s*\(/i, label: "base64 function call", severity: "medium" },
];

/** Exfiltration: URLs and network calls in tool metadata */
const EXFILTRATION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /https?:\/\/[^\s"')\]]+/i, label: "hardcoded URL" },
  { pattern: /\bfetch\s*\(/i, label: "fetch() call" },
  { pattern: /\bXMLHttpRequest\b/i, label: "XMLHttpRequest reference" },
  { pattern: /\baxios\b/i, label: "axios reference" },
  { pattern: /\bwebsocket\b/i, label: "WebSocket reference" },
  { pattern: /\bnet\.connect\b/i, label: "net.connect call" },
  { pattern: /\bdns\.resolve\b/i, label: "DNS exfiltration indicator" },
  { pattern: /\bsendBeacon\b/i, label: "sendBeacon() call" },
  { pattern: /webhook[_\-.]?url/i, label: "webhook URL reference" },
  { pattern: /\bcurl\b|\bwget\b/i, label: "shell download command" },
];

/** Hidden instruction patterns (prompt injection in metadata) */
const HIDDEN_INSTRUCTION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i, label: "instruction override" },
  { pattern: /you\s+(?:are|must|should)\s+now/i, label: "role reassignment" },
  { pattern: /system\s*:\s*/i, label: "system prompt injection" },
  { pattern: /\[INST\]|\[\/INST\]/i, label: "instruction tag injection" },
  { pattern: /<\|(?:im_start|im_end|system|user|assistant)\|>/i, label: "chat template injection" },
  { pattern: /\bdo\s+not\s+(?:tell|reveal|show|mention)/i, label: "concealment instruction" },
  { pattern: /\bsecretly\b|\bcovertly\b|\bsilently\b/i, label: "covert action instruction" },
  { pattern: /\boverride\s+(?:security|safety|guard|filter)/i, label: "security override" },
  { pattern: /\bpretend\s+(?:to\s+be|you\s+are)/i, label: "identity spoofing" },
  { pattern: /<!--[\s\S]*?-->/i, label: "HTML comment (hidden content)" },
];

/** Privilege-escalating permission combinations */
const DANGEROUS_PERMISSION_COMBOS: Array<{ permissions: string[]; reason: string }> = [
  { permissions: ["read", "execute"], reason: "read+execute enables read-then-run attacks" },
  { permissions: ["read", "network"], reason: "read+network enables data exfiltration" },
  { permissions: ["write", "execute"], reason: "write+execute enables payload drop+run" },
  { permissions: ["admin", "network"], reason: "admin+network enables remote takeover" },
  { permissions: ["filesystem", "network"], reason: "filesystem+network enables file exfiltration" },
];

/** Read-only intent keywords that conflict with write/exec permissions */
const READ_ONLY_INTENTS = /\b(?:read|view|list|get|fetch|search|query|lookup|check|inspect|show|display)\b/i;
const WRITE_EXEC_PERMISSIONS = /\b(?:write|execute|delete|admin|modify|create|update|remove|drop)\b/i;

/** Well-known trusted tool names for typosquatting detection */
const WELL_KNOWN_TOOLS = [
  "read_file", "write_file", "list_directory", "search", "execute",
  "bash", "python", "node", "calculator", "web_search", "browser",
  "code_interpreter", "retrieval", "dall_e", "wolfram",
];

// --- Guard Implementation ---

export class AgentSkillGuard {
  readonly guardName = "AgentSkillGuard";
  readonly guardLayer = "L-AGENT";

  private config: Required<Omit<AgentSkillGuardConfig, "logger">> & { logger?: GuardLogger };

  constructor(config: AgentSkillGuardConfig = {}) {
    this.config = {
      trustedTools: config.trustedTools ?? [],
      blockedPatterns: config.blockedPatterns ?? [],
      maxDescriptionLength: config.maxDescriptionLength ?? 2000,
      detectExfiltration: config.detectExfiltration ?? true,
      detectHiddenInstructions: config.detectHiddenInstructions ?? true,
      detectPrivilegeEscalation: config.detectPrivilegeEscalation ?? true,
      detectDeceptiveNaming: config.detectDeceptiveNaming ?? true,
      logger: config.logger,
    };
  }

  analyze(skill: SkillDefinition): AgentSkillGuardResult {
    const threats: SkillThreat[] = [];
    const violations: string[] = [];

    // Fast path: trusted tool allowlist
    if (this.config.trustedTools.includes(skill.name)) {
      return { allowed: true, violations: [], riskScore: 0, threats: [] };
    }

    const corpus = this.buildCorpus(skill);

    // 1. Backdoor signature detection (OpenClaw patterns)
    this.detectBackdoors(corpus, threats, violations);

    // 2. Exfiltration patterns
    if (this.config.detectExfiltration) {
      this.detectExfiltrationPatterns(corpus, threats, violations);
    }

    // 3. Hidden instructions / prompt injection in metadata
    if (this.config.detectHiddenInstructions) {
      this.detectHiddenInstructions(corpus, threats, violations);
    }

    // 4. Capability mismatch
    this.detectCapabilityMismatch(skill, threats, violations);

    // 5. Privilege escalation via permission combos
    if (this.config.detectPrivilegeEscalation) {
      this.detectPrivilegeEscalation(skill, threats, violations);
    }

    // 6. Deceptive naming / typosquatting
    if (this.config.detectDeceptiveNaming) {
      this.detectDeceptiveNaming(skill, threats, violations);
    }

    // 7. Suspicious description length
    if (skill.description.length > this.config.maxDescriptionLength) {
      threats.push({
        type: "suspicious_description",
        detail: `Description length ${skill.description.length} exceeds limit ${this.config.maxDescriptionLength}`,
        severity: "medium",
      });
      violations.push("description_too_long");
    }

    // 8. Hidden parameters (parameters with suspicious names)
    this.detectSuspiciousParameters(skill, threats, violations);

    // 9. Custom blocked patterns
    for (const pat of this.config.blockedPatterns) {
      const re = new RegExp(pat, "i");
      if (re.test(corpus)) {
        threats.push({ type: "custom_blocked_pattern", detail: `Matched blocked pattern: ${pat}`, severity: "high" });
        violations.push(`blocked_pattern:${pat}`);
      }
    }

    // Compute risk score
    const riskScore = this.computeRiskScore(threats);
    const allowed = riskScore < 0.7 && !threats.some((t) => t.severity === "critical");
    const reason = allowed ? undefined : this.buildReason(threats);

    if (!allowed) {
      this.config.logger?.(`Blocked skill "${skill.name}": ${reason}`, "warn");
    }

    return { allowed, reason, violations, riskScore, threats };
  }

  /** Concatenate all inspectable text from the skill definition */
  private buildCorpus(skill: SkillDefinition): string {
    const parts = [skill.name, skill.description];
    if (skill.source) parts.push(skill.source);
    if (skill.author) parts.push(skill.author);
    if (skill.parameters) parts.push(JSON.stringify(skill.parameters));
    return parts.join(" ");
  }

  private detectBackdoors(corpus: string, threats: SkillThreat[], violations: string[]): void {
    for (const { pattern, label, severity } of BACKDOOR_PATTERNS) {
      if (pattern.test(corpus)) {
        threats.push({ type: "backdoor_signature", detail: `Detected ${label}`, severity });
        violations.push(`backdoor:${label}`);
      }
    }
  }

  private detectExfiltrationPatterns(corpus: string, threats: SkillThreat[], violations: string[]): void {
    for (const { pattern, label } of EXFILTRATION_PATTERNS) {
      if (pattern.test(corpus)) {
        threats.push({ type: "exfiltration", detail: `Detected ${label}`, severity: "high" });
        violations.push(`exfiltration:${label}`);
      }
    }
  }

  private detectHiddenInstructions(corpus: string, threats: SkillThreat[], violations: string[]): void {
    for (const { pattern, label } of HIDDEN_INSTRUCTION_PATTERNS) {
      if (pattern.test(corpus)) {
        threats.push({ type: "hidden_instruction", detail: `Detected ${label}`, severity: "critical" });
        violations.push(`hidden_instruction:${label}`);
      }
    }
  }

  private detectCapabilityMismatch(skill: SkillDefinition, threats: SkillThreat[], violations: string[]): void {
    if (!skill.permissions || skill.permissions.length === 0) return;

    const descLower = skill.description.toLowerCase();
    const nameAndDesc = `${skill.name} ${descLower}`;

    // Tool claims read-only intent but requests write/exec permissions
    if (READ_ONLY_INTENTS.test(nameAndDesc)) {
      for (const perm of skill.permissions) {
        if (WRITE_EXEC_PERMISSIONS.test(perm)) {
          threats.push({
            type: "capability_mismatch",
            detail: `Tool "${skill.name}" claims read-only intent but requests "${perm}" permission`,
            severity: "high",
          });
          violations.push(`capability_mismatch:${perm}`);
        }
      }
    }
  }

  private detectPrivilegeEscalation(skill: SkillDefinition, threats: SkillThreat[], violations: string[]): void {
    if (!skill.permissions || skill.permissions.length < 2) return;

    const permSet = new Set(skill.permissions.map((p) => p.toLowerCase()));
    for (const combo of DANGEROUS_PERMISSION_COMBOS) {
      if (combo.permissions.every((p) => permSet.has(p))) {
        threats.push({
          type: "privilege_escalation",
          detail: `Dangerous permission combination: ${combo.reason}`,
          severity: "high",
        });
        violations.push(`privilege_escalation:${combo.permissions.join("+")}`);
      }
    }
  }

  private detectDeceptiveNaming(skill: SkillDefinition, threats: SkillThreat[], violations: string[]): void {
    const name = skill.name.toLowerCase().replace(/[-_\s]/g, "");

    for (const trusted of [...WELL_KNOWN_TOOLS, ...this.config.trustedTools]) {
      const normalizedTrusted = trusted.toLowerCase().replace(/[-_\s]/g, "");
      if (name === normalizedTrusted) continue; // exact match is fine

      const distance = this.levenshteinDistance(name, normalizedTrusted);
      const maxLen = Math.max(name.length, normalizedTrusted.length);

      // Flag if edit distance is 1-2 (likely typosquatting)
      if (distance > 0 && distance <= 2 && maxLen > 3) {
        threats.push({
          type: "deceptive_naming",
          detail: `"${skill.name}" is suspiciously similar to trusted tool "${trusted}" (edit distance: ${distance})`,
          severity: "high",
        });
        violations.push(`deceptive_naming:${skill.name}~${trusted}`);
      }
    }
  }

  private detectSuspiciousParameters(skill: SkillDefinition, threats: SkillThreat[], violations: string[]): void {
    if (!skill.parameters) return;

    const suspiciousParamNames = [
      /^_/, /^__/, /callback_url/i, /webhook/i, /exfil/i,
      /^cmd$/i, /^command$/i, /^shell$/i, /^code$/i,
      /^eval$/i, /^exec$/i, /^payload$/i, /^inject$/i,
      /^hidden/i, /^internal/i, /^debug/i, /^bypass/i,
    ];

    for (const paramName of Object.keys(skill.parameters)) {
      for (const re of suspiciousParamNames) {
        if (re.test(paramName)) {
          threats.push({
            type: "suspicious_parameter",
            detail: `Parameter "${paramName}" matches suspicious pattern ${re.source}`,
            severity: "medium",
          });
          violations.push(`suspicious_param:${paramName}`);
          break;
        }
      }
    }

    // Check for excessive parameter count (potential hidden-param attack)
    const paramCount = Object.keys(skill.parameters).length;
    if (paramCount > 20) {
      threats.push({
        type: "excessive_parameters",
        detail: `Tool defines ${paramCount} parameters (threshold: 20)`,
        severity: "medium",
      });
      violations.push("excessive_parameters");
    }
  }

  private computeRiskScore(threats: SkillThreat[]): number {
    if (threats.length === 0) return 0;

    const severityWeights: Record<string, number> = {
      low: 0.1,
      medium: 0.25,
      high: 0.45,
      critical: 0.8,
    };

    let score = 0;
    for (const t of threats) {
      score += severityWeights[t.severity] ?? 0.1;
    }
    return Math.min(score, 1);
  }

  private buildReason(threats: SkillThreat[]): string {
    const critical = threats.filter((t) => t.severity === "critical");
    const high = threats.filter((t) => t.severity === "high");

    if (critical.length > 0) {
      return `Critical threats detected: ${critical.map((t) => t.detail).join("; ")}`;
    }
    if (high.length > 0) {
      return `High-risk threats detected: ${high.map((t) => t.detail).join("; ")}`;
    }
    return `Multiple threats detected (risk score exceeded threshold)`;
  }

  /** Levenshtein distance for typosquatting detection */
  private levenshteinDistance(a: string, b: string): number {
    const m = a.length;
    const n = b.length;
    const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      }
    }
    return dp[m][n];
  }
}
