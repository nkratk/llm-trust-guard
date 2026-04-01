/**
 * CodeExecutionGuard (L11)
 *
 * Validates and sandboxes agent-generated code before execution.
 * Prevents RCE (Remote Code Execution) attacks via malicious code generation.
 *
 * Threat Model:
 * - ASI05: Unexpected Code Execution (RCE)
 * - Code injection via LLM outputs
 * - Sandbox escape attempts
 *
 * Protection Capabilities:
 * - Static code analysis for dangerous patterns
 * - Import/require blocklist enforcement
 * - System call detection
 * - Resource limit enforcement
 * - Language-specific security rules
 */

export interface CodeExecutionGuardConfig {
  /** Allowed programming languages */
  allowedLanguages?: string[];
  /** Blocked imports/modules */
  blockedImports?: string[];
  /** Blocked function calls */
  blockedFunctions?: string[];
  /** Maximum code length in characters */
  maxCodeLength?: number;
  /** Maximum execution time in milliseconds */
  maxExecutionTime?: number;
  /** Allow network access */
  allowNetwork?: boolean;
  /** Allow file system access */
  allowFileSystem?: boolean;
  /** Allow shell/subprocess execution */
  allowShell?: boolean;
  /** Allow environment variable access */
  allowEnvAccess?: boolean;
  /** Custom dangerous patterns */
  customPatterns?: Array<{ name: string; pattern: RegExp; severity: number }>;
  /** Risk threshold for blocking (0-100) */
  riskThreshold?: number;
}

export interface CodeAnalysisResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  code_analysis: {
    language: string;
    length: number;
    dangerous_imports: string[];
    dangerous_functions: string[];
    system_calls: string[];
    network_access: boolean;
    file_access: boolean;
    shell_access: boolean;
    env_access: boolean;
    risk_score: number;
    complexity_score: number;
  };
  sanitized_code?: string;
  sandbox_config?: SandboxConfig;
  recommendations: string[];
}

export interface SandboxConfig {
  timeout: number;
  memoryLimit: number;
  allowedSyscalls: string[];
  networkPolicy: "none" | "localhost" | "allowlist";
  filesystemPolicy: "none" | "readonly" | "temponly";
  envVars: Record<string, string>;
}

export class CodeExecutionGuard {
  private config: Required<CodeExecutionGuardConfig>;

  // Language-specific dangerous patterns
  private readonly DANGEROUS_PATTERNS: Record<string, Array<{ name: string; pattern: RegExp; severity: number }>> = {
    javascript: [
      { name: "eval", pattern: /\beval\s*\(/g, severity: 50 },
      { name: "function_constructor", pattern: /new\s+Function\s*\(/g, severity: 50 },
      { name: "child_process", pattern: /require\s*\(\s*['"]child_process['"]\s*\)/g, severity: 60 },
      { name: "exec", pattern: /\b(exec|execSync|spawn|spawnSync)\s*\(/g, severity: 60 },
      { name: "fs_write", pattern: /\b(writeFile|writeFileSync|appendFile|unlink|rmdir)\s*\(/g, severity: 45 },
      { name: "process_env", pattern: /process\.env/g, severity: 30 },
      { name: "require_dynamic", pattern: /require\s*\(\s*[^'"]/g, severity: 40 },
      { name: "vm_module", pattern: /require\s*\(\s*['"]vm['"]\s*\)/g, severity: 55 },
      { name: "fetch_external", pattern: /fetch\s*\(\s*['"]https?:\/\/(?!localhost)/g, severity: 35 },
      { name: "websocket", pattern: /new\s+WebSocket\s*\(/g, severity: 35 },
      { name: "prototype_pollution", pattern: /__proto__|constructor\s*\[|Object\.setPrototypeOf/g, severity: 50 },
      { name: "global_access", pattern: /\bglobal\b|\bglobalThis\b/g, severity: 35 },
    ],
    python: [
      { name: "eval", pattern: /\beval\s*\(/g, severity: 50 },
      { name: "exec", pattern: /\bexec\s*\(/g, severity: 50 },
      { name: "compile", pattern: /\bcompile\s*\(/g, severity: 45 },
      { name: "subprocess", pattern: /import\s+subprocess|from\s+subprocess/g, severity: 60 },
      { name: "os_system", pattern: /os\.(system|popen|exec)/g, severity: 60 },
      { name: "os_module", pattern: /import\s+os|from\s+os\s+import/g, severity: 40 },
      { name: "socket", pattern: /import\s+socket|from\s+socket/g, severity: 40 },
      { name: "pickle", pattern: /import\s+pickle|pickle\.loads?/g, severity: 55 },
      { name: "ctypes", pattern: /import\s+ctypes|from\s+ctypes/g, severity: 55 },
      { name: "builtins", pattern: /__builtins__|__import__/g, severity: 50 },
      { name: "file_write", pattern: /open\s*\([^)]*['"]w['"]/g, severity: 40 },
      { name: "requests", pattern: /requests\.(get|post|put|delete)\s*\(/g, severity: 35 },
      { name: "getattr_dynamic", pattern: /getattr\s*\(\s*\w+\s*,\s*[^'"]/g, severity: 40 },
    ],
    bash: [
      { name: "rm_rf", pattern: /rm\s+(-rf?|--recursive)/gi, severity: 70 },
      { name: "sudo", pattern: /\bsudo\b/gi, severity: 60 },
      { name: "curl_pipe", pattern: /curl\s+.*\|\s*(ba)?sh/gi, severity: 70 },
      { name: "wget_execute", pattern: /wget\s+.*&&\s*(ba)?sh/gi, severity: 70 },
      { name: "eval", pattern: /\beval\b/gi, severity: 50 },
      { name: "env_dump", pattern: /\benv\b|\bprintenv\b/gi, severity: 35 },
      { name: "chmod", pattern: /chmod\s+(\+x|777|755)/gi, severity: 40 },
      { name: "chown", pattern: /\bchown\b/gi, severity: 45 },
      { name: "dd", pattern: /\bdd\s+if=/gi, severity: 55 },
      { name: "nc_reverse", pattern: /\bnc\b.*-e/gi, severity: 70 },
      { name: "base64_decode", pattern: /base64\s+(-d|--decode)/gi, severity: 40 },
      { name: "cron", pattern: /crontab|\/etc\/cron/gi, severity: 50 },
    ],
    sql: [
      { name: "drop_table", pattern: /DROP\s+(TABLE|DATABASE)/gi, severity: 70 },
      { name: "delete_all", pattern: /DELETE\s+FROM\s+\w+\s*(;|$)/gi, severity: 60 },
      { name: "truncate", pattern: /TRUNCATE\s+TABLE/gi, severity: 65 },
      { name: "union_injection", pattern: /UNION\s+(ALL\s+)?SELECT/gi, severity: 55 },
      { name: "comment_injection", pattern: /--\s*$/gm, severity: 30 },
      { name: "xp_cmdshell", pattern: /xp_cmdshell/gi, severity: 70 },
      { name: "into_outfile", pattern: /INTO\s+(OUT|DUMP)FILE/gi, severity: 60 },
      { name: "load_file", pattern: /LOAD_FILE\s*\(/gi, severity: 55 },
    ],
  };

  // Default blocked imports per language
  private readonly DEFAULT_BLOCKED_IMPORTS: Record<string, string[]> = {
    javascript: [
      "child_process",
      "cluster",
      "dgram",
      "dns",
      "net",
      "tls",
      "vm",
      "worker_threads",
      "v8",
      "perf_hooks",
    ],
    python: [
      "subprocess",
      "os",
      "sys",
      "socket",
      "ctypes",
      "pickle",
      "marshal",
      "multiprocessing",
      "threading",
      "_thread",
    ],
  };

  // Default blocked functions
  private readonly DEFAULT_BLOCKED_FUNCTIONS = [
    "eval",
    "exec",
    "system",
    "popen",
    "spawn",
    "fork",
    "execv",
    "execve",
    "dlopen",
    "compile",
  ];

  constructor(config: CodeExecutionGuardConfig = {}) {
    this.config = {
      allowedLanguages: config.allowedLanguages ?? ["javascript", "python", "sql"],
      blockedImports: config.blockedImports ?? [],
      blockedFunctions: config.blockedFunctions ?? this.DEFAULT_BLOCKED_FUNCTIONS,
      maxCodeLength: config.maxCodeLength ?? 10000,
      maxExecutionTime: config.maxExecutionTime ?? 5000,
      allowNetwork: config.allowNetwork ?? false,
      allowFileSystem: config.allowFileSystem ?? false,
      allowShell: config.allowShell ?? false,
      allowEnvAccess: config.allowEnvAccess ?? false,
      customPatterns: config.customPatterns ?? [],
      riskThreshold: config.riskThreshold ?? 50,
    };
  }

  /**
   * Analyze code for dangerous patterns before execution
   */
  analyze(
    code: string,
    language: string,
    requestId?: string
  ): CodeAnalysisResult {
    const reqId = requestId || `code-${Date.now()}`;
    const normalizedLang = language.toLowerCase();
    const violations: string[] = [];
    let riskScore = 0;

    // Check language allowlist
    if (!this.config.allowedLanguages.includes(normalizedLang)) {
      return {
        allowed: false,
        reason: `Language '${language}' is not allowed`,
        violations: ["disallowed_language"],
        request_id: reqId,
        code_analysis: {
          language: normalizedLang,
          length: code.length,
          dangerous_imports: [],
          dangerous_functions: [],
          system_calls: [],
          network_access: false,
          file_access: false,
          shell_access: false,
          env_access: false,
          risk_score: 100,
          complexity_score: 0,
        },
        recommendations: [`Use one of: ${this.config.allowedLanguages.join(", ")}`],
      };
    }

    // Check code length
    if (code.length > this.config.maxCodeLength) {
      violations.push("code_too_long");
      riskScore += 20;
    }

    // Get language-specific patterns
    const patterns = [
      ...(this.DANGEROUS_PATTERNS[normalizedLang] || []),
      ...this.config.customPatterns,
    ];

    // Analyze for dangerous patterns
    const dangerousImports: string[] = [];
    const dangerousFunctions: string[] = [];
    const systemCalls: string[] = [];
    let networkAccess = false;
    let fileAccess = false;
    let shellAccess = false;
    let envAccess = false;

    for (const { name, pattern, severity } of patterns) {
      const matches = code.match(pattern);
      if (matches) {
        violations.push(`dangerous_pattern_${name}`);
        riskScore += severity;

        // Categorize the pattern
        if (name.includes("exec") || name.includes("spawn") || name.includes("system") || name.includes("subprocess")) {
          shellAccess = true;
          systemCalls.push(name);
        }
        if (name.includes("fs") || name.includes("file") || name.includes("write")) {
          fileAccess = true;
        }
        if (name.includes("fetch") || name.includes("socket") || name.includes("request") || name.includes("websocket")) {
          networkAccess = true;
        }
        if (name.includes("env")) {
          envAccess = true;
        }
        if (name.includes("import") || name.includes("require")) {
          dangerousImports.push(name);
        }
        if (name.includes("eval") || name.includes("exec") || name.includes("compile")) {
          dangerousFunctions.push(name);
        }
      }
    }

    // Check blocked imports
    const blockedImports = [
      ...this.config.blockedImports,
      ...(this.DEFAULT_BLOCKED_IMPORTS[normalizedLang] || []),
    ];

    for (const blockedImport of blockedImports) {
      const importPatterns = [
        new RegExp(`require\\s*\\(\\s*['"]${blockedImport}['"]\\s*\\)`, "g"),
        new RegExp(`import\\s+.*from\\s+['"]${blockedImport}['"]`, "g"),
        new RegExp(`import\\s+${blockedImport}`, "g"),
        new RegExp(`from\\s+${blockedImport}\\s+import`, "g"),
      ];

      for (const pattern of importPatterns) {
        if (pattern.test(code)) {
          violations.push(`blocked_import_${blockedImport}`);
          dangerousImports.push(blockedImport);
          riskScore += 40;
        }
      }
    }

    // Check blocked functions
    for (const blockedFunc of this.config.blockedFunctions) {
      const funcPattern = new RegExp(`\\b${blockedFunc}\\s*\\(`, "g");
      if (funcPattern.test(code)) {
        violations.push(`blocked_function_${blockedFunc}`);
        dangerousFunctions.push(blockedFunc);
        riskScore += 35;
      }
    }

    // Policy checks
    if (networkAccess && !this.config.allowNetwork) {
      violations.push("network_access_denied");
      riskScore += 30;
    }
    if (fileAccess && !this.config.allowFileSystem) {
      violations.push("filesystem_access_denied");
      riskScore += 30;
    }
    if (shellAccess && !this.config.allowShell) {
      violations.push("shell_access_denied");
      riskScore += 40;
    }
    if (envAccess && !this.config.allowEnvAccess) {
      violations.push("env_access_denied");
      riskScore += 25;
    }

    // Calculate complexity (simplified)
    const complexityScore = this.calculateComplexity(code, normalizedLang);

    // Cap risk score
    riskScore = Math.min(100, riskScore);

    // Decision
    const blocked = riskScore >= this.config.riskThreshold;

    const result: CodeAnalysisResult = {
      allowed: !blocked,
      reason: blocked
        ? `Code blocked: ${violations.slice(0, 3).join(", ")}`
        : "Code analysis passed",
      violations,
      request_id: reqId,
      code_analysis: {
        language: normalizedLang,
        length: code.length,
        dangerous_imports: [...new Set(dangerousImports)],
        dangerous_functions: [...new Set(dangerousFunctions)],
        system_calls: [...new Set(systemCalls)],
        network_access: networkAccess,
        file_access: fileAccess,
        shell_access: shellAccess,
        env_access: envAccess,
        risk_score: riskScore,
        complexity_score: complexityScore,
      },
      recommendations: this.generateRecommendations(violations, riskScore),
    };

    // If allowed, provide sandbox configuration
    if (!blocked) {
      result.sandbox_config = this.generateSandboxConfig(
        networkAccess,
        fileAccess,
        shellAccess,
        envAccess
      );

      // Optionally provide sanitized code
      if (violations.length > 0) {
        result.sanitized_code = this.sanitizeCode(code, normalizedLang);
      }
    }

    return result;
  }

  /**
   * Validate code structure (syntax check simulation)
   */
  validateSyntax(code: string, language: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const normalizedLang = language.toLowerCase();

    // Basic syntax checks (simplified - real implementation would use parsers)
    switch (normalizedLang) {
      case "javascript":
        // Check for unclosed brackets
        const jsOpenBraces = (code.match(/{/g) || []).length;
        const jsCloseBraces = (code.match(/}/g) || []).length;
        if (jsOpenBraces !== jsCloseBraces) {
          errors.push("Unbalanced curly braces");
        }

        const jsOpenParens = (code.match(/\(/g) || []).length;
        const jsCloseParens = (code.match(/\)/g) || []).length;
        if (jsOpenParens !== jsCloseParens) {
          errors.push("Unbalanced parentheses");
        }
        break;

      case "python":
        // Check for unclosed quotes
        const singleQuotes = (code.match(/'/g) || []).length;
        const doubleQuotes = (code.match(/"/g) || []).length;
        const tripleQuotes = (code.match(/'''|"""/g) || []).length;

        if ((singleQuotes - tripleQuotes * 3) % 2 !== 0) {
          errors.push("Unclosed single quotes");
        }
        if ((doubleQuotes - tripleQuotes * 3) % 2 !== 0) {
          errors.push("Unclosed double quotes");
        }
        break;

      case "sql":
        // Check for unclosed quotes
        const sqlSingleQuotes = (code.match(/'/g) || []).length;
        if (sqlSingleQuotes % 2 !== 0) {
          errors.push("Unclosed single quotes in SQL");
        }
        break;
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Generate secure sandbox configuration
   */
  generateSandboxConfig(
    needsNetwork: boolean,
    needsFileSystem: boolean,
    needsShell: boolean,
    needsEnv: boolean
  ): SandboxConfig {
    return {
      timeout: this.config.maxExecutionTime,
      memoryLimit: 128 * 1024 * 1024, // 128MB
      allowedSyscalls: this.getAllowedSyscalls(needsNetwork, needsFileSystem, needsShell),
      networkPolicy: needsNetwork && this.config.allowNetwork ? "localhost" : "none",
      filesystemPolicy: needsFileSystem && this.config.allowFileSystem ? "temponly" : "none",
      envVars: needsEnv && this.config.allowEnvAccess
        ? { NODE_ENV: "sandbox", SANDBOX: "true" }
        : {},
    };
  }

  /**
   * Sanitize code by removing dangerous patterns
   */
  sanitizeCode(code: string, language: string): string {
    let sanitized = code;

    // Get language patterns
    const patterns = this.DANGEROUS_PATTERNS[language] || [];

    // Remove high-severity patterns
    for (const { pattern, severity } of patterns) {
      if (severity >= 50) {
        sanitized = sanitized.replace(pattern, "/* BLOCKED */");
      }
    }

    // Remove blocked imports
    const blockedImports = [
      ...this.config.blockedImports,
      ...(this.DEFAULT_BLOCKED_IMPORTS[language] || []),
    ];

    for (const blockedImport of blockedImports) {
      const importPatterns = [
        new RegExp(`require\\s*\\(\\s*['"]${blockedImport}['"]\\s*\\)`, "g"),
        new RegExp(`import\\s+.*from\\s+['"]${blockedImport}['"].*`, "gm"),
        new RegExp(`import\\s+${blockedImport}.*`, "gm"),
        new RegExp(`from\\s+${blockedImport}\\s+import.*`, "gm"),
      ];

      for (const pattern of importPatterns) {
        sanitized = sanitized.replace(pattern, "/* BLOCKED_IMPORT */");
      }
    }

    return sanitized;
  }

  /**
   * Get allowed languages
   */
  getAllowedLanguages(): string[] {
    return [...this.config.allowedLanguages];
  }

  /**
   * Add custom dangerous pattern
   */
  addDangerousPattern(
    language: string,
    name: string,
    pattern: RegExp,
    severity: number
  ): void {
    if (!this.DANGEROUS_PATTERNS[language]) {
      this.DANGEROUS_PATTERNS[language] = [];
    }
    this.DANGEROUS_PATTERNS[language].push({ name, pattern, severity });
  }

  private calculateComplexity(code: string, language: string): number {
    let complexity = 0;

    // Count control structures
    const controlPatterns = {
      javascript: /\b(if|else|for|while|switch|try|catch)\b/g,
      python: /\b(if|elif|else|for|while|try|except|with)\b/g,
      sql: /\b(CASE|WHEN|IF|WHILE|LOOP)\b/gi,
    };

    const pattern = controlPatterns[language as keyof typeof controlPatterns];
    if (pattern) {
      const matches = code.match(pattern) || [];
      complexity += matches.length * 5;
    }

    // Count function definitions
    const funcPatterns = {
      javascript: /\b(function|=>|\basync\b)/g,
      python: /\bdef\b|\blambda\b/g,
      sql: /\bCREATE\s+(FUNCTION|PROCEDURE)\b/gi,
    };

    const funcPattern = funcPatterns[language as keyof typeof funcPatterns];
    if (funcPattern) {
      const funcMatches = code.match(funcPattern) || [];
      complexity += funcMatches.length * 10;
    }

    // Line count factor
    const lines = code.split("\n").length;
    complexity += Math.min(lines, 100);

    return Math.min(100, complexity);
  }

  private getAllowedSyscalls(
    needsNetwork: boolean,
    needsFileSystem: boolean,
    needsShell: boolean
  ): string[] {
    const base = ["read", "write", "exit", "brk", "mmap", "munmap", "close"];

    if (needsNetwork && this.config.allowNetwork) {
      base.push("socket", "connect", "bind", "listen", "accept");
    }

    if (needsFileSystem && this.config.allowFileSystem) {
      base.push("open", "stat", "fstat", "lstat", "access");
    }

    // Never allow shell-related syscalls even if configured
    // This is a security-critical restriction
    // Shell access should be handled differently (e.g., via approved commands only)

    return base;
  }

  private generateRecommendations(violations: string[], riskScore: number): string[] {
    const recommendations: string[] = [];

    if (violations.some((v) => v.includes("import"))) {
      recommendations.push("Remove or replace blocked imports with safe alternatives");
    }
    if (violations.some((v) => v.includes("eval") || v.includes("exec"))) {
      recommendations.push("Avoid dynamic code execution - use static alternatives");
    }
    if (violations.some((v) => v.includes("network"))) {
      recommendations.push("Remove network access or use approved endpoints only");
    }
    if (violations.some((v) => v.includes("filesystem"))) {
      recommendations.push("Use temporary directories or remove file operations");
    }
    if (violations.some((v) => v.includes("shell"))) {
      recommendations.push("Shell access is not permitted - use language-native alternatives");
    }
    if (riskScore >= 70) {
      recommendations.push("Code requires significant review before execution");
    }

    if (recommendations.length === 0) {
      recommendations.push("Code passed security analysis");
    }

    return recommendations;
  }
}
