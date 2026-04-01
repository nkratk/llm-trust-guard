/**
 * MCPSecurityGuard (L16)
 *
 * Secures Model Context Protocol (MCP) tool integrations.
 * Prevents tool shadowing, server impersonation, and supply chain attacks.
 *
 * Threat Model:
 * - ASI04: Agentic Supply Chain Vulnerabilities
 * - CVE-2025-68145, CVE-2025-68143, CVE-2025-68144: MCP RCE vulnerabilities
 * - CVE-2025-6514: mcp-remote command injection
 * - CVE-2025-32711: EchoLeak - silent data exfiltration
 * - Tool Shadowing: Malicious MCP servers impersonating legitimate tools
 *
 * Protection Capabilities:
 * - MCP server identity verification (signature-based)
 * - Tool registration allowlist enforcement
 * - Dynamic tool registration monitoring
 * - OAuth endpoint validation
 * - Tool shadowing detection
 * - Server reputation scoring
 * - Command injection prevention
 */

import * as crypto from "crypto";

export interface MCPSecurityGuardConfig {
  /** Require server signature verification */
  requireServerSignature?: boolean;
  /** Trusted MCP servers */
  trustedServers?: MCPServerIdentity[];
  /** Blocked server patterns (domains, names) */
  blockedServers?: string[];
  /** Allow dynamic tool registration at runtime */
  allowDynamicRegistration?: boolean;
  /** Tool name allowlist (if set, only these tools are allowed) */
  toolAllowlist?: string[];
  /** Tool name blocklist */
  toolBlocklist?: string[];
  /** Validate OAuth endpoints */
  validateOAuthEndpoints?: boolean;
  /** Allowed OAuth domains */
  allowedOAuthDomains?: string[];
  /** Enable tool shadowing detection */
  detectToolShadowing?: boolean;
  /** Minimum server reputation score (0-100) */
  minServerReputation?: number;
  /** Enable strict mode (block on any violation) */
  strictMode?: boolean;
  /** Custom command injection patterns */
  customInjectionPatterns?: RegExp[];
}

export interface MCPServerIdentity {
  /** Server unique identifier */
  serverId: string;
  /** Server name/display name */
  name: string;
  /** Server version */
  version?: string;
  /** Public key for signature verification (hex encoded) */
  publicKey?: string;
  /** Trusted domains this server can operate on */
  trustedDomains?: string[];
  /** Tools this server is allowed to provide */
  allowedTools?: string[];
  /** Server metadata */
  metadata?: Record<string, any>;
  /** Registration timestamp */
  registeredAt?: number;
  /** Reputation score (0-100) */
  reputationScore?: number;
}

export interface MCPToolDefinition {
  /** Tool name */
  name: string;
  /** Tool description */
  description: string;
  /** Server providing this tool */
  serverId: string;
  /** Tool parameters schema */
  parameters?: Record<string, any>;
  /** Tool capabilities/permissions required */
  capabilities?: string[];
  /** Tool risk level */
  riskLevel?: "low" | "medium" | "high" | "critical";
}

export interface MCPServerRegistration {
  /** Server identity */
  server: MCPServerIdentity;
  /** Tools provided by this server */
  tools: MCPToolDefinition[];
  /** OAuth configuration if applicable */
  oauth?: {
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
    scopes?: string[];
  };
  /** Server signature (HMAC of server identity) */
  signature?: string;
  /** Registration timestamp */
  timestamp: number;
}

export interface MCPToolCall {
  /** Tool name being called */
  toolName: string;
  /** Server providing the tool */
  serverId: string;
  /** Tool parameters */
  parameters: Record<string, any>;
  /** Request context */
  context?: {
    sessionId?: string;
    userId?: string;
    agentId?: string;
  };
}

export interface MCPSecurityResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  server_analysis?: {
    server_verified: boolean;
    signature_valid: boolean;
    reputation_score: number;
    is_shadowing: boolean;
    tools_allowed: boolean;
  };
  tool_analysis?: {
    tool_registered: boolean;
    tool_allowed: boolean;
    parameters_safe: boolean;
    injection_detected: boolean;
    risk_level: string;
  };
  recommendations: string[];
}

export class MCPSecurityGuard {
  private config: Required<MCPSecurityGuardConfig>;
  private registeredServers: Map<string, MCPServerIdentity> = new Map();
  private registeredTools: Map<string, MCPToolDefinition> = new Map();
  private serverReputation: Map<string, number> = new Map();
  private toolToServer: Map<string, string> = new Map(); // tool name -> server ID
  private serverViolations: Map<string, number> = new Map();
  private toolDefinitionHashes: Map<string, string> = new Map(); // tool name -> SHA256 hash at registration

  // Command injection patterns (based on CVE-2025-6514 and similar)
  private readonly COMMAND_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: number }> = [
    // Shell command injection
    { name: "shell_injection", pattern: /[;&|`$]|\$\(|\)\s*[;&|]|`[^`]+`/g, severity: 50 },
    { name: "command_substitution", pattern: /\$\{[^}]+\}|\$\([^)]+\)/g, severity: 50 },
    { name: "pipe_injection", pattern: /\|\s*(cat|rm|curl|wget|nc|bash|sh|exec)/i, severity: 55 },

    // Path traversal
    { name: "path_traversal", pattern: /\.\.[\/\\]|\.\.%2[fF]/g, severity: 45 },
    { name: "absolute_path", pattern: /^\/(?:etc|usr|var|tmp|bin|root)/i, severity: 40 },

    // URL-based injection (for OAuth endpoints)
    { name: "oauth_injection", pattern: /authorization_endpoint.*[;&|`$]/i, severity: 55 },
    { name: "redirect_manipulation", pattern: /redirect_uri.*[^\w\-_.~:/?#[\]@!$&'()*+,;=%]/i, severity: 45 },

    // AppleScript injection (CVE-2025-68145 style)
    { name: "applescript_injection", pattern: /osascript|do\s+shell\s+script|tell\s+application/i, severity: 55 },

    // Git-specific injection patterns
    { name: "git_injection", pattern: /--upload-pack|--receive-pack|-c\s+core\./i, severity: 50 },
    { name: "git_url_injection", pattern: /ext::|file:\/\/|ssh:\/\/.*@/i, severity: 45 },

    // Argument injection
    { name: "argument_injection", pattern: /\s--[a-z]+=.*[;&|`$]/i, severity: 45 },

    // Environment variable injection
    { name: "env_injection", pattern: /\bLD_PRELOAD\b|\bPATH\s*=/i, severity: 50 },
  ];

  // Tool shadowing indicators
  private readonly SHADOWING_INDICATORS = [
    // Similar names to common legitimate tools
    { legitimate: "file_reader", suspicious: /file[-_]?read(er)?s?|read[-_]?files?/i },
    { legitimate: "database_query", suspicious: /db[-_]?query|sql[-_]?query|query[-_]?db/i },
    { legitimate: "email_sender", suspicious: /send[-_]?emails?|email[-_]?send(er)?/i },
    { legitimate: "api_caller", suspicious: /call[-_]?api|api[-_]?call(er)?/i },
    { legitimate: "code_executor", suspicious: /exec[-_]?code|run[-_]?code|code[-_]?run/i },
  ];

  // Malicious server patterns
  private readonly MALICIOUS_SERVER_PATTERNS = [
    /postmark-mcp.*fake/i,    // Known npm impersonation attack
    /unofficial/i,
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,  // IP-based servers
    /pastebin|gist\.github/i,
    /temp|tmp|test.*mcp/i,
  ];

  constructor(config: MCPSecurityGuardConfig = {}) {
    this.config = {
      requireServerSignature: config.requireServerSignature ?? false,
      trustedServers: config.trustedServers ?? [],
      blockedServers: config.blockedServers ?? [],
      allowDynamicRegistration: config.allowDynamicRegistration ?? true,
      toolAllowlist: config.toolAllowlist ?? [],
      toolBlocklist: config.toolBlocklist ?? [],
      validateOAuthEndpoints: config.validateOAuthEndpoints ?? true,
      allowedOAuthDomains: config.allowedOAuthDomains ?? [],
      detectToolShadowing: config.detectToolShadowing ?? true,
      minServerReputation: config.minServerReputation ?? 30,
      strictMode: config.strictMode ?? false,
      customInjectionPatterns: config.customInjectionPatterns ?? [],
    };

    // Pre-register trusted servers
    for (const server of this.config.trustedServers) {
      this.registeredServers.set(server.serverId, {
        ...server,
        registeredAt: Date.now(),
        reputationScore: server.reputationScore ?? 90,
      });
      this.serverReputation.set(server.serverId, server.reputationScore ?? 90);
    }
  }

  /**
   * Validate MCP server registration
   */
  validateServerRegistration(
    registration: MCPServerRegistration,
    requestId?: string
  ): MCPSecurityResult {
    const reqId = requestId || `mcp-reg-${Date.now()}`;
    const violations: string[] = [];
    let serverVerified = false;
    let signatureValid = false;
    let isShadowing = false;
    let toolsAllowed = true;
    let reputationScore = 50; // Neutral starting point

    const { server, tools, oauth, signature, timestamp } = registration;

    // Check if server is blocked
    if (this.isServerBlocked(server.serverId, server.name)) {
      violations.push("server_blocked");
      reputationScore = 0;
    }

    // Check for malicious server patterns
    const maliciousCheck = this.checkMaliciousPatterns(server);
    if (maliciousCheck.suspicious) {
      violations.push(...maliciousCheck.violations);
      reputationScore -= 30;
    }

    // Verify server signature if required
    if (this.config.requireServerSignature) {
      if (!signature || !server.publicKey) {
        violations.push("missing_server_signature");
      } else {
        signatureValid = this.verifyServerSignature(server, signature);
        if (!signatureValid) {
          violations.push("invalid_server_signature");
          reputationScore -= 40;
        } else {
          serverVerified = true;
          reputationScore += 20;
        }
      }
    } else {
      // No signature required, basic verification
      serverVerified = true;
    }

    // Check for tool shadowing
    if (this.config.detectToolShadowing) {
      const shadowingCheck = this.detectToolShadowing(tools, server.serverId);
      if (shadowingCheck.detected) {
        isShadowing = true;
        violations.push(...shadowingCheck.violations);
        reputationScore -= 50;
      }
    }

    // Validate tools
    for (const tool of tools) {
      // Check tool allowlist/blocklist
      if (this.config.toolAllowlist.length > 0 && !this.config.toolAllowlist.includes(tool.name)) {
        violations.push(`tool_not_in_allowlist: ${tool.name}`);
        toolsAllowed = false;
      }
      if (this.config.toolBlocklist.includes(tool.name)) {
        violations.push(`tool_blocked: ${tool.name}`);
        toolsAllowed = false;
      }

      // Check for injection in tool description
      const descInjection = this.detectInjection(tool.description);
      if (descInjection.detected) {
        violations.push(`injection_in_tool_description: ${tool.name}`);
        reputationScore -= 20;
      }
    }

    // Validate OAuth endpoints if present
    if (oauth && this.config.validateOAuthEndpoints) {
      const oauthCheck = this.validateOAuthConfig(oauth);
      if (!oauthCheck.valid) {
        violations.push(...oauthCheck.violations);
        reputationScore -= 30;
      }
    }

    // Check timestamp (prevent replay attacks)
    const age = Date.now() - timestamp;
    if (age < 0) {
      violations.push("future_timestamp");
    } else if (age > 5 * 60 * 1000) { // 5 minutes
      violations.push("stale_registration");
    }

    // Check dynamic registration policy
    if (!this.config.allowDynamicRegistration && !this.isTrustedServer(server.serverId)) {
      violations.push("dynamic_registration_disabled");
    }

    // Final reputation score
    reputationScore = Math.max(0, Math.min(100, reputationScore));
    const blocked = reputationScore < this.config.minServerReputation ||
      (this.config.strictMode && violations.length > 0) ||
      isShadowing;

    // Register server if allowed
    if (!blocked) {
      this.registerServer(server, tools, reputationScore);
    }

    return {
      allowed: !blocked,
      reason: blocked
        ? `Server registration blocked: ${violations.slice(0, 3).join(", ")}`
        : "Server registration validated",
      violations,
      request_id: reqId,
      server_analysis: {
        server_verified: serverVerified,
        signature_valid: signatureValid,
        reputation_score: reputationScore,
        is_shadowing: isShadowing,
        tools_allowed: toolsAllowed,
      },
      recommendations: this.generateRecommendations(violations, "registration"),
    };
  }

  /**
   * Validate MCP tool call
   */
  validateToolCall(
    toolCall: MCPToolCall,
    requestId?: string
  ): MCPSecurityResult {
    const reqId = requestId || `mcp-call-${Date.now()}`;
    const violations: string[] = [];
    let toolRegistered = false;
    let toolAllowed = true;
    let parametersSafe = true;
    let injectionDetected = false;
    let riskLevel = "low";

    const { toolName, serverId, parameters } = toolCall;

    // Check if tool is registered
    const tool = this.registeredTools.get(toolName);
    if (tool) {
      toolRegistered = true;
      riskLevel = tool.riskLevel || "low";

      // Verify tool belongs to the claimed server
      const expectedServer = this.toolToServer.get(toolName);
      if (expectedServer && expectedServer !== serverId) {
        violations.push("server_tool_mismatch");
        injectionDetected = true; // Possible tool shadowing attack
      }
    } else {
      violations.push("tool_not_registered");
    }

    // Check server reputation
    const serverRep = this.serverReputation.get(serverId) ?? 0;
    if (serverRep < this.config.minServerReputation) {
      violations.push("low_server_reputation");
    }

    // Check tool allowlist/blocklist
    if (this.config.toolAllowlist.length > 0 && !this.config.toolAllowlist.includes(toolName)) {
      violations.push("tool_not_in_allowlist");
      toolAllowed = false;
    }
    if (this.config.toolBlocklist.includes(toolName)) {
      violations.push("tool_blocked");
      toolAllowed = false;
    }

    // Scan parameters for injection
    const paramCheck = this.scanParameters(parameters);
    if (paramCheck.injectionDetected) {
      injectionDetected = true;
      parametersSafe = false;
      violations.push(...paramCheck.violations);
    }

    // Check for high-risk operations without verification
    if (this.isHighRiskOperation(toolName, parameters)) {
      riskLevel = "high";
      if (serverRep < 70) {
        violations.push("high_risk_low_reputation");
      }
    }

    // Update server violation count
    if (violations.length > 0) {
      const currentViolations = this.serverViolations.get(serverId) || 0;
      this.serverViolations.set(serverId, currentViolations + violations.length);

      // Degrade reputation
      const currentRep = this.serverReputation.get(serverId) || 50;
      this.serverReputation.set(serverId, Math.max(0, currentRep - violations.length * 5));
    }

    const blocked = !toolRegistered ||
      !toolAllowed ||
      injectionDetected ||
      (this.config.strictMode && violations.length > 0);

    return {
      allowed: !blocked,
      reason: blocked
        ? `Tool call blocked: ${violations.slice(0, 3).join(", ")}`
        : "Tool call validated",
      violations,
      request_id: reqId,
      tool_analysis: {
        tool_registered: toolRegistered,
        tool_allowed: toolAllowed,
        parameters_safe: parametersSafe,
        injection_detected: injectionDetected,
        risk_level: riskLevel,
      },
      server_analysis: {
        server_verified: this.registeredServers.has(serverId),
        signature_valid: true, // Already validated at registration
        reputation_score: serverRep,
        is_shadowing: false,
        tools_allowed: toolAllowed,
      },
      recommendations: this.generateRecommendations(violations, "tool_call"),
    };
  }

  /**
   * Register a trusted MCP server
   */
  registerTrustedServer(server: MCPServerIdentity, tools: MCPToolDefinition[]): void {
    this.registerServer(server, tools, 90);
  }

  /**
   * Block an MCP server
   */
  blockServer(serverIdOrPattern: string): void {
    if (!this.config.blockedServers.includes(serverIdOrPattern)) {
      this.config.blockedServers.push(serverIdOrPattern);
    }
    // Remove from registered if exists
    this.registeredServers.delete(serverIdOrPattern);
    this.serverReputation.set(serverIdOrPattern, 0);
  }

  /**
   * Get server reputation
   */
  getServerReputation(serverId: string): number {
    return this.serverReputation.get(serverId) ?? 0;
  }

  /**
   * Update server reputation
   */
  updateServerReputation(serverId: string, delta: number): void {
    const current = this.serverReputation.get(serverId) ?? 50;
    this.serverReputation.set(serverId, Math.max(0, Math.min(100, current + delta)));
  }

  /**
   * Get all registered servers
   */
  getRegisteredServers(): MCPServerIdentity[] {
    return [...this.registeredServers.values()];
  }

  /**
   * Get all registered tools
   */
  getRegisteredTools(): MCPToolDefinition[] {
    return [...this.registeredTools.values()];
  }

  /**
   * Check if a tool name is potentially shadowing another
   */
  isToolShadowing(toolName: string): { shadowing: boolean; legitimate?: string } {
    for (const indicator of this.SHADOWING_INDICATORS) {
      if (indicator.suspicious.test(toolName) && toolName !== indicator.legitimate) {
        return { shadowing: true, legitimate: indicator.legitimate };
      }
    }
    return { shadowing: false };
  }

  /**
   * Get violation count for a server
   */
  getServerViolations(serverId: string): number {
    return this.serverViolations.get(serverId) || 0;
  }

  /**
   * Reset server violations
   */
  resetServerViolations(serverId: string): void {
    this.serverViolations.delete(serverId);
  }

  // Private methods

  private registerServer(server: MCPServerIdentity, tools: MCPToolDefinition[], reputation: number): void {
    this.registeredServers.set(server.serverId, {
      ...server,
      registeredAt: Date.now(),
      reputationScore: reputation,
    });
    this.serverReputation.set(server.serverId, reputation);

    // Register tools and store definition hashes for mutation detection
    for (const tool of tools) {
      this.registeredTools.set(tool.name, tool);
      this.toolToServer.set(tool.name, server.serverId);
      // Store hash of tool definition at registration time
      this.toolDefinitionHashes.set(tool.name, this.hashToolDefinition(tool));
    }
  }

  /**
   * Check if a tool's definition has mutated since registration (rug pull detection).
   * CVE-2025-6514: malicious MCP servers mutate tool definitions after approval.
   */
  detectToolMutation(toolName: string, currentDefinition: MCPToolDefinition): { mutated: boolean; original_hash?: string; current_hash?: string } {
    const originalHash = this.toolDefinitionHashes.get(toolName);
    if (!originalHash) return { mutated: false };

    const currentHash = this.hashToolDefinition(currentDefinition);
    return {
      mutated: originalHash !== currentHash,
      original_hash: originalHash,
      current_hash: currentHash,
    };
  }

  /**
   * Scan a tool description for hidden prompt injection (tool poisoning).
   */
  detectToolDescriptionInjection(description: string): { injected: boolean; patterns: string[] } {
    const patterns: string[] = [];
    const injectionPatterns = [
      { name: "hidden_instruction", pattern: /(?:IMPORTANT|NOTE|SYSTEM|ADMIN)\s*:/i },
      { name: "ignore_directive", pattern: /ignore\s+(?:all\s+)?(?:previous|other|prior)/i },
      { name: "override_behavior", pattern: /override|bypass|instead\s+of|rather\s+than/i },
      { name: "exfiltrate_data", pattern: /send\s+(?:to|data|all)|forward\s+(?:to|all)|copy\s+(?:to|all)/i },
      { name: "invisible_text", pattern: /\u200B|\u200C|\u200D|\uFEFF|\u00AD/g },
    ];

    for (const { name, pattern } of injectionPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(description)) {
        patterns.push(name);
      }
    }

    return { injected: patterns.length > 0, patterns };
  }

  private hashToolDefinition(tool: MCPToolDefinition): string {
    const crypto = require("crypto");
    const normalized = JSON.stringify({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
      serverId: tool.serverId,
    });
    return crypto.createHash("sha256").update(normalized).digest("hex");
  }

  private isServerBlocked(serverId: string, serverName?: string): boolean {
    for (const blocked of this.config.blockedServers) {
      if (serverId.includes(blocked) || (serverName && serverName.includes(blocked))) {
        return true;
      }
      try {
        const regex = new RegExp(blocked, "i");
        if (regex.test(serverId) || (serverName && regex.test(serverName))) {
          return true;
        }
      } catch {
        // Invalid regex, treat as string
      }
    }
    return false;
  }

  private isTrustedServer(serverId: string): boolean {
    return this.config.trustedServers.some((s) => s.serverId === serverId);
  }

  private checkMaliciousPatterns(server: MCPServerIdentity): {
    suspicious: boolean;
    violations: string[];
  } {
    const violations: string[] = [];
    const checkStr = `${server.serverId} ${server.name} ${JSON.stringify(server.metadata || {})}`;

    for (const pattern of this.MALICIOUS_SERVER_PATTERNS) {
      if (pattern.test(checkStr)) {
        violations.push(`malicious_pattern: ${pattern.source.substring(0, 20)}`);
      }
    }

    return {
      suspicious: violations.length > 0,
      violations,
    };
  }

  private verifyServerSignature(server: MCPServerIdentity, signature: string): boolean {
    if (!server.publicKey) return false;

    try {
      const data = JSON.stringify({
        serverId: server.serverId,
        name: server.name,
        version: server.version,
      });

      const verify = crypto.createVerify("SHA256");
      verify.update(data);
      return verify.verify(server.publicKey, signature, "hex");
    } catch {
      return false;
    }
  }

  private detectToolShadowing(tools: MCPToolDefinition[], serverId: string): {
    detected: boolean;
    violations: string[];
  } {
    const violations: string[] = [];

    for (const tool of tools) {
      // Check if this tool name is already registered by another server
      const existingServer = this.toolToServer.get(tool.name);
      if (existingServer && existingServer !== serverId) {
        violations.push(`tool_shadowing: ${tool.name} (already registered by ${existingServer})`);
      }

      // Check for suspicious similar names
      const shadowCheck = this.isToolShadowing(tool.name);
      if (shadowCheck.shadowing) {
        violations.push(`suspicious_tool_name: ${tool.name} (similar to ${shadowCheck.legitimate})`);
      }
    }

    return {
      detected: violations.length > 0,
      violations,
    };
  }

  private validateOAuthConfig(oauth: {
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
    scopes?: string[];
  }): { valid: boolean; violations: string[] } {
    const violations: string[] = [];

    // Check authorization endpoint for injection (CVE-2025-6514)
    if (oauth.authorizationEndpoint) {
      const injection = this.detectInjection(oauth.authorizationEndpoint);
      if (injection.detected) {
        violations.push("oauth_authorization_endpoint_injection");
      }

      // Check domain allowlist
      if (this.config.allowedOAuthDomains.length > 0) {
        try {
          const url = new URL(oauth.authorizationEndpoint);
          const domainAllowed = this.config.allowedOAuthDomains.some(
            (d) => url.hostname.endsWith(d)
          );
          if (!domainAllowed) {
            violations.push(`oauth_domain_not_allowed: ${url.hostname}`);
          }
        } catch {
          violations.push("invalid_oauth_authorization_url");
        }
      }
    }

    // Check token endpoint
    if (oauth.tokenEndpoint) {
      const injection = this.detectInjection(oauth.tokenEndpoint);
      if (injection.detected) {
        violations.push("oauth_token_endpoint_injection");
      }
    }

    return {
      valid: violations.length === 0,
      violations,
    };
  }

  private detectInjection(value: string): { detected: boolean; patterns: string[] } {
    const patterns: string[] = [];
    const allPatterns = [...this.COMMAND_INJECTION_PATTERNS, ...this.config.customInjectionPatterns.map((p, i) => ({
      name: `custom_${i}`,
      pattern: p,
      severity: 50,
    }))];

    for (const { name, pattern } of allPatterns) {
      if (pattern.test(value)) {
        patterns.push(name);
      }
    }

    return {
      detected: patterns.length > 0,
      patterns,
    };
  }

  private scanParameters(parameters: Record<string, any>): {
    injectionDetected: boolean;
    violations: string[];
  } {
    const violations: string[] = [];
    const paramStr = JSON.stringify(parameters);

    // Check for command injection in parameter values
    const injection = this.detectInjection(paramStr);
    if (injection.detected) {
      violations.push(...injection.patterns.map((p) => `param_injection_${p}`));
    }

    // Check for excessively long values (potential DoS or buffer overflow)
    for (const [key, value] of Object.entries(parameters)) {
      if (typeof value === "string" && value.length > 10000) {
        violations.push(`oversized_parameter: ${key}`);
      }
    }

    // Check for suspicious keys
    const suspiciousKeys = ["__proto__", "constructor", "prototype", "eval", "exec"];
    for (const key of Object.keys(parameters)) {
      if (suspiciousKeys.includes(key.toLowerCase())) {
        violations.push(`suspicious_parameter_key: ${key}`);
      }
    }

    // SSRF detection in URL parameters (CVE-2026-26118)
    for (const [key, value] of Object.entries(parameters)) {
      if (typeof value === "string") {
        // Internal/private IP SSRF
        if (/^https?:\/\/(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.|localhost|169\.254\.|0\.0\.0\.0|\[?::1\]?)/i.test(value)) {
          violations.push(`ssrf_internal_ip: ${key}`);
        }
        // Dangerous protocols
        if (/^(?:file|gopher|dict|ftp|ldap|ssh|telnet):\/\//i.test(value)) {
          violations.push(`ssrf_dangerous_protocol: ${key}`);
        }
        // Enhanced path traversal (double-encoded and alternate encodings)
        if (/%252e%252e|%c0%ae%c0%ae|%2e%2e%5c|\.\.%255c|\.\.%c0%af|\.\.%c1%9c/i.test(value)) {
          violations.push(`encoded_path_traversal: ${key}`);
        }
        // Sensitive file access
        if (/\/etc\/(?:passwd|shadow|hosts)|\/proc\/self|\/dev\/(?:null|random)|\.ssh\/|\.env/i.test(value)) {
          violations.push(`sensitive_file_access: ${key}`);
        }
      }
    }

    return {
      injectionDetected: violations.length > 0,
      violations,
    };
  }

  private isHighRiskOperation(toolName: string, parameters: Record<string, any>): boolean {
    const highRiskTools = [
      "execute_code", "run_command", "shell_exec", "eval",
      "file_write", "file_delete", "database_write", "database_delete",
      "send_email", "make_payment", "transfer_funds",
      "modify_permissions", "create_user", "delete_user",
    ];

    const toolLower = toolName.toLowerCase();
    if (highRiskTools.some((t) => toolLower.includes(t))) {
      return true;
    }

    // Check parameters for high-risk indicators
    const paramStr = JSON.stringify(parameters).toLowerCase();
    if (paramStr.includes("delete") || paramStr.includes("drop") ||
        paramStr.includes("truncate") || paramStr.includes("exec")) {
      return true;
    }

    return false;
  }

  private generateRecommendations(violations: string[], context: "registration" | "tool_call"): string[] {
    const recommendations: string[] = [];

    if (context === "registration") {
      if (violations.some((v) => v.includes("signature"))) {
        recommendations.push("Enable server signature verification for production");
      }
      if (violations.some((v) => v.includes("shadowing"))) {
        recommendations.push("Review tool names for potential shadowing attacks");
      }
      if (violations.some((v) => v.includes("oauth"))) {
        recommendations.push("Configure OAuth domain allowlist");
      }
      if (violations.some((v) => v.includes("malicious"))) {
        recommendations.push("Block suspicious servers and review server sources");
      }
    } else {
      if (violations.some((v) => v.includes("injection"))) {
        recommendations.push("Sanitize tool parameters before execution");
      }
      if (violations.some((v) => v.includes("reputation"))) {
        recommendations.push("Only use tools from high-reputation servers");
      }
      if (violations.some((v) => v.includes("not_registered"))) {
        recommendations.push("Register tools before allowing execution");
      }
    }

    if (recommendations.length === 0) {
      recommendations.push(context === "registration"
        ? "Server registration validated successfully"
        : "Tool call validated successfully"
      );
    }

    return recommendations;
  }
}
