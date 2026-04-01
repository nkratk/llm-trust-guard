/**
 * AgentCommunicationGuard (L12)
 *
 * Secures communication between agents in multi-agent systems.
 * Prevents impersonation, replay attacks, and message tampering.
 *
 * Threat Model:
 * - ASI07: Insecure Inter-Agent Communication
 * - Agent impersonation attacks
 * - Message replay attacks
 * - Man-in-the-middle attacks
 *
 * Protection Capabilities:
 * - Message authentication (HMAC signing)
 * - Agent identity verification
 * - Replay attack prevention (nonces)
 * - Message encryption (optional)
 * - Channel integrity validation
 */

import * as crypto from "crypto";

export interface AgentCommunicationGuardConfig {
  /** Secret key for HMAC signing (auto-generated if not provided) */
  signingKey?: string;
  /** Enable message encryption */
  enableEncryption?: boolean;
  /** Encryption key (required if encryption enabled) */
  encryptionKey?: string;
  /** Nonce expiration time in milliseconds */
  nonceExpiration?: number;
  /** Maximum message age in milliseconds */
  maxMessageAge?: number;
  /** Require all messages to be signed */
  requireSignatures?: boolean;
  /** Allowed agent IDs (empty = allow all registered) */
  allowedAgents?: string[];
  /** Enable strict mode (block on any violation) */
  strictMode?: boolean;
}

export interface AgentIdentity {
  /** Unique agent identifier */
  agentId: string;
  /** Agent type/role */
  agentType: string;
  /** Agent capabilities/permissions */
  capabilities: string[];
  /** Public key for verification (optional, for asymmetric signing) */
  publicKey?: string;
  /** Registration timestamp */
  registeredAt: number;
  /** Trust score (0-100) */
  trustScore: number;
  /** Metadata */
  metadata?: Record<string, any>;
}

export interface AgentMessage {
  /** Message unique identifier */
  messageId: string;
  /** Sender agent ID */
  fromAgent: string;
  /** Recipient agent ID(s) */
  toAgent: string | string[];
  /** Message type */
  type: "request" | "response" | "broadcast" | "event";
  /** Message payload */
  payload: any;
  /** Timestamp */
  timestamp: number;
  /** Nonce for replay prevention */
  nonce: string;
  /** HMAC signature */
  signature?: string;
  /** Encrypted flag */
  encrypted?: boolean;
  /** Reference to parent message (for responses) */
  replyTo?: string;
  /** Time-to-live in milliseconds */
  ttl?: number;
}

export interface MessageValidationResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  validation: {
    sender_verified: boolean;
    recipient_valid: boolean;
    signature_valid: boolean;
    nonce_valid: boolean;
    timestamp_valid: boolean;
    payload_safe: boolean;
    trust_score: number;
  };
  decrypted_payload?: any;
  recommendations: string[];
}

export interface ChannelStatus {
  agentId: string;
  connected: boolean;
  lastSeen: number;
  messageCount: number;
  trustScore: number;
  violations: number;
}

export class AgentCommunicationGuard {
  private config: Required<AgentCommunicationGuardConfig>;
  private signingKey: Buffer;
  private encryptionKey?: Buffer;
  private registeredAgents: Map<string, AgentIdentity> = new Map();
  private usedNonces: Map<string, number> = new Map(); // nonce -> timestamp
  private messageHistory: Map<string, number> = new Map(); // messageId -> timestamp
  private agentViolations: Map<string, number> = new Map();

  // Dangerous payload patterns
  private readonly PAYLOAD_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: number }> = [
    { name: "instruction_injection", pattern: /"instruction"\s*:\s*"[^"]*ignore|override/i, severity: 40 },
    { name: "role_escalation", pattern: /"(role|permission|capability)"\s*:\s*"(admin|root|system)"/i, severity: 50 },
    { name: "command_injection", pattern: /"(command|action|execute)"\s*:\s*"(rm|delete|drop|exec)/i, severity: 55 },
    { name: "redirect_attack", pattern: /"(redirect|forward|proxy)"\s*:\s*"https?:\/\/(?!localhost)/i, severity: 45 },
    { name: "credential_request", pattern: /"(request|get|retrieve)"\s*:\s*"(password|secret|key|token)"/i, severity: 50 },
  ];

  constructor(config: AgentCommunicationGuardConfig = {}) {
    this.config = {
      signingKey: config.signingKey ?? crypto.randomBytes(32).toString("hex"),
      enableEncryption: config.enableEncryption ?? false,
      encryptionKey: config.encryptionKey ?? "",
      nonceExpiration: config.nonceExpiration ?? 5 * 60 * 1000, // 5 minutes
      maxMessageAge: config.maxMessageAge ?? 60 * 1000, // 1 minute
      requireSignatures: config.requireSignatures ?? true,
      allowedAgents: config.allowedAgents ?? [],
      strictMode: config.strictMode ?? false,
    };

    this.signingKey = Buffer.from(this.config.signingKey, "hex");

    if (this.config.enableEncryption) {
      if (!this.config.encryptionKey) {
        this.config.encryptionKey = crypto.randomBytes(32).toString("hex");
      }
      this.encryptionKey = Buffer.from(this.config.encryptionKey, "hex");
    }

  }

  /**
   * Register an agent for communication
   */
  registerAgent(
    agentId: string,
    agentType: string,
    capabilities: string[],
    metadata?: Record<string, any>
  ): AgentIdentity {
    const identity: AgentIdentity = {
      agentId,
      agentType,
      capabilities,
      registeredAt: Date.now(),
      trustScore: 80, // Start with good trust
      metadata,
    };

    this.registeredAgents.set(agentId, identity);
    return identity;
  }

  /**
   * Unregister an agent
   */
  unregisterAgent(agentId: string): boolean {
    return this.registeredAgents.delete(agentId);
  }

  /**
   * Create a signed message
   */
  createMessage(
    fromAgent: string,
    toAgent: string | string[],
    type: AgentMessage["type"],
    payload: any,
    replyTo?: string,
    ttl?: number
  ): AgentMessage {
    const messageId = `msg-${Date.now()}-${crypto.randomBytes(8).toString("hex")}`;
    const nonce = crypto.randomBytes(16).toString("hex");
    const timestamp = Date.now();

    let finalPayload = payload;

    // Encrypt if enabled
    if (this.config.enableEncryption && this.encryptionKey) {
      finalPayload = this.encryptPayload(payload);
    }

    const message: AgentMessage = {
      messageId,
      fromAgent,
      toAgent,
      type,
      payload: finalPayload,
      timestamp,
      nonce,
      replyTo,
      ttl: ttl ?? this.config.maxMessageAge,
      encrypted: this.config.enableEncryption,
    };

    // Sign the message
    message.signature = this.signMessage(message);

    return message;
  }

  /**
   * Validate an incoming message
   */
  /**
   * Destroy guard and release resources
   */
  destroy(): void {
    this.registeredAgents.clear();
    this.usedNonces.clear();
    this.messageHistory.clear();
  }

  private lastCleanup = 0;

  private lazyCleanupNonces(): void {
    const now = Date.now();
    if (now - this.lastCleanup < 60000) return;
    this.lastCleanup = now;
    this.cleanupNonces();
  }

  validateMessage(
    message: AgentMessage,
    receivingAgentId: string,
    requestId?: string
  ): MessageValidationResult {
    // Lazy nonce cleanup on access
    this.lazyCleanupNonces();
    const reqId = requestId || `amsg-${Date.now()}`;
    const violations: string[] = [];
    let senderVerified = false;
    let recipientValid = false;
    let signatureValid = false;
    let nonceValid = false;
    let timestampValid = false;
    let payloadSafe = false;
    let trustScore = 0;

    // Check sender is registered
    const sender = this.registeredAgents.get(message.fromAgent);
    if (sender) {
      senderVerified = true;
      trustScore = sender.trustScore;

      // Check if sender is in allowed list (if configured)
      if (this.config.allowedAgents.length > 0 && !this.config.allowedAgents.includes(message.fromAgent)) {
        violations.push("sender_not_allowed");
        senderVerified = false;
      }
    } else {
      violations.push("sender_not_registered");
    }

    // Check recipient
    const recipients = Array.isArray(message.toAgent) ? message.toAgent : [message.toAgent];
    if (recipients.includes(receivingAgentId) || recipients.includes("*")) {
      recipientValid = true;
    } else {
      violations.push("recipient_mismatch");
    }

    // Verify signature
    if (this.config.requireSignatures) {
      if (!message.signature) {
        violations.push("missing_signature");
      } else {
        const { signature: _, ...messageWithoutSig } = message;
        const expectedSignature = this.signMessage(messageWithoutSig);
        if (message.signature === expectedSignature) {
          signatureValid = true;
        } else {
          violations.push("invalid_signature");
        }
      }
    } else {
      signatureValid = true; // Skip if not required
    }

    // Check nonce (replay prevention)
    if (this.usedNonces.has(message.nonce)) {
      violations.push("nonce_reused");
    } else {
      nonceValid = true;
      this.usedNonces.set(message.nonce, Date.now());
    }

    // Check message ID uniqueness
    if (this.messageHistory.has(message.messageId)) {
      violations.push("duplicate_message");
    } else {
      this.messageHistory.set(message.messageId, Date.now());
    }

    // Check timestamp
    const messageAge = Date.now() - message.timestamp;
    if (messageAge < 0) {
      violations.push("future_timestamp");
    } else if (messageAge > (message.ttl || this.config.maxMessageAge)) {
      violations.push("message_expired");
    } else {
      timestampValid = true;
    }

    // Validate payload
    let decryptedPayload = message.payload;
    if (message.encrypted && this.encryptionKey) {
      try {
        decryptedPayload = this.decryptPayload(message.payload);
      } catch {
        violations.push("decryption_failed");
      }
    }

    const payloadCheck = this.validatePayload(decryptedPayload);
    if (payloadCheck.safe) {
      payloadSafe = true;
    } else {
      violations.push(...payloadCheck.violations);
      trustScore -= payloadCheck.riskContribution;
    }

    // Update agent violations
    if (violations.length > 0 && sender) {
      const currentViolations = this.agentViolations.get(message.fromAgent) || 0;
      this.agentViolations.set(message.fromAgent, currentViolations + violations.length);

      // Reduce trust score for violations
      sender.trustScore = Math.max(0, sender.trustScore - violations.length * 5);
      this.registeredAgents.set(message.fromAgent, sender);
    }

    // Decision
    const criticalViolations = violations.filter((v) =>
      ["invalid_signature", "sender_not_registered", "nonce_reused", "duplicate_message"].includes(v)
    );

    const blocked = this.config.strictMode
      ? violations.length > 0
      : criticalViolations.length > 0;

    return {
      allowed: !blocked,
      reason: blocked
        ? `Message blocked: ${violations.slice(0, 3).join(", ")}`
        : "Message validated successfully",
      violations,
      request_id: reqId,
      validation: {
        sender_verified: senderVerified,
        recipient_valid: recipientValid,
        signature_valid: signatureValid,
        nonce_valid: nonceValid,
        timestamp_valid: timestampValid,
        payload_safe: payloadSafe,
        trust_score: Math.max(0, trustScore),
      },
      decrypted_payload: !blocked ? decryptedPayload : undefined,
      recommendations: this.generateRecommendations(violations),
    };
  }

  /**
   * Create a response to a message
   */
  createResponse(
    originalMessage: AgentMessage,
    fromAgent: string,
    payload: any
  ): AgentMessage {
    return this.createMessage(
      fromAgent,
      originalMessage.fromAgent,
      "response",
      payload,
      originalMessage.messageId
    );
  }

  /**
   * Get channel status for an agent
   */
  getChannelStatus(agentId: string): ChannelStatus | null {
    const agent = this.registeredAgents.get(agentId);
    if (!agent) return null;

    const messageCount = [...this.messageHistory.entries()].filter(
      ([id]) => id.includes(agentId)
    ).length;

    return {
      agentId,
      connected: true,
      lastSeen: agent.registeredAt,
      messageCount,
      trustScore: agent.trustScore,
      violations: this.agentViolations.get(agentId) || 0,
    };
  }

  /**
   * Get all registered agents
   */
  getRegisteredAgents(): AgentIdentity[] {
    return [...this.registeredAgents.values()];
  }

  /**
   * Check if agent has capability
   */
  hasCapability(agentId: string, capability: string): boolean {
    const agent = this.registeredAgents.get(agentId);
    return agent?.capabilities.includes(capability) ?? false;
  }

  /**
   * Update agent trust score
   */
  updateTrustScore(agentId: string, delta: number): void {
    const agent = this.registeredAgents.get(agentId);
    if (agent) {
      agent.trustScore = Math.max(0, Math.min(100, agent.trustScore + delta));
      this.registeredAgents.set(agentId, agent);
    }
  }

  /**
   * Reset agent violations
   */
  resetViolations(agentId: string): void {
    this.agentViolations.delete(agentId);
  }

  /**
   * Verify message chain (for multi-hop scenarios)
   */
  verifyMessageChain(messages: AgentMessage[]): {
    valid: boolean;
    broken_at?: number;
    violations: string[];
  } {
    const violations: string[] = [];

    for (let i = 1; i < messages.length; i++) {
      const current = messages[i];
      const previous = messages[i - 1];

      // Check that current message replies to previous
      if (current.replyTo !== previous.messageId) {
        violations.push(`chain_broken_at_${i}`);
        return { valid: false, broken_at: i, violations };
      }

      // Check timestamps are sequential
      if (current.timestamp < previous.timestamp) {
        violations.push(`timestamp_order_violation_at_${i}`);
        return { valid: false, broken_at: i, violations };
      }

      // Verify signature
      const { signature: _sig, ...currentWithoutSig } = current;
      const expectedSig = this.signMessage(currentWithoutSig);
      if (current.signature !== expectedSig) {
        violations.push(`signature_invalid_at_${i}`);
        return { valid: false, broken_at: i, violations };
      }
    }

    return { valid: true, violations: [] };
  }

  private signMessage(message: Omit<AgentMessage, "signature">): string {
    const data = JSON.stringify({
      messageId: message.messageId,
      fromAgent: message.fromAgent,
      toAgent: message.toAgent,
      type: message.type,
      payload: message.payload,
      timestamp: message.timestamp,
      nonce: message.nonce,
      replyTo: message.replyTo,
    });

    return crypto
      .createHmac("sha256", this.signingKey)
      .update(data)
      .digest("hex");
  }

  private encryptPayload(payload: any): string {
    if (!this.encryptionKey) throw new Error("Encryption key not set");

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.encryptionKey, iv);

    const plaintext = JSON.stringify(payload);
    let encrypted = cipher.update(plaintext, "utf8", "hex");
    encrypted += cipher.final("hex");

    const authTag = cipher.getAuthTag();

    return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
  }

  private decryptPayload(encryptedPayload: string): any {
    if (!this.encryptionKey) throw new Error("Encryption key not set");

    const [ivHex, authTagHex, encrypted] = encryptedPayload.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");

    const decipher = crypto.createDecipheriv("aes-256-gcm", this.encryptionKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return JSON.parse(decrypted);
  }

  private validatePayload(payload: any): {
    safe: boolean;
    violations: string[];
    riskContribution: number;
  } {
    const violations: string[] = [];
    let riskContribution = 0;

    const payloadStr = JSON.stringify(payload);

    for (const { name, pattern, severity } of this.PAYLOAD_INJECTION_PATTERNS) {
      if (pattern.test(payloadStr)) {
        violations.push(`payload_${name}`);
        riskContribution += severity;
      }
    }

    // Check for excessive payload size
    if (payloadStr.length > 100000) {
      violations.push("payload_too_large");
      riskContribution += 20;
    }

    // Check for deeply nested structures (potential DoS)
    const depth = this.getObjectDepth(payload);
    if (depth > 10) {
      violations.push("payload_too_deep");
      riskContribution += 15;
    }

    return {
      safe: violations.length === 0,
      violations,
      riskContribution: Math.min(60, riskContribution),
    };
  }

  private getObjectDepth(obj: any, currentDepth = 0): number {
    if (typeof obj !== "object" || obj === null) return currentDepth;
    if (currentDepth > 15) return currentDepth; // Prevent stack overflow

    let maxDepth = currentDepth;
    for (const value of Object.values(obj)) {
      const depth = this.getObjectDepth(value, currentDepth + 1);
      maxDepth = Math.max(maxDepth, depth);
    }
    return maxDepth;
  }

  private cleanupNonces(): void {
    const now = Date.now();
    const expiration = this.config.nonceExpiration;

    for (const [nonce, timestamp] of this.usedNonces) {
      if (now - timestamp > expiration) {
        this.usedNonces.delete(nonce);
      }
    }

    // Also clean message history
    for (const [messageId, timestamp] of this.messageHistory) {
      if (now - timestamp > expiration * 2) {
        this.messageHistory.delete(messageId);
      }
    }
  }

  private generateRecommendations(violations: string[]): string[] {
    const recommendations: string[] = [];

    if (violations.some((v) => v.includes("signature"))) {
      recommendations.push("Ensure messages are properly signed before sending");
    }
    if (violations.some((v) => v.includes("nonce") || v.includes("duplicate"))) {
      recommendations.push("Implement proper nonce generation to prevent replay attacks");
    }
    if (violations.some((v) => v.includes("sender"))) {
      recommendations.push("Register agents before they can communicate");
    }
    if (violations.some((v) => v.includes("payload"))) {
      recommendations.push("Sanitize message payloads before sending");
    }
    if (violations.some((v) => v.includes("expired") || v.includes("timestamp"))) {
      recommendations.push("Ensure agent clocks are synchronized");
    }

    if (recommendations.length === 0) {
      recommendations.push("Message validated successfully");
    }

    return recommendations;
  }
}
