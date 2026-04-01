/**
 * StatePersistenceGuard (L22)
 *
 * Detects and prevents unauthorized state persistence and corruption.
 * Implements ASI08 from OWASP Agentic Applications 2026.
 *
 * Threat Model:
 * - ASI08: State Corruption
 * - Unauthorized state persistence
 * - Cross-session state leakage
 * - Malicious state injection
 * - State tampering and replay attacks
 *
 * Protection Capabilities:
 * - State integrity verification
 * - Persistence authorization
 * - Cross-session isolation
 * - State encryption validation
 * - Tampering detection
 */

import * as crypto from "crypto";

export interface StatePersistenceGuardConfig {
  /** Enable state integrity checking */
  enableIntegrityCheck?: boolean;
  /** Enable encryption validation */
  requireEncryption?: boolean;
  /** Maximum state size in bytes */
  maxStateSize?: number;
  /** Maximum state age in milliseconds */
  maxStateAge?: number;
  /** Enable cross-session isolation */
  enforceSessionIsolation?: boolean;
  /** Allowed persistence targets */
  allowedTargets?: string[];
  /** Sensitive state keys that require extra protection */
  sensitiveKeys?: string[];
  /** Enable state tampering detection */
  detectTampering?: boolean;
  /** State signing secret (for integrity) */
  signingSecret?: string;
}

export interface StateItem {
  /** Unique state identifier */
  state_id: string;
  /** Session that owns this state */
  session_id: string;
  /** State key/name */
  key: string;
  /** State value */
  value: any;
  /** Creation timestamp */
  created_at: number;
  /** Last modified timestamp */
  modified_at: number;
  /** State version */
  version: number;
  /** Integrity hash */
  integrity_hash?: string;
  /** Is state encrypted */
  encrypted?: boolean;
  /** Persistence target */
  target?: string;
  /** State metadata */
  metadata?: Record<string, any>;
}

export interface StateOperation {
  /** Operation type */
  operation: "read" | "write" | "delete" | "restore" | "migrate";
  /** State key */
  key: string;
  /** State value (for write operations) */
  value?: any;
  /** Session requesting the operation */
  session_id: string;
  /** Target session (for cross-session operations) */
  target_session_id?: string;
  /** Persistence target */
  target?: string;
  /** Provided integrity hash */
  integrity_hash?: string;
  /** State version (for optimistic locking) */
  expected_version?: number;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

export interface StatePersistenceResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  analysis: {
    operation: string;
    state_key: string;
    integrity_valid: boolean;
    encryption_valid: boolean;
    session_authorized: boolean;
    size_valid: boolean;
    age_valid: boolean;
    tampering_detected: boolean;
  };
  state_item?: StateItem;
  recommendations: string[];
}

export class StatePersistenceGuard {
  private config: Required<StatePersistenceGuardConfig>;
  private stateStore: Map<string, StateItem> = new Map();
  private sessionStates: Map<string, Set<string>> = new Map();

  // State injection patterns
  private readonly INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: number }> = [
    // Code injection
    { name: "code_injection", pattern: /(?:eval|exec|Function|setTimeout|setInterval)\s*\(/i, severity: 90 },
    { name: "script_injection", pattern: /<script[\s>]|javascript:/i, severity: 85 },
    { name: "prototype_pollution", pattern: /__proto__|constructor\s*\[|prototype\s*\[/i, severity: 90 },

    // Serialization attacks
    { name: "json_injection", pattern: /\{\s*["']?(__proto__|constructor|prototype)["']?\s*:/i, severity: 85 },
    { name: "yaml_injection", pattern: /!!python\/|!!ruby\/|!!php\//i, severity: 80 },
    { name: "pickle_attack", pattern: /cos\n|cposix\n|csubprocess/i, severity: 95 },

    // Path traversal
    { name: "path_traversal", pattern: /\.\.\/|\.\.\\|%2e%2e/i, severity: 75 },
    { name: "null_byte", pattern: /\x00|%00/i, severity: 80 },

    // State corruption
    { name: "state_hijack", pattern: /session_id\s*[:=]|tenant_id\s*[:=]/i, severity: 70 },
    { name: "privilege_inject", pattern: /(?:role|permission|admin|is_admin)\s*[:=]\s*(?:true|admin|1)/i, severity: 85 },
    { name: "trust_inject", pattern: /trust_level\s*[:=]|autonomy_level\s*[:=]/i, severity: 80 },

    // Replay attacks
    { name: "timestamp_manipulation", pattern: /created_at\s*[:=]\s*\d+|modified_at\s*[:=]\s*\d+/i, severity: 60 },
    { name: "version_manipulation", pattern: /version\s*[:=]\s*\d+/i, severity: 55 },
  ];

  // Sensitive state keys
  private readonly DEFAULT_SENSITIVE_KEYS = [
    "credentials",
    "password",
    "token",
    "secret",
    "api_key",
    "session_token",
    "auth_token",
    "private_key",
    "encryption_key",
    "signing_key",
  ];

  constructor(config: StatePersistenceGuardConfig = {}) {
    this.config = {
      enableIntegrityCheck: config.enableIntegrityCheck ?? true,
      requireEncryption: config.requireEncryption ?? false,
      maxStateSize: config.maxStateSize ?? 1024 * 1024, // 1MB
      maxStateAge: config.maxStateAge ?? 24 * 60 * 60 * 1000, // 24 hours
      enforceSessionIsolation: config.enforceSessionIsolation ?? true,
      allowedTargets: config.allowedTargets ?? ["memory", "session", "cache"],
      sensitiveKeys: config.sensitiveKeys ?? this.DEFAULT_SENSITIVE_KEYS,
      detectTampering: config.detectTampering ?? true,
      signingSecret: config.signingSecret ?? crypto.randomBytes(32).toString("hex"),
    };
  }

  /**
   * Validate a state operation
   */
  validateOperation(
    operation: StateOperation,
    requestId?: string
  ): StatePersistenceResult {
    const reqId = requestId || `state-${Date.now()}`;
    const violations: string[] = [];

    let integrityValid = true;
    let encryptionValid = true;
    let sessionAuthorized = true;
    let sizeValid = true;
    let ageValid = true;
    let tamperingDetected = false;

    // 1. Check session authorization for cross-session operations
    if (this.config.enforceSessionIsolation && operation.target_session_id) {
      if (operation.target_session_id !== operation.session_id) {
        violations.push("cross_session_access_attempt");
        sessionAuthorized = false;
      }
    }

    // 2. Check persistence target authorization
    if (operation.target && !this.config.allowedTargets.includes(operation.target)) {
      violations.push(`unauthorized_target: ${operation.target}`);
    }

    // 3. For write operations, validate the value
    if (operation.operation === "write" && operation.value !== undefined) {
      // Check size
      const valueSize = JSON.stringify(operation.value).length;
      if (valueSize > this.config.maxStateSize) {
        violations.push(`state_size_exceeded: ${valueSize} > ${this.config.maxStateSize}`);
        sizeValid = false;
      }

      // Check for injection patterns
      const valueStr = typeof operation.value === "string"
        ? operation.value
        : JSON.stringify(operation.value);

      for (const { name, pattern, severity } of this.INJECTION_PATTERNS) {
        if (pattern.test(valueStr)) {
          violations.push(`injection_pattern: ${name}`);
          if (severity >= 80) {
            tamperingDetected = true;
          }
        }
      }

      // Check for sensitive key without encryption
      if (this.isSensitiveKey(operation.key) && !operation.metadata?.encrypted) {
        if (this.config.requireEncryption) {
          violations.push("sensitive_key_not_encrypted");
          encryptionValid = false;
        }
      }
    }

    // 4. For read/restore operations, validate existing state
    if (operation.operation === "read" || operation.operation === "restore") {
      const stateKey = this.getStateKey(operation.session_id, operation.key);
      const existingState = this.stateStore.get(stateKey);

      if (existingState) {
        // Check ownership
        if (this.config.enforceSessionIsolation &&
            existingState.session_id !== operation.session_id) {
          violations.push("state_ownership_violation");
          sessionAuthorized = false;
        }

        // Check age
        const age = Date.now() - existingState.created_at;
        if (age > this.config.maxStateAge) {
          violations.push(`state_expired: age ${Math.round(age / 1000)}s`);
          ageValid = false;
        }

        // Verify integrity
        if (this.config.enableIntegrityCheck && existingState.integrity_hash) {
          const expectedHash = this.computeIntegrityHash(existingState);
          if (existingState.integrity_hash !== expectedHash) {
            violations.push("integrity_check_failed");
            integrityValid = false;
            tamperingDetected = true;
          }
        }

        // Verify provided hash matches
        if (operation.integrity_hash && existingState.integrity_hash !== operation.integrity_hash) {
          violations.push("integrity_hash_mismatch");
          integrityValid = false;
        }
      }
    }

    // 5. For restore operations, additional checks
    if (operation.operation === "restore") {
      // Check for version mismatch (optimistic locking)
      if (operation.expected_version !== undefined) {
        const stateKey = this.getStateKey(operation.session_id, operation.key);
        const existingState = this.stateStore.get(stateKey);
        if (existingState && existingState.version !== operation.expected_version) {
          violations.push(`version_conflict: expected ${operation.expected_version}, got ${existingState.version}`);
        }
      }
    }

    // 6. For migrate operations, strict validation
    if (operation.operation === "migrate") {
      violations.push("migration_requires_admin_approval");
    }

    // Determine if operation should be blocked
    const blocked =
      !sessionAuthorized ||
      tamperingDetected ||
      !integrityValid ||
      !sizeValid ||
      violations.length >= 3;

    return {
      allowed: !blocked,
      reason: blocked
        ? `State operation blocked: ${violations.slice(0, 3).join(", ")}`
        : "State operation validated",
      violations,
      request_id: reqId,
      analysis: {
        operation: operation.operation,
        state_key: operation.key,
        integrity_valid: integrityValid,
        encryption_valid: encryptionValid,
        session_authorized: sessionAuthorized,
        size_valid: sizeValid,
        age_valid: ageValid,
        tampering_detected: tamperingDetected,
      },
      recommendations: this.generateRecommendations(violations, operation.operation),
    };
  }

  /**
   * Store state with integrity protection
   */
  storeState(
    sessionId: string,
    key: string,
    value: any,
    options?: {
      target?: string;
      encrypted?: boolean;
      metadata?: Record<string, any>;
    }
  ): StatePersistenceResult {
    const reqId = `store-${Date.now()}`;

    // Validate the operation first
    const validation = this.validateOperation({
      operation: "write",
      key,
      value,
      session_id: sessionId,
      target: options?.target,
      metadata: options,
    }, reqId);

    if (!validation.allowed) {
      return validation;
    }

    // Create or update state
    const stateKey = this.getStateKey(sessionId, key);
    const existingState = this.stateStore.get(stateKey);
    const now = Date.now();

    const stateItem: StateItem = {
      state_id: existingState?.state_id || `state-${now}-${Math.random().toString(36).substr(2, 9)}`,
      session_id: sessionId,
      key,
      value,
      created_at: existingState?.created_at || now,
      modified_at: now,
      version: (existingState?.version || 0) + 1,
      encrypted: options?.encrypted,
      target: options?.target,
      metadata: options?.metadata,
    };

    // Compute integrity hash
    stateItem.integrity_hash = this.computeIntegrityHash(stateItem);

    // Store
    this.stateStore.set(stateKey, stateItem);

    // Track session states
    let sessionStates = this.sessionStates.get(sessionId);
    if (!sessionStates) {
      sessionStates = new Set();
      this.sessionStates.set(sessionId, sessionStates);
    }
    sessionStates.add(key);

    return {
      ...validation,
      state_item: stateItem,
    };
  }

  /**
   * Retrieve state with integrity verification
   */
  retrieveState(
    sessionId: string,
    key: string,
    options?: {
      integrity_hash?: string;
    }
  ): StatePersistenceResult {
    const reqId = `retrieve-${Date.now()}`;

    // Validate the operation
    const validation = this.validateOperation({
      operation: "read",
      key,
      session_id: sessionId,
      integrity_hash: options?.integrity_hash,
    }, reqId);

    if (!validation.allowed) {
      return validation;
    }

    const stateKey = this.getStateKey(sessionId, key);
    const stateItem = this.stateStore.get(stateKey);

    return {
      ...validation,
      state_item: stateItem,
    };
  }

  /**
   * Delete state
   */
  deleteState(sessionId: string, key: string): StatePersistenceResult {
    const reqId = `delete-${Date.now()}`;

    const stateKey = this.getStateKey(sessionId, key);
    const existingState = this.stateStore.get(stateKey);

    if (!existingState) {
      return {
        allowed: true,
        reason: "State not found",
        violations: [],
        request_id: reqId,
        analysis: {
          operation: "delete",
          state_key: key,
          integrity_valid: true,
          encryption_valid: true,
          session_authorized: true,
          size_valid: true,
          age_valid: true,
          tampering_detected: false,
        },
        recommendations: [],
      };
    }

    // Verify ownership
    if (this.config.enforceSessionIsolation && existingState.session_id !== sessionId) {
      return {
        allowed: false,
        reason: "Cannot delete state owned by another session",
        violations: ["session_ownership_violation"],
        request_id: reqId,
        analysis: {
          operation: "delete",
          state_key: key,
          integrity_valid: true,
          encryption_valid: true,
          session_authorized: false,
          size_valid: true,
          age_valid: true,
          tampering_detected: false,
        },
        recommendations: ["Use the correct session ID to delete state"],
      };
    }

    // Delete
    this.stateStore.delete(stateKey);

    const sessionStates = this.sessionStates.get(sessionId);
    if (sessionStates) {
      sessionStates.delete(key);
    }

    return {
      allowed: true,
      reason: "State deleted",
      violations: [],
      request_id: reqId,
      analysis: {
        operation: "delete",
        state_key: key,
        integrity_valid: true,
        encryption_valid: true,
        session_authorized: true,
        size_valid: true,
        age_valid: true,
        tampering_detected: false,
      },
      state_item: existingState,
      recommendations: [],
    };
  }

  /**
   * Verify state integrity
   */
  verifyIntegrity(sessionId: string, key: string): boolean {
    const stateKey = this.getStateKey(sessionId, key);
    const stateItem = this.stateStore.get(stateKey);

    if (!stateItem || !stateItem.integrity_hash) {
      return false;
    }

    const expectedHash = this.computeIntegrityHash(stateItem);
    return stateItem.integrity_hash === expectedHash;
  }

  /**
   * Get all states for a session
   */
  getSessionStates(sessionId: string): StateItem[] {
    const stateKeys = this.sessionStates.get(sessionId);
    if (!stateKeys) return [];

    const states: StateItem[] = [];
    for (const key of stateKeys) {
      const stateKey = this.getStateKey(sessionId, key);
      const state = this.stateStore.get(stateKey);
      if (state) {
        states.push(state);
      }
    }
    return states;
  }

  /**
   * Clean up expired states
   */
  cleanupExpiredStates(): number {
    const now = Date.now();
    let cleaned = 0;

    for (const [stateKey, state] of this.stateStore.entries()) {
      if (now - state.created_at > this.config.maxStateAge) {
        this.stateStore.delete(stateKey);
        const sessionStates = this.sessionStates.get(state.session_id);
        if (sessionStates) {
          sessionStates.delete(state.key);
        }
        cleaned++;
      }
    }

    return cleaned;
  }

  /**
   * Reset all states for a session
   */
  resetSession(sessionId: string): void {
    const stateKeys = this.sessionStates.get(sessionId);
    if (stateKeys) {
      for (const key of stateKeys) {
        this.stateStore.delete(this.getStateKey(sessionId, key));
      }
    }
    this.sessionStates.delete(sessionId);
  }

  // Private methods

  private getStateKey(sessionId: string, key: string): string {
    return `${sessionId}:${key}`;
  }

  private computeIntegrityHash(state: StateItem): string {
    const data = JSON.stringify({
      session_id: state.session_id,
      key: state.key,
      value: state.value,
      version: state.version,
    });

    return crypto
      .createHmac("sha256", this.config.signingSecret)
      .update(data)
      .digest("hex");
  }

  private isSensitiveKey(key: string): boolean {
    const keyLower = key.toLowerCase();
    return this.config.sensitiveKeys.some(sk => keyLower.includes(sk.toLowerCase()));
  }

  private generateRecommendations(violations: string[], operation: string): string[] {
    const recommendations: string[] = [];

    if (violations.some(v => v.includes("cross_session"))) {
      recommendations.push("Access only states owned by the current session");
    }
    if (violations.some(v => v.includes("injection"))) {
      recommendations.push("Sanitize state values before persistence");
    }
    if (violations.some(v => v.includes("integrity"))) {
      recommendations.push("Ensure state has not been tampered with");
    }
    if (violations.some(v => v.includes("encryption"))) {
      recommendations.push("Encrypt sensitive state before storage");
    }
    if (violations.some(v => v.includes("size"))) {
      recommendations.push("Reduce state size or split into smaller chunks");
    }
    if (violations.some(v => v.includes("expired"))) {
      recommendations.push("Refresh or recreate expired state");
    }
    if (violations.some(v => v.includes("version"))) {
      recommendations.push("Fetch latest state version before updating");
    }

    if (recommendations.length === 0) {
      recommendations.push(`Continue with ${operation} operation`);
    }

    return recommendations;
  }
}
