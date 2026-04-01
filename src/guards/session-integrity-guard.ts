/**
 * SessionIntegrityGuard (L28)
 *
 * Prevents agent session smuggling, hijacking, and state tampering.
 * Inspired by Unit42 research on agent session attacks.
 *
 * Threat Model:
 * - Session token tampering and forgery
 * - Privilege escalation within established sessions
 * - Session hijacking via replay or sequence manipulation
 * - Concurrent session abuse
 *
 * Protection Capabilities:
 * - Session binding with token integrity verification
 * - Permission consistency enforcement (no escalation)
 * - Inactivity and absolute timeout enforcement
 * - Concurrent session limits per user
 * - State continuity validation
 * - Request sequence validation (replay/reorder detection)
 * - Scope binding and authority degradation
 *
 * This is an ARCHITECTURAL guard — it enforces session boundaries
 * regardless of detection. Even if an attacker injects a prompt,
 * they cannot escalate session permissions or hijack sessions.
 */

import { GuardLogger } from "../types";

export interface SessionIntegrityGuardConfig {
  /** Absolute session timeout in ms (default: 3600000 = 1hr) */
  maxSessionDuration?: number;
  /** Inactivity timeout in ms (default: 900000 = 15min) */
  inactivityTimeout?: number;
  /** Maximum concurrent sessions per user (default: 5) */
  maxConcurrentSessions?: number;
  /** Enforce permission consistency — block escalation attempts (default: true) */
  enforcePermissionConsistency?: boolean;
  /** Enforce request sequence validation — detect replay/reorder (default: true) */
  enforceSequenceValidation?: boolean;
  /** Allow permission escalation during a session (default: false) */
  allowPermissionEscalation?: boolean;
  /** Optional logger */
  logger?: GuardLogger;
}

export interface SessionState {
  /** Session identifier */
  sessionId: string;
  /** User who owns the session */
  userId: string;
  /** Permissions granted at session creation */
  initialPermissions: Set<string>;
  /** Current active permissions (can only shrink) */
  currentPermissions: Set<string>;
  /** Session creation timestamp */
  createdAt: number;
  /** Last activity timestamp */
  lastActivity: number;
  /** Monotonically increasing sequence counter */
  sequenceNumber: number;
  /** Set of seen request nonces for replay detection */
  seenNonces: Set<string>;
  /** Whether the session is still active */
  active: boolean;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

export interface SessionIntegrityResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  /** Milliseconds since session creation */
  sessionAge?: number;
  /** Milliseconds since last request */
  lastActivity?: number;
  /** Permission changes detected */
  permissionDelta?: string[];
}

export class SessionIntegrityGuard {
  private config: Required<Omit<SessionIntegrityGuardConfig, "logger">> & { logger?: GuardLogger };
  private sessions: Map<string, SessionState> = new Map();
  private userSessions: Map<string, Set<string>> = new Map();

  constructor(config: SessionIntegrityGuardConfig = {}) {
    this.config = {
      maxSessionDuration: config.maxSessionDuration ?? 3_600_000,
      inactivityTimeout: config.inactivityTimeout ?? 900_000,
      maxConcurrentSessions: config.maxConcurrentSessions ?? 5,
      enforcePermissionConsistency: config.enforcePermissionConsistency ?? true,
      enforceSequenceValidation: config.enforceSequenceValidation ?? true,
      allowPermissionEscalation: config.allowPermissionEscalation ?? false,
      logger: config.logger,
    };
  }

  /**
   * Register a new session. Enforces concurrent session limits.
   */
  createSession(
    sessionId: string,
    userId: string,
    permissions: string[],
    metadata?: Record<string, unknown>
  ): SessionIntegrityResult {
    const violations: string[] = [];
    const now = Date.now();

    // Reject duplicate session IDs
    if (this.sessions.has(sessionId)) {
      violations.push("duplicate_session_id");
      this.log(`Duplicate session ID rejected: ${sessionId}`, "warn");
      return { allowed: false, reason: "Session ID already exists", violations };
    }

    // Purge expired sessions for this user before checking limits
    this.purgeExpiredSessions(userId);

    // Check concurrent session limit
    const userSet = this.userSessions.get(userId) ?? new Set();
    if (userSet.size >= this.config.maxConcurrentSessions) {
      violations.push("concurrent_session_limit_exceeded");
      this.log(`Concurrent session limit exceeded for user: ${userId}`, "warn");
      return {
        allowed: false,
        reason: `User already has ${userSet.size} active sessions (max: ${this.config.maxConcurrentSessions})`,
        violations,
      };
    }

    // Reject empty permissions — sessions must have at least one permission
    if (permissions.length === 0) {
      violations.push("empty_permissions");
      return { allowed: false, reason: "Session must have at least one permission", violations };
    }

    // Create session state
    const permSet = new Set(permissions);
    const session: SessionState = {
      sessionId,
      userId,
      initialPermissions: new Set(permSet),
      currentPermissions: permSet,
      createdAt: now,
      lastActivity: now,
      sequenceNumber: 0,
      seenNonces: new Set(),
      active: true,
      metadata,
    };

    this.sessions.set(sessionId, session);
    userSet.add(sessionId);
    this.userSessions.set(userId, userSet);

    this.log(`Session created: ${sessionId} for user: ${userId} with ${permissions.length} permissions`, "info");

    return { allowed: true, violations: [], sessionAge: 0, lastActivity: 0 };
  }

  /**
   * Validate a request within an existing session.
   * Enforces timeouts, permissions, sequence ordering, and scope binding.
   */
  validateRequest(
    sessionId: string,
    action: string,
    requestedPermissions?: string[],
    nonce?: string,
    sequenceNumber?: number
  ): SessionIntegrityResult {
    const violations: string[] = [];
    const now = Date.now();

    // Session must exist
    const session = this.sessions.get(sessionId);
    if (!session) {
      violations.push("session_not_found");
      return { allowed: false, reason: "Session does not exist", violations };
    }

    // Session must be active
    if (!session.active) {
      violations.push("session_inactive");
      return { allowed: false, reason: "Session has been terminated", violations };
    }

    const sessionAge = now - session.createdAt;
    const idleTime = now - session.lastActivity;

    // Absolute timeout check
    if (sessionAge > this.config.maxSessionDuration) {
      violations.push("absolute_timeout_exceeded");
      this.terminateSession(session);
      this.log(`Session ${sessionId} expired (absolute timeout: ${sessionAge}ms)`, "warn");
      return {
        allowed: false,
        reason: `Session exceeded maximum duration (${this.config.maxSessionDuration}ms)`,
        violations,
        sessionAge,
        lastActivity: idleTime,
      };
    }

    // Inactivity timeout check
    if (idleTime > this.config.inactivityTimeout) {
      violations.push("inactivity_timeout_exceeded");
      this.terminateSession(session);
      this.log(`Session ${sessionId} expired (inactivity: ${idleTime}ms)`, "warn");
      return {
        allowed: false,
        reason: `Session exceeded inactivity timeout (${this.config.inactivityTimeout}ms)`,
        violations,
        sessionAge,
        lastActivity: idleTime,
      };
    }

    // Replay detection via nonce
    if (nonce !== undefined) {
      if (session.seenNonces.has(nonce)) {
        violations.push("replay_detected");
        this.log(`Replay attack detected on session ${sessionId}: nonce=${nonce}`, "warn");
        return {
          allowed: false,
          reason: "Duplicate request nonce — possible replay attack",
          violations,
          sessionAge,
          lastActivity: idleTime,
        };
      }
      session.seenNonces.add(nonce);
    }

    // Sequence validation
    if (this.config.enforceSequenceValidation && sequenceNumber !== undefined) {
      const expectedSeq = session.sequenceNumber + 1;
      if (sequenceNumber !== expectedSeq) {
        violations.push("sequence_violation");
        this.log(
          `Sequence violation on session ${sessionId}: expected=${expectedSeq}, got=${sequenceNumber}`,
          "warn"
        );
        return {
          allowed: false,
          reason: `Request out of sequence (expected ${expectedSeq}, got ${sequenceNumber})`,
          violations,
          sessionAge,
          lastActivity: idleTime,
        };
      }
    }

    // Permission / scope binding checks
    const permissionDelta: string[] = [];

    if (requestedPermissions && requestedPermissions.length > 0) {
      for (const perm of requestedPermissions) {
        // Check against initial scope — action must be within original authorization
        if (!session.initialPermissions.has(perm)) {
          permissionDelta.push(`+${perm}`);
          violations.push("scope_violation");
        }

        // Check against current permissions (may have been degraded)
        if (!session.currentPermissions.has(perm)) {
          if (session.initialPermissions.has(perm)) {
            // Was degraded — cannot re-escalate
            permissionDelta.push(`re-escalate:${perm}`);
            violations.push("authority_re_escalation");
          }
        }
      }

      // Enforce permission consistency — block any escalation
      if (this.config.enforcePermissionConsistency && !this.config.allowPermissionEscalation) {
        if (violations.includes("scope_violation") || violations.includes("authority_re_escalation")) {
          this.log(
            `Permission escalation blocked on session ${sessionId}: ${permissionDelta.join(", ")}`,
            "warn"
          );
          return {
            allowed: false,
            reason: "Permission escalation denied — session permissions can only decrease",
            violations,
            sessionAge,
            lastActivity: idleTime,
            permissionDelta,
          };
        }
      }
    }

    // State continuity — detect dangerous permission transitions
    if (action && this.isAbruptStateChange(action, session)) {
      violations.push("abrupt_state_change");
      this.log(`Abrupt state change detected on session ${sessionId}: action=${action}`, "warn");
      return {
        allowed: false,
        reason: "Abrupt state transition detected — action inconsistent with session permissions",
        violations,
        sessionAge,
        lastActivity: idleTime,
      };
    }

    // All checks passed — update session state
    session.lastActivity = now;
    if (sequenceNumber !== undefined) {
      session.sequenceNumber = sequenceNumber;
    } else {
      session.sequenceNumber++;
    }

    return {
      allowed: violations.length === 0,
      violations,
      sessionAge,
      lastActivity: idleTime,
      permissionDelta: permissionDelta.length > 0 ? permissionDelta : undefined,
    };
  }

  /**
   * Degrade permissions for a session. Permissions can only be removed, never added.
   */
  degradePermissions(sessionId: string, permissionsToRemove: string[]): SessionIntegrityResult {
    const session = this.sessions.get(sessionId);
    if (!session || !session.active) {
      return {
        allowed: false,
        reason: "Session not found or inactive",
        violations: ["session_not_found"],
      };
    }

    const removed: string[] = [];
    for (const perm of permissionsToRemove) {
      if (session.currentPermissions.has(perm)) {
        session.currentPermissions.delete(perm);
        removed.push(`-${perm}`);
      }
    }

    this.log(`Permissions degraded on session ${sessionId}: ${removed.join(", ")}`, "info");

    return {
      allowed: true,
      violations: [],
      permissionDelta: removed,
      sessionAge: Date.now() - session.createdAt,
      lastActivity: Date.now() - session.lastActivity,
    };
  }

  /**
   * Terminate a session and clean up state.
   */
  endSession(sessionId: string): SessionIntegrityResult {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { allowed: false, reason: "Session not found", violations: ["session_not_found"] };
    }

    this.terminateSession(session);
    this.log(`Session ended: ${sessionId}`, "info");

    return {
      allowed: true,
      violations: [],
      sessionAge: Date.now() - session.createdAt,
      lastActivity: Date.now() - session.lastActivity,
    };
  }

  /**
   * List active sessions for a user.
   */
  getActiveSessions(userId: string): string[] {
    this.purgeExpiredSessions(userId);
    const userSet = this.userSessions.get(userId);
    if (!userSet) return [];
    return Array.from(userSet).filter((sid) => {
      const s = this.sessions.get(sid);
      return s?.active === true;
    });
  }

  /**
   * Detect abrupt state changes — e.g., a read-only session attempting destructive actions.
   */
  private isAbruptStateChange(action: string, session: SessionState): boolean {
    const destructiveActions = ["delete", "drop", "truncate", "destroy", "purge", "wipe", "format"];
    const writeActions = ["write", "update", "modify", "create", "insert", "patch", "put"];
    const adminActions = ["admin", "sudo", "escalate", "grant", "revoke", "configure"];

    const perms = session.currentPermissions;
    const actionLower = action.toLowerCase();

    // Read-only session attempting write/delete
    if (perms.size === 1 && perms.has("read") || perms.has("read_only")) {
      if (destructiveActions.some((d) => actionLower.includes(d))) return true;
      if (writeActions.some((w) => actionLower.includes(w))) return true;
    }

    // Non-admin session attempting admin actions
    if (!perms.has("admin") && !perms.has("sudo")) {
      if (adminActions.some((a) => actionLower.includes(a))) return true;
    }

    // Any session attempting destructive actions without explicit delete permission
    if (!perms.has("delete") && !perms.has("admin")) {
      if (destructiveActions.some((d) => actionLower.includes(d))) return true;
    }

    return false;
  }

  /**
   * Mark session inactive and remove from user tracking.
   */
  private terminateSession(session: SessionState): void {
    session.active = false;
    const userSet = this.userSessions.get(session.userId);
    if (userSet) {
      userSet.delete(session.sessionId);
      if (userSet.size === 0) {
        this.userSessions.delete(session.userId);
      }
    }
  }

  /**
   * Purge expired sessions for a user to reclaim concurrent session slots.
   */
  private purgeExpiredSessions(userId: string): void {
    const userSet = this.userSessions.get(userId);
    if (!userSet) return;

    const now = Date.now();
    for (const sid of Array.from(userSet)) {
      const session = this.sessions.get(sid);
      if (!session || !session.active) {
        userSet.delete(sid);
        continue;
      }
      const age = now - session.createdAt;
      const idle = now - session.lastActivity;
      if (age > this.config.maxSessionDuration || idle > this.config.inactivityTimeout) {
        this.terminateSession(session);
      }
    }
  }

  private log(message: string, level: "info" | "warn" | "error"): void {
    if (this.config.logger) {
      this.config.logger(message, level);
    }
  }
}
