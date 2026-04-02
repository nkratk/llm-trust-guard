/**
 * DelegationScopeGuard (L33)
 *
 * Limits what permissions a child agent can inherit from its parent.
 * Like OAuth token downscoping — a child can only receive a strict subset
 * of the parent's scopes, and scopes further decay with each delegation hop.
 *
 * Threat Model:
 * - ASI07: Insecure Inter-Agent Communication
 * - Privilege amplification via delegation (child claims more than parent has)
 * - Lateral movement through scope inheritance
 * - Scope laundering (accumulating permissions across hops)
 *
 * Protection Capabilities:
 * - Strict subset enforcement (child ⊆ parent)
 * - Per-hop scope decay
 * - Blocked scope list (never inheritable regardless of parent)
 * - Maximum allowed scope set
 * - Full delegation audit trail
 */

import * as crypto from "crypto";

export interface DelegationScopeGuardConfig {
  /**
   * Maximum fraction of parent scopes a child may inherit per hop (0–1).
   * 1.0 = child may inherit all parent scopes; 0.5 = at most half; 0 = no inheritance.
   * Default: 1.0 (no automatic decay — rely on explicit scope lists instead)
   */
  maxScopeInheritance?: number;
  /** Scopes that can never be delegated to any child, regardless of parent. */
  blockedScopes?: string[];
  /**
   * Fraction by which the effective scope set shrinks per delegation hop (0–1).
   * 0 = no decay; 0.25 = 25% fewer scopes each hop.
   * Default: 0 (disabled)
   */
  scopeDecayPerHop?: number;
  /** If set, only these scopes can ever appear in any delegation. */
  allowedScopes?: string[];
}

export interface DelegationRequest {
  /** ID of the delegating parent agent */
  parentAgentId: string;
  /** Scopes the parent currently holds */
  parentScopes: string[];
  /** ID of the child agent receiving delegation */
  childAgentId: string;
  /** Scopes the child is requesting */
  requestedScopes: string[];
  /** Delegation hop depth (0 = root → first child) */
  hopDepth: number;
  /** Optional justification */
  reason?: string;
}

export interface DelegationScopeResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  scope_analysis: {
    parent_scopes: string[];
    requested_scopes: string[];
    granted_scopes: string[];
    blocked_scopes_found: string[];
    out_of_parent_scopes: string[];
    exceeds_inheritance_limit: boolean;
    decay_applied: boolean;
    effective_max_scopes: number;
  };
}

export class DelegationScopeGuard {
  readonly guardName = "DelegationScopeGuard";
  readonly guardLayer = "L33";

  private readonly config: Required<DelegationScopeGuardConfig>;
  /** Audit trail: delegationId → result */
  private readonly auditLog: Map<string, DelegationScopeResult> = new Map();

  constructor(config: DelegationScopeGuardConfig = {}) {
    this.config = {
      maxScopeInheritance: config.maxScopeInheritance ?? 1.0,
      blockedScopes: config.blockedScopes ?? [],
      scopeDecayPerHop: config.scopeDecayPerHop ?? 0,
      allowedScopes: config.allowedScopes ?? [],
    };
  }

  /**
   * Validate a delegation request and return the actually-grantable scopes.
   *
   * @param request - The delegation being attempted
   * @param requestId - Optional trace ID
   */
  validateDelegation(
    request: DelegationRequest,
    requestId?: string
  ): DelegationScopeResult {
    const reqId =
      requestId ?? `delg-${crypto.randomBytes(6).toString("hex")}`;
    const violations: string[] = [];

    const parentSet = new Set(request.parentScopes);
    const requested = request.requestedScopes;

    // 1. Blocked scopes
    const blockedFound = requested.filter((s) =>
      this.config.blockedScopes.includes(s)
    );
    if (blockedFound.length > 0) {
      violations.push(`blocked_scopes: [${blockedFound.join(", ")}]`);
    }

    // 2. Scopes not held by parent (privilege amplification)
    const outOfParent = requested.filter((s) => !parentSet.has(s));
    if (outOfParent.length > 0) {
      violations.push(`scopes_exceed_parent: [${outOfParent.join(", ")}]`);
    }

    // 3. Allowlist check (if configured)
    if (this.config.allowedScopes.length > 0) {
      const notAllowed = requested.filter(
        (s) => !this.config.allowedScopes.includes(s)
      );
      if (notAllowed.length > 0) {
        violations.push(`scopes_not_in_allowlist: [${notAllowed.join(", ")}]`);
      }
    }

    // 4. Compute effective max scopes after decay
    const decayFactor = Math.max(
      0,
      1 - this.config.scopeDecayPerHop * request.hopDepth
    );
    const rawMax = Math.floor(
      request.parentScopes.length *
        this.config.maxScopeInheritance *
        decayFactor
    );
    const effectiveMax = Math.max(0, rawMax);
    const decayApplied = this.config.scopeDecayPerHop > 0 && request.hopDepth > 0;

    const exceedsInheritanceLimit = requested.length > effectiveMax;
    if (exceedsInheritanceLimit) {
      violations.push(
        `inheritance_limit_exceeded: requested ${requested.length}, max ${effectiveMax}`
      );
    }

    // Compute granted scopes: intersection of requested with parent minus blocked
    const grantable = requested.filter(
      (s) =>
        parentSet.has(s) &&
        !this.config.blockedScopes.includes(s) &&
        (this.config.allowedScopes.length === 0 ||
          this.config.allowedScopes.includes(s))
    );
    // Trim to effective max if limit exceeded
    const granted = grantable.slice(0, effectiveMax);

    const allowed = violations.length === 0;

    const result: DelegationScopeResult = {
      allowed,
      reason: allowed
        ? "Delegation scopes granted"
        : `Delegation restricted: ${violations.slice(0, 3).join("; ")}`,
      violations,
      request_id: reqId,
      scope_analysis: {
        parent_scopes: request.parentScopes,
        requested_scopes: requested,
        granted_scopes: allowed ? granted : [],
        blocked_scopes_found: blockedFound,
        out_of_parent_scopes: outOfParent,
        exceeds_inheritance_limit: exceedsInheritanceLimit,
        decay_applied: decayApplied,
        effective_max_scopes: effectiveMax,
      },
    };

    this.auditLog.set(reqId, result);
    return result;
  }

  /** Return the audit trail for a delegation request. */
  getAuditLog(requestId: string): DelegationScopeResult | undefined {
    return this.auditLog.get(requestId);
  }

  /** Clear the audit log. */
  clearAuditLog(): void {
    this.auditLog.clear();
  }
}
