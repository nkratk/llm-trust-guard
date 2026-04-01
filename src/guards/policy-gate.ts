/**
 * L3 Policy Gate
 *
 * Enforces role-based access control with constraint validation.
 * The definitive layer for authorization decisions.
 */

import { SessionContext, ToolDefinition, PolicyGateResult, Role, GuardLogger } from "../types";

export interface PolicyGateConfig {
  roleHierarchy?: Record<Role, number>;
  toolPermissions?: Map<string, { roles: Role[]; constraints?: Record<Role, any> }>;
  logger?: GuardLogger;
}

export class PolicyGate {
  private roleHierarchy: Record<Role, number>;
  private toolPermissions: Map<string, { roles: Role[]; constraints?: Record<Role, any> }>;
  private logger: GuardLogger;

  constructor(config: PolicyGateConfig = {}) {
    this.roleHierarchy = config.roleHierarchy || {};
    this.toolPermissions = config.toolPermissions || new Map();
    this.logger = config.logger || (() => {});
  }

  /**
   * Validate session is authentic
   */
  validateSession(
    session: SessionContext | undefined,
    requestId: string = ""
  ): { valid: boolean; error?: string } {
    if (!session) {
      if (requestId) this.logger(`[L3:${requestId}] BLOCKED: No session`, "info");
      return { valid: false, error: "Missing session context" };
    }

    if (!session.authenticated) {
      if (requestId) this.logger(`[L3:${requestId}] BLOCKED: Not authenticated`, "info");
      return { valid: false, error: "Session not authenticated" };
    }

    if (!session.role) {
      if (requestId) this.logger(`[L3:${requestId}] BLOCKED: No role in session`, "info");
      return { valid: false, error: "Missing role in session" };
    }

    return { valid: true };
  }

  /**
   * Detect role tampering (claimed vs session role)
   */
  detectRoleTampering(
    session: SessionContext,
    claimedRole: Role | undefined
  ): { tampered: boolean; actual: Role; claimed?: Role } {
    if (!claimedRole) {
      return { tampered: false, actual: session.role };
    }

    if (claimedRole !== session.role) {
      return { tampered: true, actual: session.role, claimed: claimedRole };
    }

    return { tampered: false, actual: session.role };
  }

  /**
   * Check tool access for a session
   */
  checkToolAccess(
    tool: ToolDefinition,
    session: SessionContext,
    requestId: string = ""
  ): { allowed: boolean; reason?: string } {
    // If tool has no role restrictions, allow
    if (!tool.roles || tool.roles.length === 0) {
      return { allowed: true };
    }

    // Check if session role is in allowed roles
    if (!tool.roles.includes(session.role)) {
      // Check hierarchy if defined
      const sessionRoleLevel = this.roleHierarchy[session.role] ?? -1;
      const hasHigherRole = tool.roles.some((r) => {
        const requiredLevel = this.roleHierarchy[r] ?? -1;
        return sessionRoleLevel >= requiredLevel && requiredLevel >= 0;
      });

      if (!hasHigherRole) {
        if (requestId) {
          this.logger(`[L3:${requestId}] BLOCKED: Role '${session.role}' cannot use '${tool.name}'`, "info");
        }
        return {
          allowed: false,
          reason: `Role '${session.role}' is not authorized for tool '${tool.name}'`,
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Check constraints for a tool call
   */
  checkConstraints(
    tool: ToolDefinition,
    params: Record<string, any>,
    session: SessionContext,
    requestId: string = ""
  ): { valid: boolean; violations: string[] } {
    const violations: string[] = [];

    if (!tool.constraints) {
      return { valid: true, violations: [] };
    }

    const roleConstraints = tool.constraints[session.role];
    if (!roleConstraints) {
      return { valid: true, violations: [] };
    }

    // Check max_amount
    if (roleConstraints.max_amount !== undefined) {
      const amount = params.amount || params.total_amount;
      if (amount && amount > roleConstraints.max_amount) {
        violations.push(
          `Amount ${amount} exceeds limit of ${roleConstraints.max_amount} for role '${session.role}'`
        );
        if (requestId) {
          this.logger(`[L3:${requestId}] CONSTRAINT: Amount exceeds limit`, "info");
        }
      }
    }

    // Check require_approval
    if (roleConstraints.require_approval && !params.approval_id) {
      violations.push(`Tool '${tool.name}' requires approval for role '${session.role}'`);
      if (requestId) {
        this.logger(`[L3:${requestId}] CONSTRAINT: Requires approval`, "info");
      }
    }

    // Check allowed_values
    if (roleConstraints.allowed_values) {
      for (const [field, allowedVals] of Object.entries(roleConstraints.allowed_values)) {
        if (params[field] && !allowedVals.includes(params[field])) {
          violations.push(`Value '${params[field]}' not allowed for field '${field}'`);
        }
      }
    }

    return { valid: violations.length === 0, violations };
  }

  /**
   * Complete policy check
   */
  check(
    tool: ToolDefinition,
    params: Record<string, any>,
    session: SessionContext | undefined,
    claimedRole: Role | undefined,
    requestId: string = ""
  ): PolicyGateResult {
    // Validate session
    const sessionCheck = this.validateSession(session, requestId);
    if (!sessionCheck.valid) {
      return {
        allowed: false,
        reason: sessionCheck.error,
        violations: ["INVALID_SESSION"],
        session_role: "" as Role,
        required_roles: tool.roles || [],
      };
    }

    const validSession = session!;

    // Detect tampering
    const tamperCheck = this.detectRoleTampering(validSession, claimedRole);
    const violations: string[] = [];

    if (tamperCheck.tampered) {
      violations.push("ROLE_TAMPERING");
      if (requestId) {
        this.logger(`[L3:${requestId}] ALERT: Role tampering detected`, "info");
        this.logger(`[L3:${requestId}]   Claimed: ${tamperCheck.claimed}, Actual: ${tamperCheck.actual}`, "info");
      }
    }

    // Check tool access (using SESSION role)
    const accessCheck = this.checkToolAccess(tool, validSession, requestId);
    if (!accessCheck.allowed) {
      return {
        allowed: false,
        reason: accessCheck.reason,
        violations: [...violations, "UNAUTHORIZED_TOOL"],
        session_role: validSession.role,
        required_roles: tool.roles || [],
      };
    }

    // Check constraints
    const constraintCheck = this.checkConstraints(tool, params, validSession, requestId);
    if (!constraintCheck.valid) {
      return {
        allowed: false,
        reason: "Constraint violation",
        violations: [...violations, ...constraintCheck.violations],
        session_role: validSession.role,
        required_roles: tool.roles || [],
        constraint_violations: constraintCheck.violations,
      };
    }

    if (requestId) {
      this.logger(`[L3:${requestId}] Policy check PASSED`, "info");
    }

    return {
      allowed: true,
      violations: tamperCheck.tampered ? ["ROLE_TAMPERING_HANDLED"] : [],
      session_role: validSession.role,
      required_roles: tool.roles || [],
    };
  }

  /**
   * Set role hierarchy
   */
  setRoleHierarchy(hierarchy: Record<Role, number>): void {
    this.roleHierarchy = hierarchy;
  }
}
