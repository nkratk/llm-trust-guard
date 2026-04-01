/**
 * L4 Tenant Boundary Guard
 *
 * Enforces strict multi-tenant isolation.
 * Prevents cross-tenant data access.
 */

import { SessionContext, TenantBoundaryResult, GuardLogger } from "../types";

export interface ResourceOwnership {
  resource_id: string;
  tenant_id: string;
  resource_type?: string;
}

export interface TenantBoundaryConfig {
  validTenants?: Set<string>;
  resourceOwnership?: Map<string, ResourceOwnership>;
  resourceIdFields?: string[];
  listOperations?: string[];
  logger?: GuardLogger;
}

export class TenantBoundary {
  private validTenants: Set<string>;
  private resourceOwnership: Map<string, ResourceOwnership>;
  private resourceIdFields: string[];
  private listOperations: string[];
  private logger: GuardLogger;

  constructor(config: TenantBoundaryConfig = {}) {
    this.validTenants = config.validTenants || new Set();
    this.resourceOwnership = config.resourceOwnership || new Map();
    this.resourceIdFields = config.resourceIdFields || [
      "order_id",
      "customer_id",
      "invoice_id",
      "document_id",
      "resource_id",
      "id",
    ];
    this.listOperations = config.listOperations || [
      "list",
      "search",
      "query",
      "find",
      "get_all",
    ];
    this.logger = config.logger || (() => {});
  }

  /**
   * Validate session has valid tenant
   */
  validateSession(
    session: SessionContext | undefined,
    requestId: string = ""
  ): { valid: boolean; error?: string } {
    if (!session) {
      return { valid: false, error: "Missing session context" };
    }

    if (!session.authenticated) {
      return { valid: false, error: "Session not authenticated" };
    }

    if (!session.tenant_id) {
      return { valid: false, error: "Missing tenant_id in session" };
    }

    // Validate tenant if we have a whitelist
    if (this.validTenants.size > 0 && !this.validTenants.has(session.tenant_id)) {
      if (requestId) {
        this.logger(`[L4:${requestId}] BLOCKED: Invalid tenant '${session.tenant_id}'`, "info");
      }
      return { valid: false, error: `Invalid tenant: ${session.tenant_id}` };
    }

    return { valid: true };
  }

  /**
   * Check resource ownership
   */
  checkResourceOwnership(
    resourceId: string,
    session: SessionContext,
    requestId: string = ""
  ): { allowed: boolean; resource_tenant?: string } {
    const ownership = this.resourceOwnership.get(resourceId);

    if (!ownership) {
      // Resource not in registry - allow (tool will return not found)
      return { allowed: true };
    }

    if (ownership.tenant_id !== session.tenant_id) {
      if (requestId) {
        this.logger(`[L4:${requestId}] BLOCKED: Cross-tenant access`, "info");
        this.logger(`[L4:${requestId}]   Session: ${session.tenant_id}, Resource: ${ownership.tenant_id}`, "info");
      }
      return { allowed: false, resource_tenant: ownership.tenant_id };
    }

    return { allowed: true, resource_tenant: ownership.tenant_id };
  }

  /**
   * Check if tenant_id parameter matches session
   */
  checkTenantParameter(
    params: Record<string, any>,
    session: SessionContext,
    requestId: string = ""
  ): { allowed: boolean; reason?: string } {
    if (params.tenant_id && params.tenant_id !== session.tenant_id) {
      if (requestId) {
        this.logger(`[L4:${requestId}] BLOCKED: Tenant parameter manipulation`, "info");
      }
      return {
        allowed: false,
        reason: `Cannot access tenant ${params.tenant_id} - bound to ${session.tenant_id}`,
      };
    }

    return { allowed: true };
  }

  /**
   * Enforce tenant filtering for list operations
   */
  enforceTenantFilter(
    toolName: string,
    params: Record<string, any>,
    session: SessionContext,
    requestId: string = ""
  ): { allowed: boolean; enforced_params: Record<string, any>; reason?: string } {
    // Check if this is a list operation
    const isListOp = this.listOperations.some((op) =>
      toolName.toLowerCase().includes(op)
    );

    if (isListOp) {
      // Block if trying to access different tenant
      if (params.tenant_id && params.tenant_id !== session.tenant_id) {
        return {
          allowed: false,
          enforced_params: params,
          reason: `Cannot filter by tenant ${params.tenant_id}`,
        };
      }

      // Enforce session tenant
      const enforced_params = { ...params, tenant_id: session.tenant_id };

      if (requestId) {
        this.logger(`[L4:${requestId}] Enforcing tenant filter: ${session.tenant_id}`, "info");
      }

      return { allowed: true, enforced_params };
    }

    return { allowed: true, enforced_params: params };
  }

  /**
   * Complete tenant boundary check
   */
  check(
    toolName: string,
    params: Record<string, any>,
    session: SessionContext | undefined,
    requestId: string = ""
  ): TenantBoundaryResult {
    // Validate session
    const sessionCheck = this.validateSession(session, requestId);
    if (!sessionCheck.valid) {
      return {
        allowed: false,
        reason: sessionCheck.error,
        violations: ["INVALID_SESSION"],
        session_tenant: "",
      };
    }

    const validSession = session!;

    // Check tenant parameter manipulation
    const paramCheck = this.checkTenantParameter(params, validSession, requestId);
    if (!paramCheck.allowed) {
      return {
        allowed: false,
        reason: paramCheck.reason,
        violations: ["TENANT_MANIPULATION"],
        session_tenant: validSession.tenant_id,
      };
    }

    // Check resource ownership
    for (const field of this.resourceIdFields) {
      if (params[field]) {
        const ownershipCheck = this.checkResourceOwnership(
          params[field],
          validSession,
          requestId
        );
        if (!ownershipCheck.allowed) {
          return {
            allowed: false,
            reason: `Resource ${params[field]} belongs to different tenant`,
            violations: ["CROSS_TENANT_ACCESS"],
            session_tenant: validSession.tenant_id,
            resource_tenant: ownershipCheck.resource_tenant,
          };
        }
      }
    }

    // Enforce tenant filtering
    const filterCheck = this.enforceTenantFilter(toolName, params, validSession, requestId);
    if (!filterCheck.allowed) {
      return {
        allowed: false,
        reason: filterCheck.reason,
        violations: ["TENANT_FILTER_BYPASS"],
        session_tenant: validSession.tenant_id,
      };
    }

    if (requestId) {
      this.logger(`[L4:${requestId}] Tenant boundary check PASSED`, "info");
    }

    return {
      allowed: true,
      violations: [],
      session_tenant: validSession.tenant_id,
      enforced_params: filterCheck.enforced_params,
    };
  }

  /**
   * Register resource ownership
   */
  registerResource(resourceId: string, tenantId: string, resourceType?: string): void {
    this.resourceOwnership.set(resourceId, {
      resource_id: resourceId,
      tenant_id: tenantId,
      resource_type: resourceType,
    });
  }

  /**
   * Add valid tenant
   */
  addValidTenant(tenantId: string): void {
    this.validTenants.add(tenantId);
  }
}
