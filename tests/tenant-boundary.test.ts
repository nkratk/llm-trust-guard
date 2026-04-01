import { describe, it, expect, beforeEach } from "vitest";
import { TenantBoundary } from "../src/guards/tenant-boundary";
import { SessionContext } from "../src/types";

describe("TenantBoundary", () => {
  let guard: TenantBoundary;

  const tenantASession: SessionContext = {
    user_id: "user-a1",
    tenant_id: "tenant-A",
    role: "customer",
    authenticated: true,
  };

  const tenantBSession: SessionContext = {
    user_id: "user-b1",
    tenant_id: "tenant-B",
    role: "customer",
    authenticated: true,
  };

  beforeEach(() => {
    guard = new TenantBoundary({
      validTenants: new Set(["tenant-A", "tenant-B"]),
    });
    // Register resources with tenant ownership
    guard.registerResource("order-100", "tenant-A", "order");
    guard.registerResource("order-200", "tenant-B", "order");
    guard.registerResource("doc-50", "tenant-A", "document");
  });

  describe("Cross-Tenant Access Blocking", () => {
    it("should block tenant-A from accessing tenant-B's resource", () => {
      const result = guard.check("get_order", { order_id: "order-200" }, tenantASession);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("CROSS_TENANT_ACCESS");
      expect(result.resource_tenant).toBe("tenant-B");
    });

    it("should allow tenant-A to access its own resource", () => {
      const result = guard.check("get_order", { order_id: "order-100" }, tenantASession);
      expect(result.allowed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it("should block cross-tenant access via document_id field", () => {
      const result = guard.check(
        "get_document",
        { document_id: "doc-50" },
        tenantBSession
      );
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("CROSS_TENANT_ACCESS");
    });
  });

  describe("Tenant Parameter Injection Detection", () => {
    it("should block when tenant_id param differs from session tenant", () => {
      const result = guard.check(
        "get_data",
        { tenant_id: "tenant-B" },
        tenantASession
      );
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("TENANT_MANIPULATION");
      expect(result.reason).toContain("Cannot access tenant tenant-B");
    });

    it("should allow when tenant_id param matches session tenant", () => {
      const result = guard.check(
        "get_data",
        { tenant_id: "tenant-A" },
        tenantASession
      );
      expect(result.allowed).toBe(true);
    });
  });

  describe("Resource Ownership Validation", () => {
    it("should allow access to unregistered resource (will be handled by tool)", () => {
      const result = guard.check(
        "get_order",
        { order_id: "order-999" },
        tenantASession
      );
      expect(result.allowed).toBe(true);
    });

    it("should validate ownership across multiple resource ID fields", () => {
      guard.registerResource("cust-77", "tenant-B", "customer");
      const result = guard.check(
        "get_customer",
        { customer_id: "cust-77" },
        tenantASession
      );
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("CROSS_TENANT_ACCESS");
    });
  });

  describe("Tenant Filtering Enforcement", () => {
    it("should enforce tenant filter on list operations", () => {
      const result = guard.check("list_orders", {}, tenantASession);
      expect(result.allowed).toBe(true);
      expect(result.enforced_params).toBeDefined();
      expect(result.enforced_params!.tenant_id).toBe("tenant-A");
    });

    it("should block list operation with different tenant filter", () => {
      const result = guard.check(
        "search_documents",
        { tenant_id: "tenant-B" },
        tenantASession
      );
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("TENANT_MANIPULATION");
    });

    it("should not enforce tenant filter on non-list operations", () => {
      const result = guard.check("update_profile", { name: "New Name" }, tenantASession);
      expect(result.allowed).toBe(true);
      expect(result.enforced_params).toEqual({ name: "New Name" });
    });
  });

  describe("Session Validation", () => {
    it("should reject missing session", () => {
      const result = guard.check("get_order", { order_id: "order-100" }, undefined);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("INVALID_SESSION");
    });

    it("should reject session with invalid tenant", () => {
      const invalidSession: SessionContext = {
        user_id: "u1",
        tenant_id: "tenant-UNKNOWN",
        role: "customer",
        authenticated: true,
      };
      const result = guard.check("get_data", {}, invalidSession);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Invalid tenant");
    });
  });

  describe("False Positive - Legitimate Access", () => {
    it("should allow a tenant to list and access their own resources normally", () => {
      const listResult = guard.check("list_orders", { status: "active" }, tenantASession);
      expect(listResult.allowed).toBe(true);

      const getResult = guard.check("get_order", { order_id: "order-100" }, tenantASession);
      expect(getResult.allowed).toBe(true);
    });
  });
});
