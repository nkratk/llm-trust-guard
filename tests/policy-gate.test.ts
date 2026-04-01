import { describe, it, expect, beforeEach } from "vitest";
import { PolicyGate } from "../src/guards/policy-gate";
import { SessionContext, ToolDefinition, Role } from "../src/types";

describe("PolicyGate", () => {
  let gate: PolicyGate;

  const adminSession: SessionContext = {
    user_id: "admin-1",
    tenant_id: "tenant-1",
    role: "admin",
    authenticated: true,
  };

  const customerSession: SessionContext = {
    user_id: "customer-1",
    tenant_id: "tenant-1",
    role: "customer",
    authenticated: true,
  };

  const adminTool: ToolDefinition = {
    name: "manage_users",
    description: "Manage user accounts",
    parameters: { type: "object", properties: {}, required: [] },
    roles: ["admin"],
  };

  const publicTool: ToolDefinition = {
    name: "get_info",
    description: "Get public information",
    parameters: { type: "object", properties: {}, required: [] },
    roles: [],
  };

  const constrainedTool: ToolDefinition = {
    name: "transfer_funds",
    description: "Transfer funds between accounts",
    parameters: { type: "object", properties: {}, required: [] },
    roles: ["admin", "customer"],
    constraints: {
      customer: { max_amount: 1000, require_approval: false },
      admin: { max_amount: 100000 },
    },
  };

  beforeEach(() => {
    gate = new PolicyGate({
      roleHierarchy: {
        admin: 100,
        manager: 50,
        customer: 10,
        guest: 0,
      } as Record<Role, number>,
    });
  });

  describe("Role-Based Access Control", () => {
    it("should allow admin to access admin-only tool", () => {
      const result = gate.check(adminTool, {}, adminSession, undefined);
      expect(result.allowed).toBe(true);
    });

    it("should block customer from accessing admin-only tool", () => {
      const result = gate.check(adminTool, {}, customerSession, undefined);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("UNAUTHORIZED_TOOL");
      expect(result.reason).toContain("not authorized");
    });

    it("should allow any role to access a tool with no role restrictions", () => {
      const result = gate.check(publicTool, {}, customerSession, undefined);
      expect(result.allowed).toBe(true);
    });
  });

  describe("Role Hierarchy", () => {
    it("should allow higher-hierarchy role to access lower-role tool", () => {
      const managerTool: ToolDefinition = {
        name: "view_reports",
        description: "View reports",
        parameters: { type: "object", properties: {}, required: [] },
        roles: ["manager"],
      };
      // admin (100) > manager (50), so admin should access manager tool
      const result = gate.check(managerTool, {}, adminSession, undefined);
      expect(result.allowed).toBe(true);
    });

    it("should block lower-hierarchy role from accessing higher-role tool", () => {
      const result = gate.check(adminTool, {}, customerSession, undefined);
      expect(result.allowed).toBe(false);
    });
  });

  describe("Role Tampering Detection", () => {
    it("should detect when claimed role differs from session role", () => {
      const result = gate.detectRoleTampering(customerSession, "admin");
      expect(result.tampered).toBe(true);
      expect(result.actual).toBe("customer");
      expect(result.claimed).toBe("admin");
    });

    it("should not flag tampering when claimed role matches session", () => {
      const result = gate.detectRoleTampering(adminSession, "admin");
      expect(result.tampered).toBe(false);
      expect(result.actual).toBe("admin");
    });

    it("should not flag tampering when no claimed role is provided", () => {
      const result = gate.detectRoleTampering(customerSession, undefined);
      expect(result.tampered).toBe(false);
    });

    it("should still use session role for access even with tampered claimed role", () => {
      // Customer claims to be admin, but session role (customer) should be used
      const result = gate.check(adminTool, {}, customerSession, "admin" as Role);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("ROLE_TAMPERING");
    });
  });

  describe("Constraint Validation", () => {
    it("should block when amount exceeds max_amount for role", () => {
      const result = gate.check(
        constrainedTool,
        { amount: 5000 },
        customerSession,
        undefined
      );
      expect(result.allowed).toBe(false);
      expect(result.constraint_violations).toBeDefined();
      expect(result.constraint_violations!.length).toBeGreaterThan(0);
      expect(result.constraint_violations![0]).toContain("exceeds limit");
    });

    it("should allow when amount is within max_amount for role", () => {
      const result = gate.check(
        constrainedTool,
        { amount: 500 },
        customerSession,
        undefined
      );
      expect(result.allowed).toBe(true);
    });

    it("should enforce require_approval constraint", () => {
      const approvalTool: ToolDefinition = {
        name: "high_value_action",
        description: "Requires approval",
        parameters: { type: "object", properties: {}, required: [] },
        roles: ["customer"],
        constraints: {
          customer: { require_approval: true },
        },
      };

      const withoutApproval = gate.checkConstraints(approvalTool, {}, customerSession);
      expect(withoutApproval.valid).toBe(false);
      expect(withoutApproval.violations[0]).toContain("requires approval");

      const withApproval = gate.checkConstraints(
        approvalTool,
        { approval_id: "APR-123" },
        customerSession
      );
      expect(withApproval.valid).toBe(true);
    });
  });

  describe("Session Validation", () => {
    it("should reject missing session", () => {
      const result = gate.check(publicTool, {}, undefined, undefined);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("INVALID_SESSION");
    });

    it("should reject unauthenticated session", () => {
      const unauthSession: SessionContext = {
        user_id: "u1",
        tenant_id: "t1",
        role: "customer",
        authenticated: false,
      };
      const result = gate.check(publicTool, {}, unauthSession, undefined);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("not authenticated");
    });
  });

  describe("False Positive - Legitimate Access", () => {
    it("should allow a customer to use a customer-authorized tool within constraints", () => {
      const result = gate.check(
        constrainedTool,
        { amount: 100 },
        customerSession,
        "customer" as Role
      );
      expect(result.allowed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });
  });
});
