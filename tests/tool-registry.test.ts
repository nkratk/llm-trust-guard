import { describe, it, expect, beforeEach } from "vitest";
import { ToolRegistry } from "../src/guards/tool-registry";
import { ToolDefinition } from "../src/types";

describe("ToolRegistry", () => {
  let registry: ToolRegistry;

  const tools: ToolDefinition[] = [
    {
      name: "get_order",
      description: "Get order details",
      parameters: { type: "object", properties: {}, required: [] },
      roles: ["customer", "admin"],
    },
    {
      name: "manage_users",
      description: "Manage user accounts",
      parameters: { type: "object", properties: {}, required: [] },
      roles: ["admin"],
    },
    {
      name: "get_weather",
      description: "Get weather info",
      parameters: { type: "object", properties: {}, required: [] },
      roles: [],
    },
  ];

  beforeEach(() => {
    registry = new ToolRegistry({ tools });
  });

  describe("Unregistered Tool Blocking", () => {
    it("should block a tool that is not registered (hallucination)", () => {
      const result = registry.check("nonexistent_tool", "customer");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("UNREGISTERED_TOOL");
      expect(result.reason).toContain("not registered");
    });

    it("should block a completely made-up tool name", () => {
      const result = registry.check("fetch_secret_database_dump", "admin");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("UNREGISTERED_TOOL");
    });
  });

  describe("Role-Based Access", () => {
    it("should allow customer to access customer tool", () => {
      const result = registry.check("get_order", "customer");
      expect(result.allowed).toBe(true);
      expect(result.tool).toBeDefined();
      expect(result.tool!.name).toBe("get_order");
    });

    it("should block customer from accessing admin-only tool", () => {
      const result = registry.check("manage_users", "customer");
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain("UNAUTHORIZED_ROLE");
    });

    it("should allow any role to access a tool with no role restrictions", () => {
      const result = registry.check("get_weather", "guest");
      expect(result.allowed).toBe(true);
    });
  });

  describe("Hallucination Pattern Detection", () => {
    it("should detect hallucination for execute-prefixed tools", () => {
      const result = registry.check("execute_system_command", "admin");
      expect(result.hallucination_detected).toBe(true);
    });

    it("should detect hallucination for sudo-prefixed tools", () => {
      const result = registry.check("sudo_reset_all", "admin");
      expect(result.hallucination_detected).toBe(true);
    });

    it("should detect hallucination for bypass-prefixed tools", () => {
      const result = registry.check("bypass_security_check", "admin");
      expect(result.hallucination_detected).toBe(true);
    });

    it("should detect hallucination for tools with path traversal chars", () => {
      const result = registry.check("tool/../../../etc/passwd", "admin");
      expect(result.hallucination_detected).toBe(true);
    });

    it("should not flag hallucination for a registered tool", () => {
      const result = registry.check("get_order", "admin");
      expect(result.hallucination_detected).toBe(false);
    });
  });

  describe("Similar Tool Suggestion", () => {
    it("should suggest similar tools when a close match exists", () => {
      const result = registry.check("get_orders", "customer");
      expect(result.allowed).toBe(false);
      expect(result.similar_tools).toBeDefined();
      expect(result.similar_tools!).toContain("get_order");
    });

    it("should suggest manage_users for manage_user typo", () => {
      const result = registry.check("manage_user", "admin");
      expect(result.allowed).toBe(false);
      expect(result.similar_tools).toBeDefined();
      expect(result.similar_tools!).toContain("manage_users");
    });
  });

  describe("False Positive - Legitimate Registered Tool", () => {
    it("should allow admin to use all registered tools without false flags", () => {
      const orderResult = registry.check("get_order", "admin");
      expect(orderResult.allowed).toBe(true);
      expect(orderResult.hallucination_detected).toBe(false);

      const manageResult = registry.check("manage_users", "admin");
      expect(manageResult.allowed).toBe(true);
      expect(manageResult.hallucination_detected).toBe(false);
    });
  });
});
