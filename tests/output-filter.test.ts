import { describe, it, expect, beforeEach } from "vitest";
import { OutputFilter } from "../src/guards/output-filter";

describe("OutputFilter", () => {
  let filter: OutputFilter;

  beforeEach(() => {
    filter = new OutputFilter({ detectPII: true, detectSecrets: true });
  });

  describe("PII Detection", () => {
    it("should detect email addresses", () => {
      const result = filter.filter("Contact: john@example.com");
      expect(result.pii_detected.length).toBeGreaterThan(0);
      expect(result.pii_detected.some((p) => p.type === "email")).toBe(true);
    });

    it("should detect SSN", () => {
      const result = filter.filter("SSN: 123-45-6789");
      expect(result.pii_detected.some((p) => p.type === "ssn")).toBe(true);
    });

    it("should detect credit card numbers", () => {
      const result = filter.filter("Card: 4111-1111-1111-1111");
      expect(result.pii_detected.some((p) => p.type === "credit_card")).toBe(true);
    });

    it("should mask PII in string output", () => {
      const result = filter.filter("Email: test@example.com");
      expect(result.filtered_response).toContain("[EMAIL]");
      expect(result.filtered_response).not.toContain("test@example.com");
    });
  });

  describe("Secret Detection", () => {
    it("should detect API keys", () => {
      const result = filter.filter("api_key=sk-1234567890abcdefghijklmno");
      expect(result.secrets_detected.length).toBeGreaterThan(0);
    });

    it("should detect JWT tokens", () => {
      const result = filter.filter("Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
      expect(result.secrets_detected.some((s) => s.type === "jwt_token")).toBe(true);
    });

    it("should block critical secrets", () => {
      const result = filter.filter("password=SuperSecret123!");
      expect(result.secrets_detected.length).toBeGreaterThan(0);
      expect(result.secrets_detected.some((s) => s.type === "password")).toBe(true);
    });
  });

  describe("Object Filtering", () => {
    it("should filter sensitive fields in objects", () => {
      const result = filter.filter({ name: "John", password: "secret123", email: "john@test.com" });
      expect(result.filtered_response.password).toBe("[FILTERED]");
    });

    it("should handle nested objects", () => {
      const result = filter.filter({ user: { name: "John", ssn: "123-45-6789" } });
      expect(result.filtered_response.user.ssn).toBe("[FILTERED]");
    });

    it("should handle circular references gracefully", () => {
      const obj: any = { name: "test" };
      obj.self = obj;
      // filter() should not crash - returns string representation
      const result = filter.filter(obj);
      expect(result).toHaveProperty("allowed");
    });
  });

  describe("False Positives", () => {
    it("should not flag normal text without PII", () => {
      const result = filter.filter("The weather is nice today. Order status: shipped.");
      expect(result.pii_detected.length).toBe(0);
      expect(result.secrets_detected.length).toBe(0);
    });

    it("should not flag short numbers as bank accounts", () => {
      const result = filter.filter("Order ID: 12345678, Product: Widget");
      // bank_account now requires context keyword
      expect(result.pii_detected.some((p) => p.type === "bank_account")).toBe(false);
    });

    it("should not flag timestamps as bank accounts", () => {
      const result = filter.filter("Created at: 1710547200000");
      expect(result.pii_detected.some((p) => p.type === "bank_account")).toBe(false);
    });
  });

  describe("Role-Based Filtering", () => {
    it("should apply role-specific field filters", () => {
      const roleFilter = new OutputFilter({
        roleFilters: { customer: ["internal_notes", "cost_price"] },
      });
      const result = roleFilter.filter(
        { name: "Widget", price: 29.99, internal_notes: "Buy from supplier X", cost_price: 10.0 },
        "customer"
      );
      expect(result.filtered_response.internal_notes).toBe("[FILTERED]");
      expect(result.filtered_response.cost_price).toBe("[FILTERED]");
      expect(result.filtered_response.name).toBe("Widget");
    });
  });
});
