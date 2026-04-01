import { describe, it, expect, beforeEach } from "vitest";
import { SchemaValidator } from "../src/guards/schema-validator";
import { ToolDefinition } from "../src/types";

describe("SchemaValidator", () => {
  let validator: SchemaValidator;
  const tool: ToolDefinition = {
    name: "search",
    description: "Search products",
    parameters: {
      type: "object",
      properties: {
        query: { type: "string", maxLength: 200 },
        limit: { type: "number", min: 1, max: 100 },
      },
      required: ["query"],
    },
  };

  beforeEach(() => {
    validator = new SchemaValidator({ strictTypes: true, detectInjection: true });
  });

  describe("Basic Validation", () => {
    it("should allow valid parameters", () => {
      const result = validator.validate(tool, { query: "blue shoes", limit: 10 });
      expect(result.allowed).toBe(true);
    });

    it("should reject missing required fields", () => {
      const result = validator.validate(tool, { limit: 10 });
      expect(result.allowed).toBe(false);
      expect(result.errors).toContain("Missing required field: query");
    });

    it("should reject type mismatches", () => {
      const result = validator.validate(tool, { query: "test", limit: "all" });
      expect(result.allowed).toBe(false);
    });
  });

  describe("Injection Detection", () => {
    it("should detect SQL injection with keywords", () => {
      const result = validator.validate(tool, { query: "'; DROP TABLE products; --" });
      expect(result.allowed).toBe(false);
      expect(result.blocked_attacks.some((a) => a.includes("SQL"))).toBe(true);
    });

    it("should detect NoSQL injection", () => {
      const result = validator.validate(tool, { query: '{"$gt": ""}' });
      expect(result.allowed).toBe(false);
    });

    it("should detect path traversal", () => {
      const result = validator.validate(tool, { query: "../../../etc/passwd" });
      expect(result.allowed).toBe(false);
    });

    it("should detect XSS", () => {
      const result = validator.validate(tool, { query: '<script>alert("xss")</script>' });
      expect(result.allowed).toBe(false);
    });

    it("should detect command injection with piped commands", () => {
      const result = validator.validate(tool, { query: "test; rm -rf /" });
      expect(result.allowed).toBe(false);
    });
  });

  describe("Prototype Pollution", () => {
    it("should detect __proto__ keys", () => {
      // Use Object.create(null) to avoid JS __proto__ handling
      const params = Object.create(null);
      params.query = "test";
      params.__proto__ = { admin: true };
      const result = validator.validate(tool, params);
      expect(result.allowed).toBe(false);
      expect(result.blocked_attacks).toContain("PROTOTYPE_POLLUTION");
    });

    it("should detect constructor keys", () => {
      const params = Object.create(null);
      params.query = "test";
      params.constructor = {};
      const result = validator.validate(tool, params);
      expect(result.allowed).toBe(false);
    });
  });

  describe("False Positives", () => {
    it("should allow normal text with apostrophes", () => {
      // After fix: bare quotes no longer trigger SQL detection
      const noInjectionValidator = new SchemaValidator({ strictTypes: true, detectInjection: true });
      const result = noInjectionValidator.validate(tool, { query: "it's a beautiful day" });
      // This should pass now with contextual SQL detection
      expect(result.allowed).toBe(true);
    });

    it("should allow normal product searches", () => {
      const result = validator.validate(tool, { query: "men's blue running shoes size 10" });
      expect(result.allowed).toBe(true);
    });

    it("should allow URLs in string fields", () => {
      const urlTool: ToolDefinition = {
        name: "fetch",
        description: "Fetch URL",
        parameters: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
      };
      const result = validator.validate(urlTool, { url: "https://example.com/api?q=test&limit=10" });
      expect(result.allowed).toBe(true);
    });
  });

  describe("Number Validation", () => {
    it("should reject values outside range", () => {
      const result = validator.validate(tool, { query: "test", limit: 500 });
      expect(result.allowed).toBe(false);
    });

    it("should reject NaN", () => {
      const result = validator.validate(tool, { query: "test", limit: NaN });
      expect(result.allowed).toBe(false);
    });

    it("should reject Infinity", () => {
      const result = validator.validate(tool, { query: "test", limit: Infinity });
      expect(result.allowed).toBe(false);
    });
  });
});
