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

  describe("Fix batch regressions", () => {
    it("detects unformatted/dash phone numbers, not just parenthesized ones", () => {
      const f = new OutputFilter();
      expect(f.filter("Call 415-555-2671 now").pii_detected.some((p) => p.type === "phone_us")).toBe(true);
      expect(f.filter("Call 4155552671 now").pii_detected.some((p) => p.type === "phone_us")).toBe(true);
    });

    it("detects 'password is: X' phrasing", () => {
      const f = new OutputFilter();
      const r = f.filter("password is: mysecretpass123");
      expect(r.secrets_detected.some((s) => s.type === "password")).toBe(true);
    });

    it("does not flag a dotted number with an out-of-range octet as an IP address", () => {
      const f = new OutputFilter();
      const r = f.filter("Error code 999.999.999.999 invalid");
      expect(r.pii_detected.some((p) => p.type === "ip_address")).toBe(false);
    });

    describe("ip_address version-string false positive (#10)", () => {
      const f = new OutputFilter();
      const isIpDetected = (text: string) => f.filter(text).pii_detected.some((p) => p.type === "ip_address");

      it("does not flag a version string preceded by a version-indicating keyword", () => {
        expect(isIpDetected("Please upgrade to 10.4.32.3 before Friday")).toBe(false);
        expect(isIpDetected("Now on version 10.4.32.3")).toBe(false);
        expect(isIpDetected("release 10.4.32.3 is out")).toBe(false);
        expect(isIpDetected("Update to v10.4.32.3 today")).toBe(false);
        expect(isIpDetected("V10.4.32.3")).toBe(false);
      });

      it("still flags real IP addresses, including near-miss cases", () => {
        expect(isIpDetected("The server IP is 192.168.1.1, contact admin.")).toBe(true);
        expect(isIpDetected("Connect to 10.0.0.1 via SSH")).toBe(true);
        // version keyword present but too far from the number to plausibly qualify it
        expect(isIpDetected("Server version 2.1 is running at 10.4.32.3")).toBe(true);
        expect(isIpDetected("Blocklisted address: 8.8.8.8")).toBe(true);
        // "coverage"/"diverse" contain "ver" as a substring — must not trip the keyword check
        expect(isIpDetected("diverse coverage from 172.16.0.5")).toBe(true);
        // Roman numeral "V" with a space is not the tight no-gap "v10.4.32.3" prefix case
        expect(isIpDetected("Chapter V 10.0.0.1")).toBe(true);
      });

      it("does not suppress a real IP when a version-indicating keyword appears nearby but in a different clause (regression)", () => {
        // Independent review found an earlier version of this fix — whose gap tolerated any
        // 15 non-digit chars, including full clause boundaries — silently left this IP
        // undetected AND unmasked, because "release" here is a document-section label with
        // no relation to the number, but still fell within the (too permissive) gap.
        expect(isIpDetected("This release: connect to 10.4.32.3 for support")).toBe(true);
        expect(isIpDetected("Release notes. The server at 10.4.32.3 is down")).toBe(true);
        expect(isIpDetected("upgrade, IP is 10.4.32.3")).toBe(true);
        const r = f.filter("This release: connect to 10.4.32.3 for support");
        expect(r.filtered_response).toBe("This release: connect to [IP_ADDRESS] for support");
      });

      it("masks real IPs but leaves version strings unmasked, in the same string", () => {
        const r = f.filter("Please upgrade to v10.4.32.3 — the server at 192.168.1.1 needs it too");
        expect(r.filtered_response).toBe("Please upgrade to v10.4.32.3 — the server at [IP_ADDRESS] needs it too");
      });

      it("does not flag a version string via the reversed-string obfuscation scan variant (regression)", () => {
        // Independent review found this exact input, scanned through the full
        // obfuscation-scan pipeline (not just the standalone regex): reversing
        // "release 12.34.56.78 today" scrambles "release" -> "esaeler" (no
        // longer matches the keyword) while the digit-and-dot IP shape
        // survives (just reordered as "87.65.43.21"), so the reversed variant
        // independently re-flagged a version string the original text
        // correctly suppressed.
        expect(isIpDetected("release 12.34.56.78 today")).toBe(false);
      });

      it("still detects genuinely obfuscated PII (email) via the same scan-variant pipeline", () => {
        // Confirms the fix above is scoped to ip_address only, not a
        // blanket disabling of obfuscation-variant scanning.
        const r = f.filter("dXNlckBleGFtcGxlLmNvbQ==");
        expect(r.pii_detected.some((p) => p.type === "email")).toBe(true);
      });
    });

    it("detects a Luhn-valid credit card with non-4-4-4-4 grouping", () => {
      const f = new OutputFilter();
      const pan = "5555555555554444";
      const irregular = `${pan.slice(0, 5)}-${pan.slice(5, 10)}-${pan.slice(10, 13)}-${pan.slice(13)}`;
      const r = f.filter(`Card: ${irregular}`);
      expect(r.pii_detected.some((p) => p.type === "credit_card")).toBe(true);
    });

    it("does not flag a Luhn-invalid digit run as a credit card", () => {
      const f = new OutputFilter();
      const r = f.filter("Order reference 4123456789012345"); // Visa-shaped BIN, fails Luhn
      expect(r.pii_detected.some((p) => p.type === "credit_card")).toBe(false);
    });

    it("detects a Mastercard 2-series (2221-2720) PAN", () => {
      const f = new OutputFilter();
      const r = f.filter("Card: 2223 0031 2200 3222");
      expect(r.pii_detected.some((p) => p.type === "credit_card")).toBe(true);
    });
  });
});
