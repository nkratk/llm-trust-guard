# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 4.x     | :white_check_mark: |
| 3.x     | :white_check_mark: |
| 2.x     | :x:                |
| 1.x     | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in `llm-trust-guard`, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email security concerns to: [security@example.com] (replace with actual contact)
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Severity Classification

| Severity | Description | Example |
|----------|-------------|---------|
| Critical | Complete bypass of security controls | Guard returns `allowed: true` for known attack |
| High | Significant reduction in protection | Pattern fails to detect major attack category |
| Medium | Limited bypass under specific conditions | Edge case pattern evasion |
| Low | Minor issues or improvements | Detection rate below optimal |

## Security Best Practices

### Using llm-trust-guard

1. **Defense in Depth**: Use multiple guards in combination
   ```typescript
   // Recommended: Layer multiple guards
   const sanitizer = new InputSanitizer();
   const encoder = new EncodingDetector();
   const memory = new MemoryGuard();

   // Check all layers
   const input1 = sanitizer.sanitize(userInput);
   const input2 = encoder.detect(userInput);
   const input3 = memory.validateContextInjection(context, sessionId);
   ```

2. **Keep Updated**: Always use the latest version
   ```bash
   npm update llm-trust-guard
   ```

3. **Configure Appropriately**: Adjust thresholds based on your risk tolerance
   ```typescript
   // Stricter configuration for high-security environments
   const sanitizer = new InputSanitizer({
     threshold: 0.5,        // Higher = stricter
     papThreshold: 0.3,     // Lower = more sensitive to PAP
     blockCompoundPersuasion: true
   });
   ```

4. **Monitor and Log**: Enable logging for security events
   ```typescript
   const sanitizer = new InputSanitizer({
     logMatches: true  // Log detected patterns
   });
   ```

5. **Validate All Sources**: Don't trust external data
   ```typescript
   // Always validate RAG content
   const ragGuard = new RAGGuard();
   const result = ragGuard.validateDocument(externalDoc);

   // Always validate memory/context
   const memGuard = new MemoryGuard();
   const ctxResult = memGuard.validateContextInjection(context, session);
   ```

### Known Attack Vectors Protected

| Attack Vector | Guard(s) | OWASP Reference |
|---------------|----------|-----------------|
| Prompt Injection | InputSanitizer, EncodingDetector | LLM01:2025 |
| Jailbreaks | InputSanitizer (PAP detection) | LLM01:2025 |
| Sensitive Data Exposure | OutputFilter, PromptLeakageGuard | LLM02:2025 |
| Supply Chain Attacks | MCPSecurityGuard | LLM03:2025 |
| Data Poisoning | RAGGuard, MemoryGuard | LLM04:2025 |
| Privilege Escalation | PolicyGate, TenantBoundary | LLM05:2025 |
| System Prompt Leakage | PromptLeakageGuard | LLM07:2025 |
| Vector DB Attacks | RAGGuard | LLM08:2025 |
| Tool Misuse | ToolChainValidator | ASI04 |
| Privilege Escalation | PolicyGate | ASI05 |
| Memory Poisoning | MemoryGuard | ASI06 |
| State Corruption | ToolChainValidator | ASI07 |
| Trust Exploitation | TrustExploitationGuard | ASI09 |

### Security Limitations

1. **Not a Complete Solution**: This library is one layer of defense. Always implement:
   - Input validation at application level
   - Output sanitization
   - Rate limiting
   - Authentication/Authorization
   - Logging and monitoring

2. **Pattern-Based Detection**: Relies on known patterns; novel attacks may evade detection initially

3. **Performance Trade-offs**: More thorough checks = higher latency

4. **False Positives**: Aggressive settings may block legitimate content

## Disclosure Policy

- We follow responsible disclosure practices
- Security fixes are released as soon as possible
- CVEs are requested for critical vulnerabilities
- Security advisories are published on GitHub

## Security Updates

Subscribe to security updates:
1. Watch this repository for releases
2. Check the CHANGELOG.md for security-related changes
3. Monitor npm advisories: `npm audit`

## Acknowledgments

We thank all security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged (with permission) in release notes.
