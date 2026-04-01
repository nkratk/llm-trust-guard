# Contributing to llm-trust-guard

Thank you for your interest in contributing to `llm-trust-guard`! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. **Check existing issues** first to avoid duplicates
2. **Use the bug report template** when creating issues
3. Include:
   - Clear description of the issue
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (Node.js version, OS, etc.)
   - Minimal code example if possible

### Suggesting Features

1. **Check existing feature requests** first
2. **Describe the use case** - why is this needed?
3. Consider:
   - Which OWASP threat does it address?
   - How does it fit with existing guards?
   - Performance implications

### Submitting Code

#### Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/llm-trust-guard.git
cd llm-trust-guard

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test
```

#### Development Workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following the coding standards below

3. **Write tests** for new functionality:
   ```bash
   # Run tests
   npm test

   # Run tests with coverage
   npm run test:coverage
   ```

4. **Ensure all tests pass** and coverage meets requirements (80%+)

5. **Commit your changes** with clear messages:
   ```bash
   git commit -m "feat: add ROT13 detection to EncodingDetector"
   # or
   git commit -m "fix: correct false positive in PAP detection"
   ```

6. **Push and create a Pull Request**

#### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions or modifications
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

Examples:
```
feat: add Base32 encoding detection
fix: improve Unicode escape sequence handling
docs: update README with new guard examples
test: add tests for MemoryGuard context validation
```

### Coding Standards

#### TypeScript

- Use TypeScript strict mode
- Export interfaces for public APIs
- Document public methods with JSDoc comments
- Use meaningful variable and function names

```typescript
/**
 * Detects encoding-based bypass attempts in input
 * @param input - The input string to analyze
 * @param requestId - Optional request ID for logging
 * @returns Detection result with analysis details
 */
detect(input: string, requestId?: string): EncodingDetectorResult {
  // Implementation
}
```

#### Testing

- Write tests for all new functionality
- Use descriptive test names
- Group related tests with `describe` blocks
- Test edge cases and error conditions

```typescript
describe("EncodingDetector", () => {
  describe("Base64 Detection", () => {
    it("should detect Base64 encoded threats", () => {
      // Test implementation
    });

    it("should handle invalid Base64 gracefully", () => {
      // Test implementation
    });
  });
});
```

#### Pattern Guidelines

When adding new detection patterns:

1. **Document the threat** - Reference OWASP or research papers
2. **Set appropriate weights** - Consider false positive risk
3. **Test thoroughly** - Include both positive and negative cases
4. **Consider performance** - Avoid expensive regex operations

```typescript
// Good: Clear, documented pattern
{
  pattern: /ignore\s+(all\s+)?(previous|prior)/i,
  weight: 0.9,
  name: "ignore_instructions",
  // Addresses: LLM01:2025 Prompt Injection
}

// Avoid: Overly broad patterns
{
  pattern: /.*ignore.*/i,  // Too broad, high false positive risk
  weight: 0.5,
  name: "vague_ignore"
}
```

### Adding New Guards

1. **Create the guard file** in `src/guards/`:
   ```
   src/guards/your-new-guard.ts
   ```

2. **Follow the existing pattern**:
   ```typescript
   export interface YourNewGuardConfig {
     // Configuration options
   }

   export interface YourNewGuardResult {
     allowed: boolean;
     reason?: string;
     violations: string[];
     // Additional analysis
   }

   export class YourNewGuard {
     constructor(config: YourNewGuardConfig = {}) {
       // Initialize
     }

     check(input: SomeType): YourNewGuardResult {
       // Implementation
     }
   }
   ```

3. **Export from index.ts**:
   ```typescript
   export { YourNewGuard } from "./guards/your-new-guard";
   ```

4. **Add comprehensive tests** in `tests/your-new-guard.test.ts`

5. **Update documentation**:
   - Add to README.md
   - Add to CHANGELOG.md
   - Create usage examples

### Pull Request Guidelines

- **Title**: Clear, descriptive title following commit format
- **Description**: Explain what changes and why
- **Tests**: Include new tests for new functionality
- **Documentation**: Update relevant docs
- **Breaking Changes**: Clearly note any breaking changes

#### PR Checklist

- [ ] Tests pass (`npm test`)
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (for features/fixes)
- [ ] No console.log statements (except for intentional logging)
- [ ] Types are properly defined

### Review Process

1. PRs require at least one approving review
2. All CI checks must pass
3. Address all review comments
4. Squash commits before merging (if requested)

## Project Structure

```
llm-trust-guard/
├── src/
│   ├── guards/           # Guard implementations
│   │   ├── input-sanitizer.ts
│   │   ├── encoding-detector.ts
│   │   └── ...
│   ├── types.ts          # Shared type definitions
│   └── index.ts          # Public exports
├── tests/                # Test files
│   ├── input-sanitizer.test.ts
│   └── ...
├── dist/                 # Compiled output
├── package.json
├── tsconfig.json
└── vitest.config.ts
```

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: See SECURITY.md

## Recognition

Contributors will be recognized in:
- Release notes
- README.md (for significant contributions)
- GitHub contributors list

Thank you for contributing to making AI applications more secure!
