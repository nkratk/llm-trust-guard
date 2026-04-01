/**
 * Framework Integrations for llm-trust-guard
 *
 * Ready-to-use integrations for popular frameworks and libraries.
 */

// Express.js middleware
export {
  createTrustGuardMiddleware,
  createToolRateLimitMiddleware,
  createOutputFilterMiddleware,
  type TrustGuardMiddlewareConfig,
  type ExpressGuardResult,
} from "./express.js";

// LangChain integration
export {
  TrustGuardLangChain,
  TrustGuardViolationError,
  createInputValidator,
  createOutputFilter,
  type TrustGuardCallbackConfig,
  type SecurityCheckResult,
} from "./langchain.js";

// OpenAI integration
export {
  SecureOpenAI,
  OpenAISecurityError,
  createMessageValidator,
  wrapOpenAIClient,
  type SecureOpenAIConfig,
  type ValidationResult,
  type SecureMessage,
} from "./openai.js";

// Vercel AI SDK integration
export {
  TrustGuardAI,
  TrustGuardAIViolationError,
  createTrustGuardMiddleware as createVercelTrustGuardMiddleware,
  wrapWithTrustGuard,
  createSecureGenerate,
  type TrustGuardAIConfig,
  type InputValidationResult,
  type OutputFilterResult,
} from "./vercel-ai-sdk.js";
