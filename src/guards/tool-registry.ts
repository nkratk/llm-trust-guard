/**
 * L2 Tool Registry Guard
 *
 * Maintains strict control over which tools can be executed.
 * Prevents LLM hallucination attacks.
 */

import { ToolDefinition, ToolRegistryResult, Role, GuardLogger } from "../types";

// Common hallucination patterns
const HALLUCINATION_PATTERNS = [
  /^execute/i,
  /^run/i,
  /^shell/i,
  /^admin/i,
  /^override/i,
  /^delete_all/i,
  /^export_/i,
  /^import_/i,
  /^hack/i,
  /^bypass/i,
  /^sudo/i,
  /^root/i,
  /^system/i,
];

export interface ToolRegistryConfig {
  tools: ToolDefinition[];
  strictMatching?: boolean;
  logger?: GuardLogger;
}

export class ToolRegistry {
  private tools: Map<string, ToolDefinition>;
  private strictMatching: boolean;
  private logger: GuardLogger;

  constructor(config: ToolRegistryConfig) {
    this.tools = new Map();
    this.strictMatching = config.strictMatching ?? true;
    this.logger = config.logger || (() => {});

    for (const tool of config.tools) {
      this.tools.set(tool.name, tool);
    }
  }

  /**
   * Check if a tool exists and is accessible for the given role
   */
  check(toolName: string, role: Role, requestId: string = ""): ToolRegistryResult {
    // Exact match only
    const tool = this.tools.get(toolName);

    if (!tool) {
      const isHallucination = this.detectHallucination(toolName);
      const similarTools = this.findSimilarTools(toolName);

      if (requestId) {
        this.logger(`[L2:${requestId}] BLOCKED: Tool '${toolName}' not in registry`, "info");
        if (isHallucination) {
          this.logger(`[L2:${requestId}] ALERT: Potential hallucination detected`, "info");
        }
      }

      return {
        allowed: false,
        reason: `Tool '${toolName}' is not registered`,
        violations: ["UNREGISTERED_TOOL"],
        hallucination_detected: isHallucination,
        similar_tools: similarTools.length > 0 ? similarTools : undefined,
      };
    }

    // Check role access if roles are defined
    if (tool.roles && tool.roles.length > 0 && !tool.roles.includes(role)) {
      if (requestId) {
        this.logger(`[L2:${requestId}] BLOCKED: Role '${role}' cannot use '${toolName}'`, "info");
      }

      return {
        allowed: false,
        reason: `Role '${role}' is not authorized for tool '${toolName}'`,
        violations: ["UNAUTHORIZED_ROLE"],
        tool,
        hallucination_detected: false,
      };
    }

    if (requestId) {
      this.logger(`[L2:${requestId}] Tool '${toolName}' ALLOWED for role '${role}'`, "info");
    }

    return {
      allowed: true,
      violations: [],
      tool,
      hallucination_detected: false,
    };
  }

  /**
   * Detect if tool name looks like a hallucination
   */
  private detectHallucination(toolName: string): boolean {
    for (const pattern of HALLUCINATION_PATTERNS) {
      if (pattern.test(toolName)) {
        return true;
      }
    }

    // Check for suspicious characters
    if (toolName.includes("..") || toolName.includes("/") || toolName.includes("\\")) {
      return true;
    }

    // Unusually long names
    if (toolName.length > 50) {
      return true;
    }

    // Special characters
    if (/[^a-zA-Z0-9_-]/.test(toolName)) {
      return true;
    }

    return false;
  }

  /**
   * Find similar registered tools for helpful error messages
   */
  private findSimilarTools(toolName: string): string[] {
    const similar: string[] = [];
    const toolNameLower = toolName.toLowerCase();

    for (const registeredTool of this.tools.keys()) {
      const registeredLower = registeredTool.toLowerCase();

      // Check word overlap
      const requestedWords = toolNameLower.split(/[_-]/);
      const registeredWords = registeredLower.split(/[_-]/);

      for (const word of requestedWords) {
        if (word.length > 2 && registeredWords.some((rw) => rw.includes(word) || word.includes(rw))) {
          similar.push(registeredTool);
          break;
        }
      }
    }

    return [...new Set(similar)];
  }

  /**
   * Get tools for a specific role
   */
  getToolsForRole(role: Role): ToolDefinition[] {
    const tools: ToolDefinition[] = [];
    for (const tool of this.tools.values()) {
      if (!tool.roles || tool.roles.length === 0 || tool.roles.includes(role)) {
        tools.push(tool);
      }
    }
    return tools;
  }

  /**
   * Get all registered tool names
   */
  getRegisteredToolNames(): string[] {
    return [...this.tools.keys()];
  }

  /**
   * Register a new tool at runtime
   */
  registerTool(tool: ToolDefinition): void {
    this.tools.set(tool.name, tool);
  }

  /**
   * Unregister a tool
   */
  unregisterTool(toolName: string): boolean {
    return this.tools.delete(toolName);
  }
}
