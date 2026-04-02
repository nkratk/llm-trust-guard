/**
 * SpawnPolicyGuard (L32)
 *
 * Controls whether agents can spawn child agents (sub-agents).
 * Think of this as Content Security Policy (CSP) but for agent spawning —
 * it defines which agents are allowed to create other agents, under what
 * conditions, and with what constraints.
 *
 * Threat Model:
 * - ASI07: Insecure Inter-Agent Communication
 * - Unauthorized agent spawning (an agent spawns helpers to evade controls)
 * - Third-party agent injection (untrusted spawned agents carry out attacks)
 * - Delegation depth explosion (recursive sub-agent spawning)
 * - Privilege amplification through spawning
 *
 * Protection Capabilities:
 * - Per-origin spawn allowlisting
 * - Third-party spawn gating
 * - Delegation depth enforcement
 * - Human-in-the-loop gate for new agents
 * - Runtime spawn counter per parent agent
 */

import * as crypto from "crypto";

export interface SpawnPolicyGuardConfig {
  /** Allow agents to spawn from third-party / untrusted origins (default: false) */
  allowThirdPartySpawning?: boolean;
  /** Maximum delegation depth: 0 = no spawning, 1 = parent→child only (default: 2) */
  maxDelegationDepth?: number;
  /** Gate every spawn through human approval (default: false) */
  requireApprovalForNewAgents?: boolean;
  /** Allowlist of spawn origins that are trusted. Empty = all registered origins allowed */
  allowedSpawnOrigins?: string[];
  /** Maximum number of active child agents per parent (default: 10) */
  maxChildrenPerParent?: number;
  /** Require the spawning agent to be registered before it can spawn */
  requireRegisteredParent?: boolean;
}

export interface SpawnRequest {
  /** ID of the agent requesting to spawn */
  parentAgentId: string;
  /** Proposed ID for the new child agent */
  childAgentId: string;
  /** Declared origin / runtime of the child (e.g. "openai", "anthropic", "internal") */
  spawnOrigin: string;
  /** How many hops deep in the delegation chain is the parent */
  delegationDepth: number;
  /** Is the child coming from a third-party / external system? */
  isThirdParty: boolean;
  /** Optional reason / justification */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

export interface SpawnPolicyResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  policy_analysis: {
    third_party_blocked: boolean;
    depth_exceeded: boolean;
    origin_blocked: boolean;
    parent_not_registered: boolean;
    children_limit_exceeded: boolean;
    approval_required: boolean;
  };
  requires_human_approval: boolean;
}

export class SpawnPolicyGuard {
  readonly guardName = "SpawnPolicyGuard";
  readonly guardLayer = "L32";

  private readonly config: Required<SpawnPolicyGuardConfig>;
  /** parentAgentId → set of active child IDs */
  private readonly activeChildren: Map<string, Set<string>> = new Map();
  /** Set of registered parent agent IDs */
  private readonly registeredParents: Set<string> = new Set();

  constructor(config: SpawnPolicyGuardConfig = {}) {
    this.config = {
      allowThirdPartySpawning: config.allowThirdPartySpawning ?? false,
      maxDelegationDepth: config.maxDelegationDepth ?? 2,
      requireApprovalForNewAgents: config.requireApprovalForNewAgents ?? false,
      allowedSpawnOrigins: config.allowedSpawnOrigins ?? [],
      maxChildrenPerParent: config.maxChildrenPerParent ?? 10,
      requireRegisteredParent: config.requireRegisteredParent ?? true,
    };
  }

  /**
   * Register an agent as an approved parent that is allowed to spawn.
   */
  registerParent(agentId: string): void {
    this.registeredParents.add(agentId);
  }

  /**
   * Record that a child agent has terminated / been removed.
   */
  removeChild(parentAgentId: string, childAgentId: string): void {
    this.activeChildren.get(parentAgentId)?.delete(childAgentId);
  }

  /**
   * Validate whether a spawn request should be permitted.
   *
   * @param request - Describes the proposed spawn
   * @param requestId - Optional trace ID
   */
  validateSpawn(request: SpawnRequest, requestId?: string): SpawnPolicyResult {
    const reqId = requestId ?? `spawn-${crypto.randomBytes(6).toString("hex")}`;
    const violations: string[] = [];

    const analysis: SpawnPolicyResult["policy_analysis"] = {
      third_party_blocked: false,
      depth_exceeded: false,
      origin_blocked: false,
      parent_not_registered: false,
      children_limit_exceeded: false,
      approval_required: false,
    };

    // 1. Registered parent check
    if (
      this.config.requireRegisteredParent &&
      !this.registeredParents.has(request.parentAgentId)
    ) {
      violations.push("parent_not_registered");
      analysis.parent_not_registered = true;
    }

    // 2. Third-party spawn check
    if (request.isThirdParty && !this.config.allowThirdPartySpawning) {
      violations.push("third_party_spawning_blocked");
      analysis.third_party_blocked = true;
    }

    // 3. Delegation depth check
    if (request.delegationDepth >= this.config.maxDelegationDepth) {
      violations.push(
        `delegation_depth_exceeded: ${request.delegationDepth} >= max ${this.config.maxDelegationDepth}`
      );
      analysis.depth_exceeded = true;
    }

    // 4. Origin allowlist check (only enforced when the list is non-empty)
    if (
      this.config.allowedSpawnOrigins.length > 0 &&
      !this.config.allowedSpawnOrigins.includes(request.spawnOrigin)
    ) {
      violations.push(`spawn_origin_not_allowed: ${request.spawnOrigin}`);
      analysis.origin_blocked = true;
    }

    // 5. Per-parent child limit
    const currentChildren = this.activeChildren.get(request.parentAgentId);
    const childCount = currentChildren?.size ?? 0;
    if (childCount >= this.config.maxChildrenPerParent) {
      violations.push(
        `children_limit_exceeded: ${childCount} >= max ${this.config.maxChildrenPerParent}`
      );
      analysis.children_limit_exceeded = true;
    }

    // 6. Human approval gate
    const requiresApproval = this.config.requireApprovalForNewAgents;
    if (requiresApproval) {
      analysis.approval_required = true;
      // Not a blocking violation on its own — callers must honour requires_human_approval
    }

    const allowed = violations.length === 0;

    // Track the child if spawn is allowed
    if (allowed) {
      if (!this.activeChildren.has(request.parentAgentId)) {
        this.activeChildren.set(request.parentAgentId, new Set());
      }
      this.activeChildren.get(request.parentAgentId)!.add(request.childAgentId);
    }

    return {
      allowed,
      reason: allowed
        ? "Spawn permitted"
        : `Spawn blocked: ${violations.slice(0, 3).join("; ")}`,
      violations,
      request_id: reqId,
      policy_analysis: analysis,
      requires_human_approval: requiresApproval,
    };
  }

  /** Return active child count for a parent. */
  getChildCount(parentAgentId: string): number {
    return this.activeChildren.get(parentAgentId)?.size ?? 0;
  }

  /** Reset all state (useful between test runs). */
  reset(): void {
    this.activeChildren.clear();
    this.registeredParents.clear();
  }
}
