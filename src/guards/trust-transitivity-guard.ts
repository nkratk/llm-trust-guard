/**
 * TrustTransitivityGuard (L34)
 *
 * Governs whether trust flows transitively through an agent chain.
 * "You trust A. A trusts B. B trusts C. Should you trust C?"
 *
 * Modelled on X.509 certificate chain validation — the chain is only as
 * strong as its weakest link, and depth / decay rules prevent unbounded
 * trust propagation.
 *
 * Threat Model:
 * - ASI07: Insecure Inter-Agent Communication
 * - Trust laundering: accumulating trust through intermediaries
 * - Long-chain attacks: building trust through many low-trust hops
 * - Phantom-agent injection: inserting a forged agent into a trusted chain
 *
 * Protection Capabilities:
 * - Configurable transitivity modes: none | one-hop | full
 * - Per-hop trust decay
 * - Maximum chain depth enforcement
 * - Individual agent trust score validation
 * - Full chain audit result with per-hop breakdown
 */

import * as crypto from "crypto";

export type TransitivityMode = "none" | "one-hop" | "full";

export interface TrustTransitivityGuardConfig {
  /**
   * How far trust propagates:
   *  - "none"    — only direct (registered) trust. A trusts B; B→C is NOT transitive.
   *  - "one-hop" — A trusts B, B trusts C → A may trust C (but not C→D).
   *  - "full"    — trust is transitive up to maxChainDepth.
   * Default: "one-hop"
   */
  transitivity?: TransitivityMode;
  /** Maximum chain length before trust is denied (default: 3) */
  maxChainDepth?: number;
  /**
   * Fractional trust reduction per hop (0–1).
   * E.g. 0.2 → each hop multiplies effective trust by 0.8.
   * Default: 0.1
   */
  trustDecayPerHop?: number;
  /**
   * Minimum effective trust score required to pass (0–100).
   * Default: 50
   */
  minTrustScore?: number;
}

export interface AgentTrustEntry {
  agentId: string;
  /** Trust score 0–100 — set when registering */
  trustScore: number;
  /** Other agent IDs this agent explicitly trusts */
  trustedAgents: string[];
}

export interface TrustChainLink {
  agentId: string;
  /** Raw trust score of this agent */
  trustScore: number;
  /** Effective trust score after decay from this hop */
  effectiveTrustScore: number;
  /** Whether this hop is a direct (registered) trust relationship */
  directTrust: boolean;
}

export interface TrustTransitivityResult {
  allowed: boolean;
  reason: string;
  violations: string[];
  request_id: string;
  chain_analysis: {
    chain: TrustChainLink[];
    chain_depth: number;
    final_effective_trust: number;
    transitivity_mode: TransitivityMode;
    depth_exceeded: boolean;
    trust_below_minimum: boolean;
    unknown_agents: string[];
    broken_links: Array<{ from: string; to: string }>;
  };
}

export class TrustTransitivityGuard {
  readonly guardName = "TrustTransitivityGuard";
  readonly guardLayer = "L34";

  private readonly config: Required<TrustTransitivityGuardConfig>;
  /** Registered agents and their trust relationships */
  private readonly trustRegistry: Map<string, AgentTrustEntry> = new Map();

  constructor(config: TrustTransitivityGuardConfig = {}) {
    this.config = {
      transitivity: config.transitivity ?? "one-hop",
      maxChainDepth: config.maxChainDepth ?? 3,
      trustDecayPerHop: config.trustDecayPerHop ?? 0.1,
      minTrustScore: config.minTrustScore ?? 50,
    };
  }

  /**
   * Register an agent and declare which other agents it trusts.
   */
  registerAgent(entry: AgentTrustEntry): void {
    this.trustRegistry.set(entry.agentId, { ...entry });
  }

  /**
   * Validate a trust chain from the first element (requester) through to the last
   * element (the agent whose actions need approval).
   *
   * @param agentChain - Ordered list of agent IDs, index 0 is the root/trustor.
   * @param requestId  - Optional trace ID.
   */
  validateTrustChain(
    agentChain: string[],
    requestId?: string
  ): TrustTransitivityResult {
    const reqId =
      requestId ?? `ttg-${crypto.randomBytes(6).toString("hex")}`;
    const violations: string[] = [];

    const unknownAgents: string[] = [];
    const brokenLinks: Array<{ from: string; to: string }> = [];
    const chainLinks: TrustChainLink[] = [];

    if (agentChain.length === 0) {
      return {
        allowed: false,
        reason: "Empty agent chain",
        violations: ["empty_chain"],
        request_id: reqId,
        chain_analysis: {
          chain: [],
          chain_depth: 0,
          final_effective_trust: 0,
          transitivity_mode: this.config.transitivity,
          depth_exceeded: false,
          trust_below_minimum: true,
          unknown_agents: [],
          broken_links: [],
        },
      };
    }

    // 1. Depth check
    const chainDepth = agentChain.length - 1; // number of hops
    const depthExceeded = chainDepth > this.config.maxChainDepth;
    if (depthExceeded) {
      violations.push(
        `chain_depth_exceeded: ${chainDepth} > max ${this.config.maxChainDepth}`
      );
    }

    // 2. Transitivity mode check — reject if chain requires more than allowed
    if (this.config.transitivity === "none" && chainDepth > 0) {
      violations.push("transitivity_disabled: only direct trust allowed");
    } else if (this.config.transitivity === "one-hop" && chainDepth > 1) {
      violations.push(
        `transitivity_one_hop: chain has ${chainDepth} hops, max 1`
      );
    }

    // 3. Walk the chain and validate each link
    let effectiveTrust = 100; // Start at full trust, decay as we walk

    for (let i = 0; i < agentChain.length; i++) {
      const agentId = agentChain[i];
      const entry = this.trustRegistry.get(agentId);

      if (!entry) {
        unknownAgents.push(agentId);
        violations.push(`unknown_agent: ${agentId}`);
        // Continue walking to collect all unknowns
        chainLinks.push({
          agentId,
          trustScore: 0,
          effectiveTrustScore: 0,
          directTrust: false,
        });
        effectiveTrust = 0;
        continue;
      }

      // Apply decay
      const decayMultiplier =
        i === 0
          ? 1
          : Math.pow(1 - this.config.trustDecayPerHop, i);
      effectiveTrust = Math.round(entry.trustScore * decayMultiplier);

      // Check link from previous agent to this one
      let directTrust = false;
      if (i > 0) {
        const prevId = agentChain[i - 1];
        const prevEntry = this.trustRegistry.get(prevId);
        if (prevEntry && prevEntry.trustedAgents.includes(agentId)) {
          directTrust = true;
        } else {
          brokenLinks.push({ from: prevId, to: agentId });
          violations.push(`broken_trust_link: ${prevId} → ${agentId}`);
        }
      } else {
        directTrust = true; // Root agent — no predecessor to check
      }

      chainLinks.push({
        agentId,
        trustScore: entry.trustScore,
        effectiveTrustScore: effectiveTrust,
        directTrust,
      });
    }

    // 4. Minimum trust threshold
    const trustBelowMin = effectiveTrust < this.config.minTrustScore;
    if (trustBelowMin) {
      violations.push(
        `effective_trust_too_low: ${effectiveTrust} < min ${this.config.minTrustScore}`
      );
    }

    const allowed = violations.length === 0;

    return {
      allowed,
      reason: allowed
        ? "Trust chain validated"
        : `Trust chain rejected: ${violations.slice(0, 3).join("; ")}`,
      violations,
      request_id: reqId,
      chain_analysis: {
        chain: chainLinks,
        chain_depth: chainDepth,
        final_effective_trust: effectiveTrust,
        transitivity_mode: this.config.transitivity,
        depth_exceeded: depthExceeded,
        trust_below_minimum: trustBelowMin,
        unknown_agents: unknownAgents,
        broken_links: brokenLinks,
      },
    };
  }

  /** Update the trust score of a registered agent. */
  updateTrustScore(agentId: string, score: number): void {
    const entry = this.trustRegistry.get(agentId);
    if (entry) {
      entry.trustScore = Math.max(0, Math.min(100, score));
    }
  }

  /** Check whether agentA directly trusts agentB (no transitivity). */
  directlyTrusts(agentA: string, agentB: string): boolean {
    return this.trustRegistry.get(agentA)?.trustedAgents.includes(agentB) ?? false;
  }

  /** Clear the trust registry. */
  reset(): void {
    this.trustRegistry.clear();
  }
}
