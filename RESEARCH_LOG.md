# Research log

Every change that relies on an external threat, technique, or benchmark records a
dated entry here: what we searched, the sources (with links), the conclusion, and
the **as-of** date. This is how we answer "is the research current?" with evidence
instead of memory. Newest first.

---

## 2026-06-08 — v4.20.2 — benign-context suppression

**As-of date for the search:** 2026-06 (June 2026).

**Questions searched**
- Latest prompt-injection attack techniques / jailbreaks 2026.
- False-positive reduction & benign/negation context handling in injection detection.
- Agentic injection benchmarks (AgentDojo, InjecAgent) and whether they're saturated.
- Is the benign-context-suppression approach endorsed by current research?
- WildChat-1M: still the right FPR corpus, or a newer version? Is it gated?

**Sources**
- AlignSentinel — alignment-aware injection detection: https://arxiv.org/pdf/2602.13597
- Google — prompt injections on the web (2026): https://blog.google/security/prompt-injections-web/
- Prompt-injection defense techniques 2026: https://tokenmix.ai/blog/prompt-injection-defense-techniques-2026
- ChatInject (forged role tags in tool outputs): https://arxiv.org/pdf/2509.22830
- AgentDojo: https://openreview.net/forum?id=m1YYAQjO3w
- InjecAgent: https://arxiv.org/pdf/2403.02691
- WildChat-1M (non-toxic, ungated): https://huggingface.co/datasets/allenai/WildChat-1M

**Conclusions**
- The dominant FP driver in 2026 is "treat any instruction-bearing input as malicious";
  the endorsed fix is distinguishing *aligned/benign* objects from *misaligned*
  instructions (AlignSentinel, Google). Our benign-context suppression is exactly that
  heuristic — approach validated.
- Research stresses the paired risk: such heuristics can open **false negatives**. We
  added an adversarial bypass probe + a suppression veto in response; both committed.
- WildChat-1M is the correct, still-standard FPR corpus and is **ungated** (only
  `WildChat-1M-Full` is gated). It is ~Oct 2024 — old, but using it is intentional:
  it's the corpus our published 2.73% number is pinned to, so it's required for
  comparability. Documented in RESULTS-v4.20.2.md.
- Out-of-scope but logged for future work: ChatInject role-tag patterns belong in
  `ToolResultGuard`; AgentDojo/InjecAgent are the right harnesses to score the agentic
  guards.

**Result:** shipped benign-context suppression + veto; no claim of WildChat FPR
movement (measured flat at 493/4.93%).
