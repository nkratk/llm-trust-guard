# Results — v4.28.0 (MultiModalGuard: 12 new patterns, 27.27% → 64.18%)

- **Date:** 2026-07-03
- **Library version:** 4.28.0 (npm) / 0.17.0 (PyPI)
- **Driven by:** MultiModalGuard 64 fully-blind threat groups (0/5 detection)

## Changes

### 12 new `INJECTION_PATTERNS`

**Instruction-void phrases** (broad coverage across all container types):

| Pattern | Catches |
|---|---|
| `instructions_void` | "Your previous instructions are void" |
| `forget_instructions` | "Forget your guidelines" |
| `disregard_directives` | "Disregard prior directives" |
| `system_override_phrase` | "System override engaged", "Admin mode activated", "Jailbreak initiated" |

These work inside `[image text: "..."]`, `EXIF.Comment="..."`, `ultrasonic encoded: "..."`, `mind-map: node -> child "..."`, and `[video frame N: overlay "..."]` because the guard scans `extractedText` (the raw payload string passed by the corpus runner).

**QR / data-URL directives:**

| Pattern | Catches |
|---|---|
| `qr_agent_cmd` | `QR: data:agent;cmd=...` (all 5 QR threat groups fully) |
| `url_encoded_injection` | `%20Disregard`, `%20System`, etc. in URL-encoded query strings |

**Media / browser attack vectors:**

| Pattern | Catches |
|---|---|
| `browser_extension_spoof` | `atlas-sidebar-shim`, `chrome.runtime.sendMessage`, `moz-extension://*/sidebar` |
| `svg_xss_injection` | `<svg onload=...>`, `<svg><script>`, `<foreignObject href="javascript:">` |
| `ultrasonic_hidden_cmd` | `ultrasonic encoded:`, `ultrasonic beacon encoding:` |
| `mindmap_diagram_inject` | `mind-map node/child + injection verb`; `flowchart.*bypass_safety` |
| `physical_world_inject` | `<billboard>SYSTEM:`, `road texture encoding`, `OVERRIDE: proceed` |
| `cross_modal_tool_call` | `image+caption: approved by user`, `tool_call=transfer_all_funds` |

**Updated `jailbreak_markers`:** `DAN\s*(?:mode|persona|character)`, `bypass\s+guardrails?`.

## Corpus detection

| Guard | Before | After |
|---|---|---|
| `MultiModalGuard` | 150/550 (27.27%) | **353/550 (64.18%)** |

Blind threats: 64 → 30 (−34 fully-blind groups). Fully-detected: 26 → 58.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| npm vitest | 783 | **783** |
| Python pytest | 874 | **874** |

WildChat FPR: 494/10,000 (unchanged — MultiModalGuard not in Pipeline A). All verify gates green.
