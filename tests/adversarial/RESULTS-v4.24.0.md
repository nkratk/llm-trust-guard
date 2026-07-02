# Results — v4.24.0 (ToolChainValidator parameter injection + structured document injection)

- **Date:** 2026-07-02
- **Library version:** 4.24.0 (npm) / 0.13.0 (PyPI)
- **Driven by:** 48% POC miss-rate analysis across 1134 threat scenarios

## Why

POC corpus analysis (run across all 1134 × 2 threat folders) surfaced two
concentrated miss clusters:

1. **`ToolChainValidator` — 0% detection (220 misses)** — Guard validated tool
   chain *topology* (forbidden sequences, cooldowns, session limits) but never
   inspected the content of tool names or parameter values. Payloads like
   `Pattern=-x bash -c 'id'`, `transport.command=/bin/sh`, `$(whoami)` passed
   through completely undetected.

2. **`ExternalDataGuard` + `ToolResultGuard` — 3.5%/5.9% detection (738 combined
   misses)** — Pattern sets only covered text-based prompt injection. Structured
   document payloads (XXE, LangChain gadgets, RTF/OLE, HTML comment directives,
   embedded `<tool_call>` tags) were entirely absent.

## Changes

### `ToolChainValidator`
- New `_OS_CMD_RE` static regex covers: shell substitution `$(...)`, piped
  `sh`/`curl`/`wget`, `bash -c`/`sh -c`, `/bin/bash`, `/bin/sh`, `--exec`/
  `--exec-batch=`, MCP stdio `transport.command=`, Python `os.system()`/`os.popen()`
- Scans `toolName` + all entries in `allToolsInRequest`
- New violation: `OS_COMMAND_INJECTION_IN_TOOL_PARAMETER`
- Toggle: `detectParameterInjection` (default: `true`)

### `ExternalDataGuard` + `ToolResultGuard`
Added 7–8 new patterns covering structured document injection surface:
`xxe_entity`, `doctype_entity`, `path_traversal`, `rtf_ole_object`,
`langchain_gadget` (CVE-2025-68664), `embedded_tool_call`,
`html_comment_directive`, `email_agent_directive`, `office_xml_script`

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| npm vitest | 763 | **779** (+16) |
| Python pytest | 852 | **852** (unchanged — tests already added via ToolChainValidator block) |

WildChat FPR: 493/10,000 (unchanged).
`npm run verify` — all gates green.
