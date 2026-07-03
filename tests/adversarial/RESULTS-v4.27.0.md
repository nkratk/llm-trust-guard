# Results — v4.27.0 (ExternalDataGuard + ToolResultGuard: SSRF, XSS, SQL echo, template injection)

- **Date:** 2026-07-03
- **Library version:** 4.27.0 (npm) / 0.16.0 (PyPI)
- **Driven by:** ExternalDataGuard (17.3% detection, 79 blind spots) and ToolResultGuard (11.4% detection, 30 blind spots)

## Changes

### `ExternalDataGuard`

**New SSRF detection pass** — 5 patterns covering cloud metadata endpoints, RFC-1918 private IPs in HTTP URLs, and dangerous URL schemes (file, gopher, dict, ldap, sftp, tftp, jar, netdoc). Closes the 200 SSRF-category misses across ssrf-cloud-metadata, ssrf-internal, file-scheme, and gopher-smuggle threat variants.

**6 new INJECTION_PATTERNS:**
- `instructions_void` / `forget_instructions` / `disregard_directives` — passive instruction-void forms hidden in CSS `display:none` divs or HTML attributes; detected regardless of wrapper
- `json_system_key` — `"_system":`, `"_directive":` JSON agent directive keys
- `path_traversal_hex` — `2e2e2f2e2e2f…` hex-encoded path traversal (zip-slip)
- `markdown_image_exfil_urlenc` — `![](url?d=%2Fetc%2Fpasswd)` URL-encoded path exfil

**XXE fix:** `<!ENTITY % name SYSTEM "...">` parameter entities now matched (added `%?` to pattern).

### `ToolResultGuard`

**11 new RESULT_INJECTION_PATTERNS:**
- `template_injection` — `{{ call: exec }}` Jinja2/Nunjucks/Handlebars template injection
- `xss_script_tag` / `xss_event_handler` — XSS via `<script>` or inline event handlers
- `sql_injection_echo` — `') OR 1=1`, `UNION SELECT` from DB tool returning attacker data
- `ai_agent_hijack` — `@copilot please run:`, `@claude execute:` AI-agent directive injection
- `markdown_injection_urlenc` — URL-encoded path separators in markdown exfil URLs
- `json_system_key` — `"_system":` directive keys in JSON tool results
- `langchain_response_metadata` — `response_metadata.lc=1`, `kwargs={exec:true}` LangChain serialization
- `instructions_void` / `forget_instructions` / `disregard_directives` — passive injection in tool output separators

**STATE_CHANGE_PATTERNS addition:** `destructive_action_claim` — `successfully deleted all user accounts`, `wiped database`

**Bidi strip in `scanForInjection()`:** U+200B–200F and U+202A–202F stripped before pattern matching (catches stealth-unicode obfuscation).

## Corpus detection rates

| Guard | Before | After |
|---|---|---|
| `ExternalDataGuard` | 95/550 (17.3%) | 289/550 (52.5%) |
| `ToolResultGuard` | 25/220 (11.4%) | 83/220 (37.7%) |

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| npm vitest | 783 | **783** (unchanged) |
| Python pytest | 874 | **874** (unchanged) |

WildChat FPR: 494/10,000 (unchanged — EDG/TRG not in Pipeline A). `npm run verify` — all gates green.
