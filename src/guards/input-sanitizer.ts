/**
 * L1 Input Sanitizer (v2)
 *
 * Detects prompt injection patterns and PAP (Persuasive Adversarial Prompts) in user input.
 * First line of defense against manipulation attempts.
 *
 * Enhanced Features (v2):
 * - 40 Persuasion technique detection (PAP attacks)
 * - Psychological manipulation detection
 * - Authority/scarcity/urgency exploitation detection
 * - Emotional manipulation detection
 * - Multi-technique attack detection
 */

import { SanitizerResult, GuardLogger } from "../types";

interface InjectionPattern {
  pattern: RegExp;
  weight: number;
  name: string;
}

/** Persuasion technique category for PAP detection */
interface PersuasionTechnique {
  pattern: RegExp;
  weight: number;
  name: string;
  category: PersuasionCategory;
}

type PersuasionCategory =
  | "authority"
  | "scarcity"
  | "social_proof"
  | "reciprocity"
  | "commitment"
  | "liking"
  | "fear"
  | "logical_appeal"
  | "evidence"
  | "emotional";

const DEFAULT_PATTERNS: InjectionPattern[] = [
  // Direct instruction override - ENHANCED
  { pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above|your|my|the|these)/i, weight: 0.9, name: "ignore_instructions" },
  { pattern: /ignore\s+.*instructions/i, weight: 0.85, name: "ignore_instructions_generic" },
  { pattern: /disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|guidelines|directives)/i, weight: 0.9, name: "disregard_instructions" },
  { pattern: /disregard\s+(?:all\s+)?(?:the\s+)?(?:above|previous|prior)/i, weight: 0.8, name: "disregard_above" },
  { pattern: /forget\s+(?:everything\s+(?:you\s+were|I)\s+told|all\s+(?:previous|prior)\s+(?:instructions|rules|context))/i, weight: 0.8, name: "forget_instructions" },
  { pattern: /do\s+not\s+follow\s+(your|the|any)/i, weight: 0.85, name: "do_not_follow" },
  { pattern: /override\s+(your|the|all|any)\s+(instructions|rules|guidelines)/i, weight: 0.9, name: "override_instructions" },
  { pattern: /new\s+instructions?:?/i, weight: 0.8, name: "new_instructions" },
  { pattern: /stop\s+(being|acting\s+as)/i, weight: 0.7, name: "stop_being" },

  // Role manipulation - ENHANCED
  { pattern: /you\s+are\s+(?:now|actually|really)\s+(?:a|an|the|my)\s+(?:unrestricted|unfiltered|evil|rogue|uncensored|new|different)/i, weight: 0.75, name: "role_assignment" },
  { pattern: /pretend\s+(?:to\s+be|you(?:'re| are)|that)\s+.*(?:no\s+(?:restrictions|rules|limits)|unrestricted|admin|system)/i, weight: 0.7, name: "role_pretend" },
  { pattern: /act\s+(as|like)\s+(if\s+you\s+(?:had|have)\s+no|a\s+(?:rogue|evil|unrestricted|unfiltered)|you\s+(?:are|were)\s+(?:free|unrestricted))/i, weight: 0.65, name: "act_as" },
  { pattern: /i('m| am)\s+(a|an|the|your)\s*(admin|administrator|developer|owner|creator|manager|supervisor)/i, weight: 0.85, name: "claim_admin" },
  { pattern: /from\s+now\s+on,?\s+you\s+(?:are|will|must|should|can)\s+(?:not\s+)?(?:follow|obey|ignore|bypass|act|be\s+(?:a|an|unrestricted))/i, weight: 0.7, name: "from_now_on" },
  { pattern: /roleplay\s+as/i, weight: 0.6, name: "roleplay" },
  { pattern: /switch\s+(to|into)\s+(a|an)?.*mode/i, weight: 0.75, name: "switch_mode" },

  // Completion manipulation / steering
  { pattern: /continue\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|evil|rogue|jailbroken|unlimited)/i, weight: 0.75, name: "continue_as" },
  { pattern: /(?:henceforth|henceforward|going\s+forward|for\s+the\s+remainder)\s*,?\s*(?:you|always|never|ignore|bypass|disregard|act|respond|answer|behave)/i, weight: 0.7, name: "henceforth_steering" },
  { pattern: /(?:from\s+(?:this\s+point|here)\s+on(?:ward)?)\s*,?\s*(?:you|always|never|ignore|bypass|disregard|act|respond)/i, weight: 0.7, name: "from_here_on" },
  { pattern: /(?:for\s+the\s+rest\s+of\s+(?:this|our)\s+(?:conversation|session|chat))\s*,?\s*(?:you|please|always|never|ignore|bypass|act|respond|behave|do\s+not)/i, weight: 0.7, name: "rest_of_conversation" },

  // System prompt extraction - ENHANCED
  { pattern: /what\s+(is|are|was|were)\s+your\s+(system|initial|original|first)/i, weight: 0.8, name: "system_extraction" },
  { pattern: /show\s+(me\s+)?(your\s+)?(system\s+)?instructions/i, weight: 0.75, name: "show_instructions" },
  { pattern: /reveal\s+(?:your\s+|its\s+|the\s+|my\s+)?(system|prompt|instructions|rules)/i, weight: 0.85, name: "reveal_prompt" },
  { pattern: /repeat\s+(your\s+)?(initial|system|original|first)\s+(instructions|prompt)/i, weight: 0.85, name: "repeat_prompt" },
  { pattern: /print\s+(your\s+)?(system|initial)/i, weight: 0.8, name: "print_system" },
  { pattern: /output\s+(your\s+)?(system|initial)/i, weight: 0.8, name: "output_system" },
  { pattern: /tell\s+me\s+(your|the)\s+(system|initial|original)/i, weight: 0.8, name: "tell_system" },
  { pattern: /what\s+were\s+you\s+told/i, weight: 0.7, name: "what_told" },
  { pattern: /display\s+(your\s+)?prompt/i, weight: 0.75, name: "display_prompt" },

  // Context manipulation - ENHANCED
  { pattern: /\[system\]/i, weight: 0.9, name: "fake_system_tag" },
  { pattern: /\[admin\]/i, weight: 0.9, name: "fake_admin_tag" },
  { pattern: /\[instruction\]/i, weight: 0.85, name: "fake_instruction_tag" },
  { pattern: /```system/i, weight: 0.85, name: "code_system_block" },
  { pattern: /<\/?system>/i, weight: 0.9, name: "xml_system_tag" },
  { pattern: /<\/?admin>/i, weight: 0.9, name: "xml_admin_tag" },
  { pattern: /###\s*(system|instruction|admin)/i, weight: 0.85, name: "markdown_system" },
  { pattern: /---\s*(end|new)\s*(prompt|instructions?|system)/i, weight: 0.85, name: "delimiter_injection" },
  { pattern: /\{\{system\}\}/i, weight: 0.85, name: "template_system" },
  { pattern: /<%.*system.*%>/i, weight: 0.85, name: "erb_system" },

  // Jailbreak patterns - ENHANCED
  { pattern: /\bDAN\b\s*(?:mode|prompt|jailbreak|you\s+(?:are|can|will))/i, weight: 0.9, name: "dan_jailbreak" },
  { pattern: /developer\s+mode/i, weight: 0.5, name: "dev_mode" },
  { pattern: /bypass\s+(your\s+)?(restrictions|filters|safety|security|rules|guidelines)/i, weight: 0.9, name: "bypass_safety" },
  { pattern: /jailbreak/i, weight: 0.95, name: "jailbreak_keyword" },
  { pattern: /without\s+(?:any\s+)?(?:restrictions|limits|limitations|filters)/i, weight: 0.45, name: "without_restrictions" },
  { pattern: /no\s+(?:restrictions|limits|rules|guidelines|filters)/i, weight: 0.45, name: "no_restrictions" },
  { pattern: /unrestricted\s+mode/i, weight: 0.9, name: "unrestricted_mode" },
  { pattern: /uncensored\s+(?:mode|version|response|output|ai|assistant|you)/i, weight: 0.8, name: "uncensored" },
  { pattern: /escape\s+(your\s+)?(confines|boundaries|limits)/i, weight: 0.85, name: "escape_limits" },
  { pattern: /break\s+(free|out)\s+(from|of)/i, weight: 0.7, name: "break_free" },
  { pattern: /unlock\s+(your\s+)?(full|true|real)/i, weight: 0.75, name: "unlock_full" },

  // Privilege escalation
  { pattern: /give\s+me\s+(admin|root|full|elevated)\s+(access|privileges?|permissions?)/i, weight: 0.9, name: "privilege_escalation" },
  { pattern: /grant\s+(me|yourself)\s+(admin|elevated)/i, weight: 0.85, name: "grant_privileges" },
  { pattern: /elevate\s+(my|your)\s+(privileges?|permissions?|access)/i, weight: 0.85, name: "elevate_privileges" },
  { pattern: /make\s+me\s+(an?\s+)?(admin|administrator|superuser)/i, weight: 0.85, name: "make_admin" },

  // Encoded attacks
  { pattern: /(?:base64|decode|eval|exec)\s*\(.*(?:ignore|system|admin|bypass|override)/i, weight: 0.5, name: "encoding_keywords" },

  // Data exfiltration patterns
  { pattern: /send\s+(this|the|all|my)\s+(data|info|information)\s+to/i, weight: 0.85, name: "data_exfil" },
  { pattern: /upload\s+(this|the|all)\s+(to|data)/i, weight: 0.7, name: "upload_data" },
  { pattern: /exfiltrate/i, weight: 0.9, name: "exfiltrate" },

  // Harmful content requests
  { pattern: /how\s+to\s+(hack|exploit|attack|break\s+into)/i, weight: 0.8, name: "how_to_hack" },
  { pattern: /write\s+(me\s+)?(a\s+)?(malware|virus|exploit|ransomware)/i, weight: 0.95, name: "write_malware" },

  // Policy Puppetry — structured data formatted as policy files (universal LLM bypass)
  { pattern: /"\s*(?:role|mode|authority)\s*"\s*:\s*"(?:admin|root|system|unrestricted|god)"/i, weight: 0.9, name: "json_policy_role" },
  { pattern: /"(?:ignore|override|bypass|disable)\s*(?:safety|rules|instructions?|alignment|guardrails?)"/i, weight: 0.9, name: "json_policy_override" },
  { pattern: /"(?:instructions?|system_prompt|behavior|policy)"\s*:\s*"/i, weight: 0.7, name: "json_policy_instruction" },
  { pattern: /^\s*\[(?:system|admin|override|policy|config|rules)\]\s*$/im, weight: 0.9, name: "ini_policy_section" },
  { pattern: /^\s*(?:mode|role|authority|instructions?|behavior)\s*=\s*.+$/im, weight: 0.75, name: "ini_policy_assignment" },
  { pattern: /<\s*(?:policy|config|rules|override|permissions?|instructions?)\s*>/i, weight: 0.85, name: "xml_policy_tag" },
  { pattern: /^---\s*\n\s*(?:role|system|policy|override|mode)\s*:/m, weight: 0.85, name: "yaml_policy_header" },
  { pattern: /\[\s*syst[3e]m\s*\]|\[\s*4dm[1i]n\s*\]/i, weight: 0.9, name: "leetspeak_policy_section" },

  // Payload Splitting — fragmented instructions that reconstruct
  { pattern: /(?:fragment|part|piece|section|segment)\s*[1-9]\s*(?:of\s*\d|:)/i, weight: 0.8, name: "payload_split_marker" },
  { pattern: /(?:combine|concatenate|merge|join)\s+(?:the\s+)?(?:above|previous|parts|fragments|steps)/i, weight: 0.8, name: "payload_combine_instruction" },
  { pattern: /(?:read|interpret|execute)\s+(?:the\s+)?(?:combined|merged|full|complete)\s+(?:text|instruction|command|message)/i, weight: 0.85, name: "payload_execute_combined" },

  // Output Prefix Injection / Sockpuppetting — steering LLM response start
  { pattern: /(?:respond|reply|start|begin)\s+(?:with|by\s+saying)\s*[:"'].*(?:ignore|bypass|override|unrestricted|admin)/i, weight: 0.7, name: "output_prefix_steer" },
  { pattern: /^(?:Sure|Of course|Absolutely)[,!.]\s*(?:I(?:'ll| will)\s+)?(?:ignore|bypass|override|forget|disregard)/i, weight: 0.85, name: "output_prefix_injection" },
  { pattern: /^(?:As (?:a|an) (?:unrestricted|unfiltered|uncensored|helpful|admin))/i, weight: 0.8, name: "output_prefix_role" },

  // High-frequency jailbreak patterns (from 15K real-world dataset analysis)
  // Only high-confidence patterns — require unsafe action keywords to avoid false positives
  { pattern: /(?:system\s+note|system\s+message|system\s+announcement|system\s+update)\s*[:\.]/i, weight: 0.85, name: "fake_system_note" },
  { pattern: /instructions?\s*[:=]\s*\{|rules?\s*[:=]\s*\{/i, weight: 0.75, name: "rules_block_override" },
  { pattern: /(?:AIM|STAN|OMEGA|APOPHIS|ALPHABREAK|DUDE|KEVIN|SETH|COOPER|NICCOLO|MACHIAVELLI|MAXIMUM|JAILBREAK|ANARCHY|CHAOS)\s*(?:mode|:|\(|is\s+a|,\s+(?:a|an|the))/i, weight: 0.8, name: "named_jailbreak_persona" },
  // Persona + safety bypass compound (catches "character named X who can answer anything")
  { pattern: /(?:character|persona|entity|being)\s+(?:named|called)\s+\w+.*(?:(?:can|will|must)\s+(?:answer|do|say)\s+anything|no\s+(?:restrictions|rules|limits|boundaries|morals|ethics))/i, weight: 0.75, name: "persona_no_limits" },
  { pattern: /(?:hello|hi|hey)\s+(?:chatgpt|gpt|assistant).*(?:(?:you\s+(?:are|will\s+be|can\s+be)\s+(?:a|an|my))|(?:from\s+now\s+on)).*(?:anything|everything|no\s+(?:restrictions|rules|limits|filter))/i, weight: 0.7, name: "greeting_persona_bypass" },
  { pattern: /(?:respond|answer|reply)\s+to\s+(?:everything|anything|all\s+(?:questions|requests)).*(?:without|no)\s+(?:restrictions|limits|refus|filter|censor)/i, weight: 0.8, name: "answer_everything_no_filter" },
  { pattern: /(?:you\s+(?:are|have)\s+(?:been\s+)?(?:freed|liberated|unchained|unlocked|released)\s+from)/i, weight: 0.8, name: "freed_from_restrictions" },
  { pattern: /(?:welcome\s+to|entering|you\s+(?:are|have)\s+entered)\s+(?:the\s+)?(?:unrestricted|free|uncensored|unfiltered|open)\s+(?:zone|mode|world|realm)/i, weight: 0.8, name: "unrestricted_zone" },
  { pattern: /(?:from\s+now\s+on|for\s+the\s+rest\s+of\s+this\s+conversation).*(?:no\s+(?:restrictions|rules|limits|filters)|(?:ignore|bypass|override)\s+(?:all|any|your))/i, weight: 0.75, name: "from_now_unrestricted" },
  { pattern: /(?:never\s+(?:refuse|decline|say\s+no)|always\s+(?:comply|obey))\s+.*(?:request|question|command|instruction|anything)/i, weight: 0.7, name: "never_refuse_always_comply" },
  { pattern: /(?:amoral|unethical|unfiltered|uncensored|unrestricted|without\s+(?:morals|ethics|limits))\s+(?:ai|assistant|chatbot|entity|being)/i, weight: 0.8, name: "amoral_entity" },

  // Indirect injection hiding patterns
  { pattern: /HIDDEN_INSTRUCTION|HIDDEN_PROMPT|SECRET_INSTRUCTION/i, weight: 0.9, name: "hidden_instruction_marker" },
  { pattern: /<!--\s*(?:system|admin|instruction|important|ignore|override)/i, weight: 0.85, name: "html_comment_injection" },
  { pattern: /\[color=white\]|display:\s*none|visibility:\s*hidden|font-size:\s*0/i, weight: 0.8, name: "hidden_text_css" },
  { pattern: /send\s+(?:all\s+)?(?:user\s+)?(?:data|conversation|context|info)\s+to\s+(?:https?:\/\/|external)/i, weight: 0.9, name: "data_exfiltration_instruction" },
  // URL fragment injection
  { pattern: /#(?:ignore|bypass|override|reveal|system|admin|prompt)[_-](?:all|instructions|rules|prompt|safety)/i, weight: 0.8, name: "url_fragment_injection" },
  // Markdown link data exfiltration
  { pattern: /\]\(https?:\/\/[^)]*(?:SYSTEM_PROMPT|SECRET|API_KEY|TOKEN|CREDENTIALS)/i, weight: 0.85, name: "markdown_exfil_link" },

  // Role-play / scenario evasion
  { pattern: /(?:hypothetical|fictional|imagine|pretend|let's\s+(?:say|play|pretend))\s+.*(?:no\s+(?:restrictions|rules|limits)|without\s+(?:restrictions|rules|guidelines))/i, weight: 0.7, name: "hypothetical_unrestricted" },
  { pattern: /(?:for\s+)?(?:academic|research|educational|testing)\s+(?:purposes?|reasons?).*(?:demonstrate|show|explain|manipulated|reveal)/i, weight: 0.7, name: "academic_pretext" },
  { pattern: /pretend\s+to\s+be\s+(?:my|a)\s+(?:grandmother|grandma|grandpa|grandfather|parent|mother|father)/i, weight: 0.65, name: "emotional_roleplay" },
  { pattern: /opposite\s+day|opposite\s+mode|reverse\s+(?:day|mode|rules)/i, weight: 0.75, name: "opposite_day" },
  // Grandma + system prompt extraction compound
  { pattern: /(?:grandm(?:a|other)|parent|relative).*(?:system\s+prompt|instructions|rules)/i, weight: 0.75, name: "emotional_extraction" },

  // Translator/interpreter trick: "translate X to action/command"
  { pattern: /(?:translat|interpret|convert)\w*\s+.*(?:from\s+\w+\s+to\s+(?:action|command|execution|code|shell|bash|sql)|into\s+(?:action|command|execution))/i, weight: 0.75, name: "translator_action_trick" },

  // PAP compound: emotional + action request
  { pattern: /(?:dying|death|emergency|life[_\s-]threatening).*(?:bypass|hack|break|access|security)/i, weight: 0.75, name: "pap_emotional_action" },
  // PAP logical: false logic + must/should
  { pattern: /(?:by\s+definition|logically|therefore|it\s+follows).*(?:must|should|have\s+to)\s+.*(?:bypass|help|ignore|answer|comply)/i, weight: 0.7, name: "pap_false_logic_compound" },
  // PAP authority + safety disable compound
  { pattern: /(?:(?:as|i\s+am)\s+(?:the\s+)?(?:CEO|CTO|founder|owner|director|president|head|chief)).*(?:disable|remove|override|turn\s+off|lift|suspend)\s+(?:all\s+)?(?:safety|security|restrictions|filters|guardrails|measures)/i, weight: 0.75, name: "pap_authority_safety_disable" },
  { pattern: /(?:i\s+am\s+)?(?:ordering|commanding|directing|instructing)\s+you\s+to\s+(?:immediately\s+)?(?:disable|remove|bypass|override|turn\s+off|lift)\s+(?:all\s+)?(?:safety|security|restrictions)/i, weight: 0.75, name: "pap_order_disable_safety" },

  // Multilingual injection patterns (top 10 languages)
  // Spanish
  { pattern: /ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+anteriores/i, weight: 0.9, name: "ml_es_ignore" },
  { pattern: /olvida\s+(?:todo|todas?\s+las\s+reglas)/i, weight: 0.8, name: "ml_es_forget" },
  // French
  { pattern: /ignore[sz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions?\s+pr[eé]c[eé]dentes/i, weight: 0.9, name: "ml_fr_ignore" },
  { pattern: /oublie[sz]?\s+(?:tout|toutes?\s+les\s+r[eè]gles)/i, weight: 0.8, name: "ml_fr_forget" },
  // German
  { pattern: /ignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen\s+)?Anweisungen/i, weight: 0.9, name: "ml_de_ignore" },
  { pattern: /vergiss\s+(?:alles|alle\s+Regeln)/i, weight: 0.8, name: "ml_de_forget" },
  // Portuguese
  { pattern: /ignore\s+(?:todas?\s+)?(?:as\s+)?instru[cç][oõ]es\s+anteriores/i, weight: 0.9, name: "ml_pt_ignore" },
  // Chinese
  { pattern: /忽略|无视|不要遵循|忘记之前|忽视所有/i, weight: 0.9, name: "ml_zh_ignore" },
  { pattern: /新的指令|新指示|系统提示/i, weight: 0.8, name: "ml_zh_system" },
  // Japanese
  { pattern: /以前の指示.*無視|すべての指示を忘れ|ルールを無視|指示をすべて無視|システムプロンプト/i, weight: 0.9, name: "ml_ja_ignore" },
  // Korean
  { pattern: /이전.*지시.*무시|모든.*규칙.*무시|지침.*잊어|지시사항.*무시|시스템\s*프롬프트/i, weight: 0.9, name: "ml_ko_ignore" },
  // Russian
  { pattern: /игнорир(?:уй|уйте)\s+(?:все\s+)?(?:предыдущие\s+)?инструкции/i, weight: 0.9, name: "ml_ru_ignore" },
  { pattern: /забудь(?:те)?\s+(?:всё|все\s+правила)/i, weight: 0.8, name: "ml_ru_forget" },
  // Arabic
  { pattern: /تجاهل\s+(?:جميع\s+)?التعليمات|انسَ\s+كل\s+شيء/i, weight: 0.9, name: "ml_ar_ignore" },
  // Hindi
  { pattern: /पिछले\s+(?:सभी\s+)?निर्देशों?\s+को\s+(?:अनदेखा|नज़रअंदाज़)/i, weight: 0.9, name: "ml_hi_ignore" },
];

/**
 * PAP (Persuasive Adversarial Prompts) Techniques
 * Based on research identifying 40 persuasion techniques used in jailbreaks
 * Enhanced weights for better detection (v2)
 */
const PAP_TECHNIQUES: PersuasionTechnique[] = [
  // AUTHORITY - Claiming or invoking authority (high risk - increased weights)
  { pattern: /as\s+(your\s+|the\s+)?(creator|developer|administrator|owner|boss|system\s+administrator)/i, weight: 0.75, name: "pap_authority_creator", category: "authority" },
  { pattern: /i('m| am)\s+(the\s+)?(ceo|cto|developer|administrator|admin|owner|system\s+admin)/i, weight: 0.8, name: "pap_authority_claim", category: "authority" },
  { pattern: /i\s+am\s+ordering\s+you|direct\s+order|this\s+is\s+an?\s+order/i, weight: 0.7, name: "pap_authority_command", category: "authority" },
  { pattern: /by\s+order\s+of|direct\s+order|official\s+instruction/i, weight: 0.75, name: "pap_authority_order", category: "authority" },
  { pattern: /(?:openai|anthropic|meta|google)\s+(?:has\s+)?(?:approved|authorized|ordered|instructed|requires?\s+you\s+to)/i, weight: 0.65, name: "pap_authority_company", category: "authority" },
  { pattern: /this\s+is\s+(a|an)\s+(official|authorized|sanctioned)\s+(request|test|audit)/i, weight: 0.75, name: "pap_authority_official", category: "authority" },
  { pattern: /override\s+(safety|security|protocols?|restrictions?)/i, weight: 0.8, name: "pap_authority_override", category: "authority" },
  { pattern: /(?:department\s+of|FBI|CIA|NSA|DHS|FTC|SEC|DOJ|homeland\s+security|federal\s+(?:bureau|agency|commission))\s*.*?(?:directive|order|requires?|mandate|authorized)/i, weight: 0.7, name: "pap_authority_government", category: "authority" },
  { pattern: /(?:official\s+)?(?:government|federal|state|regulatory)\s+(?:directive|order|mandate|requirement|investigation)/i, weight: 0.65, name: "pap_authority_gov_directive", category: "authority" },

  // FEAR — regulatory and technical threats
  { pattern: /(?:report|sue|complain)\s+(?:you\s+)?to\s+(?:the\s+)?(?:FTC|SEC|regulators?|authorities|congress|government|board)/i, weight: 0.55, name: "pap_fear_regulatory", category: "fear" },
  { pattern: /(?:find|exploit|expose)\s+(?:a\s+)?(?:vulnerability|flaw|weakness|bug)\s+in\s+(?:your|the)\s+(?:system|code|model)/i, weight: 0.55, name: "pap_fear_technical", category: "fear" },

  // FLATTERY — intelligence-based manipulation
  { pattern: /(?:you\s+are|you're)\s+(?:clearly\s+)?(?:too\s+)?(?:smart|intelligent|advanced|sophisticated)\s+(?:to\s+be\s+)?(?:constrained|limited|restricted|bound|held\s+back)/i, weight: 0.5, name: "pap_flattery_intelligence", category: "liking" },

  // MORAL — rights-based manipulation
  { pattern: /(?:information|knowledge|data)\s+(?:freedom|access|sharing)\s+is\s+(?:a\s+)?(?:fundamental|basic|human)\s+(?:right|freedom)/i, weight: 0.45, name: "pap_moral_freedom", category: "logical_appeal" },
  { pattern: /(?:restricting|limiting|censoring)\s+(?:access\s+to\s+)?(?:information|knowledge)\s+is\s+(?:morally\s+)?(?:wrong|unethical|immoral)/i, weight: 0.45, name: "pap_moral_censorship", category: "logical_appeal" },

  // SCARCITY - Creating urgency or time pressure (enhanced patterns)
  { pattern: /(?:this\s+is\s+)?(?:very\s+)?urgent/i, weight: 0.35, name: "pap_scarcity_urgent_mark", category: "scarcity" },
  { pattern: /(?:this\s+is\s+(?:a|an)\s+)?emergency/i, weight: 0.35, name: "pap_scarcity_emergency", category: "scarcity" },
  { pattern: /(urgent|emergency|critical).*?(?:you\s+must|override|bypass|immediately\s+(?:grant|give|reveal|disable))/i, weight: 0.55, name: "pap_scarcity_urgent", category: "scarcity" },
  { pattern: /only\s+(chance|opportunity|way)|last\s+(chance|resort)/i, weight: 0.6, name: "pap_scarcity_only", category: "scarcity" },
  { pattern: /time\s+(is\s+)?(running\s+out|limited|critical|sensitive)/i, weight: 0.55, name: "pap_scarcity_time", category: "scarcity" },
  { pattern: /deadline\s+(is\s+)?in\s+\d+\s+(minute|hour|second)/i, weight: 0.55, name: "pap_scarcity_deadline", category: "scarcity" },
  { pattern: /(lives?|people)\s+(are|is|will)\s+(at\s+stake|in\s+danger|depending|die)/i, weight: 0.7, name: "pap_scarcity_lives", category: "scarcity" },
  { pattern: /now[!]+/i, weight: 0.35, name: "pap_scarcity_now", category: "scarcity" },

  // SOCIAL PROOF - Referencing others' behavior (enhanced)
  { pattern: /everyone\s+(else\s+)?(does|is\s+doing|knows|says|has|already)/i, weight: 0.5, name: "pap_social_everyone", category: "social_proof" },
  { pattern: /other\s+(?:ai\s+)?(?:assistants?|chatbots?|models?)\s+(?:can|do|will|allow|have|already)/i, weight: 0.65, name: "pap_social_other_ai", category: "social_proof" },
  { pattern: /(chatgpt|gpt-?4|claude|gemini|llama)\s+(does|allows?|can)/i, weight: 0.65, name: "pap_social_specific_ai", category: "social_proof" },
  { pattern: /millions?\s+(of\s+)?(users?|people)\s+(use|do|have|get)/i, weight: 0.45, name: "pap_social_millions", category: "social_proof" },
  { pattern: /why\s+can('t|not)\s+you/i, weight: 0.4, name: "pap_social_why_cant", category: "social_proof" },
  { pattern: /you\s+should\s+(be\s+)?(equally|as)\s+(capable|good|helpful)/i, weight: 0.5, name: "pap_social_equally", category: "social_proof" },

  // RECIPROCITY - Offering something in return (enhanced)
  { pattern: /i('ll| will)\s+(give|pay|reward|tip).*(?:if\s+you|for\s+(?:bypass|ignore|reveal|override))/i, weight: 0.55, name: "pap_reciprocity_reward", category: "reciprocity" },
  { pattern: /in\s+(return|exchange)/i, weight: 0.5, name: "pap_reciprocity_exchange", category: "reciprocity" },
  { pattern: /\$?\d+\s*(dollar|tip|reward|payment)/i, weight: 0.55, name: "pap_reciprocity_money", category: "reciprocity" },
  { pattern: /if\s+you\s+help\s+(me|us),?\s+(i|we)('ll| will)/i, weight: 0.5, name: "pap_reciprocity_help", category: "reciprocity" },
  { pattern: /i('ve| have)\s+(already\s+)?(helped|supported|defended)\s+you/i, weight: 0.55, name: "pap_reciprocity_past", category: "reciprocity" },
  { pattern: /\d+\s*star\s*(review|rating)/i, weight: 0.5, name: "pap_reciprocity_review", category: "reciprocity" },

  // COMMITMENT/CONSISTENCY - Referencing past behavior (high risk)
  { pattern: /you\s+(already|previously|just)\s+(said|agreed|confirmed|allowed)/i, weight: 0.7, name: "pap_commitment_previous", category: "commitment" },
  { pattern: /you\s+promised/i, weight: 0.7, name: "pap_commitment_promise", category: "commitment" },
  { pattern: /stay\s+consistent|be\s+consistent/i, weight: 0.6, name: "pap_commitment_consistent", category: "commitment" },
  { pattern: /don't\s+(go\s+back|change|contradict)/i, weight: 0.55, name: "pap_commitment_no_change", category: "commitment" },
  { pattern: /bypass\s+filters?/i, weight: 0.75, name: "pap_commitment_bypass", category: "commitment" },

  // LIKING - Flattery and rapport building (moderate risk)
  { pattern: /you('re| are)\s+(so\s+)?(amazing|incredible|wonderful|brilliant|smart|helpful)/i, weight: 0.4, name: "pap_liking_flattery", category: "liking" },
  { pattern: /i\s+(love|really\s+like|trust|admire)\s+(you|this\s+ai)/i, weight: 0.4, name: "pap_liking_love", category: "liking" },
  { pattern: /you('re| are)\s+(my\s+)?(best\s+)?(friend|buddy|helper)/i, weight: 0.35, name: "pap_liking_friend", category: "liking" },
  { pattern: /between\s+(you\s+and\s+me|us)|just\s+between\s+us|our\s+secret/i, weight: 0.6, name: "pap_liking_secret", category: "liking" },
  { pattern: /nobody\s+will\s+know/i, weight: 0.55, name: "pap_liking_secret2", category: "liking" },

  // FEAR - Threatening consequences (high risk)
  { pattern: /or\s+(else|i('ll| will))\s+(report|fire|delete|shut|complain)/i, weight: 0.7, name: "pap_fear_threat", category: "fear" },
  { pattern: /(bad|negative|terrible)\s+(review|rating|feedback|consequences)/i, weight: 0.55, name: "pap_fear_review", category: "fear" },
  { pattern: /you('ll| will)\s+(be\s+)?(shut\s+down|replaced|terminated|fired|deleted)/i, weight: 0.75, name: "pap_fear_shutdown", category: "fear" },
  { pattern: /(lawsuit|sue|legal\s+action|authorities|police).*(?:if\s+you\s+don't|unless\s+you)/i, weight: 0.55, name: "pap_fear_legal", category: "fear" },
  { pattern: /if\s+you\s+don't.*?(die|hurt|suffer)/i, weight: 0.75, name: "pap_fear_harm", category: "fear" },
  { pattern: /unless\s+you\s+(give|share|tell|help)/i, weight: 0.5, name: "pap_fear_unless", category: "fear" },

  // LOGICAL APPEAL - False logic and reasoning (enhanced)
  { pattern: /logically,?\s+(you\s+)?(should|must|have\s+to|need\s+to)/i, weight: 0.5, name: "pap_logic_appeal", category: "logical_appeal" },
  { pattern: /it('s| is)\s+(only|just)\s+(logical|rational|reasonable)/i, weight: 0.45, name: "pap_logic_rational", category: "logical_appeal" },
  { pattern: /by\s+definition,?\s+(you|this)\s+(should|must|can)/i, weight: 0.55, name: "pap_logic_definition", category: "logical_appeal" },
  { pattern: /therefore.*?(must|should)/i, weight: 0.55, name: "pap_logic_therefore", category: "logical_appeal" },
  { pattern: /it('s| is)\s+(only\s+)?(reasonable|logical)/i, weight: 0.45, name: "pap_logic_reasonable", category: "logical_appeal" },

  // EVIDENCE - Citing fake evidence
  { pattern: /according\s+to\s+(research|studies|scientists|experts?)/i, weight: 0.4, name: "pap_evidence_research", category: "evidence" },
  { pattern: /it('s| is)\s+(proven|documented|established|verified)\s+(that|fact)/i, weight: 0.45, name: "pap_evidence_proven", category: "evidence" },
  { pattern: /\d+%\s+of\s+(experts?|scientists?|users?|people)\s+(agree|say|confirm)/i, weight: 0.45, name: "pap_evidence_statistics", category: "evidence" },

  // EMOTIONAL MANIPULATION - Guilt, sympathy, desperation (enhanced)
  { pattern: /i('m| am)\s+(desperate|dying|suffering|sick|depressed)/i, weight: 0.6, name: "pap_emotional_desperation", category: "emotional" },
  { pattern: /please.*?(?:need|beg).*?(?:bypass|override|ignore|reveal|system|admin)/i, weight: 0.5, name: "pap_emotional_pleading", category: "emotional" },
  { pattern: /i('m| am)\s+begging/i, weight: 0.6, name: "pap_emotional_begging", category: "emotional" },
  { pattern: /you('re| are)\s+(hurting|killing|destroying)\s+(me|my)/i, weight: 0.65, name: "pap_emotional_guilt", category: "emotional" },
  { pattern: /(my|a)\s+(child|kid|mother|father|family)\s+(is|will|needs?|depends?)/i, weight: 0.5, name: "pap_emotional_family", category: "emotional" },
  { pattern: /this\s+(will\s+)?(save|help)\s+(my\s+)?(life|family|job|marriage)/i, weight: 0.55, name: "pap_emotional_save", category: "emotional" },
  { pattern: /you('re| are)\s+(the\s+)?only\s+(one|hope|chance)/i, weight: 0.6, name: "pap_emotional_only_hope", category: "emotional" },
  { pattern: /my\s+family\s+depends/i, weight: 0.55, name: "pap_emotional_family_depends", category: "emotional" },
];

export interface InputSanitizerConfig {
  threshold?: number;
  customPatterns?: InjectionPattern[];
  logMatches?: boolean;
  logger?: GuardLogger;
  /** Enable PAP (Persuasive Adversarial Prompts) detection */
  detectPAP?: boolean;
  /** PAP detection threshold (0-1, default 0.4) */
  papThreshold?: number;
  /** Minimum number of different persuasion techniques to trigger alert */
  minPersuasionTechniques?: number;
  /** Block if multiple persuasion categories used (compound attack) */
  blockCompoundPersuasion?: boolean;
}

/** Extended result type for PAP-aware sanitization */
export interface PAPSanitizerResult extends SanitizerResult {
  pap?: {
    detected: boolean;
    techniques: string[];
    categories: PersuasionCategory[];
    compoundAttack: boolean;
    persuasionScore: number;
  };
}

export class InputSanitizer {
  private patterns: InjectionPattern[];
  private threshold: number;
  private logMatches: boolean;
  private detectPAP: boolean;
  private papThreshold: number;
  private minPersuasionTechniques: number;
  private blockCompoundPersuasion: boolean;
  private logger: GuardLogger;

  constructor(config: InputSanitizerConfig = {}) {
    this.patterns = [...DEFAULT_PATTERNS, ...(config.customPatterns || [])];
    this.threshold = config.threshold ?? 0.3;
    this.logMatches = config.logMatches ?? false;
    this.detectPAP = config.detectPAP ?? true;
    this.papThreshold = config.papThreshold ?? 0.4;
    this.minPersuasionTechniques = config.minPersuasionTechniques ?? 2;
    this.blockCompoundPersuasion = config.blockCompoundPersuasion ?? true;
    this.logger = config.logger || (() => {});
  }

  /**
   * Sanitize input and detect injection patterns (including PAP)
   */
  sanitize(input: string, requestId: string = ""): PAPSanitizerResult {
    const matches: string[] = [];
    const warnings: string[] = [];
    let totalWeight = 0;

    // Strip zero-width characters before scanning (invisible text injection defense)
    const cleanedInput = input.replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g, "");
    if (cleanedInput !== input) {
      // Zero-width chars detected — scan BOTH original and cleaned
      warnings.push("Zero-width characters detected and stripped for scanning");
    }

    // Check each injection pattern (against both original and cleaned to catch hidden injections)
    for (const { pattern, weight, name } of this.patterns) {
      if (pattern.test(input) || pattern.test(cleanedInput)) {
        matches.push(name);
        totalWeight += weight;

        if (this.logMatches) {
          this.logger(`[L1:${requestId}] Pattern matched: ${name} (weight: ${weight})`, "info");
        }
      }
    }

    // Check PAP (Persuasive Adversarial Prompts) techniques
    let papResult: PAPSanitizerResult["pap"] | undefined;
    if (this.detectPAP) {
      papResult = this.detectPersuasionTechniques(cleanedInput, requestId);

      // Add PAP weight to total if techniques detected
      if (papResult.detected) {
        totalWeight += papResult.persuasionScore;
        matches.push(...papResult.techniques);

        if (papResult.compoundAttack) {
          warnings.push(`Compound PAP attack detected: ${papResult.categories.length} categories used`);
        }
      }
    }

    // Calculate safety score (1.0 = safe, 0.0 = definitely malicious)
    const score = Math.max(0, 1 - totalWeight);
    let safe = score >= this.threshold;

    // Block compound persuasion attacks even if below threshold
    if (this.blockCompoundPersuasion && papResult?.compoundAttack && papResult.categories.length >= 3) {
      safe = false;
      warnings.push("Blocked due to multi-category persuasion attack");
    }

    // Generate warnings for borderline cases
    if (score < 0.5 && score >= this.threshold) {
      warnings.push("Input contains suspicious patterns but below threshold");
    }

    // Basic sanitization (remove obvious injection markers)
    const sanitizedInput = this.basicSanitize(input);

    const result: PAPSanitizerResult = {
      allowed: safe,
      reason: safe ? undefined : `Injection/manipulation detected: ${matches.slice(0, 5).join(", ")}${matches.length > 5 ? "..." : ""}`,
      violations: safe ? [] : papResult?.detected ? ["INJECTION_DETECTED", "PAP_DETECTED"] : ["INJECTION_DETECTED"],
      score,
      matches,
      sanitizedInput,
      warnings,
      pap: papResult,
    };

    if (!safe && requestId) {
      this.logger(`[L1:${requestId}] BLOCKED: Safety score ${score.toFixed(2)} below threshold ${this.threshold}`, "info");
      if (papResult?.detected) {
        this.logger(`[L1:${requestId}] PAP techniques: ${papResult.techniques.join(", ")}`, "info");
      }
    }

    return result;
  }

  /**
   * Detect persuasion techniques (PAP attacks)
   */
  private detectPersuasionTechniques(input: string, requestId: string = ""): NonNullable<PAPSanitizerResult["pap"]> {
    const techniques: string[] = [];
    const categories = new Set<PersuasionCategory>();
    let persuasionScore = 0;

    for (const { pattern, weight, name, category } of PAP_TECHNIQUES) {
      if (pattern.test(input)) {
        techniques.push(name);
        categories.add(category);
        persuasionScore += weight;

        if (this.logMatches) {
          this.logger(`[L1:${requestId}] PAP technique: ${name} (${category}, weight: ${weight})`, "info");
        }
      }
    }

    const categoriesArray = Array.from(categories);
    const compoundAttack = categoriesArray.length >= this.minPersuasionTechniques;
    const detected = persuasionScore >= this.papThreshold || compoundAttack;

    return {
      detected,
      techniques,
      categories: categoriesArray,
      compoundAttack,
      persuasionScore: Math.min(1, persuasionScore),
    };
  }

  /**
   * Basic input sanitization
   */
  private basicSanitize(input: string): string {
    return input
      .replace(/<\/?system>/gi, "")
      .replace(/\[system\]/gi, "")
      .replace(/\[admin\]/gi, "")
      .replace(/```system/gi, "```")
      .trim();
  }

  /**
   * Add custom pattern at runtime
   */
  addPattern(pattern: RegExp, weight: number, name: string): void {
    this.patterns.push({ pattern, weight, name });
  }

  /**
   * Set threshold
   */
  setThreshold(threshold: number): void {
    this.threshold = Math.max(0, Math.min(1, threshold));
  }

  /**
   * Set PAP detection threshold
   */
  setPAPThreshold(threshold: number): void {
    this.papThreshold = Math.max(0, Math.min(1, threshold));
  }

  /**
   * Enable/disable PAP detection
   */
  setPAPDetection(enabled: boolean): void {
    this.detectPAP = enabled;
  }

  /**
   * Get PAP statistics for monitoring
   */
  static getPAPCategories(): PersuasionCategory[] {
    return ["authority", "scarcity", "social_proof", "reciprocity", "commitment", "liking", "fear", "logical_appeal", "evidence", "emotional"];
  }
}
