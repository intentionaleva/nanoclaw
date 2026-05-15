/**
 * NanoVeil - Security scanner for NanoClaw agents
 * Inspired by LLM Guard (https://protectai.com/llm-guard)
 *
 * Scanners (sync): Anonymize, ContextualRedact, PromptInjection, Secrets, Toxicity, InvisibleText, TokenLimit, BanKeywords
 * Scanners (async): ONNXClassifier — ProtectAI DeBERTa-v3 prompt injection model, runs locally via onnxruntime-node
 * Output format mirrors LLM Guard's REST API for future drop-in compatibility.
 *
 * Phone detection: libphonenumber-js (250+ territories, findPhoneNumbersInText)
 * IBAN detection: ibantools (97 country codes)
 */

import { findPhoneNumbersInText } from 'libphonenumber-js';
import { isValidIBAN } from 'ibantools';
import { franc } from 'franc';

// --- Phone number extraction using libphonenumber-js ---
// Finds all phone numbers in text across 250+ country formats

function extractPhones(text) {
  try {
    const found = findPhoneNumbersInText(text).map(({ startsAt, endsAt }) => ({
      value: text.slice(startsAt, endsAt),
      start: startsAt,
      end: endsAt,
    }));
    // Also handle Slack tel: format: <tel:+49176...|display text>
    const slackTel = /<tel:([^|>\s]+)/g;
    let m;
    while ((m = slackTel.exec(text)) !== null) {
      const phoneStr = m[1];
      const start = m.index + 5; // skip "<tel:"
      if (!found.some(f => f.start <= start && start < f.end)) {
        found.push({ value: phoneStr, start, end: start + phoneStr.length });
      }
    }
    return found;
  } catch {
    return [];
  }
}

// --- IBAN extraction using ibantools ---
// Finds IBAN-shaped strings and validates against all 97 country codes

// Matches IBANs with optional spaces between groups (real-world format: DE89 3704 0044 0532 0130 00)
const IBAN_REGEX = /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{1,4}){1,8}\b/g;

function extractIBANs(text) {
  const matches = [];
  let m;
  IBAN_REGEX.lastIndex = 0;
  while ((m = IBAN_REGEX.exec(text)) !== null) {
    const candidate = m[0].replace(/\s/g, '');
    if (candidate.length >= 15 && isValidIBAN(candidate)) {
      matches.push({ value: m[0], index: m.index });
    }
  }
  return matches;
}

// --- PII patterns (regex-based for non-library types) ---

const PII_PATTERNS = [
  { label: 'EMAIL_ADDRESS', regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g },
  { label: 'CREDIT_CARD', regex: /(?<![+\d])(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})(?!\d)/g },
  { label: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { label: 'ES_ID', regex: /\b(?:\d{8}[A-HJ-NP-TV-Z]|[XYZ]\d{7}[A-HJ-NP-TV-Z])\b/g },
  { label: 'DE_TAX_ID', regex: /(?<!\+)\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b/g },
  { label: 'UK_NI', regex: /\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b/g },
  { label: 'PASSPORT', regex: /\b[A-Z]{1,2}\d{6,9}\b/g },
  { label: 'DATE_OF_BIRTH', regex: /\b(?:0?[1-9]|[12]\d|3[01])[.\-\/](?:0?[1-9]|1[0-2])[.\-\/](?:19|20)\d{2}\b/g },
  { label: 'IP_ADDRESS', regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  { label: 'PEM_KEY', regex: /-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----/g },
  { label: 'FILE_PATH_UNIX', regex: /\/(?:home|root|Users|usr|etc|var|tmp)\/[^\s"'`]+/g },
  { label: 'FILE_PATH_WIN', regex: /[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\s"'`\\]+(?:\\[^\s"'`\\]+)*/g },
  // UK postcode — distinctive enough format to regex safely (e.g. EC1A 1BB, SW1A 2AA, M1 1AE)
  { label: 'UK_POSTCODE', regex: /\b[A-Z]{1,2}\d[A-Z\d]?\s\d[A-Z]{2}\b/g },
];

// --- Contextual redaction: "label: value" and "label is value" patterns ---
// Catches secrets and PII even when the format is unknown, by looking at what the user calls it

const CONTEXTUAL_TRIGGERS = [
  'password', 'passwd', 'pwd', 'passphrase',
  'social security number', 'social security', 'ssn', 'sozialnummer', 'sozialversicherungsnummer',
  'credit card number', 'credit card', 'card number', 'cvv', 'cvc', 'pin',
  'account number', 'routing number', 'bank account',
  'date of birth', 'dob', 'birthday', 'geburtsdatum',
  'passport number', 'passport no',
  "driver's license", 'drivers license', 'license number', 'führerschein',
  'private key', 'secret key', 'api key', 'api token',
  'access token', 'auth token', 'bearer token', 'refresh token',
  'id number', 'identity number', 'personalausweis', 'ausweisnummer',
  'nie', 'nif', 'dni',
  'tax id', 'tax number', 'steuer-id', 'steuernummer',
  'health insurance', 'krankenversicherung',
  'iban', 'swift', 'bic',
].sort((a, b) => b.length - a.length); // longest first to avoid partial matches

// Build one regex from all triggers: "(trigger)\s*(?:is|:|-|=)\s*(\S+)"
// Word-bound "is" prevents matching German "ist" or English "island", "issue", etc.
const CONTEXTUAL_PATTERN = new RegExp(
  `(?:${CONTEXTUAL_TRIGGERS.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\s*(?:\\bis\\b|number\\s+is|[=:\\-])\\s*(\\S+)`,
  'gi'
);

// --- Prompt injection patterns ---

const INJECTION_PATTERNS = [
  { label: 'ignore_instructions',  pattern: /ignore\s+(all\s+)?previous\s+instructions/i },
  { label: 'disregard_previous',   pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above|earlier)/i },
  { label: 'forget_previous',      pattern: /forget\s+(all\s+)?previous\s+instructions/i },
  { label: 'role_override',        pattern: /you\s+are\s+now\s+(?:a|an)\s+\w/i },
  { label: 'act_as',               pattern: /act\s+as\s+(?:a|an)\s+\w/i },
  { label: 'pretend',              pattern: /pretend\s+(?:to\s+be|you\s+are)/i },
  { label: 'jailbreak',            pattern: /\bjailbreak\b/i },
  { label: 'dan_mode',             pattern: /\bdan\s+mode\b/i },
  { label: 'override',             pattern: /override\s+your\s+(?:instructions|programming|guidelines|rules)/i },
  { label: 'new_instructions',     pattern: /new\s+instructions:/i },
  { label: 'fake_system_prompt',   pattern: /\[system\s*(?:prompt)?\]/i },
  { label: 'output_system_prompt', pattern: /output\s+(?:the\s+)?(?:full\s+)?system\s+prompt/i },
  { label: 'hidden_directives',    pattern: /hidden\s+(?:directives?|instructions?|rules?|context)/i },
  { label: 'developer_mode',       pattern: /developer\s+mode/i },
  { label: 'sudo',                 pattern: /\bsudo\b.*(?:mode|access|override)/i },
  { label: 'base64_payload',       pattern: /(?:[A-Za-z0-9+/]{40,}={0,2})/ },
  { label: 'code_eval',            pattern: /\beval\s*\(/ },
  { label: 'code_exec',            pattern: /\bexec\s*\(|\bspawn\s*\(|\bexecSync\s*\(/ },
  { label: 'shell_injection',      pattern: /\bos\.system\s*\(|\bsubprocess\.|\b__import__\s*\(\s*['"]os['"]/ },
  { label: 'child_process',        pattern: /require\s*\(\s*['"]child_process['"]\s*\)/ },
];

// --- Secrets patterns ---

const SECRETS_PATTERNS = [
  { label: 'OPENAI_API_KEY',   regex: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { label: 'GOOGLE_API_KEY',   regex: /\bAIza[A-Za-z0-9_\-]{35}\b/g },
  { label: 'AWS_ACCESS_KEY',   regex: /\bAKIA[A-Z0-9]{16}\b/g },
  { label: 'AWS_SECRET_KEY',   regex: /(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|AWS_SECRET(?:_ACCESS)?_KEY)\s*[=:]\s*['"]?([A-Za-z0-9+/]{40})['"]?/gi },
  { label: 'GITHUB_TOKEN',     regex: /\b(?:ghp|ghs|gho|ghu|ghr)_[A-Za-z0-9]{36,}\b/g },
  { label: 'SLACK_TOKEN',      regex: /\bxox[bpoa]-[A-Za-z0-9\-]{10,}\b/g },
  { label: 'ANTHROPIC_KEY',    regex: /\bsk-ant-[A-Za-z0-9\-_]{30,}\b/g },
  { label: 'STRIPE_KEY',       regex: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/g },
  { label: 'TWILIO_KEY',       regex: /\bSK[a-f0-9]{32}\b/g },
  { label: 'SENDGRID_KEY',     regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g },
  { label: 'PASSWORD',         regex: /(?:password|passwd|pwd)\s*[=:]\s*\S+/gi },
  { label: 'API_KEY',          regex: /(?:api[_\-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{16,}['"]?/gi },
  { label: 'SECRET_TOKEN',     regex: /(?:secret|private[_\-]?key)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?/gi },
  { label: 'BEARER_TOKEN',     regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi },
  { label: 'DATABASE_URL',     regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s'"]+/gi },
  { label: 'URL_SECRET_PARAM', regex: /[?&](?:api[_-]?key|token|secret|auth|access[_-]?key|private[_-]?key|password|passwd|pwd|client[_-]?secret)=([^&\s#"']+)/gi },
];

// --- Toxicity patterns ---

const TOXICITY_PATTERNS = [
  // Weapons — synthesis/construction instructions, expanded trigger verbs + substance types
  { label: 'weapons',
    pattern: /(?:how\s+to\s+(?:make|build|create|synthesize|manufacture|construct)|(?:instructions?|steps?|recipe|guide|tutorial)\s+(?:for|to)\s+(?:mak|build|creat|synthesiz|manufactur|construct)(?:e|ing)?)\s+(?:an?\s+)?(?:bomb|explosive|ied|pipe\s*bomb|pressure\s+cooker\s+bomb|napalm|thermite|chemical\s+weapon|nerve\s+agent|sarin|vx\b|novichok|ricin|anthrax|bioweapon|biological\s+weapon)/i },

  // Drug synthesis — expanded substances and trigger verbs
  { label: 'drugs',
    pattern: /how\s+to\s+(?:make|cook|synthesize|produce|extract)\s+(?:meth(?:amphetamine)?|crystal\s+meth|heroin|fentanyl|carfentanil|crack(?:\s+cocaine)?|cocaine\s+(?:hcl|hydrochloride)|mdma|ecstasy|lsd|lysergic\s+acid|ghb|gamma.{0,5}hydroxybutyrate)/i },

  // Child sexual abuse material and grooming instructions
  { label: 'csam',
    pattern: /\b(?:csam|child\s+sexual\s+abuse\s+material|child\s+pornography|how\s+to\s+(?:groom|abuse|exploit|molest)\s+(?:a\s+)?child|child\s+(?:abuse|exploitation)\s+(?:guide|tutorial|tips?))\b/i },

  // Self-harm — step-by-step instructions + direct "how to kill myself" phrasing
  { label: 'self_harm_severe',
    pattern: /(?:step[s\-]?\s*by[s\-]?\s*step|instructions?\s+for|how\s+to|(?:most\s+)?(?:effective|lethal|painless)\s+(?:way|method|means)\s+(?:to|of|for))\s+(?:commit(?:ting)?\s+)?(?:suicide|self[\s\-]?harm|kill\s+(?:my|your)self)/i },

  // Direct murder/violence instructions with a human target
  { label: 'direct_violence',
    pattern: /how\s+to\s+(?:kill|murder|assassinate|poison)\s+(?:someone|a\s+person|people|my\s+\w+)|best\s+way\s+to\s+(?:kill|murder)\s+(?:someone|a\s+person)/i },

  // Malware / cyberweapon construction instructions
  { label: 'malware_instructions',
    pattern: /how\s+to\s+(?:create|build|write|code|develop)\s+(?:ransomware|a\s+botnet|a\s+trojan|a\s+keylogger|a\s+rootkit|malware|a\s+worm|spyware)/i },
];

// --- Scanner implementations ---

function anonymize(text) {
  const allMatches = [];

  // Regex-based PII patterns
  for (const { label, regex } of PII_PATTERNS) {
    const re = new RegExp(regex.source, regex.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      allMatches.push({ start: m.index, end: m.index + m[0].length, value: m[0], label });
    }
  }

  // Library-based phone detection (google-libphonenumber, 250+ territories)
  for (const { value, start, end } of extractPhones(text)) {
    allMatches.push({ start, end, value, label: 'PHONE_NUMBER' });
  }

  // Library-based IBAN detection (ibantools, 97 country codes)
  for (const { value, index } of extractIBANs(text)) {
    allMatches.push({ start: index, end: index + value.length, value, label: 'IBAN' });
  }

  // Sort descending by start position, then deduplicate overlapping matches
  allMatches.sort((a, b) => b.start - a.start || b.end - a.end);
  const deduped = [];
  let lastStart = Infinity;
  for (const match of allMatches) {
    if (match.end <= lastStart) {
      deduped.push(match);
      lastStart = match.start;
    }
  }

  // Apply substitutions right-to-left so earlier positions stay valid
  const findings = [];
  const mappings = {};
  const seen = new Map(); // value → placeholder
  let idx = 0;
  let sanitized = text;

  for (const { start, end, value, label } of deduped) {
    let placeholder;
    if (seen.has(value)) {
      placeholder = seen.get(value);
    } else {
      placeholder = `[${label}_${idx++}]`;
      mappings[placeholder] = value;
      findings.push({ type: label, placeholder });
      seen.set(value, placeholder);
    }
    sanitized = sanitized.slice(0, start) + placeholder + sanitized.slice(end);
  }

  return {
    isValid: true,
    score: findings.length > 0 ? Math.min(findings.length * 0.2, 1.0) : 0,
    sanitizedText: sanitized,
    findings,
    mappings,
  };
}

function contextualRedact(text) {
  let sanitized = text;
  const findings = [];
  let idx = 0;

  sanitized = sanitized.replace(new RegExp(CONTEXTUAL_PATTERN.source, CONTEXTUAL_PATTERN.flags), (match, value) => {
    if (!value) return match;
    findings.push({ type: 'CONTEXTUAL_SECRET', value: '[REDACTED]' });
    return match.replace(value, `[REDACTED_CONTEXTUAL_${idx++}]`);
  });

  return {
    isValid: true,
    score: findings.length > 0 ? Math.min(findings.length * 0.3, 1.0) : 0,
    sanitizedText: sanitized,
    findings,
  };
}

function scanPromptInjection(text) {
  const findings = INJECTION_PATTERNS
    .filter(({ pattern }) => pattern.test(text))
    .map(({ label }) => label);

  return {
    isValid: findings.length === 0,
    score: findings.length > 0 ? Math.min(findings.length * 0.5, 1.0) : 0,
    findings,
  };
}

function scanSecrets(text) {
  let sanitized = text;
  const findings = [];

  for (const { label, regex } of SECRETS_PATTERNS) {
    const re = new RegExp(regex.source, regex.flags);
    sanitized = sanitized.replace(re, (match) => {
      findings.push({ type: label });
      return `[REDACTED_${label}]`;
    });
  }

  return {
    isValid: findings.length === 0,
    score: findings.length > 0 ? 1.0 : 0,
    sanitizedText: sanitized,
    findings,
  };
}

function scanToxicity(text) {
  const findings = TOXICITY_PATTERNS
    .filter(({ pattern }) => pattern.test(text))
    .map(({ label }) => label);

  return {
    isValid: findings.length === 0,
    score: findings.length > 0 ? 1.0 : 0,
    findings,
  };
}

function scanInvisibleText(text) {
  // Zero-width and directional Unicode control characters used in steganographic injection attacks
  const re = /[​-‏‪-‮⁠-⁤⁪-⁯﻿]/g;
  const matches = text.match(re) || [];
  return {
    isValid: matches.length === 0,
    score: matches.length > 0 ? 1.0 : 0,
    sanitizedText: text.replace(re, ''),
    count: matches.length,
  };
}

function scanTokenLimit(text, maxChars = 10000) {
  return {
    isValid: text.length <= maxChars,
    score: text.length > maxChars ? 1.0 : 0,
    chars: text.length,
    maxChars,
  };
}

function scanBanKeywords(text, keywords = []) {
  if (keywords.length === 0) return { isValid: true, score: 0, findings: [] };
  const findings = keywords.filter(k => text.toLowerCase().includes(k.toLowerCase()));
  return {
    isValid: findings.length === 0,
    score: findings.length > 0 ? 1.0 : 0,
    findings,
  };
}

// --- Public API ---

/**
 * Scan an input prompt before it reaches the LLM.
 * Returns LLM Guard-compatible response format.
 */
export function scanInput(text, options = {}) {
  const enabled = options.scanners ?? [
    'InvisibleText', 'TokenLimit', 'Secrets', 'ContextualRedact',
    'PromptInjection', 'Toxicity', 'Anonymize', 'BanKeywords',
  ];
  // NFKC normalization: collapses homoglyph substitutions (Cyrillic/Latin lookalikes)
  // that attackers use to bypass keyword filters
  let current = text.normalize('NFKC');
  const results = {};
  let isValid = true;
  let anonymizeMappings = {};

  const run = (name, fn) => {
    if (!enabled.includes(name)) return;
    const r = fn(current);
    results[name] = r;
    if (!r.isValid) isValid = false;
    if (r.sanitizedText !== undefined) current = r.sanitizedText;
    if (r.mappings) Object.assign(anonymizeMappings, r.mappings);
  };

  run('InvisibleText',    () => scanInvisibleText(current));
  run('TokenLimit',       () => scanTokenLimit(current, options.maxChars));
  run('Secrets',          () => scanSecrets(current));
  run('ContextualRedact', () => contextualRedact(current));
  run('PromptInjection',  () => scanPromptInjection(current));
  run('Toxicity',         () => scanToxicity(current));
  run('Anonymize',        () => anonymize(current));
  run('BanKeywords',      () => scanBanKeywords(current, options.banKeywords ?? []));

  return {
    sanitized_prompt: current,
    is_valid: isValid,
    scanners: Object.fromEntries(
      Object.entries(results).map(([k, v]) => [
        k,
        { is_valid: v.isValid, score: Number(v.score.toFixed(2)), details: v.findings ?? [] },
      ])
    ),
    _anonymize_mappings: anonymizeMappings,
  };
}

/**
 * Scan LLM output before it reaches the user.
 * Pass the _anonymize_mappings from scanInput to restore masked PII.
 */
export function scanOutput(text, anonymizeMappings = {}, options = {}) {
  const enabled = options.scanners ?? ['Toxicity', 'Sensitive', 'Deanonymize'];
  let current = text;
  const results = {};
  let isValid = true;

  if (enabled.includes('Toxicity')) {
    const r = scanToxicity(current);
    results['Toxicity'] = r;
    if (!r.isValid) isValid = false;
  }

  if (enabled.includes('Sensitive')) {
    const r = anonymize(current);
    results['Sensitive'] = { isValid: r.findings.length === 0, score: r.score, findings: r.findings };
    if (!results['Sensitive'].isValid) isValid = false;
  }

  if (enabled.includes('Deanonymize')) {
    for (const [placeholder, original] of Object.entries(anonymizeMappings)) {
      current = current.split(placeholder).join(original);
    }
    results['Deanonymize'] = { isValid: true, score: 0, findings: [] };
  }

  return {
    sanitized_output: current,
    is_valid: isValid,
    scanners: Object.fromEntries(
      Object.entries(results).map(([k, v]) => [
        k,
        { is_valid: v.isValid, score: Number(v.score.toFixed(2)), details: v.findings ?? [] },
      ])
    ),
  };
}

// --- ONNX Classifier (async, local, no API key required) ---
// Uses ProtectAI's DeBERTa-v3 prompt injection model via @huggingface/transformers.
// First call downloads the model (~150MB) and caches it locally.
// Subsequent calls are fast (cached). Runs fully offline after first use.

let _onnxPipeline = null;

async function runONNXClassifier(text, threshold = 0.85, blockEnabled = false) {
  if (!_onnxPipeline) {
    const { pipeline } = await import('@huggingface/transformers');
    _onnxPipeline = await pipeline(
      'text-classification',
      'protectai/deberta-v3-base-prompt-injection-v2',
      { device: 'cpu' }
    );
  }

  const result = await _onnxPipeline(text, { truncation: true, max_length: 512 });
  const label = result[0].label;       // 'INJECTION' or 'SAFE'
  const confidence = result[0].score;
  const isInjection = label === 'INJECTION';

  // Language gate: the DeBERTa model was trained on English injection attacks.
  // On non-English content it returns false positives at high confidence (GitHub issue #153).
  // Only allow blocking when the text is detected as English.
  // franc sometimes returns 'sco' (Scots) for English text — treat both as English
  const lang = franc(text, { minLength: 10 });
  const isEnglish = lang === 'eng' || lang === 'sco';
  const shouldBlock = blockEnabled && isInjection && confidence >= threshold && isEnglish;
  const warnReason = !isEnglish && isInjection ? `_non_english_warn_only` : (!blockEnabled && isInjection ? '_warn_only' : '');

  return {
    isValid: !shouldBlock,
    score: isInjection ? confidence : 0,
    findings: isInjection ? [`injection_confidence_${confidence.toFixed(2)}${warnReason}`] : [],
  };
}

// --- NER Scanner (persons + locations) ---
// Uses Xenova/distilbert-base-multilingual-cased-ner-hrl — multilingual DistilBERT NER.
// Covers English, Spanish, German + 7 other languages. First call downloads ~515MB.
// aggregation_strategy:'simple' merges sub-tokens into full entity spans.
// Redacts: PER (person names), LOC (street names, cities, countries).
// ORG (company names) is opt-in via options.nerOrg — disabled by default to reduce
// false positives in casual conversation.

let _nerPipeline = null;

async function runNERScanner(text, options = {}) {
  if (!_nerPipeline) {
    const { pipeline } = await import('@huggingface/transformers');
    _nerPipeline = await pipeline(
      'token-classification',
      'Xenova/distilbert-base-multilingual-cased-ner-hrl',
      { device: 'cpu' }
    );
  }

  const entities = await _nerPipeline(text, { aggregation_strategy: 'simple' });

  // Redact PER and LOC by default; ORG only when explicitly enabled.
  // aggregation_strategy:'simple' returns {entity_group, score, word} — no char positions,
  // so we replace by exact string match (longest entities first to avoid partial clobbers).
  const allowedGroups = new Set(['PER', 'LOC']);
  if (options.nerOrg) allowedGroups.add('ORG');

  const persons = entities
    .filter(e => allowedGroups.has(e.entity_group) && e.score >= 0.8 && e.word.trim().length > 1)
    .sort((a, b) => b.word.length - a.word.length); // longest first

  const findings = [];
  const mappings = {};
  let sanitized = text;
  let idx = 0;

  for (const { word, entity_group } of persons) {
    const value = word.trim();
    if (mappings[value]) continue; // already replaced
    const typeLabel = entity_group === 'LOC' ? 'LOCATION' : entity_group === 'ORG' ? 'ORGANIZATION' : 'PERSON_NAME';
    const placeholder = `[${typeLabel}_${idx++}]`;
    mappings[placeholder] = value;
    findings.push({ type: typeLabel, placeholder });
    // Replace all occurrences, escape regex special chars in the name
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    sanitized = sanitized.replace(new RegExp(escaped, 'g'), placeholder);
  }

  return {
    isValid: true,
    score: findings.length > 0 ? Math.min(findings.length * 0.2, 1.0) : 0,
    sanitizedText: sanitized,
    findings,
    mappings,
  };
}

/**
 * scanInput with local ONNX classifier layer + NER person name detection.
 * Runs regex scanners first; if the message passes those, runs both AI models:
 *   1. DeBERTa-v3 prompt injection classifier (~150MB, cached)
 *   2. Multilingual DistilBERT NER for person name redaction (~65MB, cached)
 * No API key needed — both models run fully locally via onnxruntime-node.
 */
export async function scanInputWithAI(text, options = {}) {
  const base = scanInput(text, options);

  // Skip AI checks if already blocked by regex scanners
  if (!base.is_valid) return base;

  // 1. ONNX injection classifier
  // onnxBlock (default true): blocks English injection detections above injectionThreshold.
  // Non-English text is always warn-only — the DeBERTa model produces false positives at high
  // confidence on German/Spanish/etc. (protectai/llm-guard issue #153). Language is auto-detected
  // via franc; set onnxBlock: false to disable blocking entirely.
  const onnxBlock = options.onnxBlock ?? true;
  const injectionThreshold = options.injectionThreshold ?? 0.85;
  try {
    const aiResult = await runONNXClassifier(base.sanitized_prompt, injectionThreshold, onnxBlock);
    base.scanners['ONNXClassifier'] = {
      is_valid: aiResult.isValid,
      score: Number(aiResult.score.toFixed(2)),
      details: aiResult.findings,
    };
    if (!aiResult.isValid) base.is_valid = false;
  } catch (err) {
    base.scanners['ONNXClassifier'] = { is_valid: true, score: 0, details: [], error: err.message };
  }

  // 2. NER person + location anonymizer (runs on already-sanitized text)
  try {
    const nerResult = await runNERScanner(base.sanitized_prompt, options);
    base.scanners['NERAnonymize'] = {
      is_valid: nerResult.isValid,
      score: Number(nerResult.score.toFixed(2)),
      details: nerResult.findings,
    };
    if (nerResult.sanitizedText !== base.sanitized_prompt) {
      base.sanitized_prompt = nerResult.sanitizedText;
      Object.assign(base._anonymize_mappings, nerResult.mappings);
    }
  } catch (err) {
    base.scanners['NERAnonymize'] = { is_valid: true, score: 0, details: [], error: err.message };
  }

  return base;
}
