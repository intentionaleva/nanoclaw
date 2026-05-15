# NanoVeil

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

Data protection for NanoClaw agents. Replaces PII, credentials, and secrets with
placeholders before the message text is processed — keeping them out of API logs,
training pipelines, and any upstream system.

---

## Table of contents

- [How it works](#how-it-works-as-a-skill)
- [What it protects](#what-it-protects)
- [What it catches](#what-it-catches)
- [What it does NOT catch](#what-it-does-not-catch)
- [First run: model download](#first-run-model-download)
- [Installation](#installation)
- [Roadmap](#roadmap)
- [Confidence and scope](#confidence-and-scope)

---

## How it works as a skill

Once installed, NanoVeil runs automatically on every message. There are no commands to
invoke.

**Before → after:**

```
User sends:  "Draft a payment confirmation for Maria Santos, IBAN DE89370400440532013000,
              email maria@example.com."

Agent sees:  "Draft a payment confirmation for [PERSON_NAME_0], IBAN [IBAN_0],
              email [EMAIL_ADDRESS_1]."

Agent drafts: "Dear [PERSON_NAME_0], your payment has been received. A confirmation
               has been sent to [EMAIL_ADDRESS_1]. Reference: [IBAN_0]."

User sees:   "Dear Maria Santos, your payment has been received. A confirmation
              has been sent to maria@example.com. Reference: DE89370400440532013000."
```

The raw PII never appears inline in the message text Claude processes. API logs,
training pipelines, and upstream services only ever receive the sanitized version.
The agent works with placeholders and its response has real values restored before
reaching the user — so the output is still useful.

> **Note on LLM-opacity:** The scan tooling passes a mappings vault through the agent's
> context, so the model technically has access to original values via that route. For
> stronger protection where the model cannot access original values at all, see
> [Roadmap](#roadmap).

---

## What it protects

A user uploads a document containing a name, address, bank account number, and email.
NanoVeil replaces each piece with a placeholder before the message text is processed.
API logs, third-party providers, and training pipelines upstream only ever see the
sanitized version. When the agent responds, NanoVeil restores the original values so
the reply makes sense to the user.

That is the primary use case: **keep your data out of upstream systems.**

---

## What it catches

### PII (redacts, then restores in the response)

| Type | Coverage |
|---|---|
| Email addresses | All formats |
| Phone numbers | 250+ country formats |
| IBANs | 97 countries |
| Credit card numbers | Luhn-validated |
| Social Security Numbers | US format |
| IP addresses | IPv4 and IPv6 |
| Passport numbers | Multiple country formats |
| UK postcodes | Pattern match |
| National IDs | Spanish DNI (others via NER) |
| Person names | Multilingual NER (EN/ES/DE + 7 languages) |
| Addresses / locations | City and location names via NER |
| File paths | Unix and Windows |
| Dates of birth | Common formats |

### Secrets (blocks the message outright)

API keys and tokens from 20+ providers: AWS, Anthropic, OpenAI, GitHub, Stripe, Slack,
Twilio, Google, and more. Also: database connection strings (PostgreSQL, MySQL, MongoDB,
Redis), bearer tokens, and private key headers.

### Prompt injection (blocks)

Regex patterns for jailbreaks, role-override attempts ("ignore all previous instructions",
"you are now DAN"), and system-prompt disclosure requests — plus a DeBERTa-v3 ONNX
classifier for subtler English-language injection.

### Invisible text (blocks)

Zero-width Unicode characters used to embed hidden payloads in otherwise normal-looking
messages.

### Harmful content — WIP, basic coverage (blocks)

Regex patterns for weapons synthesis, drug production, CSAM, severe self-harm instructions,
direct violence instructions, and malware creation requests. **This is a first-filter for
multi-user deployments** (schools, customer service bots, platforms where the agent operator
controls who can send messages). It can be bypassed by rephrasing and is not a replacement
for model-level safety. For individual use, this scanner adds little value.

---

## What it does NOT catch

- **House numbers in street addresses** — NER detects city and location names but not
  "12" in "Calle Mayor 12, Madrid". The city is caught; the street number is not.
- **Non-UK postal codes** — German and Spanish 5-digit codes look too much like other
  numbers to pattern-match without false positives. UK postcodes are matched.
- **Organization names** — Off by default (too many false positives in normal business
  context). Enable with `--ner-org true` if you need it.
- **Non-English prompt injection** — The ONNX classifier is calibrated for English.
  Non-English input is flagged but not blocked. Regex-based injection patterns still apply.
- **Attached files** — Only message text is scanned. If a user pastes document text into
  a message, that text is scanned. Binary file attachments and their metadata are not.
- **Toxicity bypass** — The harmful content filter can be circumvented by paraphrasing.
  It catches direct phrasing, not intent.

---

## First run: model download

NanoVeil downloads two ONNX models on first use:

- DeBERTa-v3 prompt injection classifier: **705 MB**
- DistilBERT multilingual NER: **515 MB**
- **Total: ~1.2 GB**

Both are cached locally after that. All inference runs fully offline — no data leaves
your machine for model calls.

The download happens automatically the first time a message is scanned. On a typical
connection this takes 2-5 minutes. Subsequent runs use the local cache.

---

## Installation

**1. Copy the skill files** into your NanoClaw agent's workspace:

```bash
cp -r nanoveil/ /path/to/your/agent/nanoveil/
```

**2. Install dependencies:**

```bash
cd /path/to/your/agent/nanoveil
npm install
```

The two ONNX packages (`@huggingface/transformers`, `onnxruntime-node`) are listed as
optional. Without them, NanoVeil falls back to regex and pattern-matching only — no NER
name/location detection, no AI-based injection classification. To include the full AI
layer:

```bash
npm install --include=optional
```

**3. Add the skill** — copy `skill.md` into your agent's skills configuration so the agent
reads and applies it on every turn.

Node.js 18 or higher required.

---

## Roadmap

**v1.1 — Operator entity configuration:** Allow agent operators to exclude specific entity
types from scanning at the skill configuration level. For example, a workflow that genuinely
needs the LLM to reason about IBANs (bank lookup, validation) could disable IBAN redaction
while keeping all other scanners active. This follows the operator-level configuration
pattern used by LLM Guard — exclusions are set in config, not per-message by users.

**v1.2 — Faker replacements:** Instead of opaque placeholders like `[EMAIL_ADDRESS_1]`,
replace PII with realistic fake values (`fake_elena@webmail.de`, `+49 30 12345678`). The LLM
reasons naturally with plausible data; the vault maps fake→real for output restoration. Uses
`@faker-js/faker` (7M weekly downloads, locale-aware for DE/ES/FR and others).

**v2 — LLM-opacity (platform hooks):** Currently, NanoVeil runs as a skill inside the
agent — the scanner is local and offline, but the vault (mappings of placeholder → original
value) passes through the agent's context. This means the LLM technically has access to
original values, which is a weaker guarantee than server-side tools like LLM Guard where
the vault never enters the LLM's context at all.

Full LLM-opacity requires NanoClaw platform-level message hooks:
`process_message_before_context` (intercept before the LLM sees the message) and
`process_response_before_send` (restore PII after the LLM responds, before the user sees it).
When that capability is available in NanoClaw, NanoVeil will be upgraded to use it.

---

## Confidence and scope

NanoVeil is well-suited for: protecting personal PII in everyday workflows, preventing
accidental credential leaks, catching common injection attempts in English.

It is not a complete data-loss-prevention system and does not claim to be. The gaps above
are real. For regulated industries (healthcare, finance) with strict DLP requirements,
treat NanoVeil as one layer in a defence-in-depth stack, not a standalone compliance tool.

---

## License

MIT. See `LICENSE`.
