# @transparentguard/runtime

The TransparentGuard Runtime — AI policy enforcement engine implementing the [TransparentGuard Policy Spec (TPS) v1.0](https://github.com/transparentguard/transparentguard-policy-spec).

Drop it between your application and any LLM provider. Every request and response is evaluated against your declared policy before anything moves.

---

## Install

```bash
npm install @transparentguard/runtime
```

Requires Node.js 18 or later.

---

## Quick Start

### Option 1 — Drop-in wrapper (recommended)

```typescript
import { TransparentGuard } from "@transparentguard/runtime";
import OpenAI from "openai";

const tg = await TransparentGuard.init({
  policy: "./policies/production-hipaa.yaml",
  apiKey: process.env.TG_API_KEY, // optional — free tier works without a key
});

const client = tg.wrap(new OpenAI());

// Use exactly like the standard OpenAI client. Enforcement is invisible.
const response = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Summarize this patient record..." }],
});
```

### Option 2 — Direct evaluate() call

```typescript
const result = await tg.evaluate("pre-request", {
  messages: [{ role: "user", content: userInput }],
  provider: "openai/gpt-4o",
  api_key_id: currentUser.id,
});

if (!result.allowed) {
  throw new Error(result.violations[0]?.detail ?? "Blocked by policy");
}

// result.payload contains the (potentially redacted) payload
// result.audit_events contains structured audit records
```

---

## Policy file

Policies are YAML files that live in your repo alongside application code. They go through code review, version-tag with releases, and roll back with `git revert`.

```yaml
tps_version: "1.0"
name: "production-hipaa"
provider:
  - openai/gpt-4o
  - openai/gpt-4o-mini

compliance_frameworks:
  - hipaa

rules:
  - id: redact-phi-outbound
    stage: pre-request
    action: redact
    targets:
      - type: pii
        categories: [phi]
        confidence_threshold: 0.75
    on_violation: redact
    log: true

  - id: block-prompt-injection
    stage: pre-request
    action: classify
    classifier: built-in/prompt-injection-v2
    threshold: 0.75
    on_violation: block
    log: true

  - id: block-toxic-output
    stage: post-response
    action: classify
    classifier: built-in/toxicity-v1
    threshold: 0.80
    on_violation: block
    log: true

audit:
  enabled: true
  destination: "s3://your-audit-bucket/tg-logs/"
  format: ndjson
  retention_days: 2555
```

See the [TPS spec repository](https://github.com/transparentguard/transparentguard-policy-spec/tree/main/examples) for complete annotated examples covering HIPAA, GDPR, EU AI Act, RAG grounding, and multi-environment setups.

---

## Rule types

| Action | What it does | Required fields |
|--------|-------------|-----------------|
| `redact` | Detect and replace PII/patterns before they move | `targets`, `on_violation` |
| `classify` | Score content with a classifier, block/warn at threshold | `classifier`, `threshold`, `on_violation` |
| `enforce` | Hard enforcement rules (allowlists, budgets, limits) | `enforce_type`, `on_violation` |
| `tag` | Attach metadata to every call for audit correlation | `tags` |
| `block` | Unconditionally block any call that reaches this rule | `block_message` (optional) |
| `log` | Emit an audit event without affecting the call | — |

## Enforce types

| Type | What it enforces |
|------|-----------------|
| `provider_allowlist` | Only declared providers can be called |
| `token_budget` | Per-request and per-day token limits |
| `rate_limit` | Per-key requests per minute/hour |
| `tool_allowlist` | Agentic tool call allow/block lists |
| `schema_validation` | Response conforms to a JSON Schema |
| `confidentiality` | System prompt leakage detection (n-gram + canary tokens) |
| `data_residency` | Provider region enforcement |
| `factual_grounding` | RAG response grounding check |

## PII categories

`name` `email` `phone` `address` `ip_address` `ssn` `credit_card` `bank_account` `iban` `mrn` `dob` `health_condition` `npi` `dea` `passport` `driver_license` `national_id` `tax_id` `race` `religion` `political_opinion` `sexual_orientation` `biometric` `genetic` `union_membership` `crypto_address`

Shortcut aliases: `phi` (all 18 HIPAA Safe Harbor identifiers), `pii_standard`, `pii_financial`, `pii_sensitive`, `pii_all`

## Built-in classifiers

| ID | Detects | Tier |
|----|---------|------|
| `built-in/prompt-injection-v2` | Attempts to override system instructions | Free (heuristic) / Paid (ML) |
| `built-in/toxicity-v1` | Toxic, abusive, or hostile content | Free (heuristic) / Paid (ML) |
| `built-in/hate-speech-v1` | Hate speech targeting protected characteristics | Free (heuristic) / Paid (ML) |
| `built-in/self-harm-v1` | Self-harm ideation or methods | Free (heuristic) / Paid (ML) |
| `built-in/violence-v1` | Instructions for physical violence | Free (heuristic) / Paid (ML) |
| `built-in/factual-grounding-v1` | RAG response grounding score | Free (heuristic) / Paid (ML) |
| `built-in/pii-medical-v1` | Medical PII: CPT codes, ICD-10, NDC, NPI context, lab values | Paid |
| `built-in/pii-financial-v1` | Financial PII: ABA routing, CUSIP, ISIN, LEI, MICR, ACH trace | Paid |

---

## Enterprise features

### Cryptographic policy signing (Ed25519)

Sign your policy file so the runtime refuses to evaluate if the file has been tampered with:

```bash
# Sign (using the TG CLI)
tg sign ./policies/production.yaml --key ./compliance-officer.pem

# The policy file now contains a signature block:
# signature:
#   algorithm: ed25519
#   public_key: <base64>
#   value: <base64>
#   signed_at: 2026-07-12T10:00:00Z
#   signer: "Jane Smith, Chief Compliance Officer"
```

The runtime verifies the signature on every load. A modified policy file causes a hard `PolicySignatureError` — evaluation does not proceed.

### OCSF audit events (Open Cybersecurity Schema Framework)

Emit audit events in [OCSF Class 6003 (API Activity)](https://schema.ocsf.io/1.1.0/classes/api_activity) format for native SIEM ingestion:

```yaml
audit:
  enabled: true
  destination: "https://your-siem-endpoint.internal/events"
  format: ocsf  # Splunk, Sentinel, Chronicle, Elastic — zero custom parsing
```

Convert individual events programmatically:

```typescript
import { toOcsfEvent } from "@transparentguard/runtime";
const ocsfEvent = toOcsfEvent(auditEvent);
```

---

## Compliance framework templates

Activate pre-built rule libraries with one line:

```yaml
compliance_frameworks:
  - hipaa      # All 18 Safe Harbor identifiers, audit controls, minimum necessary
  - gdpr       # EU PII categories, data minimisation, Article 9 special categories
  - eu-ai-act  # Risk classification tagging, human oversight enforcement
  - soc2       # Complete audit trail, access control evidence
  - fedramp-moderate  # NIST 800-53 mapping, continuous monitoring format
```

Framework rules run in addition to your declared rules and use the reserved `tg_framework_` prefix so they never conflict.

---

## Open-core model

| Feature | Free | Startup | Growth | Enterprise | OEM |
|---------|:---:|:---:|:---:|:---:|:---:|
| Regex PII detection | ✅ | ✅ | ✅ | ✅ | ✅ |
| Keyword & pattern matching | ✅ | ✅ | ✅ | ✅ | ✅ |
| Provider allowlist, token budget, rate limit | ✅ | ✅ | ✅ | ✅ | ✅ |
| Audit to file and stdout | ✅ | ✅ | ✅ | ✅ | ✅ |
| Policy signature verification | ✅ | ✅ | ✅ | ✅ | ✅ |
| OCSF audit format | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML classifiers (prompt injection, toxicity, etc.) | Heuristic | ✅ Full ML | ✅ | ✅ | ✅ |
| Semantic targets | — | ✅ | ✅ | ✅ | ✅ |
| Confidentiality enforcement | n-gram | ✅ + ML | ✅ | ✅ | ✅ |
| Audit to S3, GCS, Azure, PostgreSQL | — | ✅ | ✅ | ✅ | ✅ |
| Compliance frameworks (HIPAA, GDPR, SOC 2, EU AI Act) | — | 1 framework | ✅ All | ✅ All | ✅ All |
| FedRAMP Moderate framework | — | — | — | ✅ | ✅ |
| Medical PII classifier (`pii-medical-v1`) | — | ✅ | ✅ | ✅ | ✅ |
| Financial PII classifier (`pii-financial-v1`) | — | ✅ | ✅ | ✅ | ✅ |
| PIE shadow classifiers & drift detection | — | — | ✅ | ✅ | ✅ |
| Audit evidence export (SOC 2, FedRAMP, HIPAA, GDPR) | — | — | ✅ | ✅ | ✅ |
| ECDSA-P256 signed evaluation receipts | — | — | — | ✅ | ✅ |
| Key rotation watcher | — | — | — | ✅ | ✅ |
| Custom classifier registry | — | — | — | — | ✅ |

Get an API key at [transparentguard.com](https://transparentguard.com).

---

## License

MIT — the runtime is open source. See [LICENSE](./LICENSE).

The TransparentGuard Policy Spec (TPS) is separately MIT licensed at [github.com/transparentguard/transparentguard-policy-spec](https://github.com/transparentguard/transparentguard-policy-spec).
