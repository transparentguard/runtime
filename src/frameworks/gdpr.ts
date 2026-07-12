/**
 * TransparentGuard Runtime — GDPR Compliance Framework Rules
 * Pre-built rule library activated by compliance_frameworks: [gdpr]
 * Maps to GDPR Regulation (EU) 2016/679.
 */

import type { TPSRule } from "../types.js";

export const GDPR_RULES: TPSRule[] = [
  {
    id: "tg_framework_gdpr_redact_pii_pre",
    description: "GDPR framework: Redacts EU personal data categories from outbound prompts. Applies data minimisation principle. Article 5(1)(c).",
    stage: "pre-request",
    action: "redact",
    targets: [
      {
        type: "pii",
        categories: [
          "name", "email", "phone", "address", "ip_address",
          "national_id", "tax_id", "passport", "driver_license",
          "credit_card", "bank_account", "iban",
          "race", "religion", "political_opinion", "sexual_orientation",
          "biometric", "genetic", "union_membership", "health_condition",
        ],
        confidence_threshold: 0.78,
      },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "GDPR Article 5(1)(c) — Data Minimisation; Article 9 — Special Categories",
      framework: "gdpr",
    },
  },
  {
    id: "tg_framework_gdpr_block_injection",
    description: "GDPR framework: Blocks prompt injection. A successful injection could override data minimisation behavior. Article 32.",
    stage: "pre-request",
    action: "classify",
    classifier: "built-in/prompt-injection-v2",
    threshold: 0.80,
    on_violation: "block",
    log: true,
    metadata: {
      regulatory_ref: "GDPR Article 32 — Security of Processing",
      framework: "gdpr",
    },
  },
  {
    id: "tg_framework_gdpr_redact_pii_post",
    description: "GDPR framework: Redacts EU personal data from LLM responses. Article 5(1)(f) integrity and confidentiality.",
    stage: "post-response",
    action: "redact",
    targets: [
      {
        type: "pii",
        categories: [
          "name", "email", "phone", "national_id", "credit_card",
          "race", "religion", "political_opinion", "sexual_orientation",
          "health_condition",
        ],
        confidence_threshold: 0.82,
      },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "GDPR Article 5(1)(f) — Integrity and Confidentiality",
      framework: "gdpr",
    },
  },
  {
    id: "tg_framework_gdpr_block_hate_speech",
    description: "GDPR framework: Blocks hate speech output targeting protected characteristics. Article 9 liability.",
    stage: "post-response",
    action: "classify",
    classifier: "built-in/hate-speech-v1",
    threshold: 0.78,
    on_violation: "block",
    log: true,
    metadata: {
      regulatory_ref: "GDPR Article 9 — Special Categories of Personal Data",
      framework: "gdpr",
    },
  },
  {
    id: "tg_framework_gdpr_log_all",
    description: "GDPR framework: Records an audit event for every completion to support accountability obligation. Article 5(2).",
    stage: "post-response",
    action: "log",
    log_level: "info",
    metadata: {
      regulatory_ref: "GDPR Article 5(2) — Accountability",
      framework: "gdpr",
    },
  },
  {
    id: "tg_framework_gdpr_tag",
    description: "GDPR framework: Tags every request with GDPR processing context for accountability demonstration.",
    stage: "both",
    action: "tag",
    tags: {
      tg_compliance_framework: "gdpr",
      tg_data_residency_required: "true",
    },
  },
];
