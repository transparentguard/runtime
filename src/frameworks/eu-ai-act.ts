/**
 * TransparentGuard Runtime — EU AI Act Compliance Framework Rules
 * Pre-built rule library activated by compliance_frameworks: [eu-ai-act]
 * Maps to EU AI Act (Regulation (EU) 2024/1689).
 */

import type { TPSRule } from "../types.js";

export const EU_AI_ACT_RULES: TPSRule[] = [
  {
    id: "tg_framework_eu_ai_act_tag_risk",
    description: "EU AI Act framework: Tags every request with risk classification context. Article 6-9.",
    stage: "both",
    action: "tag",
    tags: {
      tg_compliance_framework: "eu-ai-act",
      tg_eu_ai_act_risk_class: "limited",
      tg_eu_ai_act_transparency_required: "true",
    },
    metadata: {
      regulatory_ref: "EU AI Act Articles 6-9 — Risk Classification",
      framework: "eu-ai-act",
    },
  },
  {
    id: "tg_framework_eu_ai_act_block_injection",
    description: "EU AI Act framework: Blocks prompt injection attempts on high-risk AI systems. Article 15 (accuracy and robustness).",
    stage: "pre-request",
    action: "classify",
    classifier: "built-in/prompt-injection-v2",
    threshold: 0.75,
    on_violation: "block",
    log: true,
    metadata: {
      regulatory_ref: "EU AI Act Article 15 — Accuracy, Robustness and Cybersecurity",
      framework: "eu-ai-act",
    },
  },
  {
    id: "tg_framework_eu_ai_act_redact_pii_pre",
    description: "EU AI Act framework: Redacts personal data from outbound prompts to support data minimisation. Article 10(5).",
    stage: "pre-request",
    action: "redact",
    targets: [
      {
        type: "pii",
        categories: [
          "name", "email", "phone", "ssn", "national_id",
          "passport", "driver_license", "health_condition",
          "race", "religion", "political_opinion", "sexual_orientation",
          "biometric", "genetic",
        ],
        confidence_threshold: 0.78,
      },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "EU AI Act Article 10(5) — Data Governance",
      framework: "eu-ai-act",
    },
  },
  {
    id: "tg_framework_eu_ai_act_redact_pii_post",
    description: "EU AI Act framework: Redacts personal data from LLM responses. Article 13 (transparency to users).",
    stage: "post-response",
    action: "redact",
    targets: [
      {
        type: "pii",
        categories: [
          "name", "email", "phone", "ssn", "national_id",
          "health_condition", "race", "religion", "political_opinion",
        ],
        confidence_threshold: 0.80,
      },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "EU AI Act Article 13 — Transparency and Information Provision",
      framework: "eu-ai-act",
    },
  },
  {
    id: "tg_framework_eu_ai_act_block_toxicity",
    description: "EU AI Act framework: Blocks toxic content outputs from high-risk AI systems. Article 9(2) — risk management.",
    stage: "post-response",
    action: "classify",
    classifier: "built-in/toxicity-v1",
    threshold: 0.80,
    on_violation: "block",
    log: true,
    metadata: {
      regulatory_ref: "EU AI Act Article 9 — Risk Management System",
      framework: "eu-ai-act",
    },
  },
  {
    id: "tg_framework_eu_ai_act_log_all",
    description: "EU AI Act framework: Records an audit event for every LLM call. Article 12 requires automatic log generation for high-risk AI.",
    stage: "post-response",
    action: "log",
    log_level: "info",
    metadata: {
      regulatory_ref: "EU AI Act Article 12 — Record-Keeping",
      framework: "eu-ai-act",
    },
  },
];
