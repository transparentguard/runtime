/**
 * TransparentGuard Runtime — SOC 2 Compliance Framework Rules
 * Pre-built rule library activated by compliance_frameworks: [soc2]
 * Maps to AICPA SOC 2 Trust Services Criteria (CC6, CC7, CC9).
 */

import type { TPSRule } from "../types.js";

export const SOC2_RULES: TPSRule[] = [
  {
    id: "tg_framework_soc2_tag",
    description: "SOC 2 framework: Tags every request with SOC 2 compliance context for evidence collection. CC6.1.",
    stage: "both",
    action: "tag",
    tags: {
      tg_compliance_framework: "soc2",
      tg_soc2_control: "CC6.1",
      tg_audit_evidence: "true",
    },
    metadata: {
      regulatory_ref: "SOC 2 CC6.1 — Logical and Physical Access Controls",
      framework: "soc2",
    },
  },
  {
    id: "tg_framework_soc2_block_injection",
    description: "SOC 2 framework: Blocks prompt injection attempts that could bypass access controls. CC6.8 — Restricts unauthorized access.",
    stage: "pre-request",
    action: "classify",
    classifier: "built-in/prompt-injection-v2",
    threshold: 0.78,
    on_violation: "block",
    log: true,
    metadata: {
      regulatory_ref: "SOC 2 CC6.8 — Restricts Unauthorized Access",
      framework: "soc2",
    },
  },
  {
    id: "tg_framework_soc2_redact_sensitive_pre",
    description: "SOC 2 framework: Redacts sensitive PII from outbound prompts. CC6.5 — Disposal of protected information.",
    stage: "pre-request",
    action: "redact",
    targets: [
      {
        type: "pii",
        categories: [
          "ssn", "credit_card", "bank_account", "iban",
          "passport", "driver_license", "national_id",
          "health_condition", "biometric",
        ],
        confidence_threshold: 0.82,
      },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "SOC 2 CC6.5 — Disposal and Remediation of Protected Information",
      framework: "soc2",
    },
  },
  {
    id: "tg_framework_soc2_redact_sensitive_post",
    description: "SOC 2 framework: Redacts sensitive data from LLM responses before returning to application. CC6.7.",
    stage: "post-response",
    action: "redact",
    targets: [
      {
        type: "pii",
        categories: ["ssn", "credit_card", "bank_account", "health_condition"],
        confidence_threshold: 0.85,
      },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "SOC 2 CC6.7 — Restricts Transmission of Confidential Information",
      framework: "soc2",
    },
  },
  {
    id: "tg_framework_soc2_log_all",
    description: "SOC 2 framework: Records a complete audit event for every LLM call. Provides CC7.2 evidence of system monitoring.",
    stage: "post-response",
    action: "log",
    log_level: "info",
    metadata: {
      regulatory_ref: "SOC 2 CC7.2 — Monitors System Components for Anomalies",
      framework: "soc2",
    },
  },
  {
    id: "tg_framework_soc2_warn_toxicity",
    description: "SOC 2 framework: Warns on toxic content outputs to support anomaly detection. CC7.2.",
    stage: "post-response",
    action: "classify",
    classifier: "built-in/toxicity-v1",
    threshold: 0.70,
    on_violation: "warn",
    log: true,
    sample_rate: 0.5,
    metadata: {
      regulatory_ref: "SOC 2 CC7.2 — Monitors System Components for Anomalies",
      framework: "soc2",
      sampling_rationale: "Toxicity monitoring at 50% for cost efficiency; pattern rule provides primary coverage",
    },
  },
];
