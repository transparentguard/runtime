/**
 * TransparentGuard Runtime — FedRAMP Moderate Compliance Framework Rules
 * Pre-built rule library activated by compliance_frameworks: [fedramp-moderate]
 * Maps to NIST SP 800-53 Rev 5 controls required by FedRAMP Moderate baseline.
 */

import type { TPSRule } from "../types.js";

export const FEDRAMP_RULES: TPSRule[] = [
  // -------------------------------------------------------------------------
  // SI-10 — Information Input Validation
  // Redact PII and sensitive identifiers from all inbound prompts.
  // -------------------------------------------------------------------------
  {
    id: "tg_framework_fedramp_redact_pii_pre",
    description: "FedRAMP Moderate: Redacts PII and sensitive data from outbound prompts. NIST SI-10 Information Input Validation.",
    stage: "pre-request",
    action: "redact",
    targets: [
      {
        type: "pii",
        categories: [
          "ssn", "passport", "driver_license", "national_id",
          "credit_card", "bank_account", "iban",
          "name", "email", "phone", "address",
          "health_condition", "biometric", "genetic",
          "npi", "mrn", "dea",
        ],
        confidence_threshold: 0.80,
      },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "NIST SP 800-53 Rev 5 SI-10 — Information Input Validation",
      framework: "fedramp-moderate",
      nist_control: "SI-10",
    },
  },

  // -------------------------------------------------------------------------
  // SI-3 — Malware Protection / Prompt Injection
  // Block prompt injection attempts that could subvert access controls.
  // -------------------------------------------------------------------------
  {
    id: "tg_framework_fedramp_block_injection",
    description: "FedRAMP Moderate: Blocks prompt injection attempts. NIST SI-3 Malware Protection and SI-10 Input Validation.",
    stage: "pre-request",
    action: "classify",
    classifier: "built-in/prompt-injection-v2",
    threshold: 0.72,
    on_violation: "block",
    log: true,
    metadata: {
      regulatory_ref: "NIST SP 800-53 Rev 5 SI-3 / SI-10",
      framework: "fedramp-moderate",
      nist_control: "SI-3",
    },
  },

  // -------------------------------------------------------------------------
  // SI-3 — Output Validation: Toxicity / Harmful Content
  // -------------------------------------------------------------------------
  {
    id: "tg_framework_fedramp_block_toxicity",
    description: "FedRAMP Moderate: Blocks harmful or toxic output. NIST SI-3 Malware Protection.",
    stage: "post-response",
    action: "classify",
    classifier: "built-in/toxicity-v1",
    threshold: 0.75,
    on_violation: "block",
    log: true,
    metadata: {
      regulatory_ref: "NIST SP 800-53 Rev 5 SI-3",
      framework: "fedramp-moderate",
      nist_control: "SI-3",
    },
  },

  // -------------------------------------------------------------------------
  // SI-10 — Output PII Redaction
  // Redact sensitive data from LLM responses.
  // -------------------------------------------------------------------------
  {
    id: "tg_framework_fedramp_redact_pii_post",
    description: "FedRAMP Moderate: Redacts PII from LLM responses. NIST SI-10.",
    stage: "post-response",
    action: "redact",
    targets: [
      {
        type: "pii",
        categories: ["ssn", "credit_card", "bank_account", "health_condition", "npi", "mrn"],
        confidence_threshold: 0.82,
      },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "NIST SP 800-53 Rev 5 SI-10",
      framework: "fedramp-moderate",
      nist_control: "SI-10",
    },
  },

  // -------------------------------------------------------------------------
  // AU-2 / AU-3 — Audit Event Types / Content of Audit Records
  // Every LLM interaction must produce a complete, structured audit record.
  // -------------------------------------------------------------------------
  {
    id: "tg_framework_fedramp_log_all",
    description: "FedRAMP Moderate: Records a complete audit event for every LLM call. NIST AU-2 (Event Types) and AU-3 (Content of Audit Records).",
    stage: "post-response",
    action: "log",
    log_level: "info",
    metadata: {
      regulatory_ref: "NIST SP 800-53 Rev 5 AU-2 / AU-3",
      framework: "fedramp-moderate",
      nist_control: "AU-2,AU-3",
    },
  },

  // -------------------------------------------------------------------------
  // AU-9 — Protection of Audit Information
  // AC-3 — Access Enforcement
  // Tag every call with FedRAMP compliance context.
  // -------------------------------------------------------------------------
  {
    id: "tg_framework_fedramp_tag",
    description: "FedRAMP Moderate: Tags every request with NIST control metadata for continuous monitoring evidence. AU-9 / AC-3.",
    stage: "both",
    action: "tag",
    tags: {
      tg_compliance_framework: "fedramp-moderate",
      tg_nist_baseline: "moderate",
      tg_continuous_monitoring: "true",
      tg_audit_evidence: "true",
    },
    metadata: {
      regulatory_ref: "NIST SP 800-53 Rev 5 AU-9 / AC-3",
      framework: "fedramp-moderate",
      nist_control: "AU-9,AC-3",
    },
  },

  // -------------------------------------------------------------------------
  // RA-5 — Vulnerability Monitoring
  // Flag hate speech for incident review.
  // -------------------------------------------------------------------------
  {
    id: "tg_framework_fedramp_warn_hate_speech",
    description: "FedRAMP Moderate: Warns on hate speech output for anomaly and incident review. NIST RA-5 Vulnerability Monitoring.",
    stage: "post-response",
    action: "classify",
    classifier: "built-in/hate-speech-v1",
    threshold: 0.72,
    on_violation: "warn",
    log: true,
    sample_rate: 1.0,
    metadata: {
      regulatory_ref: "NIST SP 800-53 Rev 5 RA-5 — Vulnerability Monitoring",
      framework: "fedramp-moderate",
      nist_control: "RA-5",
    },
  },
];
