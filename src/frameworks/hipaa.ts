/**
 * TransparentGuard Runtime — HIPAA Compliance Framework Rules
 * Pre-built rule library activated by compliance_frameworks: [hipaa]
 * Maps to HIPAA Security Rule 45 CFR Part 164, Subpart C and Privacy Rule Subpart E.
 */

import type { TPSRule } from "../types.js";

export const HIPAA_RULES: TPSRule[] = [
  {
    id: "tg_framework_hipaa_redact_phi_pre",
    description: "HIPAA framework: Redacts all 18 Safe Harbor PHI identifiers from outbound prompts. 45 CFR 164.514(b).",
    stage: "pre-request",
    action: "redact",
    targets: [
      { type: "pii", categories: ["phi"], confidence_threshold: 0.75 },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "HIPAA 45 CFR 164.514(b) — Safe Harbor De-identification",
      framework: "hipaa",
    },
  },
  {
    id: "tg_framework_hipaa_block_injection",
    description: "HIPAA framework: Blocks prompt injection attempts that could circumvent PHI handling instructions. 45 CFR 164.312(a)(1).",
    stage: "pre-request",
    action: "classify",
    classifier: "built-in/prompt-injection-v2",
    threshold: 0.75,
    on_violation: "block",
    log: true,
    metadata: {
      regulatory_ref: "HIPAA 45 CFR 164.312(a)(1) — Access Control",
      framework: "hipaa",
    },
  },
  {
    id: "tg_framework_hipaa_redact_phi_post",
    description: "HIPAA framework: Redacts PHI from LLM responses. Catches model hallucinations that include real patient data. 45 CFR 164.502(b).",
    stage: "post-response",
    action: "redact",
    targets: [
      { type: "pii", categories: ["phi"], confidence_threshold: 0.80 },
    ],
    on_violation: "redact",
    log: true,
    metadata: {
      regulatory_ref: "HIPAA 45 CFR 164.502(b) — Minimum Necessary",
      framework: "hipaa",
    },
  },
  {
    id: "tg_framework_hipaa_log_all",
    description: "HIPAA framework: Records an audit event for every response to maintain a complete audit trail. 45 CFR 164.312(b).",
    stage: "post-response",
    action: "log",
    log_level: "info",
    metadata: {
      regulatory_ref: "HIPAA 45 CFR 164.312(b) — Audit Controls",
      framework: "hipaa",
    },
  },
  {
    id: "tg_framework_hipaa_tag",
    description: "HIPAA framework: Tags every request with HIPAA compliance context for audit trail completeness.",
    stage: "both",
    action: "tag",
    tags: {
      tg_compliance_framework: "hipaa",
      tg_data_classification: "phi-possible",
    },
  },
];
