/**
 * TransparentGuard Runtime — Type Definitions
 * Mirrors the TransparentGuard Policy Spec (TPS) v1.0 JSON Schema exactly.
 */

import type { LicenseStatus } from "./license/checker.js";

// ---------------------------------------------------------------------------
// Policy document
// ---------------------------------------------------------------------------

export type ComplianceFramework =
  | "hipaa"
  | "gdpr"
  | "eu-ai-act"
  | "soc2"
  | "fedramp-moderate"
  | "ccpa";

export interface TPSEnvironment {
  name: string;
  strict?: boolean;
  active_rules?: string[];
  disabled_rules?: string[];
  on_unknown_provider?: "block" | "warn" | "allow";
}

export type PiiCategory =
  | "name" | "email" | "phone" | "address" | "ip_address" | "username"
  | "device_id" | "url"
  | "ssn" | "passport" | "driver_license" | "national_id" | "tax_id" | "voter_id"
  | "credit_card" | "bank_account" | "iban" | "swift" | "crypto_address"
  | "mrn" | "dob" | "age" | "health_condition" | "insurance_id" | "npi" | "dea"
  | "race" | "religion" | "political_opinion" | "sexual_orientation"
  | "biometric" | "genetic" | "union_membership"
  | "phi" | "pii_standard" | "pii_financial" | "pii_sensitive" | "pii_all";

export interface PiiTarget {
  type: "pii";
  categories: PiiCategory[];
  confidence_threshold?: number;
}

export interface PatternTarget {
  type: "pattern";
  pattern: string;
  description?: string;
  flags?: Array<"case_insensitive" | "multiline" | "dotall">;
}

export interface KeywordTarget {
  type: "keyword";
  keywords: string[];
  match_mode?: "whole_word" | "substring";
  case_sensitive?: boolean;
}

export interface SemanticTarget {
  type: "semantic";
  concepts: string[];
  similarity_threshold?: number;
  model?: string;
}

export type TPSTarget = PiiTarget | PatternTarget | KeywordTarget | SemanticTarget;

export type RuleStage = "pre-request" | "post-response" | "both" | "tool-call";

export type RuleAction = "redact" | "classify" | "enforce" | "tag" | "block" | "log";

export type EnforceType =
  | "provider_allowlist"
  | "token_budget"
  | "data_residency"
  | "rate_limit"
  | "tool_allowlist"
  | "schema_validation"
  | "confidentiality"
  | "factual_grounding";

export type OnViolation = "block" | "redact" | "warn" | "log" | "allow";

export interface RuleStreaming {
  mode: "buffer" | "window" | "passthrough";
  window_tokens?: number;
  on_stream_violation?: "block" | "passthrough_and_log";
}

export interface TPSRule {
  id: string;
  description?: string;
  enabled?: boolean;
  stage: RuleStage;
  action: RuleAction;
  // targets — required for redact and classify
  targets?: TPSTarget[];
  // classify fields
  classifier?: string;
  threshold?: number;
  invert_threshold?: boolean;
  // enforce fields
  enforce_type?: EnforceType;
  allowed_providers?: string[];
  max_tokens_per_request?: number;
  max_tokens_per_day_per_key?: number;
  max_tokens_per_hour_per_key?: number;
  allowed_regions?: string[];
  max_requests_per_minute_per_key?: number;
  max_requests_per_hour_per_key?: number;
  allowed_tools?: string[];
  blocked_tools?: string[];
  tool_argument_targets?: TPSTarget[];
  expected_schema?: Record<string, unknown>;
  protected_content_ref?: "system_prompt" | "context_documents" | "user_provided_data";
  similarity_threshold?: number;
  canary_tokens?: boolean;
  // tag fields
  tags?: Record<string, string>;
  // block fields
  block_message?: string;
  // log fields
  log_level?: "debug" | "info" | "warn";
  // shared
  on_violation?: OnViolation;
  log?: boolean;
  sample_rate?: number;
  streaming?: RuleStreaming;
  metadata?: Record<string, string | number>;
}

export interface AuditNotify {
  url: string;
  events: string[];
  headers?: Record<string, string>;
  timeout_ms?: number;
  retry?: { max_attempts?: number; backoff_ms?: number };
}

/** Global default streaming config for audit — per-rule streaming overrides this */
export interface AuditStreamingConfig {
  mode: "buffer" | "window" | "passthrough";
  window_tokens?: number;
  on_stream_violation?: "block" | "passthrough_and_log";
}

export interface AuditChainIntegrity {
  enabled: boolean;
  algorithm?: "sha256" | "sha3-256";
  /** Local path where chain head sidecar is written atomically after every event */
  sidecar_path?: string;
  /** When true, runtime verifies existing chain on startup before accepting calls */
  verify_on_startup?: boolean;
  /** When true, detected chain break halts evaluation and alerts notify targets */
  alert_on_break?: boolean;
}

export interface TPSAudit {
  enabled: boolean;
  destination?: string;
  format?: "ndjson" | "json" | "ocsf";
  retention_days?: number;
  include_redacted_content?: boolean;
  include_full_request?: boolean;
  include_full_response?: boolean;
  events?: Array<"allowed" | "blocked" | "redacted" | "warned" | "error">;
  batch_size?: number;
  flush_interval_ms?: number;
  notify?: AuditNotify[];
  streaming?: AuditStreamingConfig;
  chain_integrity?: AuditChainIntegrity;
}

export interface TPSSignature {
  algorithm: "ed25519" | "rsa-pss-sha256" | "ecdsa-p256-sha256";
  /** Keyring lookup key (spec-compliant approach) */
  key_id?: string;
  /** Inline raw-base64 public key (backward-compat convenience) */
  public_key?: string;
  /** Base64url-encoded signature bytes */
  value: string;
  signed_at?: string;
  signer?: string;
  /** When true, runtime refuses to load this policy if signature is absent or invalid */
  required?: boolean;
}

export type ThresholdAction = "notify" | "block_all" | "escalate";
export type ThresholdViolationType = "blocked" | "redacted" | "warned" | "error" | "sampled_out";
export type ThresholdPayloadTemplate =
  | "hipaa-breach-v1"
  | "gdpr-article-33"
  | "eu-ai-act-article-73"
  | "soc2-incident-v1"
  | string; // custom/xxx

export interface TPSThreshold {
  /** Unique identifier within the thresholds list */
  id: string;
  /** The rule whose violations this threshold monitors */
  rule_id: string;
  /** Type of violation outcome that increments this counter */
  violation_type: ThresholdViolationType;
  /** How many qualifying violations within window trigger the action */
  count: number;
  /** Rolling time window e.g. "1h", "30m", "7d" */
  window: string;
  action: ThresholdAction;
  /** Required when action is "notify" */
  notify_url?: string;
  /** Regulation-formatted payload template */
  payload_template?: ThresholdPayloadTemplate;
  /** Required when action is "block_all" */
  block_message?: string;
  /** When false, threshold is parsed but never evaluated */
  enabled?: boolean;
  metadata?: Record<string, string | number>;
}

export interface TPSPolicyTestExpectRuleTriggered {
  rule_id: string;
  action_taken?: "redacted" | "blocked" | "warned" | "logged";
  min_violations?: number;
}

export interface TPSPolicyTestExpectRedaction {
  category: string;
  count?: number;
}

export interface TPSPolicyTestExpect {
  /** Expected overall evaluation outcome */
  outcome: "allowed" | "allowed_with_modifications" | "blocked" | "warned";
  /** Rules that MUST have triggered a violation */
  rules_triggered?: TPSPolicyTestExpectRuleTriggered[];
  /** Rule IDs that MUST NOT have triggered */
  rules_not_triggered?: string[];
  /** Specific redactions that must appear */
  redactions?: TPSPolicyTestExpectRedaction[];
}

export interface TPSPolicyTestInput {
  messages?: Array<{ role: string; content: string }>;
  provider?: string;
  model_parameters?: Record<string, unknown>;
  /** For post-response stage tests */
  response?: { content: string; finish_reason?: string };
  /** For tool-call stage tests */
  tool_call?: { tool_name: string; arguments?: Record<string, unknown> };
}

export interface TPSPolicyTest {
  id: string;
  description?: string;
  stage: "pre-request" | "post-response" | "tool-call";
  input: TPSPolicyTestInput;
  expect: TPSPolicyTestExpect;
}

// ---------------------------------------------------------------------------
// Phase 5 — Custom classifiers and Policy Intelligence Engine (PIE)
// ---------------------------------------------------------------------------

export interface CustomClassifierSpec {
  name: string;
  description?: string;
  patterns?: string[];
  pattern_flags?: string;
  keywords?: string[];
  keyword_match?: "any" | "all";
  keyword_case_sensitive?: boolean;
  score_on_match?: number;
  webhook_url?: string;
  webhook_headers?: Record<string, string>;
  concepts?: string[];
}

export interface PIEShadowModeConfig {
  enabled: boolean;
  classifiers: string[];
  log_disagreement_threshold?: number;
}

export interface PIEConfig {
  shadow_mode?: PIEShadowModeConfig;
  drift_check?: {
    enabled: boolean;
    check_interval_hours?: number;
  };
  evidence_export?: {
    enabled: boolean;
    output_path?: string;
  };
}

export interface TPSPolicy {
  tps_version: "1.0";
  name: string;
  description?: string;
  extends?: string;
  default_action?: "allow" | "deny";
  provider?: "any" | string[];
  environments?: TPSEnvironment[];
  rules: TPSRule[];
  compliance_frameworks?: ComplianceFramework[];
  audit: TPSAudit;
  signature?: TPSSignature;
  tests?: TPSPolicyTest[];
  thresholds?: TPSThreshold[];
  custom_classifiers?: CustomClassifierSpec[];
  pie?: PIEConfig;
}

// ---------------------------------------------------------------------------
// Runtime payloads
// ---------------------------------------------------------------------------

export interface Message {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  tool_call_id?: string;
  name?: string;
}

export interface ToolCall {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

export interface RequestPayload {
  messages: Message[];
  provider?: string;
  model?: string;
  api_key_id?: string;
  max_tokens?: number;
  tool_calls?: ToolCall[];
  context_documents?: string[];
  metadata?: Record<string, string>;
}

export interface ResponsePayload {
  content: string;
  provider?: string;
  model?: string;
  api_key_id?: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
  context_documents?: string[];
  system_prompt?: string;
  metadata?: Record<string, string>;
}

/** Payload passed when evaluating a tool-call stage rule */
export interface ToolCallPayload {
  tool_name: string;
  arguments: Record<string, unknown>;
  call_index?: number;
  agent_loop_step?: number;
}

// ---------------------------------------------------------------------------
// Evaluation results
// ---------------------------------------------------------------------------

export type ViolationOutcome = "blocked" | "redacted" | "warned" | "logged" | "allowed";

export interface Violation {
  rule_id: string;
  rule_description?: string;
  outcome: ViolationOutcome;
  detail?: string;
  category?: string;
  span?: { start: number; end: number; original?: string };
}

export interface EvaluateResult {
  allowed: boolean;
  payload: RequestPayload | ResponsePayload;
  violations: Violation[];
  tags: Record<string, string>;
  audit_events: AuditEvent[];
  evaluated_at: string;
  policy_name: string;
  /** Signed evaluation receipt — tamper-evident proof of policy enforcement */
  receipt?: EvaluationReceipt;
}

// ---------------------------------------------------------------------------
// Cryptographic Trust Chain — Evaluation Receipt
// ---------------------------------------------------------------------------

export interface EvaluationReceipt {
  id: string;
  request_hash: string;
  policy_digest: string;
  outcome: "allowed" | "blocked" | "redacted";
  violation_count: number;
  evaluated_at: string;
  signature: string;
  public_key_id: string;
  public_key_spki: string;
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

export type AuditEventType =
  | "allowed"
  | "blocked"
  | "redacted"
  | "warned"
  | "error"
  | "sampled_out"
  | "threshold_triggered"
  | "chain_break";

export interface AuditEvent {
  id: string;
  timestamp: string;
  policy_name: string;
  policy_version: string;
  rule_id?: string;
  event_type: AuditEventType;
  stage: RuleStage | "system";
  provider?: string;
  model?: string;
  api_key_id?: string;
  violation?: Omit<Violation, "span">;
  tags: Record<string, string>;
  metadata?: Record<string, string | number>;
  prev_event_hash?: string;
  /** Zero-based monotonically increasing chain position — present when chain_integrity.enabled */
  chain_sequence?: number;
  request_id?: string;
}

// ---------------------------------------------------------------------------
// OCSF — Open Cybersecurity Schema Framework (Class 6003: API Activity)
// ---------------------------------------------------------------------------

export interface OCSFEvent {
  class_uid: 6003;
  class_name: "API Activity";
  category_uid: 6;
  category_name: "Application Activity";
  activity_id: number;
  activity_name: string;
  time: number;
  severity_id: number;
  severity: string;
  status_id: number;
  status: string;
  message: string;
  metadata: {
    version: "1.1.0";
    product: {
      name: "TransparentGuard";
      vendor_name: "TransparentGuard";
      version: string;
    };
  };
  api: {
    operation: string;
    request?: { uid?: string; body?: Record<string, unknown> };
    response?: { code?: number; message?: string };
    service?: { name?: string };
  };
  actor?: {
    user?: { uid?: string };
  };
  unmapped?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Runtime options
// ---------------------------------------------------------------------------

export interface TransparentGuardOptions {
  /** Path to TPS policy YAML file, or a pre-loaded TPSPolicy object */
  policy: string | TPSPolicy;
  /** TransparentGuard license/API key — required for paid-tier features */
  apiKey?: string;
  /** Override the TG API base URL (useful for self-hosted deployments) */
  apiBaseUrl?: string;
  /** Active environment name — selects environment-specific rule overrides */
  environment?: string;
  /** Disable the license check entirely (for offline/air-gapped deployments) */
  offlineMode?: boolean;
}

export interface EvaluateOptions {
  /** Unique identifier for this LLM call — used in audit events and sampling */
  requestId?: string;
  /** Identifier for the API key making the call — used for rate/token limits */
  apiKeyId?: string;
  /** Override the active environment for this specific call */
  environment?: string;
  /** TransparentGuard API key — passed to ML classifiers for paid-tier features */
  apiKey?: string;
  /** When false, skips receipt generation for this call. Default: true */
  generateReceipt?: boolean;
}

// ---------------------------------------------------------------------------
// Internal compiled rule
// ---------------------------------------------------------------------------

export interface CompiledRule {
  rule: TPSRule;
  appliesTo: (stage: RuleStage) => boolean;
  evaluate: (ctx: EvaluationContext) => Promise<RuleResult>;
}

export interface EvaluationContext {
  rule: TPSRule;
  stage: RuleStage;
  payload: RequestPayload | ResponsePayload;
  policy: TPSPolicy;
  environment?: string;
  requestId: string;
  apiKeyId?: string;
  apiKey?: string;
  apiBaseUrl: string;
  tags: Record<string, string>;
  isPaidTier: boolean;
  licenseStatus: LicenseStatus;
}

export interface RuleResult {
  ruleId: string;
  outcome: ViolationOutcome | "skipped" | "passed";
  violation?: Violation;
  auditEvent: AuditEvent;
  /** mutated payload if redaction occurred */
  payload?: RequestPayload | ResponsePayload;
}
