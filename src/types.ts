/**
 * TransparentGuard Runtime — Type Definitions
 * Mirrors the TransparentGuard Policy Spec (TPS) v1.0 JSON Schema exactly.
 */

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
}

export interface AuditStreamingConfig {
  mode: "buffer" | "passthrough";
  max_buffer_tokens?: number;
}

export interface AuditChainIntegrity {
  enabled: boolean;
  algorithm?: "sha256";
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
  algorithm: "ed25519";
  public_key: string;
  value: string;
  signed_at?: string;
  signer?: string;
}

export interface TPSThreshold {
  rule_id: string;
  count: number;
  window_seconds: number;
  action: "notify" | "block_key" | "alert";
  notify_url?: string;
}

export interface TPSPolicyTest {
  id: string;
  description?: string;
  stage: RuleStage;
  input: Record<string, unknown>;
  expect: {
    allowed?: boolean;
    violations?: Array<{ rule_id: string }>;
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
  | "threshold_triggered";

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
}

export interface RuleResult {
  ruleId: string;
  outcome: ViolationOutcome | "skipped" | "passed";
  violation?: Violation;
  auditEvent: AuditEvent;
  /** mutated payload if redaction occurred */
  payload?: RequestPayload | ResponsePayload;
}
