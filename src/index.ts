/**
 * @transparentguard/runtime
 *
 * TransparentGuard Runtime — AI policy enforcement engine.
 * Implements the TransparentGuard Policy Spec (TPS) v1.0.
 *
 * @example Drop-in wrapper (recommended):
 * ```typescript
 * import { TransparentGuard } from "@transparentguard/runtime";
 * import OpenAI from "openai";
 *
 * const tg = await TransparentGuard.init({
 *   policy: "./policies/production-hipaa.yaml",
 *   apiKey: process.env.TG_API_KEY,
 * });
 *
 * const client = tg.wrap(new OpenAI());
 * const response = await client.chat.completions.create({ ... });
 * ```
 *
 * @example Direct evaluate() call:
 * ```typescript
 * const result = await tg.evaluate("pre-request", {
 *   messages: [{ role: "user", content: "Hello" }],
 *   provider: "openai/gpt-4o",
 * });
 * if (!result.allowed) throw new Error(result.violations[0]?.detail ?? "Blocked");
 * ```
 */

import type {
  EvaluateOptions,
  EvaluateResult,
  RequestPayload,
  ResponsePayload,
  RuleStage,
  TPSPolicy,
  TransparentGuardOptions,
} from "./types.js";
import { loadPolicy, parsePolicy } from "./loader.js";
import { evaluate as coreEvaluate } from "./engine.js";
import { checkLicense } from "./license/checker.js";
import { AuditEmitter } from "./audit/emitter.js";
import { WrappedOpenAIClient } from "./wrappers/openai.js";
import { WrappedAnthropicClient } from "./wrappers/anthropic.js";
import { runPolicyTests, formatTestResults } from "./testing/runner.js";
import type { LicenseStatus } from "./license/checker.js";
import type { OpenAIClientLike } from "./wrappers/openai.js";
import type { AnthropicClientLike } from "./wrappers/anthropic.js";
import type { PolicyTestSuiteResult } from "./testing/runner.js";

// ---------------------------------------------------------------------------
// Public type exports
// ---------------------------------------------------------------------------

export type {
  // Policy types
  TPSPolicy,
  TPSRule,
  TPSAudit,
  TPSEnvironment,
  TPSSignature,
  TPSPolicyTest,
  TPSPolicyTestExpect,
  TPSPolicyTestInput,
  TPSPolicyTestExpectRuleTriggered,
  TPSPolicyTestExpectRedaction,
  TPSThreshold,
  ThresholdAction,
  ThresholdViolationType,
  ThresholdPayloadTemplate,
  ComplianceFramework,
  PiiCategory,
  PiiTarget,
  PatternTarget,
  KeywordTarget,
  SemanticTarget,
  TPSTarget,
  RuleStage,
  RuleAction,
  EnforceType,
  OnViolation,
  RuleStreaming,
  AuditNotify,
  AuditStreamingConfig,
  AuditChainIntegrity,
  // Payload types
  Message,
  RequestPayload,
  ResponsePayload,
  ToolCall,
  ToolCallPayload,
  // Result types
  EvaluateResult,
  Violation,
  ViolationOutcome,
  AuditEvent,
  AuditEventType,
  OCSFEvent,
  // Options
  TransparentGuardOptions,
  EvaluateOptions,
  // Internal
  CompiledRule,
  EvaluationContext,
  RuleResult,
} from "./types.js";

export { PolicyLoadError, PolicySignatureError } from "./loader.js";
export { TransparentGuardError, verifyOfflineKey } from "./license/checker.js";
export type { LicenseStatus, LicenseTier, LicenseFeature } from "./license/checker.js";
export { toOcsfEvent } from "./audit/ocsf.js";
export { approximateTokenCount } from "./enforcements/token-budget.js";
export { detectPii, redactText, expandCategories } from "./evaluators/pii.js";
export { runPolicyTests, formatTestResults } from "./testing/runner.js";
export type { PolicyTestResult, PolicyTestSuiteResult } from "./testing/runner.js";
export { getBlockAllState, clearBlockAll, parseWindowMs } from "./threshold/engine.js";

// ---------------------------------------------------------------------------
// Phase 5 — Compliance framework rule sets
// ---------------------------------------------------------------------------
export { HIPAA_RULES } from "./frameworks/hipaa.js";
export { GDPR_RULES } from "./frameworks/gdpr.js";
export { SOC2_RULES } from "./frameworks/soc2.js";
export { EU_AI_ACT_RULES } from "./frameworks/eu-ai-act.js";
export { FEDRAMP_RULES } from "./frameworks/fedramp.js";

// ---------------------------------------------------------------------------
// Phase 5 — Advanced classifiers
// ---------------------------------------------------------------------------
export { classifyMedicalPii } from "./evaluators/built-in/pii-medical-v1.js";
export { classifyFinancialPii } from "./evaluators/built-in/pii-financial-v1.js";

// ---------------------------------------------------------------------------
// Phase 5 — Custom classifier registry (OEM)
// ---------------------------------------------------------------------------
export {
  registerClassifier,
  getClassifier,
  listClassifiers,
  resolveCustomClassifier,
} from "./evaluators/classifier-registry.js";
export type { CustomClassifierDef } from "./evaluators/classifier-registry.js";

// ---------------------------------------------------------------------------
// Phase 5 — Policy Intelligence Engine (PIE)
// ---------------------------------------------------------------------------
export { generateEvidencePackage } from "./pie/evidence.js";
export type { EvidencePackage, EvidenceControl, EvidenceExportOptions } from "./pie/evidence.js";
export { checkFrameworkDrift, getFrameworkVersion, getAllFrameworkVersions } from "./pie/drift.js";
export type { DriftWarning } from "./pie/drift.js";
export { runShadowClassifier } from "./pie/shadow.js";
export type { PIEShadowModeConfig as PIEShadowConfig } from "./pie/shadow.js";

// ---------------------------------------------------------------------------
// Phase 5 — Cryptographic Trust Chain
// ---------------------------------------------------------------------------
export { generateReceipt, verifyReceipt, getSigningPublicKey } from "./trust/receipt.js";
export {
  startKeyRotationWatcher,
  stopKeyRotationWatcher,
  getActivePublicKeys,
  getActiveKeySet,
  findPublicKey,
} from "./trust/keys.js";
export type { JwkPublicKey, KeySet } from "./trust/keys.js";

// ---------------------------------------------------------------------------
// Main class
// ---------------------------------------------------------------------------

export class TransparentGuard {
  private readonly policy: TPSPolicy;
  private readonly license: LicenseStatus;
  private readonly options: TransparentGuardOptions;
  private readonly emitter: AuditEmitter;

  private constructor(
    policy: TPSPolicy,
    license: LicenseStatus,
    options: TransparentGuardOptions,
  ) {
    this.policy = policy;
    this.license = license;
    this.options = options;
    this.emitter = new AuditEmitter(policy.audit, license.features);
  }

  /**
   * Initialize TransparentGuard with a policy file path or inline policy object.
   * Validates the policy, resolves `extends` chains, verifies signatures, and checks the license.
   */
  static async init(options: TransparentGuardOptions): Promise<TransparentGuard> {
    let policy: TPSPolicy;
    if (typeof options.policy === "string") {
      policy = await loadPolicy(options.policy);
    } else {
      policy = options.policy;
    }

    const license = await checkLicense(
      options.apiKey,
      options.apiBaseUrl,
      options.offlineMode,
    );

    return new TransparentGuard(policy, license, options);
  }

  /**
   * Evaluate a request or response payload against the loaded policy.
   * The stored apiKey is automatically injected for paid-tier classifier access.
   */
  async evaluate(
    stage: RuleStage,
    payload: RequestPayload | ResponsePayload,
    evaluateOptions: EvaluateOptions = {},
  ): Promise<EvaluateResult> {
    const result = await coreEvaluate(
      stage,
      payload,
      this.policy,
      this.license,
      {
        apiKey: this.options.apiKey, // inject stored apiKey
        ...evaluateOptions,            // caller options take precedence
      },
    );
    this.emitter.enqueueMany(result.audit_events);
    return result;
  }

  /**
   * Wraps an OpenAI or Anthropic client with transparent policy enforcement.
   * The returned client is a drop-in replacement — use it exactly like the standard SDK.
   */
  wrap(client: OpenAIClientLike): WrappedOpenAIClient;
  wrap(client: AnthropicClientLike): WrappedAnthropicClient;
  wrap(client: OpenAIClientLike | AnthropicClientLike): WrappedOpenAIClient | WrappedAnthropicClient {
    if (isOpenAIClient(client)) {
      return new WrappedOpenAIClient(client, this.policy, this.license, this.options);
    }
    if (isAnthropicClient(client)) {
      return new WrappedAnthropicClient(client, this.policy, this.license, this.options);
    }
    throw new Error(
      "TransparentGuard.wrap(): unrecognized client type. " +
      "Supported clients: OpenAI, Anthropic. " +
      "For other providers, use the direct evaluate() API.",
    );
  }

  /**
   * Runs all inline tests declared in the policy's `tests` section.
   * No real LLM calls are made — only policy evaluation logic is exercised.
   */
  async test(): Promise<PolicyTestSuiteResult> {
    return runPolicyTests(this.policy, this.license);
  }

  /** Returns the loaded and validated policy object. */
  getPolicy(): TPSPolicy {
    return this.policy;
  }

  /** Returns the current license status. */
  getLicenseStatus(): LicenseStatus {
    return this.license;
  }

  /**
   * Flushes all buffered audit events to the configured destination.
   * Call before process shutdown to ensure no events are lost.
   */
  async flushAudit(): Promise<void> {
    await this.emitter.flush();
  }
}

// ---------------------------------------------------------------------------
// Convenience factory — functional style
// ---------------------------------------------------------------------------

/**
 * @example
 * ```typescript
 * import { tg } from "@transparentguard/runtime";
 * const client = await tg.init({ policy: "./policy.yaml" });
 * ```
 */
export const tg = {
  init: TransparentGuard.init.bind(TransparentGuard),
};

// ---------------------------------------------------------------------------
// Standalone utilities — no init required
// ---------------------------------------------------------------------------

export { parsePolicy, loadPolicy };

// Wrapper client types — re-exported for SDK and consumer use
export type {
  OpenAIClientLike,
  OpenAIChatCompletionCreateParams,
  OpenAIChatCompletion,
  OpenAIChatCompletionChunk,
  OpenAIChatCompletionChunkDelta,
  OpenAIChatCompletionChoice,
  OpenAIChatCompletionChunkChoice,
  WrappedOpenAIClient,
} from "./wrappers/openai.js";

export type {
  AnthropicClientLike,
  AnthropicCreateParams,
  AnthropicResponse,
  AnthropicStreamEvent,
  AnthropicMessage,
  AnthropicContentBlock,
  WrappedAnthropicClient,
} from "./wrappers/anthropic.js";

/** Run policy tests without a TransparentGuard instance (CI helper) */
export async function testPolicy(policy: TPSPolicy): Promise<PolicyTestSuiteResult> {
  const { checkLicense: cl } = await import("./license/checker.js");
  const license = await cl(undefined, undefined, false);
  return runPolicyTests(policy, license);
}

// ---------------------------------------------------------------------------
// Type guards for client detection
// ---------------------------------------------------------------------------

function isOpenAIClient(client: unknown): client is OpenAIClientLike {
  return (
    typeof client === "object" &&
    client !== null &&
    "chat" in client &&
    typeof (client as { chat: unknown }).chat === "object" &&
    (client as { chat: { completions?: unknown } }).chat !== null &&
    "completions" in ((client as { chat: { completions?: unknown } }).chat ?? {})
  );
}

function isAnthropicClient(client: unknown): client is AnthropicClientLike {
  return (
    typeof client === "object" &&
    client !== null &&
    "messages" in client &&
    typeof (client as { messages: unknown }).messages === "object" &&
    (client as { messages: { create?: unknown } }).messages !== null &&
    "create" in ((client as { messages: { create?: unknown } }).messages ?? {})
  );
}

// Re-export formatTestResults at top level for CLI usage
export { formatTestResults as formatPolicyTestResults };
