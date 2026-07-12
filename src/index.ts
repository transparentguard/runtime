/**
 * @transparentguard/runtime
 *
 * TransparentGuard Runtime — AI policy enforcement engine.
 * Implements the TransparentGuard Policy Spec (TPS) v1.0.
 *
 * @example Drop-in wrapper (recommended for new builds):
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
 * // Enforcement is invisible — use exactly like the standard OpenAI client.
 * ```
 *
 * @example Direct evaluate() call:
 * ```typescript
 * const result = await tg.evaluate("pre-request", {
 *   messages: [{ role: "user", content: "Hello" }],
 *   provider: "openai/gpt-4o",
 * });
 *
 * if (!result.allowed) {
 *   throw new Error(result.violations[0]?.detail ?? "Blocked by policy");
 * }
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
import type { LicenseStatus } from "./license/checker.js";
import type { OpenAIClientLike } from "./wrappers/openai.js";
import type { AnthropicClientLike } from "./wrappers/anthropic.js";

export type {
  // Policy types
  TPSPolicy,
  TPSRule,
  TPSAudit,
  TPSEnvironment,
  TPSSignature,
  TPSPolicyTest,
  TPSThreshold,
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
  // Payload types
  Message,
  RequestPayload,
  ResponsePayload,
  ToolCall,
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
} from "./types.js";

export { PolicyLoadError, PolicySignatureError } from "./loader.js";
export { TransparentGuardError } from "./license/checker.js";
export type { LicenseStatus, LicenseTier, LicenseFeature } from "./license/checker.js";
export { toOcsfEvent } from "./audit/ocsf.js";
export { approximateTokenCount } from "./enforcements/token-budget.js";
export { detectPii, redactText, expandCategories } from "./evaluators/pii.js";

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
    this.emitter = new AuditEmitter(policy.audit);
  }

  /**
   * Initialize TransparentGuard with a policy file path or inline policy object.
   * Validates the policy, verifies its signature (if present), and checks the license.
   */
  static async init(options: TransparentGuardOptions): Promise<TransparentGuard> {
    // Load policy
    let policy: TPSPolicy;
    if (typeof options.policy === "string") {
      policy = await loadPolicy(options.policy);
    } else {
      policy = options.policy;
    }

    // Check license
    const license = await checkLicense(
      options.apiKey,
      options.apiBaseUrl,
      options.offlineMode,
    );

    return new TransparentGuard(policy, license, options);
  }

  /**
   * Evaluate a request or response payload against the loaded policy.
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
      evaluateOptions,
    );
    this.emitter.enqueueMany(result.audit_events);
    return result;
  }

  /**
   * Wraps an OpenAI client with transparent policy enforcement.
   * The returned client is a drop-in replacement — use it exactly
   * like the standard openai client.
   */
  wrap(client: OpenAIClientLike): WrappedOpenAIClient;

  /**
   * Wraps an Anthropic client with transparent policy enforcement.
   */
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
   * Returns the loaded and validated policy object.
   */
  getPolicy(): TPSPolicy {
    return this.policy;
  }

  /**
   * Returns the current license status.
   */
  getLicenseStatus(): LicenseStatus {
    return this.license;
  }

  /**
   * Flushes all buffered audit events to the configured destination.
   * Call this before process shutdown to ensure no events are lost.
   */
  async flushAudit(): Promise<void> {
    await this.emitter.flush();
  }
}

// ---------------------------------------------------------------------------
// Convenience factory — functional style for users who prefer it
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
// Standalone utility functions — no init required
// ---------------------------------------------------------------------------

/**
 * Parses and validates a TPS policy YAML string.
 * Useful for CI validation of policy files.
 */
export { parsePolicy, loadPolicy };

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
