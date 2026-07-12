/**
 * TransparentGuard Runtime — Anthropic Wrapper
 * Drop-in replacement for the Anthropic client that enforces TPS policies
 * transparently on every messages.create() call.
 *
 * Usage:
 *   import { tg } from "@transparentguard/runtime";
 *   import Anthropic from "@anthropic-ai/sdk";
 *
 *   const client = tg.wrap(new Anthropic(), { policy: "./policies/production.yaml" });
 *   const response = await client.messages.create({ ... });
 */

import type { TransparentGuardOptions, EvaluateOptions, RequestPayload, ResponsePayload, Message } from "../types.js";
import type { LicenseStatus } from "../license/checker.js";
import { evaluate } from "../engine.js";
import { AuditEmitter } from "../audit/emitter.js";
import { TransparentGuardError } from "../license/checker.js";

// ---------------------------------------------------------------------------
// Minimal Anthropic type surface
// ---------------------------------------------------------------------------

export interface AnthropicMessage {
  role: "user" | "assistant";
  content: string | Array<{ type: string; text?: string }>;
}

export interface AnthropicCreateParams {
  messages: AnthropicMessage[];
  model: string;
  system?: string;
  max_tokens: number;
  [key: string]: unknown;
}

export interface AnthropicContentBlock {
  type: "text";
  text: string;
}

export interface AnthropicResponse {
  id: string;
  type: "message";
  role: "assistant";
  content: AnthropicContentBlock[];
  model: string;
  stop_reason?: string;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
  [key: string]: unknown;
}

export interface AnthropicClientLike {
  messages: {
    create(params: AnthropicCreateParams): Promise<AnthropicResponse>;
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractAnthropicText(content: AnthropicMessage["content"]): string {
  if (typeof content === "string") return content;
  return content
    .filter((b) => b.type === "text" && b.text)
    .map((b) => b.text ?? "")
    .join("\n");
}

// ---------------------------------------------------------------------------
// Wrapped client
// ---------------------------------------------------------------------------

export class WrappedAnthropicClient {
  private readonly inner: AnthropicClientLike;
  private readonly policy: import("../types.js").TPSPolicy;
  private readonly license: LicenseStatus;
  private readonly options: TransparentGuardOptions;
  private readonly emitter: AuditEmitter;

  constructor(
    inner: AnthropicClientLike,
    policy: import("../types.js").TPSPolicy,
    license: LicenseStatus,
    options: TransparentGuardOptions,
  ) {
    this.inner = inner;
    this.policy = policy;
    this.license = license;
    this.options = options;
    this.emitter = new AuditEmitter(policy.audit);
  }

  get messages() {
    return {
      create: this.createMessage.bind(this),
    };
  }

  private async createMessage(
    params: AnthropicCreateParams,
    evaluateOptions: EvaluateOptions = {},
  ): Promise<AnthropicResponse> {
    // Convert Anthropic messages to TPS RequestPayload
    const messages: Message[] = [];

    // System prompt as a synthetic system message
    if (params.system) {
      messages.push({ role: "system", content: params.system });
    }

    for (const msg of params.messages) {
      messages.push({
        role: msg.role as "user" | "assistant",
        content: extractAnthropicText(msg.content),
      });
    }

    const requestPayload: RequestPayload = {
      messages,
      provider: `anthropic/${params.model}`,
      model: params.model,
      api_key_id: evaluateOptions.apiKeyId,
      max_tokens: params.max_tokens,
    };

    // Pre-request evaluation
    const preResult = await evaluate(
      "pre-request",
      requestPayload,
      this.policy,
      this.license,
      evaluateOptions,
    );

    this.emitter.enqueueMany(preResult.audit_events);

    if (!preResult.allowed) {
      const violation = preResult.violations[0];
      await this.emitter.flush();
      throw new TransparentGuardError(
        violation?.detail ?? "Request blocked by TransparentGuard policy.",
        "feature_requires_paid_tier",
      );
    }

    // Rebuild Anthropic params with redacted content
    const redactedPayload = preResult.payload as RequestPayload;
    const redactedMessages = redactedPayload.messages.filter(
      (m) => m.role !== "system",
    );
    const redactedSystem = redactedPayload.messages.find((m) => m.role === "system")?.content ?? params.system;

    const redactedParams: AnthropicCreateParams = {
      ...params,
      messages: redactedMessages.map((m) => ({
        role: m.role as "user" | "assistant",
        content: m.content ?? "",
      })),
      ...(redactedSystem ? { system: redactedSystem } : {}),
    };

    // Call the real Anthropic API
    const response = await this.inner.messages.create(redactedParams);

    // Extract text content from response
    const responseText = response.content
      .filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("\n");

    // Build response payload
    const responsePayload: ResponsePayload = {
      content: responseText,
      provider: `anthropic/${response.model}`,
      model: response.model,
      api_key_id: evaluateOptions.apiKeyId,
      usage: {
        prompt_tokens: response.usage?.input_tokens,
        completion_tokens: response.usage?.output_tokens,
      },
      system_prompt: params.system,
    };

    // Post-response evaluation
    const postResult = await evaluate(
      "post-response",
      responsePayload,
      this.policy,
      this.license,
      evaluateOptions,
    );

    this.emitter.enqueueMany(postResult.audit_events);

    if (!postResult.allowed) {
      const violation = postResult.violations[0];
      await this.emitter.flush();
      throw new TransparentGuardError(
        violation?.detail ?? "Response blocked by TransparentGuard policy.",
        "feature_requires_paid_tier",
      );
    }

    // Return response with potentially redacted content
    const finalPayload = postResult.payload as ResponsePayload;
    const finalContent = finalPayload.content;

    void this.emitter.flush();

    return {
      ...response,
      content: [{ type: "text", text: finalContent }],
    };
  }
}
