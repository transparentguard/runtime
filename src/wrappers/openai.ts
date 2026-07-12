/**
 * TransparentGuard Runtime — OpenAI Wrapper
 * Drop-in replacement for the OpenAI client that enforces TPS policies
 * transparently on every chat completion call.
 *
 * Usage:
 *   import { tg } from "@transparentguard/runtime";
 *   import OpenAI from "openai";
 *
 *   const client = tg.wrap(new OpenAI(), { policy: "./policies/production.yaml" });
 *   const response = await client.chat.completions.create({ ... });
 *   // Identical to standard OpenAI usage — enforcement is invisible.
 */

import type { TransparentGuardOptions, EvaluateOptions, RequestPayload, ResponsePayload, Message } from "../types.js";
import type { LicenseStatus } from "../license/checker.js";
import { evaluate } from "../engine.js";
import { AuditEmitter } from "../audit/emitter.js";
import { TransparentGuardError } from "../license/checker.js";

// ---------------------------------------------------------------------------
// Minimal OpenAI type surface — avoids requiring openai as a peer dep at compile time
// ---------------------------------------------------------------------------

export interface OpenAIMessage {
  role: "system" | "user" | "assistant" | "tool" | "function";
  content: string | null;
  name?: string;
  tool_call_id?: string;
}

export interface OpenAIChatCompletionCreateParams {
  messages: OpenAIMessage[];
  model: string;
  max_tokens?: number;
  stream?: boolean;
  [key: string]: unknown;
}

export interface OpenAIChatCompletionChoice {
  message: OpenAIMessage;
  finish_reason?: string;
  index?: number;
}

export interface OpenAIChatCompletion {
  id: string;
  choices: OpenAIChatCompletionChoice[];
  model: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
  [key: string]: unknown;
}

export interface OpenAIClientLike {
  chat: {
    completions: {
      create(params: OpenAIChatCompletionCreateParams): Promise<OpenAIChatCompletion>;
    };
  };
}

// ---------------------------------------------------------------------------
// Wrapped client
// ---------------------------------------------------------------------------

export class WrappedOpenAIClient {
  private readonly inner: OpenAIClientLike;
  private readonly policy: import("../types.js").TPSPolicy;
  private readonly license: LicenseStatus;
  private readonly options: TransparentGuardOptions;
  private readonly emitter: AuditEmitter;

  constructor(
    inner: OpenAIClientLike,
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

  get chat() {
    return {
      completions: {
        create: this.createCompletion.bind(this),
      },
    };
  }

  private async createCompletion(
    params: OpenAIChatCompletionCreateParams,
    evaluateOptions: EvaluateOptions = {},
  ): Promise<OpenAIChatCompletion> {
    // Build request payload
    const requestPayload: RequestPayload = {
      messages: params.messages.map((m): Message => ({
        role: m.role as Message["role"],
        content: m.content,
        name: m.name,
        tool_call_id: m.tool_call_id,
      })),
      provider: `openai/${params.model}`,
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

    // Use potentially redacted payload for the actual API call
    const redactedPayload = preResult.payload as RequestPayload;
    const redactedParams: OpenAIChatCompletionCreateParams = {
      ...params,
      messages: redactedPayload.messages.map((m) => ({
        role: m.role,
        content: m.content,
        ...(m.name ? { name: m.name } : {}),
        ...(m.tool_call_id ? { tool_call_id: m.tool_call_id } : {}),
      })),
    };

    // Call the real OpenAI API
    const completion = await this.inner.chat.completions.create(redactedParams);

    // Extract response content
    const responseContent = completion.choices[0]?.message?.content ?? "";

    // Build response payload for post-response evaluation
    const responsePayload: ResponsePayload = {
      content: responseContent,
      provider: `openai/${completion.model}`,
      model: completion.model,
      api_key_id: evaluateOptions.apiKeyId,
      usage: completion.usage,
      // Pass system prompt for confidentiality checking
      system_prompt: params.messages.find((m) => m.role === "system")?.content ?? undefined,
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

    // Return completion with potentially redacted response content
    const finalPayload = postResult.payload as ResponsePayload;
    const finalContent = finalPayload.content;

    const result: OpenAIChatCompletion = {
      ...completion,
      choices: completion.choices.map((choice, i) => {
        if (i === 0) {
          return {
            ...choice,
            message: {
              ...choice.message,
              content: finalContent,
            },
          };
        }
        return choice;
      }),
    };

    // Flush audit events asynchronously
    void this.emitter.flush();

    return result;
  }
}
