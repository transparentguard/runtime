/**
 * TransparentGuard Runtime — Anthropic Wrapper
 * Drop-in replacement for the Anthropic client that enforces TPS policies
 * transparently on every messages.create() call.
 * Supports both streaming and non-streaming modes.
 *
 * Usage:
 *   import { tg } from "@transparentguard/runtime";
 *   import Anthropic from "@anthropic-ai/sdk";
 *
 *   const client = tg.wrap(new Anthropic(), { policy: "./policies/production.yaml" });
 *   const response = await client.messages.create({ ... });
 */

import type {
  TransparentGuardOptions,
  EvaluateOptions,
  RequestPayload,
  ResponsePayload,
  Message,
  TPSPolicy,
} from "../types.js";
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
  stream?: boolean;
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

/** Streaming event from Anthropic SSE */
export interface AnthropicStreamEvent {
  type: string;
  delta?: { type: string; text?: string };
  message?: AnthropicResponse;
  index?: number;
  [key: string]: unknown;
}

export interface AnthropicClientLike {
  messages: {
    create(params: AnthropicCreateParams): Promise<AnthropicResponse>;
    create(params: AnthropicCreateParams & { stream: true }): Promise<AsyncIterable<AnthropicStreamEvent>>;
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
  private readonly policy: TPSPolicy;
  private readonly license: LicenseStatus;
  private readonly options: TransparentGuardOptions;
  private readonly emitter: AuditEmitter;

  constructor(
    inner: AnthropicClientLike,
    policy: TPSPolicy,
    license: LicenseStatus,
    options: TransparentGuardOptions,
  ) {
    this.inner = inner;
    this.policy = policy;
    this.license = license;
    this.options = options;
    this.emitter = new AuditEmitter(policy.audit, license.features);
  }

  get messages() {
    return {
      create: this.createMessage.bind(this) as typeof this.createMessage,
    };
  }

  async createMessage(
    params: AnthropicCreateParams & { stream?: false },
    evaluateOptions?: EvaluateOptions,
  ): Promise<AnthropicResponse>;
  async createMessage(
    params: AnthropicCreateParams & { stream: true },
    evaluateOptions?: EvaluateOptions,
  ): Promise<AsyncGenerator<AnthropicStreamEvent>>;
  async createMessage(
    params: AnthropicCreateParams,
    evaluateOptions: EvaluateOptions = {},
  ): Promise<AnthropicResponse | AsyncGenerator<AnthropicStreamEvent>> {
    // Merge API key from stored options
    const evalOptions: EvaluateOptions = {
      ...evaluateOptions,
      apiKey: evaluateOptions.apiKey ?? this.options.apiKey,
    };

    // Convert Anthropic messages to TPS RequestPayload
    const messages: Message[] = [];
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
      api_key_id: evalOptions.apiKeyId,
      max_tokens: params.max_tokens,
    };

    // Pre-request evaluation
    const preResult = await evaluate(
      "pre-request",
      requestPayload,
      this.policy,
      this.license,
      evalOptions,
    );

    this.emitter.enqueueMany(preResult.audit_events);

    if (!preResult.allowed) {
      const violation = preResult.violations[0];
      await this.emitter.flush();
      throw new TransparentGuardError(
        violation?.detail ?? "Request blocked by TransparentGuard policy.",
        "policy_violation",
      );
    }

    // Rebuild Anthropic params with redacted content
    const redactedPayload = preResult.payload as RequestPayload;
    const redactedMessages = redactedPayload.messages.filter((m) => m.role !== "system");
    const redactedSystem = redactedPayload.messages.find((m) => m.role === "system")?.content ?? params.system;

    const redactedParams: AnthropicCreateParams = {
      ...params,
      messages: redactedMessages.map((m) => ({
        role: m.role as "user" | "assistant",
        content: m.content ?? "",
      })),
      ...(redactedSystem ? { system: redactedSystem } : {}),
    };

    if (params.stream === true) {
      return this.createStreamingMessage(redactedParams, params, evalOptions);
    }

    return this.createNonStreamingMessage(redactedParams, params, evalOptions);
  }

  private async createNonStreamingMessage(
    redactedParams: AnthropicCreateParams,
    originalParams: AnthropicCreateParams,
    evalOptions: EvaluateOptions,
  ): Promise<AnthropicResponse> {
    const response = await this.inner.messages.create(redactedParams);

    const responseText = response.content
      .filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("\n");

    const responsePayload: ResponsePayload = {
      content: responseText,
      provider: `anthropic/${response.model}`,
      model: response.model,
      api_key_id: evalOptions.apiKeyId,
      usage: {
        prompt_tokens: response.usage?.input_tokens,
        completion_tokens: response.usage?.output_tokens,
      },
      system_prompt: originalParams.system,
    };

    const postResult = await evaluate(
      "post-response",
      responsePayload,
      this.policy,
      this.license,
      evalOptions,
    );

    this.emitter.enqueueMany(postResult.audit_events);

    if (!postResult.allowed) {
      const violation = postResult.violations[0];
      await this.emitter.flush();
      throw new TransparentGuardError(
        violation?.detail ?? "Response blocked by TransparentGuard policy.",
        "policy_violation",
      );
    }

    const finalPayload = postResult.payload as ResponsePayload;
    void this.emitter.flush();

    return {
      ...response,
      content: [{ type: "text", text: finalPayload.content }],
    };
  }

  private async createStreamingMessage(
    redactedParams: AnthropicCreateParams,
    originalParams: AnthropicCreateParams,
    evalOptions: EvaluateOptions,
  ): Promise<AsyncGenerator<AnthropicStreamEvent>> {
    const streamParams = { ...redactedParams, stream: true as const };
    const stream = await (this.inner.messages.create(streamParams) as unknown as Promise<AsyncIterable<AnthropicStreamEvent>>);

    const events: AnthropicStreamEvent[] = [];
    let fullText = "";
    let finalMessage: AnthropicResponse | undefined;

    for await (const event of stream) {
      events.push(event);
      if (event.type === "content_block_delta" && event.delta?.type === "text_delta" && event.delta.text) {
        fullText += event.delta.text;
      }
      if (event.type === "message_stop" && event.message) {
        finalMessage = event.message;
      }
    }

    const model = finalMessage?.model ?? redactedParams.model;

    const responsePayload: ResponsePayload = {
      content: fullText,
      provider: `anthropic/${model}`,
      model,
      api_key_id: evalOptions.apiKeyId,
      usage: {
        prompt_tokens: finalMessage?.usage?.input_tokens,
        completion_tokens: finalMessage?.usage?.output_tokens,
      },
      system_prompt: originalParams.system,
    };

    const postResult = await evaluate(
      "post-response",
      responsePayload,
      this.policy,
      this.license,
      evalOptions,
    );

    this.emitter.enqueueMany(postResult.audit_events);

    if (!postResult.allowed) {
      const violation = postResult.violations[0];
      await this.emitter.flush();
      const err = new TransparentGuardError(
        violation?.detail ?? "Response blocked by TransparentGuard policy.",
        "policy_violation",
      );
      return (async function* () { throw err; })();
    }

    const finalPayload = postResult.payload as ResponsePayload;
    const contentModified = finalPayload.content !== fullText;
    void this.emitter.flush();

    const eventsToYield = events;
    const outputContent = finalPayload.content;

    return (async function* () {
      if (contentModified) {
        // Yield a synthetic text delta with the redacted content
        yield {
          type: "content_block_delta",
          index: 0,
          delta: { type: "text_delta", text: outputContent },
        } as AnthropicStreamEvent;
        yield { type: "message_stop" } as AnthropicStreamEvent;
      } else {
        for (const event of eventsToYield) {
          yield event;
        }
      }
    })();
  }
}
