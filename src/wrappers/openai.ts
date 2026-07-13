/**
 * TransparentGuard Runtime — OpenAI Wrapper
 * Drop-in replacement for the OpenAI client that enforces TPS policies
 * transparently on every chat completion call.
 * Supports both streaming and non-streaming modes.
 * Streaming uses buffer mode by default: chunks are collected, the assembled
 * response is evaluated, then content is re-yielded as an async generator.
 *
 * Usage:
 *   import { tg } from "@transparentguard/runtime";
 *   import OpenAI from "openai";
 *
 *   const client = tg.wrap(new OpenAI(), { policy: "./policies/production.yaml" });
 *   const response = await client.chat.completions.create({ ... });
 */

import type {
  TransparentGuardOptions,
  EvaluateOptions,
  RequestPayload,
  ResponsePayload,
  Message,
} from "../types.js";
import type { LicenseStatus } from "../license/checker.js";
import { evaluate } from "../engine.js";
import { AuditEmitter } from "../audit/emitter.js";
import { TransparentGuardError } from "../license/checker.js";
import type { TPSPolicy } from "../types.js";

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

/** Streaming chunk delta */
export interface OpenAIChatCompletionChunkDelta {
  role?: string;
  content?: string | null;
}

export interface OpenAIChatCompletionChunkChoice {
  delta: OpenAIChatCompletionChunkDelta;
  finish_reason?: string | null;
  index?: number;
}

export interface OpenAIChatCompletionChunk {
  id: string;
  model: string;
  choices: OpenAIChatCompletionChunkChoice[];
  [key: string]: unknown;
}

export interface OpenAIClientLike {
  chat: {
    completions: {
      create(params: OpenAIChatCompletionCreateParams): Promise<OpenAIChatCompletion>;
      create(params: OpenAIChatCompletionCreateParams & { stream: true }): Promise<AsyncIterable<OpenAIChatCompletionChunk>>;
    };
  };
}

// ---------------------------------------------------------------------------
// Wrapped client
// ---------------------------------------------------------------------------

export class WrappedOpenAIClient {
  private readonly inner: OpenAIClientLike;
  private readonly policy: TPSPolicy;
  private readonly license: LicenseStatus;
  private readonly options: TransparentGuardOptions;
  private readonly emitter: AuditEmitter;

  constructor(
    inner: OpenAIClientLike,
    policy: TPSPolicy,
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
        create: this.createCompletion.bind(this) as typeof this.createCompletion,
      },
    };
  }

  async createCompletion(
    params: OpenAIChatCompletionCreateParams & { stream?: false },
    evaluateOptions?: EvaluateOptions,
  ): Promise<OpenAIChatCompletion>;
  async createCompletion(
    params: OpenAIChatCompletionCreateParams & { stream: true },
    evaluateOptions?: EvaluateOptions,
  ): Promise<AsyncGenerator<OpenAIChatCompletionChunk>>;
  async createCompletion(
    params: OpenAIChatCompletionCreateParams,
    evaluateOptions: EvaluateOptions = {},
  ): Promise<OpenAIChatCompletion | AsyncGenerator<OpenAIChatCompletionChunk>> {
    // Merge API key from stored options
    const evalOptions: EvaluateOptions = {
      ...evaluateOptions,
      apiKey: evaluateOptions.apiKey ?? this.options.apiKey,
    };

    // Build request payload for pre-request evaluation
    const requestPayload: RequestPayload = {
      messages: params.messages.map((m): Message => ({
        role: m.role as Message["role"],
        content: m.content,
        name: m.name,
        tool_call_id: m.tool_call_id,
      })),
      provider: `openai/${params.model}`,
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

    // Streaming path — buffer all chunks, evaluate full response, re-yield
    if (params.stream === true) {
      return this.createStreamingCompletion(redactedParams, params, evalOptions);
    }

    // Non-streaming path
    return this.createNonStreamingCompletion(redactedParams, params, evalOptions);
  }

  private async createNonStreamingCompletion(
    redactedParams: OpenAIChatCompletionCreateParams,
    originalParams: OpenAIChatCompletionCreateParams,
    evalOptions: EvaluateOptions,
  ): Promise<OpenAIChatCompletion> {
    const completion = await this.inner.chat.completions.create(redactedParams);

    const responseContent = completion.choices[0]?.message?.content ?? "";

    const responsePayload: ResponsePayload = {
      content: responseContent,
      provider: `openai/${completion.model}`,
      model: completion.model,
      api_key_id: evalOptions.apiKeyId,
      usage: completion.usage,
      system_prompt: originalParams.messages.find((m) => m.role === "system")?.content ?? undefined,
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

    const result: OpenAIChatCompletion = {
      ...completion,
      choices: completion.choices.map((choice, i) => {
        if (i === 0) {
          return {
            ...choice,
            message: { ...choice.message, content: finalPayload.content },
          };
        }
        return choice;
      }),
    };

    void this.emitter.flush();
    return result;
  }

  private async createStreamingCompletion(
    redactedParams: OpenAIChatCompletionCreateParams,
    originalParams: OpenAIChatCompletionCreateParams,
    evalOptions: EvaluateOptions,
  ): Promise<AsyncGenerator<OpenAIChatCompletionChunk>> {
    // Buffer mode: collect all streaming chunks, evaluate, then re-yield as async generator.
    // This gives full post-response coverage at the cost of delaying first-token.
    // For window or passthrough mode, callers can use the runtime evaluate() API directly.
    const streamParams = { ...redactedParams, stream: true as const };
    const stream = await (this.inner.chat.completions.create(streamParams) as unknown as Promise<AsyncIterable<OpenAIChatCompletionChunk>>);

    const chunks: OpenAIChatCompletionChunk[] = [];
    let fullContent = "";
    let lastChunk: OpenAIChatCompletionChunk | undefined;

    for await (const chunk of stream) {
      chunks.push(chunk);
      const delta = chunk.choices[0]?.delta?.content;
      if (delta) fullContent += delta;
      lastChunk = chunk;
    }

    if (!lastChunk) {
      // Empty stream — return empty generator
      return (async function* () { /* empty */ })();
    }

    const responsePayload: ResponsePayload = {
      content: fullContent,
      provider: `openai/${lastChunk.model}`,
      model: lastChunk.model,
      api_key_id: evalOptions.apiKeyId,
      system_prompt: originalParams.messages.find((m) => m.role === "system")?.content ?? undefined,
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
      // Return a generator that immediately throws
      return (async function* () { throw err; })();
    }

    const finalPayload = postResult.payload as ResponsePayload;
    const finalContent = finalPayload.content;
    void this.emitter.flush();

    // Re-yield: if content was redacted, yield a single synthetic chunk with the redacted content.
    // Otherwise yield all original chunks as-is.
    const contentWasModified = finalContent !== fullContent;
    const chunksToYield = chunks;

    return (async function* () {
      if (contentWasModified && chunksToYield.length > 0) {
        // Yield a single synthetic chunk with the redacted/modified full content
        const syntheticChunk: OpenAIChatCompletionChunk = {
          ...chunksToYield[0]!,
          choices: [{
            delta: { role: "assistant", content: finalContent },
            finish_reason: "stop",
            index: 0,
          }],
        };
        yield syntheticChunk;
      } else {
        for (const chunk of chunksToYield) {
          yield chunk;
        }
      }
    })();
  }
}
