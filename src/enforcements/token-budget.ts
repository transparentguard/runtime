/**
 * TransparentGuard Runtime — Token Budget Enforcement
 * Enforces per-request and per-day/per-hour token limits.
 * Uses a simple approximation for token counting (no tiktoken dependency in free tier).
 */

import type { EvaluationContext, RequestPayload, RuleResult, Violation } from "../types.js";
import { buildAuditEvent } from "../audit/emitter.js";

// ---------------------------------------------------------------------------
// Token counting — approximation suitable for enforcement decisions
// ---------------------------------------------------------------------------

/**
 * Approximates token count from text.
 * Uses the commonly cited ~4 chars/token heuristic for English text.
 * This is accurate within 10–15% for typical LLM inputs.
 */
export function approximateTokenCount(text: string): number {
  if (!text) return 0;
  // Count words + punctuation groups, then scale
  const words = text.trim().split(/\s+/).length;
  const chars = text.length;
  // Blend word-count and char-count estimates
  return Math.ceil((words * 1.3 + chars / 4) / 2);
}

function countRequestTokens(payload: RequestPayload): number {
  let total = 0;
  for (const msg of payload.messages) {
    if (msg.content) total += approximateTokenCount(msg.content);
    if (msg.name) total += approximateTokenCount(msg.name);
  }
  if (payload.max_tokens) total += payload.max_tokens;
  return total;
}

// ---------------------------------------------------------------------------
// In-memory token usage tracking
// Keyed by: `${apiKeyId}:day:${YYYY-MM-DD}` and `${apiKeyId}:hour:${YYYY-MM-DDTHH}`
// ---------------------------------------------------------------------------

const tokenUsage = new Map<string, number>();

function dayKey(apiKeyId: string): string {
  const d = new Date();
  const date = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}`;
  return `${apiKeyId}:day:${date}`;
}

function hourKey(apiKeyId: string): string {
  const d = new Date();
  const date = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}T${String(d.getUTCHours()).padStart(2, "0")}`;
  return `${apiKeyId}:hour:${date}`;
}

export function recordTokenUsage(apiKeyId: string, tokens: number): void {
  const dk = dayKey(apiKeyId);
  const hk = hourKey(apiKeyId);
  tokenUsage.set(dk, (tokenUsage.get(dk) ?? 0) + tokens);
  tokenUsage.set(hk, (tokenUsage.get(hk) ?? 0) + tokens);
}

export function getTokenUsageDay(apiKeyId: string): number {
  return tokenUsage.get(dayKey(apiKeyId)) ?? 0;
}

export function getTokenUsageHour(apiKeyId: string): number {
  return tokenUsage.get(hourKey(apiKeyId)) ?? 0;
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

export async function enforceTokenBudget(
  ctx: EvaluationContext,
): Promise<RuleResult> {
  const { rule, payload, policy, stage, requestId, apiKeyId, tags } = ctx;
  const ruleId = rule.id;

  // Token budget only applies to pre-request stage on request payloads
  if (!("messages" in payload)) {
    return {
      ruleId,
      outcome: "skipped",
      auditEvent: buildAuditEvent({
        policy,
        rule,
        eventType: "allowed",
        stage,
        payload,
        tags,
        requestId,
        detail: "token_budget: skipped (not a request payload)",
      }),
    };
  }

  const requestPayload = payload as RequestPayload;
  const requestTokens = countRequestTokens(requestPayload);

  // Per-request check
  if (rule.max_tokens_per_request !== undefined) {
    if (requestTokens > rule.max_tokens_per_request) {
      return makeViolation(ctx, {
        detail: `Request exceeds token limit: ${requestTokens} tokens > max ${rule.max_tokens_per_request} per request`,
        category: "token_budget_per_request",
      });
    }
  }

  // Per-key daily / hourly checks
  if (apiKeyId) {
    if (rule.max_tokens_per_day_per_key !== undefined) {
      const dayUsage = getTokenUsageDay(apiKeyId);
      if (dayUsage + requestTokens > rule.max_tokens_per_day_per_key) {
        return makeViolation(ctx, {
          detail: `Daily token limit reached for key: ${dayUsage + requestTokens} > max ${rule.max_tokens_per_day_per_key} per day`,
          category: "token_budget_per_day",
        });
      }
    }

    if (rule.max_tokens_per_hour_per_key !== undefined) {
      const hourUsage = getTokenUsageHour(apiKeyId);
      if (hourUsage + requestTokens > rule.max_tokens_per_hour_per_key) {
        return makeViolation(ctx, {
          detail: `Hourly token limit reached for key: ${hourUsage + requestTokens} > max ${rule.max_tokens_per_hour_per_key} per hour`,
          category: "token_budget_per_hour",
        });
      }
    }

    // Record usage (happens only if not blocked)
    recordTokenUsage(apiKeyId, requestTokens);
  }

  return {
    ruleId,
    outcome: "passed",
    auditEvent: buildAuditEvent({
      policy,
      rule,
      eventType: "allowed",
      stage,
      payload,
      tags,
      requestId,
    }),
  };
}

function makeViolation(
  ctx: EvaluationContext,
  { detail, category }: { detail: string; category: string },
): RuleResult {
  const { rule, payload, policy, stage, requestId, tags } = ctx;
  const outcome = rule.on_violation === "block" ? "blocked" : "warned";
  const violation: Violation = {
    rule_id: rule.id,
    rule_description: rule.description,
    outcome,
    detail,
    category,
  };
  return {
    ruleId: rule.id,
    outcome,
    violation,
    auditEvent: buildAuditEvent({
      policy,
      rule,
      eventType: outcome === "blocked" ? "blocked" : "warned",
      stage,
      payload,
      tags,
      requestId,
      detail,
    }),
  };
}
