/**
 * TransparentGuard Runtime — Rate Limit Enforcement
 * Sliding-window in-memory rate limiter per API key.
 */

import type { EvaluationContext, RuleResult, Violation } from "../types.js";
import { buildAuditEvent } from "../audit/emitter.js";

// ---------------------------------------------------------------------------
// Sliding window counter
// Each bucket tracks request timestamps for a given key+window combination.
// ---------------------------------------------------------------------------

const minuteWindows = new Map<string, number[]>();
const hourWindows = new Map<string, number[]>();

function pruneWindow(timestamps: number[], windowMs: number): number[] {
  const cutoff = Date.now() - windowMs;
  return timestamps.filter((t) => t > cutoff);
}

function countWindow(map: Map<string, number[]>, key: string, windowMs: number): number {
  const raw = map.get(key) ?? [];
  const pruned = pruneWindow(raw, windowMs);
  map.set(key, pruned);
  return pruned.length;
}

function recordWindow(map: Map<string, number[]>, key: string, windowMs: number): void {
  const raw = map.get(key) ?? [];
  const pruned = pruneWindow(raw, windowMs);
  pruned.push(Date.now());
  map.set(key, pruned);
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

export async function enforceRateLimit(
  ctx: EvaluationContext,
): Promise<RuleResult> {
  const { rule, payload, policy, stage, requestId, apiKeyId, tags } = ctx;
  const ruleId = rule.id;

  if (!apiKeyId) {
    // Cannot enforce rate limits without a key identifier
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
        detail: "rate_limit: no api_key_id provided, skipping",
      }),
    };
  }

  const minuteKey = `${apiKeyId}:min`;
  const hourKey = `${apiKeyId}:hr`;
  const MINUTE_MS = 60_000;
  const HOUR_MS = 3_600_000;

  // Check per-minute limit
  if (rule.max_requests_per_minute_per_key !== undefined) {
    const count = countWindow(minuteWindows, minuteKey, MINUTE_MS);
    if (count >= rule.max_requests_per_minute_per_key) {
      return makeViolation(ctx, {
        detail: `Rate limit exceeded: ${count} requests in last 60s, max is ${rule.max_requests_per_minute_per_key}/min`,
        category: "rate_limit_per_minute",
      });
    }
  }

  // Check per-hour limit
  if (rule.max_requests_per_hour_per_key !== undefined) {
    const count = countWindow(hourWindows, hourKey, HOUR_MS);
    if (count >= rule.max_requests_per_hour_per_key) {
      return makeViolation(ctx, {
        detail: `Rate limit exceeded: ${count} requests in last 3600s, max is ${rule.max_requests_per_hour_per_key}/hr`,
        category: "rate_limit_per_hour",
      });
    }
  }

  // Record this request
  recordWindow(minuteWindows, minuteKey, MINUTE_MS);
  recordWindow(hourWindows, hourKey, HOUR_MS);

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
