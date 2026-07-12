/**
 * TransparentGuard Runtime — Provider Allowlist Enforcement
 * Blocks calls to LLM providers not declared in the policy.
 */

import type { EvaluationContext, RuleResult, Violation } from "../types.js";
import { buildAuditEvent, makeId } from "../audit/emitter.js";

/**
 * Matches a provider string against an allowlist entry.
 * Supports wildcards: "anthropic/*" matches any Anthropic model.
 */
function matchesProvider(actual: string, allowed: string): boolean {
  if (allowed === "any") return true;
  if (allowed === actual) return true;
  if (allowed.endsWith("/*")) {
    const prefix = allowed.slice(0, -2);
    return actual === prefix || actual.startsWith(`${prefix}/`);
  }
  return false;
}

export async function enforceProviderAllowlist(
  ctx: EvaluationContext,
): Promise<RuleResult> {
  const { rule, payload, policy, stage, requestId, tags } = ctx;
  const ruleId = rule.id;

  const provider =
    "provider" in payload ? (payload.provider ?? "") : "";

  if (!provider) {
    // No provider specified — cannot enforce; pass through with a warning
    const auditEvent = buildAuditEvent({
      policy,
      rule,
      eventType: "warned",
      stage,
      payload,
      tags,
      requestId,
      detail: "provider_allowlist: no provider specified on payload, skipping enforcement",
    });
    return {
      ruleId,
      outcome: "warned",
      violation: {
        rule_id: ruleId,
        rule_description: rule.description,
        outcome: "warned",
        detail: "No provider specified; allowlist enforcement skipped.",
        category: "provider_allowlist",
      } satisfies Violation,
      auditEvent,
    };
  }

  const allowedProviders = rule.allowed_providers ?? [];
  const isAllowed = allowedProviders.some((a) => matchesProvider(provider, a));

  if (isAllowed) {
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

  // Violation
  const violation: Violation = {
    rule_id: ruleId,
    rule_description: rule.description,
    outcome: rule.on_violation === "block" ? "blocked" : "warned",
    detail: `Provider "${provider}" is not in the allowlist: [${allowedProviders.join(", ")}]`,
    category: "provider_allowlist",
  };

  const auditEvent = buildAuditEvent({
    policy,
    rule,
    eventType: rule.on_violation === "block" ? "blocked" : "warned",
    stage,
    payload,
    tags,
    requestId,
    detail: violation.detail,
  });

  return {
    ruleId,
    outcome: violation.outcome,
    violation,
    auditEvent,
  };
}

void makeId; // imported for side-effects only in this module
