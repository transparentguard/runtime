/**
 * TransparentGuard Runtime — Data Residency Enforcement
 * Blocks requests routed to LLM providers outside declared allowed regions.
 */

import type { EvaluationContext, RequestPayload, RuleResult, Violation } from "../types.js";
import { buildAuditEvent } from "../audit/emitter.js";

export async function enforceDataResidency(
  ctx: EvaluationContext,
): Promise<RuleResult> {
  const { rule, payload, policy, stage, requestId, tags } = ctx;
  const ruleId = rule.id;

  const requestPayload = payload as Partial<RequestPayload>;
  const region =
    requestPayload.metadata?.["tg_region"] ??
    requestPayload.metadata?.["region"] ??
    requestPayload.metadata?.["provider_region"];

  if (!region) {
    // No region metadata — cannot enforce; warn and pass
    const violation: Violation = {
      rule_id: ruleId,
      rule_description: rule.description,
      outcome: "warned",
      detail: "data_residency: no region metadata on request (set metadata.tg_region). Cannot enforce residency.",
      category: "data_residency_missing_region",
    };
    return {
      ruleId,
      outcome: "warned",
      violation,
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "warned", stage, payload, tags, requestId,
        detail: violation.detail,
      }),
    };
  }

  const allowedRegions = rule.allowed_regions ?? [];
  const isAllowed = allowedRegions.some((allowed) => {
    if (allowed === region) return true;
    // Prefix match: "eu-*" matches "eu-west-1", "eu-central-1", etc.
    if (allowed.endsWith("-*")) {
      const prefix = allowed.slice(0, -2);
      return region.startsWith(prefix);
    }
    return false;
  });

  if (isAllowed) {
    return {
      ruleId,
      outcome: "passed",
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "allowed", stage, payload, tags, requestId,
      }),
    };
  }

  const outcome = rule.on_violation === "block" ? "blocked" : "warned";
  const violation: Violation = {
    rule_id: ruleId,
    rule_description: rule.description,
    outcome,
    detail: `Region "${region}" is not in the allowed regions list: [${allowedRegions.join(", ")}]. Data may not leave the declared residency boundary.`,
    category: "data_residency_violation",
  };

  return {
    ruleId,
    outcome,
    violation,
    auditEvent: buildAuditEvent({
      policy, rule,
      eventType: outcome === "blocked" ? "blocked" : "warned",
      stage, payload, tags, requestId,
      detail: violation.detail,
    }),
  };
}
