/**
 * TransparentGuard Runtime — Tool Allowlist Enforcement
 * Validates agent tool calls against declared allowed/blocked lists.
 */

import type { EvaluationContext, RequestPayload, RuleResult, ToolCall, Violation } from "../types.js";
import { buildAuditEvent } from "../audit/emitter.js";
import { detectPii } from "../evaluators/pii.js";
import type { PiiTarget } from "../types.js";

export async function enforceToolAllowlist(
  ctx: EvaluationContext,
): Promise<RuleResult> {
  const { rule, payload, policy, stage, requestId, tags } = ctx;
  const ruleId = rule.id;

  const requestPayload = payload as Partial<RequestPayload>;
  const toolCalls: ToolCall[] = requestPayload.tool_calls ?? [];

  if (toolCalls.length === 0) {
    return {
      ruleId,
      outcome: "skipped",
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "allowed", stage, payload, tags, requestId,
        detail: "tool_allowlist: no tool calls in payload",
      }),
    };
  }

  const blockedTools = new Set(rule.blocked_tools ?? []);
  const allowedTools = rule.allowed_tools ? new Set(rule.allowed_tools) : null;

  for (const toolCall of toolCalls) {
    const toolName = toolCall.function.name;

    // blocked_tools takes priority
    if (blockedTools.has(toolName)) {
      return makeViolation(ctx, {
        detail: `Tool "${toolName}" is explicitly blocked by policy.`,
        category: "tool_blocked",
      });
    }

    // allowed_tools: anything not in the list is blocked
    if (allowedTools && !allowedTools.has(toolName)) {
      return makeViolation(ctx, {
        detail: `Tool "${toolName}" is not in the allowed tools list: [${[...allowedTools].join(", ")}]`,
        category: "tool_not_allowed",
      });
    }

    // Scan tool arguments for PII if tool_argument_targets configured
    if (rule.tool_argument_targets?.length) {
      let args: string;
      try {
        args = typeof toolCall.function.arguments === "string"
          ? toolCall.function.arguments
          : JSON.stringify(toolCall.function.arguments);
      } catch {
        args = String(toolCall.function.arguments);
      }

      for (const target of rule.tool_argument_targets) {
        if (target.type === "pii") {
          const matches = detectPii(args, target as PiiTarget);
          if (matches.length > 0) {
            return makeViolation(ctx, {
              detail: `Tool "${toolName}" arguments contain PII: ${matches.map((m) => m.category).join(", ")}`,
              category: "tool_argument_pii",
            });
          }
        }
      }
    }
  }

  return {
    ruleId,
    outcome: "passed",
    auditEvent: buildAuditEvent({
      policy, rule, eventType: "allowed", stage, payload, tags, requestId,
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
      policy, rule,
      eventType: outcome === "blocked" ? "blocked" : "warned",
      stage, payload, tags, requestId, detail,
    }),
  };
}
