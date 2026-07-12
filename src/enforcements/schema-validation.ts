/**
 * TransparentGuard Runtime — Schema Validation Enforcement
 * Validates LLM response content against a declared JSON Schema.
 */

import Ajv from "ajv";
import addFormats from "ajv-formats";
import type { EvaluationContext, ResponsePayload, RuleResult, Violation } from "../types.js";
import { buildAuditEvent } from "../audit/emitter.js";

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv as Parameters<typeof addFormats>[0]);

// Cache compiled validators keyed by rule ID
const validatorCache = new Map<string, ReturnType<typeof ajv.compile>>();

export async function enforceSchemaValidation(
  ctx: EvaluationContext,
): Promise<RuleResult> {
  const { rule, payload, policy, stage, requestId, tags } = ctx;
  const ruleId = rule.id;

  if (!("content" in payload)) {
    return {
      ruleId,
      outcome: "skipped",
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "allowed", stage, payload, tags, requestId,
        detail: "schema_validation: skipped (not a response payload)",
      }),
    };
  }

  const responsePayload = payload as ResponsePayload;
  const content = responsePayload.content;

  // Attempt to parse content as JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return makeViolation(ctx, {
      detail: "Response content is not valid JSON and cannot be validated against the expected schema.",
      category: "schema_validation_parse_error",
    });
  }

  // Get or compile validator
  let validate = validatorCache.get(ruleId);
  if (!validate) {
    try {
      validate = ajv.compile(rule.expected_schema!);
      validatorCache.set(ruleId, validate);
    } catch (err) {
      // Schema itself is invalid — treat as a runtime error
      return {
        ruleId,
        outcome: "warned",
        violation: {
          rule_id: ruleId,
          rule_description: rule.description,
          outcome: "warned",
          detail: `Invalid expected_schema in rule "${ruleId}": ${String(err)}`,
          category: "schema_validation_config_error",
        } satisfies Violation,
        auditEvent: buildAuditEvent({
          policy, rule, eventType: "warned", stage, payload, tags, requestId,
          detail: `Invalid schema configuration: ${String(err)}`,
        }),
      };
    }
  }

  const valid = validate(parsed);
  if (valid) {
    return {
      ruleId,
      outcome: "passed",
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "allowed", stage, payload, tags, requestId,
      }),
    };
  }

  const messages = (validate.errors ?? [])
    .map((e) => `${e.instancePath || "/"}: ${e.message}`)
    .join("; ");

  return makeViolation(ctx, {
    detail: `Response does not conform to expected schema: ${messages}`,
    category: "schema_validation_mismatch",
  });
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
