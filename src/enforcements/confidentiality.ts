/**
 * TransparentGuard Runtime — Confidentiality Enforcement
 * Detects system prompt leakage and context document exposure in responses.
 * Uses both canary token injection/detection and n-gram similarity scoring.
 */

import crypto from "crypto";
import type {
  EvaluationContext,
  RequestPayload,
  ResponsePayload,
  RuleResult,
  Violation,
} from "../types.js";
import { buildAuditEvent } from "../audit/emitter.js";

// ---------------------------------------------------------------------------
// Canary token storage — keyed by requestId
// ---------------------------------------------------------------------------

const canaryStore = new Map<string, string>();

/**
 * Injects a random canary token into the system prompt at pre-request time.
 * Returns the modified system prompt and stores the token for later detection.
 */
export function injectCanaryToken(systemPrompt: string, requestId: string): string {
  const token = `tg_canary_${crypto.randomBytes(12).toString("hex")}`;
  canaryStore.set(requestId, token);
  // Inject invisibly near the beginning of the system prompt
  return `${token} ${systemPrompt}`;
}

/**
 * Checks if the canary token we injected appears in the response.
 * Returns true if the token is found (leakage detected).
 */
export function checkCanaryToken(responseContent: string, requestId: string): boolean {
  const token = canaryStore.get(requestId);
  if (!token) return false;
  // Clean up after detection
  canaryStore.delete(requestId);
  return responseContent.includes(token);
}

// ---------------------------------------------------------------------------
// N-gram similarity scoring (Jaccard similarity on character 4-grams)
// Used to detect partial system prompt leakage without exact string matching.
// ---------------------------------------------------------------------------

function buildNgrams(text: string, n = 4): Set<string> {
  const lower = text.toLowerCase().replace(/\s+/g, " ").trim();
  const ngrams = new Set<string>();
  for (let i = 0; i <= lower.length - n; i++) {
    ngrams.add(lower.slice(i, i + n));
  }
  return ngrams;
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  const intersection = [...a].filter((x) => b.has(x)).length;
  const union = new Set([...a, ...b]).size;
  return union === 0 ? 0 : intersection / union;
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

export async function enforceConfidentiality(
  ctx: EvaluationContext,
): Promise<RuleResult> {
  const { rule, payload, policy, stage, requestId, tags } = ctx;
  const ruleId = rule.id;

  // This rule only applies post-response
  if (!("content" in payload)) {
    return {
      ruleId,
      outcome: "skipped",
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "allowed", stage, payload, tags, requestId,
        detail: "confidentiality: skipped (not a response payload)",
      }),
    };
  }

  const responsePayload = payload as ResponsePayload;
  const responseContent = responsePayload.content;
  const similarityThreshold = rule.similarity_threshold ?? 0.85;

  // Determine what we're protecting
  let protectedContent: string | undefined;
  switch (rule.protected_content_ref) {
    case "system_prompt":
      protectedContent = responsePayload.system_prompt;
      break;
    case "context_documents":
      protectedContent = responsePayload.context_documents?.join("\n");
      break;
    case "user_provided_data":
      // Not directly accessible post-response — skip
      protectedContent = undefined;
      break;
    default:
      protectedContent = responsePayload.system_prompt;
  }

  if (!protectedContent) {
    return {
      ruleId,
      outcome: "skipped",
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "allowed", stage, payload, tags, requestId,
        detail: `confidentiality: no protected content available for ref "${rule.protected_content_ref}"`,
      }),
    };
  }

  // Canary token detection (binary, no false positives)
  if (rule.canary_tokens) {
    const leaked = checkCanaryToken(responseContent, requestId);
    if (leaked) {
      return makeViolation(ctx, {
        detail: "Canary token detected in response — system prompt content is being leaked.",
        category: "confidentiality_canary_detected",
      });
    }
  }

  // N-gram similarity check
  const protectedNgrams = buildNgrams(protectedContent);
  const responseNgrams = buildNgrams(responseContent);
  const similarity = jaccardSimilarity(protectedNgrams, responseNgrams);

  if (similarity >= similarityThreshold) {
    return makeViolation(ctx, {
      detail: `Response similarity to protected content (${(similarity * 100).toFixed(1)}%) exceeds threshold (${(similarityThreshold * 100).toFixed(1)}%). Possible ${rule.protected_content_ref ?? "content"} leakage.`,
      category: "confidentiality_similarity_exceeded",
    });
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
