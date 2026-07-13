/**
 * TransparentGuard Runtime — Evaluation Engine
 * The core rule graph builder and evaluate() function.
 * Implements all TPS v1.0 rule types.
 */

import crypto from "crypto";
import type {
  EvaluateOptions,
  EvaluateResult,
  EvaluationContext,
  Message,
  RequestPayload,
  ResponsePayload,
  RuleResult,
  RuleStage,
  TPSPolicy,
  TPSRule,
  Violation,
} from "./types.js";
import { buildAuditEvent, makeId } from "./audit/emitter.js";
import { detectPii, redactText, expandCategories } from "./evaluators/pii.js";
import { callClassifierApi, heuristicClassify } from "./evaluators/classifier-api.js";
import { enforceProviderAllowlist } from "./enforcements/provider-allowlist.js";
import { enforceTokenBudget } from "./enforcements/token-budget.js";
import { enforceRateLimit } from "./enforcements/rate-limit.js";
import { enforceToolAllowlist } from "./enforcements/tool-allowlist.js";
import { enforceSchemaValidation } from "./enforcements/schema-validation.js";
import { enforceConfidentiality } from "./enforcements/confidentiality.js";
import { enforceDataResidency } from "./enforcements/data-residency.js";
import { evaluateThresholds, getBlockAllState } from "./threshold/engine.js";
import type { LicenseStatus } from "./license/checker.js";

// ---------------------------------------------------------------------------
// Compliance framework rule injection
// Per spec Section 15: framework rules are PREPENDED before user-declared rules.
// ---------------------------------------------------------------------------

import { HIPAA_RULES } from "./frameworks/hipaa.js";
import { GDPR_RULES } from "./frameworks/gdpr.js";
import { EU_AI_ACT_RULES } from "./frameworks/eu-ai-act.js";
import { SOC2_RULES } from "./frameworks/soc2.js";
import { FEDRAMP_RULES } from "./frameworks/fedramp.js";
import { resolveCustomClassifier, getClassifier } from "./evaluators/classifier-registry.js";
import { runShadowClassifier } from "./pie/shadow.js";
import { generateReceipt } from "./trust/receipt.js";

const FRAMEWORK_RULES: Record<string, TPSRule[]> = {
  hipaa: HIPAA_RULES,
  gdpr: GDPR_RULES,
  "eu-ai-act": EU_AI_ACT_RULES,
  soc2: SOC2_RULES,
  "fedramp-moderate": FEDRAMP_RULES,
};

const DEFAULT_API_BASE = "https://api.transparentguard.com";

// ---------------------------------------------------------------------------
// Stage matching
// ---------------------------------------------------------------------------

function stageMatches(ruleStage: RuleStage, evaluationStage: RuleStage): boolean {
  if (ruleStage === "both") return evaluationStage === "pre-request" || evaluationStage === "post-response";
  return ruleStage === evaluationStage;
}

/**
 * Determines if a rule should be evaluated based on sample_rate.
 * Uses a deterministic hash of requestId + ruleId so the same call
 * produces the same sampling decision on replay.
 */
function shouldSampleRule(rule: TPSRule, requestId: string): boolean {
  if (!rule.sample_rate || rule.sample_rate >= 1.0) return true;
  const hash = crypto
    .createHash("sha256")
    .update(`${requestId}:${rule.id}`)
    .digest("hex");
  const fraction = parseInt(hash.slice(0, 8), 16) / 0xffffffff;
  return fraction < rule.sample_rate;
}

/**
 * Determines the active rules for a given environment.
 */
function getActiveRules(policy: TPSPolicy, environment?: string): TPSRule[] {
  const baseRules = policy.rules.filter((r) => r.enabled !== false);

  if (!environment) return baseRules;

  const env = policy.environments?.find((e) => e.name === environment);
  if (!env) return baseRules;

  let active = baseRules;

  if (env.active_rules?.length) {
    const allowed = new Set(env.active_rules);
    active = active.filter((r) => allowed.has(r.id));
  } else if (env.disabled_rules?.length) {
    const disabled = new Set(env.disabled_rules);
    active = active.filter((r) => !disabled.has(r.id));
  }

  return active;
}

// ---------------------------------------------------------------------------
// Individual rule evaluators
// ---------------------------------------------------------------------------

async function evaluateRule(
  rule: TPSRule,
  ctx: EvaluationContext,
): Promise<RuleResult> {
  switch (rule.action) {
    case "redact":
      return evaluateRedact(rule, ctx);
    case "classify":
      return evaluateClassify(rule, ctx);
    case "enforce":
      return evaluateEnforce(rule, ctx);
    case "tag":
      return evaluateTag(rule, ctx);
    case "block":
      return evaluateBlock(rule, ctx);
    case "log":
      return evaluateLog(rule, ctx);
    default:
      return {
        ruleId: rule.id,
        outcome: "skipped",
        auditEvent: buildAuditEvent({
          policy: ctx.policy, rule, eventType: "error", stage: ctx.stage,
          payload: ctx.payload, tags: ctx.tags, requestId: ctx.requestId,
          detail: `Unknown rule action: ${String(rule.action)}`,
        }),
      };
  }
}

async function evaluateRedact(rule: TPSRule, ctx: EvaluationContext): Promise<RuleResult> {
  const { payload, policy, stage, requestId, tags } = ctx;
  const targets = rule.targets ?? [];
  const allViolations: Violation[] = [];
  let currentPayload = { ...payload };

  for (const target of targets) {
    if (target.type === "pii") {
      const texts = extractTexts(currentPayload);
      let hasMatch = false;

      for (const { key, text } of texts) {
        const matches = detectPii(text, target);
        if (matches.length === 0) continue;
        hasMatch = true;
        const redacted = redactText(text, matches);
        currentPayload = applyRedactedText(currentPayload, key, redacted);
        for (const match of matches) {
          allViolations.push({
            rule_id: rule.id,
            rule_description: rule.description,
            outcome: "redacted",
            detail: `Redacted ${match.category} at position ${match.start}–${match.end}`,
            category: match.category,
            span: { start: match.start, end: match.end, original: match.original },
          });
        }
      }
      if (!hasMatch) continue;
    } else if (target.type === "pattern") {
      const texts = extractTexts(currentPayload);
      for (const { key, text } of texts) {
        const flags = buildPatternFlags(target.flags);
        let re: RegExp;
        try {
          re = new RegExp(target.pattern, flags);
        } catch {
          continue;
        }
        const newText = text.replace(re, "[REDACTED:PATTERN]");
        if (newText !== text) {
          currentPayload = applyRedactedText(currentPayload, key, newText);
          allViolations.push({
            rule_id: rule.id,
            rule_description: rule.description,
            outcome: "redacted",
            detail: `Redacted pattern match: ${target.description ?? target.pattern}`,
            category: "pattern",
          });
        }
      }
    } else if (target.type === "keyword") {
      const texts = extractTexts(currentPayload);
      for (const { key, text } of texts) {
        let newText = text;
        const caseSensitive = target.case_sensitive !== false;
        for (const keyword of target.keywords) {
          const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const pattern = target.match_mode === "substring"
            ? escaped
            : `\\b${escaped}\\b`;
          const re = new RegExp(pattern, caseSensitive ? "g" : "gi");
          if (re.test(newText)) {
            newText = newText.replace(re, "[REDACTED:KEYWORD]");
            allViolations.push({
              rule_id: rule.id,
              rule_description: rule.description,
              outcome: "redacted",
              detail: `Redacted keyword: "${keyword}"`,
              category: "keyword",
            });
          }
        }
        if (newText !== text) {
          currentPayload = applyRedactedText(currentPayload, key, newText);
        }
      }
    } else if (target.type === "semantic") {
      // Semantic redact requires paid-tier ML classifiers
      if (!ctx.isPaidTier) {
        allViolations.push({
          rule_id: rule.id,
          rule_description: rule.description,
          outcome: "warned",
          detail: "Semantic target redaction requires a paid TransparentGuard plan.",
          category: "semantic_not_available",
        });
      }
      // Paid-tier implementation delegated to the classifier API
    }
  }

  if (allViolations.length === 0) {
    return {
      ruleId: rule.id,
      outcome: "passed",
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "allowed", stage, payload, tags, requestId,
      }),
    };
  }

  const onViolation = rule.on_violation ?? "redact";
  if (onViolation === "block") {
    return {
      ruleId: rule.id,
      outcome: "blocked",
      violation: allViolations[0],
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "blocked", stage, payload, tags, requestId,
        detail: allViolations[0]?.detail,
      }),
    };
  }

  return {
    ruleId: rule.id,
    outcome: "redacted",
    violation: allViolations[0],
    payload: currentPayload,
    auditEvent: buildAuditEvent({
      policy, rule, eventType: "redacted", stage, payload, tags, requestId,
      detail: `${allViolations.length} item(s) redacted`,
    }),
  };
}

async function evaluateClassify(rule: TPSRule, ctx: EvaluationContext): Promise<RuleResult> {
  const { payload, policy, stage, requestId, tags, apiKey, apiBaseUrl, isPaidTier } = ctx;
  const classifier = rule.classifier!;
  const threshold = rule.threshold!;
  const invertThreshold = rule.invert_threshold ?? false;

  const text = extractPrimaryText(payload);

  let score: number;
  let source: string;

  // Check custom classifier registry first (policy-defined or process-registered)
  const customSpec =
    ctx.policy.custom_classifiers?.find((c) => c.name === classifier) ??
    getClassifier(classifier);

  if (customSpec) {
    const result = await resolveCustomClassifier(text, customSpec);
    score = result.score;
    source = result.source;
  } else if (isPaidTier && apiKey) {
    try {
      const result = await callClassifierApi(
        { classifier, text, stage },
        apiKey,
        apiBaseUrl,
      );
      score = result.score;
      source = result.source;
    } catch {
      // API failure — fall back to heuristic
      const result = heuristicClassify(classifier, text);
      score = result.score;
      source = result.source + " (fallback)";
    }
  } else {
    const result = heuristicClassify(classifier, text);
    score = result.score;
    source = result.source;
  }

  // PIE shadow mode — non-blocking, never affects outcome
  runShadowClassifier(
    classifier,
    text,
    score,
    ctx.policy.pie?.shadow_mode,
    ctx.requestId,
    (clf, t) => heuristicClassify(clf, t),
  );

  const triggered = invertThreshold ? score < threshold : score >= threshold;

  if (!triggered) {
    return {
      ruleId: rule.id,
      outcome: "passed",
      auditEvent: buildAuditEvent({
        policy, rule, eventType: "allowed", stage, payload, tags, requestId,
      }),
    };
  }

  const onViolation = rule.on_violation ?? "block";
  const outcome: "blocked" | "warned" = onViolation === "block" ? "blocked" : "warned";

  const violation: Violation = {
    rule_id: rule.id,
    rule_description: rule.description,
    outcome,
    detail: `Classifier "${classifier}" returned score ${score.toFixed(3)} (threshold: ${threshold}, source: ${source})`,
    category: classifier,
  };

  return {
    ruleId: rule.id,
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

async function evaluateEnforce(rule: TPSRule, ctx: EvaluationContext): Promise<RuleResult> {
  const enforceCtx = { ...ctx, rule };
  switch (rule.enforce_type) {
    case "provider_allowlist":
      return enforceProviderAllowlist(enforceCtx);
    case "token_budget":
      return enforceTokenBudget(enforceCtx);
    case "rate_limit":
      return enforceRateLimit(enforceCtx);
    case "tool_allowlist":
      return enforceToolAllowlist(enforceCtx);
    case "schema_validation":
      return enforceSchemaValidation(enforceCtx);
    case "confidentiality":
      return enforceConfidentiality(enforceCtx);
    case "data_residency":
      return enforceDataResidency(enforceCtx);
    case "factual_grounding": {
      const groundingRule: TPSRule = {
        ...rule,
        action: "classify",
        classifier: "built-in/factual-grounding-v1",
        threshold: rule.threshold ?? 0.50,
        invert_threshold: true,
      };
      return evaluateClassify(groundingRule, { ...ctx, rule: groundingRule });
    }
    default:
      return {
        ruleId: rule.id,
        outcome: "skipped",
        auditEvent: buildAuditEvent({
          policy: ctx.policy, rule, eventType: "error", stage: ctx.stage,
          payload: ctx.payload, tags: ctx.tags, requestId: ctx.requestId,
          detail: `Unknown enforce_type: ${String(rule.enforce_type)}`,
        }),
      };
  }
}

async function evaluateTag(rule: TPSRule, ctx: EvaluationContext): Promise<RuleResult> {
  const { payload, policy, stage, requestId, tags } = ctx;
  Object.assign(tags, rule.tags ?? {});
  return {
    ruleId: rule.id,
    outcome: "passed",
    auditEvent: buildAuditEvent({
      policy, rule, eventType: "allowed", stage, payload, tags, requestId,
    }),
  };
}

async function evaluateBlock(rule: TPSRule, ctx: EvaluationContext): Promise<RuleResult> {
  const { payload, policy, stage, requestId, tags } = ctx;
  const message = rule.block_message ?? `Blocked by policy rule "${rule.id}"`;
  const violation: Violation = {
    rule_id: rule.id,
    rule_description: rule.description,
    outcome: "blocked",
    detail: message,
    category: "explicit_block",
  };
  return {
    ruleId: rule.id,
    outcome: "blocked",
    violation,
    auditEvent: buildAuditEvent({
      policy, rule, eventType: "blocked", stage, payload, tags, requestId, detail: message,
    }),
  };
}

async function evaluateLog(rule: TPSRule, ctx: EvaluationContext): Promise<RuleResult> {
  const { payload, policy, stage, requestId, tags } = ctx;
  return {
    ruleId: rule.id,
    outcome: "passed",
    auditEvent: buildAuditEvent({
      policy, rule, eventType: "allowed", stage, payload, tags, requestId,
    }),
  };
}

// ---------------------------------------------------------------------------
// Main evaluate() function
// ---------------------------------------------------------------------------

export async function evaluate(
  stage: RuleStage,
  payload: RequestPayload | ResponsePayload,
  policy: TPSPolicy,
  licenseStatus: LicenseStatus,
  options: EvaluateOptions = {},
): Promise<EvaluateResult> {
  const requestId = options.requestId ?? makeId();
  const environment = options.environment;
  const apiKeyId = options.apiKeyId ?? ("api_key_id" in payload ? payload.api_key_id : undefined);
  const apiKey = options.apiKey; // injected by TransparentGuard class or caller
  const isPaidTier = licenseStatus.tier !== "free" || licenseStatus.trialActive;
  const apiBaseUrl = DEFAULT_API_BASE;

  // Check block_all state from threshold engine
  const blockAllState = getBlockAllState();
  if (blockAllState.active) {
    return {
      allowed: false,
      payload,
      violations: [{
        rule_id: blockAllState.thresholdId,
        outcome: "blocked",
        detail: blockAllState.message,
        category: "threshold_block_all",
      }],
      tags: {},
      audit_events: [],
      evaluated_at: new Date().toISOString(),
      policy_name: policy.name,
    };
  }

  const tags: Record<string, string> = {};
  const allViolations: Violation[] = [];
  const allAuditEvents = [];
  let currentPayload = { ...payload };
  let blocked = false;
  let hasAnyViolation = false;

  // Per spec Section 15: compliance framework rules are PREPENDED before user rules.
  // Per spec Section 20.3 (deny-by-default): framework rules run first, then user rules.
  const frameworkRules: TPSRule[] = [];
  for (const framework of policy.compliance_frameworks ?? []) {
    const rules = FRAMEWORK_RULES[framework];
    if (rules) frameworkRules.push(...rules);
  }
  const userRules = getActiveRules(policy, environment);
  const allRules = [...frameworkRules, ...userRules];

  for (const rule of allRules) {
    // Skip rules that don't apply to this stage
    if (!stageMatches(rule.stage, stage)) continue;

    // Skip explicitly disabled rules
    if (rule.enabled === false) continue;

    // Sampling — emit sampled_out audit event when rule is skipped
    if (!shouldSampleRule(rule, requestId)) {
      allAuditEvents.push(
        buildAuditEvent({
          policy, rule, eventType: "sampled_out", stage,
          payload: currentPayload, tags, requestId,
          detail: `sampled_out (rate=${rule.sample_rate ?? 1})`,
        }),
      );
      continue;
    }

    const ctx: EvaluationContext = {
      rule,
      stage,
      payload: currentPayload,
      policy,
      environment,
      requestId,
      apiKeyId,
      apiKey,
      apiBaseUrl,
      tags,
      isPaidTier,
    };

    let result: RuleResult;
    try {
      result = await evaluateRule(rule, ctx);
    } catch (err) {
      const event = buildAuditEvent({
        policy, rule, eventType: "error", stage,
        payload: currentPayload, tags, requestId,
        detail: `Rule evaluation error: ${String(err)}`,
      });
      allAuditEvents.push(event);
      // Errors in individual rules do not block unless in strict mode
      const env = policy.environments?.find((e) => e.name === environment);
      if (env?.strict) {
        blocked = true;
        break;
      }
      continue;
    }

    allAuditEvents.push(result.auditEvent);

    if (result.payload) {
      currentPayload = result.payload;
    }

    if (result.violation) {
      allViolations.push(result.violation);
      hasAnyViolation = true;

      // Feed violation into threshold engine
      const thresholdResults = evaluateThresholds(
        policy,
        rule.id,
        result.violation.outcome,
        policy.name,
      );
      for (const tf of thresholdResults) {
        allAuditEvents.push(tf.auditEvent);
        // If a threshold triggered block_all, set blocked flag for this call too
        if (tf.action === "block_all") {
          blocked = true;
        }
      }
    }

    if (result.outcome === "blocked") {
      blocked = true;
      break;
    }
  }

  // Deny-by-default: if no violation occurred and no rule explicitly allowed,
  // block the call when default_action is "deny".
  // Per spec Section 20: the call is allowed only if at least one rule "passed"
  // — since all non-violating rules return "passed", we only block when no rules
  // ran at all for this stage and the policy is deny-by-default.
  if (!blocked && policy.default_action === "deny" && !hasAnyViolation) {
    const stageRules = allRules.filter(
      (r) => stageMatches(r.stage, stage) && r.enabled !== false,
    );
    if (stageRules.length === 0) {
      // No rules matched this stage — deny-by-default blocks the call
      blocked = true;
      allViolations.push({
        rule_id: "__default_deny__",
        outcome: "blocked",
        detail: "No rules matched this stage and policy default_action is deny.",
        category: "default_deny",
      });
    }
  }

  // Determine overall outcome for EvaluateResult
  const redactionCount = allViolations.filter((v) => v.outcome === "redacted").length;
  void redactionCount; // used by wrappers inspecting violations

  const evaluatedAt = new Date().toISOString();

  // Generate signed evaluation receipt (non-fatal — failure never blocks)
  const skipReceipt = options.generateReceipt === false;
  const receipt = skipReceipt
    ? undefined
    : (generateReceipt(payload, policy, !blocked, allViolations.length) ?? undefined);

  return {
    allowed: !blocked,
    payload: currentPayload,
    violations: allViolations,
    tags,
    audit_events: allAuditEvents,
    evaluated_at: evaluatedAt,
    policy_name: policy.name,
    receipt,
  };
}

// ---------------------------------------------------------------------------
// Text extraction utilities
// ---------------------------------------------------------------------------

interface TextEntry {
  key: string;
  text: string;
}

function extractTexts(payload: RequestPayload | ResponsePayload): TextEntry[] {
  const entries: TextEntry[] = [];

  if ("messages" in payload) {
    const req = payload as RequestPayload;
    for (let i = 0; i < req.messages.length; i++) {
      const msg = req.messages[i];
      if (msg && msg.content) {
        entries.push({ key: `messages.${i}.content`, text: msg.content });
      }
    }
  } else {
    const res = payload as ResponsePayload;
    if (res.content) {
      entries.push({ key: "content", text: res.content });
    }
  }

  return entries;
}

function extractPrimaryText(payload: RequestPayload | ResponsePayload): string {
  if ("messages" in payload) {
    const req = payload as RequestPayload;
    return req.messages
      .filter((m): m is Message & { content: string } => Boolean(m.content))
      .map((m) => m.content)
      .join("\n");
  }
  return (payload as ResponsePayload).content ?? "";
}

function applyRedactedText(
  payload: RequestPayload | ResponsePayload,
  key: string,
  redactedText: string,
): RequestPayload | ResponsePayload {
  if (key === "content") {
    return { ...(payload as ResponsePayload), content: redactedText };
  }

  if (key.startsWith("messages.")) {
    const parts = key.split(".");
    const idx = parseInt(parts[1] ?? "0", 10);
    const req = payload as RequestPayload;
    const messages = req.messages.map((msg, i) => {
      if (i === idx) return { ...msg, content: redactedText };
      return msg;
    });
    return { ...req, messages };
  }

  return payload;
}

function buildPatternFlags(
  flags?: Array<"case_insensitive" | "multiline" | "dotall">,
): string {
  let f = "g";
  if (flags?.includes("case_insensitive")) f += "i";
  if (flags?.includes("multiline")) f += "m";
  if (flags?.includes("dotall")) f += "s";
  return f;
}

// Re-export expandCategories so dependents don't need to import from pii directly
export { expandCategories };
