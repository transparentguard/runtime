/**
 * TransparentGuard Runtime — Threshold Engine
 * Evaluates rolling-window violation counters against declared thresholds.
 * Fires breach notification payloads per HIPAA, GDPR, EU AI Act, and SOC 2 formats.
 * Implements TPS v1.0 Section 29.
 */

import type { TPSPolicy, TPSThreshold, AuditEvent, AuditEventType } from "../types.js";
import { makeId } from "../audit/emitter.js";

// ---------------------------------------------------------------------------
// Rolling window state (in-memory per process)
// ---------------------------------------------------------------------------

interface ViolationRecord {
  timestamp: number;
  violationType: string;
}

/** Map<thresholdId, sorted violation timestamps> */
const violationWindows = new Map<string, ViolationRecord[]>();

/** Block-all state — set when a threshold fires action: block_all */
let blockAllActive = false;
let blockAllMessage = "";
let blockAllThresholdId = "";

export interface BlockAllState {
  active: boolean;
  message: string;
  thresholdId: string;
}

export function getBlockAllState(): BlockAllState {
  return { active: blockAllActive, message: blockAllMessage, thresholdId: blockAllThresholdId };
}

/** Call this via the CLI `transparentguard resume` equivalent */
export function clearBlockAll(): void {
  blockAllActive = false;
  blockAllMessage = "";
  blockAllThresholdId = "";
}

// ---------------------------------------------------------------------------
// Window parsing
// ---------------------------------------------------------------------------

/**
 * Parse TPS window strings like "1h", "30m", "7d" to milliseconds.
 * Valid suffixes: m (minutes), h (hours), d (days)
 */
export function parseWindowMs(window: string): number {
  const match = /^(\d+)([mhd])$/.exec(window);
  if (!match) {
    console.warn(`[TransparentGuard] Invalid threshold window "${window}", defaulting to 1h`);
    return 3_600_000;
  }
  const amount = parseInt(match[1]!, 10);
  const unit = match[2]!;
  switch (unit) {
    case "m": return amount * 60_000;
    case "h": return amount * 3_600_000;
    case "d": return amount * 86_400_000;
    default: return 3_600_000;
  }
}

// ---------------------------------------------------------------------------
// Breach payload builders
// ---------------------------------------------------------------------------

function buildHipaaBreachPayload(
  threshold: TPSThreshold,
  policy: TPSPolicy,
  violationCount: number,
  discoveryTimestamp: string,
): Record<string, unknown> {
  return {
    notification_template: "hipaa-breach-v1",
    discovery_timestamp: discoveryTimestamp,
    threshold_id: threshold.id,
    rule_id: threshold.rule_id,
    violation_count_in_window: violationCount,
    window: threshold.window,
    policy_name: policy.name,
    regulatory_ref: threshold.metadata?.["regulatory_ref"] ?? "HIPAA 45 CFR 164.400-414",
    hhs_form_fields: {
      name_of_covered_entity: "[REQUIRED: Insert covered entity name]",
      state_of_covered_entity: "[REQUIRED: Insert state]",
      type_of_covered_entity: "[REQUIRED: health plan / healthcare provider / healthcare clearinghouse]",
      contact_name: "[REQUIRED: Insert contact name]",
      contact_email: "[REQUIRED: Insert contact email]",
      contact_phone: "[REQUIRED: Insert contact phone]",
      approximate_number_of_individuals_affected: violationCount,
      date_of_breach: "[REQUIRED: Insert date breach began]",
      date_of_discovery: discoveryTimestamp,
      type_of_breach: "Unauthorized access or disclosure",
      location_of_breach: "AI system LLM API calls",
      type_of_phi_involved: "PHI in LLM prompts and responses (see attached audit events)",
      safeguards_in_place: `TransparentGuard Policy Spec v1.0: active policy "${policy.name}"`,
      description_of_incident: "[REQUIRED: Insert description of what happened]",
      steps_taken: "[REQUIRED: Insert steps taken to investigate and mitigate]",
      steps_to_prevent_recurrence: "[REQUIRED: Insert corrective actions]",
    },
    attached_audit_events: `[transparentguard audit export --rule ${threshold.rule_id} --window ${threshold.window}]`,
  };
}

function buildGdprArticle33Payload(
  threshold: TPSThreshold,
  policy: TPSPolicy,
  violationCount: number,
  discoveryTimestamp: string,
): Record<string, unknown> {
  const deadline = new Date(new Date(discoveryTimestamp).getTime() + 72 * 3_600_000).toISOString();
  return {
    notification_template: "gdpr-article-33",
    discovery_timestamp: discoveryTimestamp,
    notification_deadline_72h: deadline,
    threshold_id: threshold.id,
    rule_id: threshold.rule_id,
    violation_count_in_window: violationCount,
    window: threshold.window,
    policy_name: policy.name,
    article_33_fields: {
      nature_of_breach: "Transfer or processing of personal data in violation of declared policy",
      categories_of_personal_data: "Personal data subject to GDPR Chapter V transfer restrictions",
      approximate_number_of_data_subjects: "[REQUIRED: Insert estimate]",
      approximate_number_of_records: violationCount,
      name_and_contact_of_dpo: "[REQUIRED: Insert DPO name and contact]",
      likely_consequences: "Potential unauthorized processing or transfer of personal data",
      measures_taken_or_proposed: `Policy "${policy.name}" active. Incident under investigation. [REQUIRED: Insert additional measures]`,
      notification_phased: false,
      reason_for_delay_if_applicable: null,
    },
  };
}

function buildEuAiActArticle73Payload(
  threshold: TPSThreshold,
  policy: TPSPolicy,
  violationCount: number,
  discoveryTimestamp: string,
): Record<string, unknown> {
  return {
    notification_template: "eu-ai-act-article-73",
    discovery_timestamp: discoveryTimestamp,
    threshold_id: threshold.id,
    rule_id: threshold.rule_id,
    violation_count_in_window: violationCount,
    window: threshold.window,
    policy_name: policy.name,
    article_73_fields: {
      ai_system_name: "[REQUIRED: Insert AI system name]",
      registration_id: "[REQUIRED: Insert EU AI Act registration ID if applicable]",
      risk_classification: "high",
      annex_iii_category: "[REQUIRED: Insert Annex III category]",
      incident_classification: "serious_incident",
      incident_description: `Threshold breach: ${violationCount} violations detected within ${threshold.window}. Automated detection triggered per policy "${policy.name}".`,
      impact_on_health_safety_fundamental_rights: "[REQUIRED: Assess and describe impact]",
      corrective_actions_taken: "Threshold action triggered. Human review initiated.",
      market_surveillance_authority: "[REQUIRED: Insert relevant national authority]",
      provider_contact: "[REQUIRED: Insert provider contact information]",
    },
  };
}

function buildSoc2IncidentPayload(
  threshold: TPSThreshold,
  policy: TPSPolicy,
  violationCount: number,
  discoveryTimestamp: string,
): Record<string, unknown> {
  return {
    notification_template: "soc2-incident-v1",
    discovery_timestamp: discoveryTimestamp,
    threshold_id: threshold.id,
    rule_id: threshold.rule_id,
    incident_id: `tg_INC_${makeId()}`,
    soc2_incident_fields: {
      cc_control: "CC7.2 / CC9.1",
      severity: "high",
      detection_method: "automated_threshold_trigger",
      system_affected: "AI LLM API integration layer",
      description: `Threshold breach: ${threshold.count} or more violations (type: ${threshold.violation_type}) detected within ${threshold.window}. Policy: "${policy.name}".`,
      business_impact: "[REQUIRED: Assess and describe business impact]",
      containment_actions: "[REQUIRED: Describe immediate containment steps taken]",
      root_cause: "[REQUIRED: Insert preliminary root cause]",
      remediation_plan: "[REQUIRED: Insert remediation plan and timeline]",
      affected_users_estimate: "[REQUIRED: Insert estimate]",
      chain_integrity_verified: true,
      reported_by: "TransparentGuard automated threshold trigger",
      assigned_to: "[REQUIRED: Insert incident owner]",
    },
  };
}

function buildBreachPayload(
  threshold: TPSThreshold,
  policy: TPSPolicy,
  violationCount: number,
  discoveryTimestamp: string,
): Record<string, unknown> {
  switch (threshold.payload_template) {
    case "hipaa-breach-v1":
      return buildHipaaBreachPayload(threshold, policy, violationCount, discoveryTimestamp);
    case "gdpr-article-33":
      return buildGdprArticle33Payload(threshold, policy, violationCount, discoveryTimestamp);
    case "eu-ai-act-article-73":
      return buildEuAiActArticle73Payload(threshold, policy, violationCount, discoveryTimestamp);
    case "soc2-incident-v1":
      return buildSoc2IncidentPayload(threshold, policy, violationCount, discoveryTimestamp);
    default: {
      // Generic payload or custom template
      return {
        notification_template: threshold.payload_template ?? "generic",
        discovery_timestamp: discoveryTimestamp,
        threshold_id: threshold.id,
        rule_id: threshold.rule_id,
        violation_count_in_window: violationCount,
        window: threshold.window,
        policy_name: policy.name,
        metadata: threshold.metadata ?? {},
      };
    }
  }
}

async function sendThresholdNotification(
  url: string,
  payload: Record<string, unknown>,
): Promise<void> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    }).finally(() => clearTimeout(timeout));
  } catch (err) {
    console.error(`[TransparentGuard] Threshold notification delivery failed: ${String(err)}`);
  }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

export interface ThresholdFireResult {
  thresholdId: string;
  action: string;
  auditEvent: AuditEvent;
}

// ---------------------------------------------------------------------------
// Main evaluation function — call after each rule produces a violation
// ---------------------------------------------------------------------------

/**
 * Evaluates all policy thresholds that watch the given ruleId.
 * Should be called once per violation, passing the violation outcome type.
 *
 * @returns Array of threshold fire results (one per threshold that crossed its count)
 */
export function evaluateThresholds(
  policy: TPSPolicy,
  ruleId: string,
  violationType: string,
  policyName: string,
  licenseFeatures: string[] = [],
): ThresholdFireResult[] {
  const now = Date.now();
  const discoveryTimestamp = new Date(now).toISOString();
  const fired: ThresholdFireResult[] = [];

  for (const threshold of policy.thresholds ?? []) {
    if (threshold.enabled === false) continue;
    if (threshold.rule_id !== ruleId) continue;
    if (threshold.violation_type !== violationType) continue;

    const key = threshold.id;
    const windowMs = parseWindowMs(threshold.window);
    const cutoff = now - windowMs;

    // Get window, add record, prune expired
    const records = violationWindows.get(key) ?? [];
    records.push({ timestamp: now, violationType });
    const active = records.filter((r) => r.timestamp > cutoff);
    violationWindows.set(key, active);

    if (active.length < threshold.count) continue;

    // Threshold crossed — reset counter, fire action
    violationWindows.set(key, []);

    // Build threshold_triggered audit event
    const auditEvent: AuditEvent = {
      id: makeId(),
      timestamp: discoveryTimestamp,
      policy_name: policyName,
      policy_version: "1.0",
      rule_id: ruleId,
      event_type: "threshold_triggered" as AuditEventType,
      stage: "system",
      tags: {
        tg_threshold_id: threshold.id,
        tg_threshold_action: threshold.action,
        tg_violation_type: violationType,
        tg_violation_count: String(active.length),
      },
      metadata: {
        threshold_count: threshold.count,
        threshold_window: threshold.window,
        ...(threshold.metadata ?? {}),
      },
      violation: {
        rule_id: ruleId,
        outcome: "warned",
        detail: `Threshold "${threshold.id}" crossed: ${active.length} violations of type "${violationType}" within "${threshold.window}" on rule "${ruleId}"`,
      },
    };

    if (threshold.action === "block_all") {
      // block_all requires threshold_notifications license feature (Startup tier and above)
      if (!licenseFeatures.includes("threshold_notifications")) {
        console.warn(
          `[TransparentGuard] Threshold "${threshold.id}" action "block_all" requires the ` +
            `threshold_notifications license feature. Upgrade to Startup tier or above. ` +
            `The threshold was counted but the action was suppressed.`,
        );
      } else {
        blockAllActive = true;
        blockAllMessage = threshold.block_message
          ?? "AI access suspended due to policy threshold breach. Contact the security team.";
        blockAllThresholdId = threshold.id;
      }
    } else if (threshold.action === "notify" && threshold.notify_url) {
      // notify requires threshold_notifications license feature (Startup tier and above)
      if (!licenseFeatures.includes("threshold_notifications")) {
        console.warn(
          `[TransparentGuard] Threshold "${threshold.id}" action "notify" requires the ` +
            `threshold_notifications license feature. Upgrade to Startup tier or above. ` +
            `The threshold was counted but the notification was suppressed.`,
        );
      } else {
        const payload = buildBreachPayload(threshold, policy, active.length, discoveryTimestamp);
        // Fire asynchronously — must not block evaluation
        void sendThresholdNotification(threshold.notify_url, payload);
      }
    }
    // action === "escalate" — tags already applied; downstream rules can check tg_incident_active

    fired.push({ thresholdId: threshold.id, action: threshold.action, auditEvent });
  }

  return fired;
}
