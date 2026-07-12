/**
 * TransparentGuard Runtime — OCSF Event Conversion
 * Converts TG audit events to OCSF Class 6003 (API Activity) format.
 *
 * OCSF Specification: https://schema.ocsf.io/1.1.0/classes/api_activity
 * Class UID: 6003
 * Category: Application Activity (6)
 *
 * This enables native ingestion by Splunk, Microsoft Sentinel,
 * Google Chronicle, Elastic Security, and any other OCSF-compatible SIEM.
 */

import type { AuditEvent, OCSFEvent } from "../types.js";

// OCSF Activity IDs for Class 6003 (API Activity)
const ACTIVITY_MAP: Record<string, { id: number; name: string }> = {
  allowed:  { id: 1, name: "Create" },    // Request allowed through
  blocked:  { id: 4, name: "Delete" },    // Request suppressed / blocked
  redacted: { id: 3, name: "Update" },    // Content modified (redacted)
  warned:   { id: 99, name: "Other" },    // Warning emitted
  error:    { id: 99, name: "Other" },    // Evaluation error
};

// OCSF Severity IDs
const SEVERITY_MAP: Record<string, { id: number; label: string }> = {
  allowed:  { id: 1, label: "Informational" },
  blocked:  { id: 4, label: "High" },
  redacted: { id: 3, label: "Medium" },
  warned:   { id: 2, label: "Low" },
  error:    { id: 5, label: "Critical" },
};

// OCSF Status IDs
const STATUS_MAP: Record<string, { id: number; label: string }> = {
  allowed:  { id: 1, label: "Success" },
  blocked:  { id: 2, label: "Failure" },
  redacted: { id: 1, label: "Success" },
  warned:   { id: 1, label: "Success" },
  error:    { id: 99, label: "Other" },
};

/**
 * Converts a TransparentGuard AuditEvent to OCSF Class 6003 (API Activity).
 *
 * Field mapping:
 *   tg.event_type     → ocsf.activity_id / severity_id / status_id
 *   tg.rule_id        → ocsf.api.operation
 *   tg.policy_name    → ocsf.api.service.name
 *   tg.provider       → ocsf.api.service.name (if no policy_name)
 *   tg.model          → ocsf.api.request.body.model
 *   tg.api_key_id     → ocsf.actor.user.uid
 *   tg.request_id     → ocsf.api.request.uid
 *   tg.violation      → ocsf.message
 *   tg.tags           → ocsf.unmapped
 */
export function toOcsfEvent(event: AuditEvent): OCSFEvent {
  const eventType = event.event_type;
  const activity = ACTIVITY_MAP[eventType] ?? { id: 99, name: "Other" };
  const severity = SEVERITY_MAP[eventType] ?? { id: 1, label: "Informational" };
  const status = STATUS_MAP[eventType] ?? { id: 99, label: "Other" };

  const message =
    event.violation?.detail ??
    `TransparentGuard policy evaluation: ${eventType} [rule: ${event.rule_id ?? "system"}]`;

  const ocsf: OCSFEvent = {
    class_uid: 6003,
    class_name: "API Activity",
    category_uid: 6,
    category_name: "Application Activity",
    activity_id: activity.id,
    activity_name: activity.name,
    // OCSF time is epoch milliseconds
    time: new Date(event.timestamp).getTime(),
    severity_id: severity.id,
    severity: severity.label,
    status_id: status.id,
    status: status.label,
    message,
    metadata: {
      version: "1.1.0",
      product: {
        name: "TransparentGuard",
        vendor_name: "TransparentGuard",
        version: event.policy_version,
      },
    },
    api: {
      operation: event.rule_id ?? "policy_evaluation",
      request: event.request_id
        ? {
            uid: event.request_id,
            body: {
              model: event.model,
              provider: event.provider,
              stage: event.stage,
              policy: event.policy_name,
            },
          }
        : {
            body: {
              model: event.model,
              provider: event.provider,
              stage: event.stage,
              policy: event.policy_name,
            },
          },
      response: {
        code: status.id === 1 ? 200 : 403,
        message: status.label,
      },
      service: {
        name: event.policy_name,
      },
    },
  };

  // Actor — populated if we have an API key ID
  if (event.api_key_id) {
    ocsf.actor = {
      user: { uid: event.api_key_id },
    };
  }

  // Unmapped fields — TG-specific data that OCSF does not have a native slot for
  const unmapped: Record<string, unknown> = {
    tg_event_id: event.id,
    tg_rule_id: event.rule_id,
    tg_policy_name: event.policy_name,
    tg_stage: event.stage,
    tg_tags: event.tags,
  };
  if (event.prev_event_hash) {
    unmapped["tg_prev_event_hash"] = event.prev_event_hash;
  }
  if (event.violation) {
    unmapped["tg_violation"] = event.violation;
  }
  if (event.metadata) {
    unmapped["tg_metadata"] = event.metadata;
  }
  ocsf.unmapped = unmapped;

  return ocsf;
}
