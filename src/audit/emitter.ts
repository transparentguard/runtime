/**
 * TransparentGuard Runtime — Audit Event Emitter
 * Builds structured audit events and routes them to configured destinations.
 * Supports ndjson, json, and OCSF output formats.
 */

import crypto from "crypto";
import type {
  AuditEvent,
  AuditEventType,
  EvaluationContext,
  RequestPayload,
  ResponsePayload,
  RuleStage,
  TPSAudit,
  TPSPolicy,
  TPSRule,
} from "../types.js";
import { toOcsfEvent } from "./ocsf.js";
import { FileDestination } from "./destinations/file.js";
import { StdoutDestination } from "./destinations/stdout.js";
import { HttpDestination } from "./destinations/http.js";

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

export function makeId(): string {
  return `tge_${crypto.randomBytes(12).toString("hex")}`;
}

// ---------------------------------------------------------------------------
// Chain integrity (hash chaining for tamper-evident audit logs)
// ---------------------------------------------------------------------------

let lastEventHash: string | undefined;

function hashEvent(event: AuditEvent): string {
  const canonical = JSON.stringify({
    id: event.id,
    timestamp: event.timestamp,
    policy_name: event.policy_name,
    rule_id: event.rule_id,
    event_type: event.event_type,
    prev_event_hash: event.prev_event_hash,
  });
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

// ---------------------------------------------------------------------------
// Build audit event
// ---------------------------------------------------------------------------

export interface BuildAuditEventParams {
  policy: TPSPolicy;
  rule: TPSRule;
  eventType: AuditEventType;
  stage: RuleStage;
  payload: RequestPayload | ResponsePayload;
  tags: Record<string, string>;
  requestId?: string;
  detail?: string;
}

export function buildAuditEvent(params: BuildAuditEventParams): AuditEvent {
  const { policy, rule, eventType, stage, payload, tags, requestId, detail } = params;

  const provider =
    "provider" in payload ? (payload.provider) : undefined;
  const model =
    "model" in payload ? (payload.model) : undefined;
  const apiKeyId =
    "api_key_id" in payload ? (payload.api_key_id) : undefined;

  const chainIntegrity = policy.audit.chain_integrity;
  const prevHash = chainIntegrity?.enabled ? lastEventHash : undefined;

  const event: AuditEvent = {
    id: makeId(),
    timestamp: new Date().toISOString(),
    policy_name: policy.name,
    policy_version: policy.tps_version,
    rule_id: rule.id,
    event_type: eventType,
    stage,
    provider,
    model,
    api_key_id: apiKeyId,
    violation:
      detail
        ? {
            rule_id: rule.id,
            rule_description: rule.description,
            outcome: eventType as "blocked" | "redacted" | "warned" | "logged" | "allowed",
            detail,
          }
        : undefined,
    tags: { ...tags },
    metadata: rule.metadata
      ? (rule.metadata as Record<string, string | number>)
      : undefined,
    prev_event_hash: prevHash,
    request_id: requestId,
  };

  // Update chain
  if (chainIntegrity?.enabled) {
    lastEventHash = hashEvent(event);
  }

  return event;
}

export function buildSystemAuditEvent(params: {
  policy: TPSPolicy;
  eventType: AuditEventType;
  detail: string;
  tags: Record<string, string>;
  requestId?: string;
}): AuditEvent {
  const { policy, eventType, detail, tags, requestId } = params;
  const event: AuditEvent = {
    id: makeId(),
    timestamp: new Date().toISOString(),
    policy_name: policy.name,
    policy_version: policy.tps_version,
    event_type: eventType,
    stage: "system",
    tags: { ...tags },
    violation: {
      rule_id: "system",
      outcome: eventType as "blocked" | "redacted" | "warned" | "logged" | "allowed",
      detail,
    },
    request_id: requestId,
  };
  return event;
}

// ---------------------------------------------------------------------------
// Destination router
// ---------------------------------------------------------------------------

export type AuditDestination = {
  write(events: AuditEvent[], format: "ndjson" | "json" | "ocsf"): Promise<void>;
  flush(): Promise<void>;
};

const destinations = new Map<string, AuditDestination>();

function getDestination(uri: string): AuditDestination {
  const cached = destinations.get(uri);
  if (cached) return cached;

  let dest: AuditDestination;
  if (uri === "stdout://" || uri === "stdout:///" ) {
    dest = new StdoutDestination();
  } else if (uri.startsWith("file://")) {
    const filePath = uri.slice("file://".length);
    dest = new FileDestination(filePath);
  } else if (uri.startsWith("https://") || uri.startsWith("http://")) {
    dest = new HttpDestination(uri);
  } else {
    // Unsupported destination — fall back to stdout with a warning
    console.warn(
      `[TransparentGuard] Unsupported audit destination: "${uri}". Falling back to stdout. ` +
      `S3, GCS, Azure, and PostgreSQL destinations require a paid-tier API key.`,
    );
    dest = new StdoutDestination();
  }

  destinations.set(uri, dest);
  return dest;
}

// ---------------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------------

export class AuditEmitter {
  private readonly audit: TPSAudit;
  private readonly buffer: AuditEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(audit: TPSAudit) {
    this.audit = audit;
  }

  /** Enqueue an audit event. Flushes when buffer hits batch_size. */
  enqueue(event: AuditEvent): void {
    if (!this.audit.enabled) return;

    const allowedTypes = this.audit.events ?? [
      "allowed", "blocked", "redacted", "warned", "error",
    ];
    if (!allowedTypes.includes(event.event_type as typeof allowedTypes[number])) return;

    this.buffer.push(event);

    const batchSize = this.audit.batch_size ?? 100;
    if (this.buffer.length >= batchSize) {
      void this.flush();
    } else {
      this.scheduleFlush();
    }
  }

  enqueueMany(events: AuditEvent[]): void {
    for (const e of events) this.enqueue(e);
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return;
    const intervalMs = this.audit.flush_interval_ms ?? 5000;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      void this.flush();
    }, intervalMs);
  }

  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    const events = this.buffer.splice(0);
    if (!this.audit.destination) return;

    const format = this.audit.format ?? "ndjson";
    const dest = getDestination(this.audit.destination);
    try {
      await dest.write(events, format);
    } catch (err) {
      // Audit failures must never crash the application
      console.error(`[TransparentGuard] Audit write failed: ${String(err)}`);
    }

    // Webhook notifications
    if (this.audit.notify?.length) {
      await this.sendNotifications(events);
    }
  }

  private async sendNotifications(events: AuditEvent[]): Promise<void> {
    const violationEvents = events.filter(
      (e) => e.event_type === "blocked" || e.event_type === "redacted" || e.event_type === "warned",
    );
    if (violationEvents.length === 0) return;

    for (const notify of this.audit.notify ?? []) {
      const filteredEvents = violationEvents.filter((e) =>
        notify.events.includes(e.event_type),
      );
      if (filteredEvents.length === 0) continue;

      try {
        const controller = new AbortController();
        const timeout = setTimeout(
          () => controller.abort(),
          notify.timeout_ms ?? 5000,
        );
        await fetch(notify.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(notify.headers ?? {}),
          },
          body: JSON.stringify({ events: filteredEvents }),
          signal: controller.signal,
        }).finally(() => clearTimeout(timeout));
      } catch {
        // Notification failures are non-fatal
      }
    }
  }

  /** Serialize events in the requested format */
  static serialize(events: AuditEvent[], format: "ndjson" | "json" | "ocsf"): string {
    if (format === "ndjson") {
      return events.map((e) => JSON.stringify(e)).join("\n") + "\n";
    }
    if (format === "json") {
      return JSON.stringify(events, null, 2) + "\n";
    }
    if (format === "ocsf") {
      return events.map((e) => JSON.stringify(toOcsfEvent(e))).join("\n") + "\n";
    }
    return events.map((e) => JSON.stringify(e)).join("\n") + "\n";
  }
}
