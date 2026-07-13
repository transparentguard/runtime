/**
 * TransparentGuard Runtime — Audit Event Emitter
 * Builds structured audit events and routes them to configured destinations.
 * Supports ndjson, json, and OCSF output formats.
 * Implements RFC 8785-compatible canonical form for tamper-evident chain integrity.
 */

import crypto from "crypto";
import fs from "fs";
import path from "path";
import type {
  AuditEvent,
  AuditEventType,
  RuleStage,
  TPSAudit,
  TPSPolicy,
  TPSRule,
  RequestPayload,
  ResponsePayload,
} from "../types.js";
import { toOcsfEvent } from "./ocsf.js";
import { FileDestination } from "./destinations/file.js";
import { StdoutDestination } from "./destinations/stdout.js";
import { HttpDestination } from "./destinations/http.js";
import { S3Destination } from "./destinations/s3.js";
import { PostgresDestination } from "./destinations/postgres.js";
import { OtlpDestination } from "./destinations/otlp.js";

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

export function makeId(): string {
  return `tge_${crypto.randomBytes(12).toString("hex")}`;
}

// ---------------------------------------------------------------------------
// RFC 8785 canonical JSON — sort keys recursively, no extra whitespace
// ---------------------------------------------------------------------------

function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sortObjectKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as object).sort()) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

function canonicalize(obj: unknown): string {
  return JSON.stringify(sortObjectKeys(obj));
}

// ---------------------------------------------------------------------------
// Chain integrity helpers
// ---------------------------------------------------------------------------

function computeEventHash(event: AuditEvent, algorithm: "sha256" | "sha3-256" = "sha256"): string {
  // Exclude prev_event_hash from the hashed content per spec Section 28.3
  const { prev_event_hash: _prevHash, chain_sequence: _seq, ...rest } = event;
  void _prevHash;
  void _seq;
  const canonical = canonicalize(rest);
  const hash = algorithm === "sha3-256"
    ? crypto.createHash("sha3-256").update(canonical, "utf8").digest("hex")
    : crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
  return `${algorithm}:${hash}`;
}

interface ChainSidecar {
  tg_sidecar_version: "1.0";
  chain_root_nonce: string;
  algorithm: "sha256" | "sha3-256";
  last_event_id: string;
  last_event_hash: string;
  last_sequence: number;
  last_updated: string;
  destination: string;
}

function writeSidecarAtomic(sidecarPath: string, data: ChainSidecar): void {
  try {
    const dir = path.dirname(sidecarPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = `${sidecarPath}.tmp.${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf8");
    fs.renameSync(tmp, sidecarPath);
  } catch (err) {
    console.error(`[TransparentGuard] Failed to write chain sidecar: ${String(err)}`);
  }
}

function readSidecar(sidecarPath: string): ChainSidecar | null {
  try {
    if (!fs.existsSync(sidecarPath)) return null;
    const raw = fs.readFileSync(sidecarPath, "utf8");
    return JSON.parse(raw) as ChainSidecar;
  } catch {
    return null;
  }
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

  const provider = "provider" in payload ? payload.provider : undefined;
  const model = "model" in payload ? payload.model : undefined;
  const apiKeyId = "api_key_id" in payload ? payload.api_key_id : undefined;

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
    // prev_event_hash and chain_sequence are set by AuditEmitter.enqueue()
    request_id: requestId,
  };

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
  if (uri === "stdout://" || uri === "stdout:///") {
    dest = new StdoutDestination();
  } else if (uri.startsWith("file://")) {
    const filePath = uri.slice("file://".length);
    dest = new FileDestination(filePath);
  } else if (uri.startsWith("https://") || uri.startsWith("http://")) {
    dest = new HttpDestination(uri);
  } else if (uri.startsWith("s3://")) {
    dest = new S3Destination(uri);
  } else if (uri.startsWith("postgres://") || uri.startsWith("postgresql://")) {
    dest = new PostgresDestination(uri);
  } else if (uri.startsWith("otlp://") || uri.startsWith("otlps://")) {
    dest = new OtlpDestination(uri);
  } else {
    console.warn(
      `[TransparentGuard] Unrecognised audit destination scheme: "${uri}". Falling back to stdout. ` +
      `Supported schemes: stdout://, file://, http://, https://, s3://, postgres://, otlp://, otlps://`,
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
  private readonly licenseFeatures: string[];
  private readonly buffer: AuditEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  // Per-instance chain integrity state (fixes the module-level shared state bug)
  private lastEventHash: string | undefined;
  private chainSequence: number = 0;
  private chainRootNonce: string | undefined;
  private chainInitialized = false;

  constructor(audit: TPSAudit, licenseFeatures: string[] = []) {
    this.audit = audit;
    this.licenseFeatures = licenseFeatures;
    this.initChain();
  }

  private initChain(): void {
    const ci = this.audit.chain_integrity;
    if (!ci?.enabled) return;
    // Chain integrity requires audit_chain_integrity license feature (Startup tier and above)
    if (!this.licenseFeatures.includes("audit_chain_integrity")) {
      console.warn(
        "[TransparentGuard] audit.chain_integrity requires the audit_chain_integrity license feature. " +
          "Upgrade to Startup tier or above. Chain integrity has been disabled for this session.",
      );
      return;
    }

    if (ci.sidecar_path) {
      const existing = readSidecar(ci.sidecar_path);
      if (existing) {
        this.chainRootNonce = existing.chain_root_nonce;
        this.lastEventHash = existing.last_event_hash;
        this.chainSequence = existing.last_sequence + 1;
        this.chainInitialized = true;
        return;
      }
    }

    // Fresh chain — generate root nonce
    this.chainRootNonce = crypto.randomBytes(32).toString("base64url");
    const algorithm = ci.algorithm ?? "sha256";
    const nonceHash = algorithm === "sha3-256"
      ? crypto.createHash("sha3-256").update(this.chainRootNonce, "utf8").digest("hex")
      : crypto.createHash("sha256").update(this.chainRootNonce, "utf8").digest("hex");
    this.lastEventHash = `${algorithm}:${nonceHash}`;
    this.chainSequence = 0;
    this.chainInitialized = true;
  }

  /** Enqueue an audit event. Flushes when buffer hits batch_size. */
  enqueue(event: AuditEvent): void {
    if (!this.audit.enabled) return;

    const allowedTypes = this.audit.events ?? [
      "allowed", "blocked", "redacted", "warned", "error",
    ];
    if (!allowedTypes.includes(event.event_type as typeof allowedTypes[number])) return;

    // Apply chain integrity fields before buffering
    const ci = this.audit.chain_integrity;
    if (ci?.enabled && this.chainInitialized) {
      event.chain_sequence = this.chainSequence;
      event.prev_event_hash = this.lastEventHash;
      this.lastEventHash = computeEventHash(event, ci.algorithm ?? "sha256");
      this.chainSequence++;
    }

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
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
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

    // Update chain sidecar after writing events
    const ci = this.audit.chain_integrity;
    if (ci?.enabled && ci.sidecar_path && this.chainRootNonce && events.length > 0) {
      const lastEvent = events[events.length - 1];
      if (lastEvent) {
        writeSidecarAtomic(ci.sidecar_path, {
          tg_sidecar_version: "1.0",
          chain_root_nonce: this.chainRootNonce,
          algorithm: ci.algorithm ?? "sha256",
          last_event_id: lastEvent.id,
          last_event_hash: this.lastEventHash ?? "",
          last_sequence: lastEvent.chain_sequence ?? this.chainSequence - 1,
          last_updated: new Date().toISOString(),
          destination: this.audit.destination ?? "",
        });
      }
    }

    // Webhook notifications (fire-and-forget, non-blocking)
    if (this.audit.notify?.length) {
      void this.sendNotifications(events);
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

      const maxAttempts = notify.retry?.max_attempts ?? 3;
      const backoffMs = notify.retry?.backoff_ms ?? 500;

      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(
            () => controller.abort(),
            notify.timeout_ms ?? 5000,
          );
          const response = await fetch(notify.url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(notify.headers ?? {}),
            },
            body: JSON.stringify({
              notification_type: "violation_alert",
              events: filteredEvents,
            }),
            signal: controller.signal,
          });
          clearTimeout(timeout);
          if (response.ok) break;
          // Non-2xx — retry
        } catch {
          // Network error — retry with backoff
        }
        if (attempt < maxAttempts - 1) {
          await new Promise<void>((resolve) =>
            setTimeout(resolve, backoffMs * Math.pow(2, attempt)),
          );
        }
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
