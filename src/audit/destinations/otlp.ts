/**
 * TransparentGuard Runtime — OTLP Logs Audit Destination
 *
 * Sends audit events as OpenTelemetry Log Records via OTLP HTTP/JSON.
 * Works with any OTEL-compatible collector: Grafana Loki, Datadog, Elastic,
 * Honeycomb, AWS CloudWatch, GCP Cloud Logging, Azure Monitor.
 *
 * No additional npm packages required — uses Node's built-in fetch.
 *
 * URI formats:
 *   otlp://host:4318       → http://host:4318/v1/logs
 *   otlps://host:4317      → https://host:4317/v1/logs
 *
 * Standard OTEL env vars are also honoured:
 *   OTEL_EXPORTER_OTLP_ENDPOINT   (e.g. http://localhost:4318)
 *   OTEL_EXPORTER_OTLP_HEADERS    (comma-separated key=value pairs)
 */

import type { AuditEvent } from "../../types.js";

// ---------------------------------------------------------------------------
// OTLP JSON Logs payload types (OTLP 1.0 spec)
// ---------------------------------------------------------------------------

interface OtlpAnyValue {
  stringValue?: string;
  intValue?: number;
  boolValue?: boolean;
}

interface OtlpAttribute {
  key: string;
  value: OtlpAnyValue;
}

interface OtlpLogRecord {
  timeUnixNano: string;
  observedTimeUnixNano: string;
  severityNumber: number;
  severityText: string;
  body: { stringValue: string };
  attributes: OtlpAttribute[];
  traceId?: string;
  spanId?: string;
}

interface OtlpScopeLogs {
  scope: { name: string; version: string };
  logRecords: OtlpLogRecord[];
}

interface OtlpResourceLogs {
  resource: { attributes: OtlpAttribute[] };
  scopeLogs: OtlpScopeLogs[];
}

interface OtlpLogsPayload {
  resourceLogs: OtlpResourceLogs[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Map TG event_type to OTEL severity number (SeverityNumber enum) */
function toSeverityNumber(eventType: string): number {
  switch (eventType) {
    case "allowed":          return 9;  // INFO
    case "redacted":         return 13; // WARN
    case "warned":           return 13; // WARN
    case "blocked":          return 17; // ERROR
    case "error":            return 17; // ERROR
    case "threshold_triggered": return 17; // ERROR
    case "chain_break":      return 21; // FATAL
    default:                 return 9;  // INFO
  }
}

function toSeverityText(eventType: string): string {
  switch (eventType) {
    case "allowed":             return "INFO";
    case "redacted":
    case "warned":
    case "sampled_out":         return "WARN";
    case "blocked":
    case "error":
    case "threshold_triggered": return "ERROR";
    case "chain_break":         return "FATAL";
    default:                    return "INFO";
  }
}

function strAttr(key: string, value: string): OtlpAttribute {
  return { key, value: { stringValue: value } };
}

function intAttr(key: string, value: number): OtlpAttribute {
  return { key, value: { intValue: value } };
}

function auditEventToLogRecord(event: AuditEvent): OtlpLogRecord {
  const tsNano = String(new Date(event.timestamp).getTime() * 1_000_000);
  const nowNano = String(Date.now() * 1_000_000);

  const attributes: OtlpAttribute[] = [
    strAttr("tg.event_id", event.id),
    strAttr("tg.event_type", event.event_type),
    strAttr("tg.stage", event.stage),
    strAttr("tg.policy_name", event.policy_name),
    strAttr("tg.policy_version", event.policy_version),
  ];

  if (event.rule_id)    attributes.push(strAttr("tg.rule_id", event.rule_id));
  if (event.provider)   attributes.push(strAttr("tg.provider", event.provider));
  if (event.model)      attributes.push(strAttr("tg.model", event.model));
  if (event.api_key_id) attributes.push(strAttr("tg.api_key_id", event.api_key_id));
  if (event.request_id) attributes.push(strAttr("tg.request_id", event.request_id));

  if (event.violation) {
    attributes.push(strAttr("tg.outcome", event.violation.outcome));
    if (event.violation.detail) {
      attributes.push(strAttr("tg.violation.detail", event.violation.detail));
    }
    if (event.violation.category) {
      attributes.push(strAttr("tg.violation.category", event.violation.category));
    }
  }

  if (event.chain_sequence !== undefined) {
    attributes.push(intAttr("tg.chain_sequence", event.chain_sequence));
  }

  // Flatten tags as tg.tag.* attributes
  for (const [k, v] of Object.entries(event.tags ?? {})) {
    attributes.push(strAttr(`tg.tag.${k}`, v));
  }

  return {
    timeUnixNano: tsNano,
    observedTimeUnixNano: nowNano,
    severityNumber: toSeverityNumber(event.event_type),
    severityText: toSeverityText(event.event_type),
    body: { stringValue: JSON.stringify(event) },
    attributes,
  };
}

function parseOtlpUri(uri: string): { endpoint: string; headers: Record<string, string> } {
  // Resolve endpoint from URI or env var
  let base: string;

  if (uri.startsWith("otlps://")) {
    base = "https://" + uri.slice("otlps://".length);
  } else if (uri.startsWith("otlp://")) {
    base = "http://" + uri.slice("otlp://".length);
  } else {
    base = uri;
  }

  // Prefer OTEL_EXPORTER_OTLP_ENDPOINT env var if set (standard OTEL config)
  const envEndpoint = process.env["OTEL_EXPORTER_OTLP_ENDPOINT"];
  if (envEndpoint) base = envEndpoint;

  const endpoint = base.replace(/\/$/, "") + "/v1/logs";

  // Parse OTEL_EXPORTER_OTLP_HEADERS env var: "key1=val1,key2=val2"
  const headers: Record<string, string> = {};
  const envHeaders = process.env["OTEL_EXPORTER_OTLP_HEADERS"];
  if (envHeaders) {
    for (const pair of envHeaders.split(",")) {
      const eqIdx = pair.indexOf("=");
      if (eqIdx > 0) {
        headers[pair.slice(0, eqIdx).trim()] = pair.slice(eqIdx + 1).trim();
      }
    }
  }

  return { endpoint, headers };
}

// ---------------------------------------------------------------------------
// OTLP Destination
// ---------------------------------------------------------------------------

const RESOURCE_ATTRIBUTES: OtlpAttribute[] = [
  { key: "service.name",    value: { stringValue: "transparentguard" } },
  { key: "service.version", value: { stringValue: "0.1.1" } },
];

export class OtlpDestination {
  private readonly endpoint: string;
  private readonly headers: Record<string, string>;

  constructor(uri: string) {
    const { endpoint, headers } = parseOtlpUri(uri);
    this.endpoint = endpoint;
    this.headers = headers;
  }

  async write(events: AuditEvent[], _format: "ndjson" | "json" | "ocsf"): Promise<void> {
    if (events.length === 0) return;

    const payload: OtlpLogsPayload = {
      resourceLogs: [{
        resource: { attributes: RESOURCE_ATTRIBUTES },
        scopeLogs: [{
          scope: { name: "transparentguard.audit", version: "0.1.1" },
          logRecords: events.map(auditEventToLogRecord),
        }],
      }],
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    try {
      const response = await fetch(this.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this.headers,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(`OTLP endpoint returned ${response.status}: ${text}`);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  async flush(): Promise<void> {
    // writes are immediate — nothing to flush
  }
}
