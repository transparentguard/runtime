/**
 * TransparentGuard Runtime — HTTP(S) Audit Destination
 * Posts audit events to an HTTPS webhook endpoint.
 */

import type { AuditEvent } from "../../types.js";
import { AuditEmitter } from "../emitter.js";

const DEFAULT_TIMEOUT_MS = 10_000;

export class HttpDestination {
  private readonly url: string;

  constructor(url: string) {
    this.url = url;
  }

  async write(events: AuditEvent[], format: "ndjson" | "json" | "ocsf"): Promise<void> {
    if (events.length === 0) return;

    const body = AuditEmitter.serialize(events, format);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

    try {
      const response = await fetch(this.url, {
        method: "POST",
        headers: {
          "Content-Type":
            format === "json" ? "application/json" : "application/x-ndjson",
          "User-Agent": "transparentguard-runtime/0.1.0",
        },
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(`HTTP audit destination returned ${response.status}: ${text}`);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  async flush(): Promise<void> {
    // HTTP writes are fire-and-forget in write() — nothing to flush
  }
}
