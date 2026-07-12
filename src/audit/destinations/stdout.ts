/**
 * TransparentGuard Runtime — Stdout Audit Destination
 * Writes audit events to stdout. Useful for development and log aggregators.
 */

import type { AuditEvent } from "../../types.js";
import { AuditEmitter } from "../emitter.js";

export class StdoutDestination {
  async write(events: AuditEvent[], format: "ndjson" | "json" | "ocsf"): Promise<void> {
    if (events.length === 0) return;
    const data = AuditEmitter.serialize(events, format);
    process.stdout.write(data);
  }

  async flush(): Promise<void> {
    // stdout is unbuffered — nothing to flush
  }
}
