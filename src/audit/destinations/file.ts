/**
 * TransparentGuard Runtime — File Audit Destination
 * Appends audit events to a local file in ndjson, json, or ocsf format.
 */

import fs from "fs";
import path from "path";
import type { AuditEvent } from "../../types.js";
import { AuditEmitter } from "../emitter.js";

export class FileDestination {
  private readonly filePath: string;
  private ensuredDir = false;

  constructor(filePath: string) {
    // Strip leading slash if file:// was stripped already (e.g. "file://./logs/audit.jsonl")
    this.filePath = path.resolve(filePath.startsWith("/") ? filePath : filePath);
  }

  async write(events: AuditEvent[], format: "ndjson" | "json" | "ocsf"): Promise<void> {
    if (events.length === 0) return;

    if (!this.ensuredDir) {
      const dir = path.dirname(this.filePath);
      fs.mkdirSync(dir, { recursive: true });
      this.ensuredDir = true;
    }

    const data = AuditEmitter.serialize(events, format);
    fs.appendFileSync(this.filePath, data, "utf8");
  }

  async flush(): Promise<void> {
    // File writes are synchronous — nothing to flush
  }
}
