/**
 * TransparentGuard Runtime — S3 Audit Destination
 *
 * Uploads audit events to Amazon S3 (or any S3-compatible endpoint).
 * Uses batched PutObject calls keyed by timestamp for Athena/Glue compatibility.
 *
 * Requirements:
 *   npm install @aws-sdk/client-s3
 *   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION (standard AWS SDK env vars)
 *
 * URI format: s3://bucket-name/optional/prefix/
 */

import type { AuditEvent } from "../../types.js";
import { AuditEmitter } from "../emitter.js";

// ---------------------------------------------------------------------------
// Minimal inline types — avoids importing @aws-sdk/client-s3 at type-check time.
// The actual implementation loads the SDK dynamically at runtime.
// ---------------------------------------------------------------------------

interface S3ClientConfig {
  region?: string;
  endpoint?: string;
  forcePathStyle?: boolean;
}

interface PutObjectInput {
  Bucket: string;
  Key: string;
  Body: string;
  ContentType: string;
}

interface S3Sdk {
  S3Client: new (config: S3ClientConfig) => { send(cmd: unknown): Promise<unknown> };
  PutObjectCommand: new (input: PutObjectInput) => unknown;
}

function loadSdk(): S3Sdk {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("@aws-sdk/client-s3") as S3Sdk;
  } catch {
    throw new Error(
      "[TransparentGuard] @aws-sdk/client-s3 is required for S3 audit destinations.\n" +
      "Install it: npm install @aws-sdk/client-s3",
    );
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseS3Uri(uri: string): { bucket: string; prefix: string } {
  const withoutScheme = uri.slice("s3://".length);
  const slashIdx = withoutScheme.indexOf("/");
  if (slashIdx === -1) {
    return { bucket: withoutScheme, prefix: "" };
  }
  const bucket = withoutScheme.slice(0, slashIdx);
  let prefix = withoutScheme.slice(slashIdx + 1);
  // Ensure trailing slash on prefix
  if (prefix && !prefix.endsWith("/")) prefix += "/";
  return { bucket, prefix };
}

function buildS3Key(prefix: string, batchId: string): string {
  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(now.getUTCDate()).padStart(2, "0");
  const hh = String(now.getUTCHours()).padStart(2, "0");
  return `${prefix}${yyyy}/${mm}/${dd}/${hh}/tg-audit-${batchId}.jsonl`;
}

// ---------------------------------------------------------------------------
// S3 Destination
// ---------------------------------------------------------------------------

export class S3Destination {
  private readonly bucket: string;
  private readonly prefix: string;
  private readonly region: string | undefined;
  private readonly endpoint: string | undefined;
  private sdk: S3Sdk | null = null;

  constructor(s3Uri: string) {
    const { bucket, prefix } = parseS3Uri(s3Uri);
    this.bucket = bucket;
    this.prefix = prefix;
    this.region = process.env["AWS_REGION"] ?? process.env["AWS_DEFAULT_REGION"];
    this.endpoint = process.env["AWS_S3_ENDPOINT"]; // for MinIO / S3-compatible stores
  }

  private getSdk(): S3Sdk {
    if (!this.sdk) this.sdk = loadSdk();
    return this.sdk;
  }

  async write(events: AuditEvent[], format: "ndjson" | "json" | "ocsf"): Promise<void> {
    if (events.length === 0) return;

    const { S3Client, PutObjectCommand } = this.getSdk();
    const client = new S3Client({
      region: this.region,
      ...(this.endpoint ? { endpoint: this.endpoint, forcePathStyle: true } : {}),
    });

    const batchId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const key = buildS3Key(this.prefix, batchId);
    const body = AuditEmitter.serialize(events, format);
    const contentType =
      format === "ocsf" || format === "ndjson"
        ? "application/x-ndjson"
        : "application/json";

    await client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
      }),
    );
  }

  async flush(): Promise<void> {
    // S3 writes are one-shot in write() — nothing to flush
  }
}
