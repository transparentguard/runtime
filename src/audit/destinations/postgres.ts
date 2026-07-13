/**
 * TransparentGuard Runtime — PostgreSQL Audit Destination
 *
 * Inserts audit events into a PostgreSQL table.
 * Auto-creates the `tg_audit_events` table and indexes on first write.
 *
 * Requirements:
 *   npm install pg
 *
 * URI format: postgres://user:password@host:5432/database
 */

import type { AuditEvent } from "../../types.js";

// ---------------------------------------------------------------------------
// Minimal inline types — avoids importing `pg` at type-check time.
// ---------------------------------------------------------------------------

interface PgPool {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
  end(): Promise<void>;
}

interface PgPoolConfig {
  connectionString: string;
  max?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
}

interface PgSdk {
  Pool: new (config: PgPoolConfig) => PgPool;
}

const DDL = `
CREATE TABLE IF NOT EXISTS tg_audit_events (
  id             TEXT        PRIMARY KEY,
  timestamp      TIMESTAMPTZ NOT NULL,
  policy_name    TEXT,
  rule_id        TEXT,
  event_type     TEXT        NOT NULL,
  stage          TEXT        NOT NULL,
  provider       TEXT,
  model          TEXT,
  api_key_id     TEXT,
  request_id     TEXT,
  outcome        TEXT,
  tags           JSONB,
  violation      JSONB,
  metadata       JSONB,
  raw            JSONB       NOT NULL,
  chain_sequence BIGINT,
  prev_hash      TEXT
);
CREATE INDEX IF NOT EXISTS tg_audit_events_ts_idx        ON tg_audit_events (timestamp);
CREATE INDEX IF NOT EXISTS tg_audit_events_request_id_idx ON tg_audit_events (request_id);
CREATE INDEX IF NOT EXISTS tg_audit_events_event_type_idx ON tg_audit_events (event_type);
CREATE INDEX IF NOT EXISTS tg_audit_events_policy_idx    ON tg_audit_events (policy_name);
`.trim();

function loadSdk(): PgSdk {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("pg") as PgSdk;
  } catch {
    throw new Error(
      "[TransparentGuard] `pg` is required for PostgreSQL audit destinations.\n" +
      "Install it: npm install pg",
    );
  }
}

// ---------------------------------------------------------------------------
// Postgres Destination
// ---------------------------------------------------------------------------

export class PostgresDestination {
  private readonly connectionString: string;
  private pool: PgPool | null = null;
  private ddlApplied = false;

  constructor(postgresUri: string) {
    this.connectionString = postgresUri;
  }

  private getPool(): PgPool {
    if (!this.pool) {
      const { Pool } = loadSdk();
      this.pool = new Pool({
        connectionString: this.connectionString,
        max: 5,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 5_000,
      });
    }
    return this.pool;
  }

  private async ensureDdl(): Promise<void> {
    if (this.ddlApplied) return;
    await this.getPool().query(DDL);
    this.ddlApplied = true;
  }

  async write(events: AuditEvent[], _format: "ndjson" | "json" | "ocsf"): Promise<void> {
    if (events.length === 0) return;

    await this.ensureDdl();
    const pool = this.getPool();

    // Build a multi-row INSERT for the batch
    const rows: string[] = [];
    const params: unknown[] = [];
    let pIdx = 1;

    for (const e of events) {
      rows.push(
        `($${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++}, ` +
        `$${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++}, ` +
        `$${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++}, $${pIdx++}, ` +
        `$${pIdx++}, $${pIdx++})`,
      );
      params.push(
        e.id,
        e.timestamp,
        e.policy_name,
        e.rule_id ?? null,
        e.event_type,
        e.stage,
        e.provider ?? null,
        e.model ?? null,
        e.api_key_id ?? null,
        e.request_id ?? null,
        e.violation?.outcome ?? null,
        e.tags ? JSON.stringify(e.tags) : null,
        e.violation ? JSON.stringify(e.violation) : null,
        e.metadata ? JSON.stringify(e.metadata) : null,
        JSON.stringify(e),
        e.chain_sequence ?? null,
        e.prev_event_hash ?? null,
      );
    }

    const text =
      `INSERT INTO tg_audit_events ` +
      `(id, timestamp, policy_name, rule_id, event_type, stage, ` +
      `provider, model, api_key_id, request_id, outcome, tags, violation, ` +
      `metadata, raw, chain_sequence, prev_hash) ` +
      `VALUES ${rows.join(", ")} ` +
      `ON CONFLICT (id) DO NOTHING`;

    await pool.query(text, params);
  }

  async flush(): Promise<void> {
    // All writes are immediate in write() — nothing to flush
  }
}
