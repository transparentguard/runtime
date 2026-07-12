/**
 * TransparentGuard Runtime — Policy Loader
 * Reads a TPS YAML file, validates it against the JSON Schema,
 * and verifies the Ed25519 cryptographic signature if present.
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";
import yaml from "js-yaml";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import type { TPSPolicy, TPSRule, TPSSignature } from "./types.js";

// ---------------------------------------------------------------------------
// JSON Schema — loaded at module init so validation is fast on every call
// ---------------------------------------------------------------------------

// We ship the schema inline to avoid a runtime file read dependency
const TPS_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://transparentguard.dev/schema/tps-v1.json",
  title: "TransparentGuard Policy Spec v1.0",
  type: "object",
  required: ["tps_version", "name", "rules", "audit"],
  additionalProperties: true, // permissive for forward-compat; deep rules validated by types
  properties: {
    tps_version: { type: "string", enum: ["1.0"] },
    name: { type: "string", minLength: 1, maxLength: 128 },
    description: { type: "string", maxLength: 512 },
    extends: { type: "string", minLength: 1 },
    default_action: { type: "string", enum: ["allow", "deny"] },
    rules: { type: "array", minItems: 1 },
    audit: {
      type: "object",
      required: ["enabled"],
      properties: {
        enabled: { type: "boolean" },
        destination: { type: "string" },
        format: { type: "string", enum: ["ndjson", "json", "ocsf"] },
        retention_days: { type: "integer", minimum: 1 },
      },
    },
  },
};

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv as Parameters<typeof addFormats>[0]);
const validateSchema = ajv.compile(TPS_SCHEMA);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class PolicyLoadError extends Error {
  constructor(
    message: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
    this.name = "PolicyLoadError";
  }
}

export class PolicySignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicySignatureError";
  }
}

// ---------------------------------------------------------------------------
// Signature verification (Ed25519)
// ---------------------------------------------------------------------------

/**
 * Verifies the Ed25519 signature on a raw policy YAML string.
 *
 * The signature covers the policy content with the `signature` field
 * stripped — so the signed payload is the canonical policy minus its own
 * signature block. This matches the signing convention used by the
 * TransparentGuard CLI `tg sign` command.
 */
function verifySignature(rawYaml: string, sig: TPSSignature): void {
  if (sig.algorithm !== "ed25519") {
    throw new PolicySignatureError(
      `Unsupported signature algorithm: ${sig.algorithm}. Only ed25519 is supported.`,
    );
  }

  // Reconstruct the canonical signed payload:
  // Parse → strip signature field → re-serialize to stable JSON.
  let doc: Record<string, unknown>;
  try {
    doc = yaml.load(rawYaml) as Record<string, unknown>;
  } catch (err) {
    throw new PolicySignatureError(`Cannot parse policy for signature verification: ${String(err)}`);
  }

  const { signature: _sig, ...docWithoutSig } = doc;
  void _sig; // intentionally unused

  // Canonical form: sorted-key JSON, no trailing whitespace
  const canonical = JSON.stringify(sortObjectKeys(docWithoutSig));

  let publicKeyDer: Buffer;
  try {
    // public_key is base64-encoded raw 32-byte Ed25519 public key
    const rawKey = Buffer.from(sig.public_key, "base64");
    if (rawKey.length !== 32) {
      throw new PolicySignatureError(
        `Invalid Ed25519 public key length: expected 32 bytes, got ${rawKey.length}.`,
      );
    }
    // Node crypto expects DER-encoded SubjectPublicKeyInfo for Ed25519
    // Prefix: 302a300506032b6570032100
    const derPrefix = Buffer.from("302a300506032b6570032100", "hex");
    publicKeyDer = Buffer.concat([derPrefix, rawKey]);
  } catch (err) {
    if (err instanceof PolicySignatureError) throw err;
    throw new PolicySignatureError(`Invalid public key encoding: ${String(err)}`);
  }

  let signatureBytes: Buffer;
  try {
    signatureBytes = Buffer.from(sig.value, "base64");
    if (signatureBytes.length !== 64) {
      throw new PolicySignatureError(
        `Invalid Ed25519 signature length: expected 64 bytes, got ${signatureBytes.length}.`,
      );
    }
  } catch (err) {
    if (err instanceof PolicySignatureError) throw err;
    throw new PolicySignatureError(`Invalid signature encoding: ${String(err)}`);
  }

  const publicKey = crypto.createPublicKey({
    key: publicKeyDer,
    format: "der",
    type: "spki",
  });

  const valid = crypto.verify(
    null, // Ed25519 does not use a hash algorithm parameter
    Buffer.from(canonical, "utf8"),
    publicKey,
    signatureBytes,
  );

  if (!valid) {
    throw new PolicySignatureError(
      "Policy signature verification failed. The policy file may have been tampered with. " +
        "Evaluation refused. Contact your compliance officer to re-sign the policy.",
    );
  }
}

/** Recursively sorts object keys for stable canonical serialization */
function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sortObjectKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as object).sort()) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

// ---------------------------------------------------------------------------
// Policy cache — avoids re-reading and re-validating on every evaluate() call
// ---------------------------------------------------------------------------

interface CacheEntry {
  policy: TPSPolicy;
  mtime: number;
}

const policyCache = new Map<string, CacheEntry>();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Loads a TPS policy from a YAML file path.
 * Validates the structure and verifies the Ed25519 signature if present.
 * Results are cached by file path and invalidated when the file changes.
 */
export async function loadPolicy(filePath: string): Promise<TPSPolicy> {
  const resolved = path.resolve(filePath);

  // Cache check
  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch (err) {
    throw new PolicyLoadError(`Policy file not found: ${resolved}`, err);
  }

  const cached = policyCache.get(resolved);
  if (cached && cached.mtime === stat.mtimeMs) {
    return cached.policy;
  }

  // Read raw YAML
  let rawYaml: string;
  try {
    rawYaml = fs.readFileSync(resolved, "utf8");
  } catch (err) {
    throw new PolicyLoadError(`Cannot read policy file: ${resolved}`, err);
  }

  const policy = parseAndValidate(rawYaml, resolved);

  policyCache.set(resolved, { policy, mtime: stat.mtimeMs });
  return policy;
}

/**
 * Parses and validates a TPS policy from a raw YAML string.
 * Use this when you have the policy content in memory (e.g. from a database or API).
 */
export function parsePolicy(rawYaml: string, sourceName = "<inline>"): TPSPolicy {
  return parseAndValidate(rawYaml, sourceName);
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

function parseAndValidate(rawYaml: string, sourceName: string): TPSPolicy {
  // Parse YAML
  let doc: unknown;
  try {
    doc = yaml.load(rawYaml);
  } catch (err) {
    throw new PolicyLoadError(`YAML parse error in ${sourceName}: ${String(err)}`, err);
  }

  if (!doc || typeof doc !== "object") {
    throw new PolicyLoadError(`Policy file ${sourceName} is empty or not a YAML object.`);
  }

  // JSON Schema validation
  const valid = validateSchema(doc);
  if (!valid) {
    const messages = (validateSchema.errors ?? [])
      .map((e) => `  • ${e.instancePath || "/"}: ${e.message}`)
      .join("\n");
    throw new PolicyLoadError(
      `Policy validation failed in ${sourceName}:\n${messages}`,
    );
  }

  const policy = doc as TPSPolicy;

  // Audit destination required when enabled
  if (policy.audit.enabled && !policy.audit.destination) {
    throw new PolicyLoadError(
      `Policy ${policy.name}: audit.destination is required when audit.enabled is true.`,
    );
  }

  // Validate rule IDs are unique
  const ids = new Set<string>();
  for (const rule of policy.rules) {
    if (ids.has(rule.id)) {
      throw new PolicyLoadError(
        `Policy ${policy.name}: duplicate rule id "${rule.id}". Rule IDs must be unique.`,
      );
    }
    ids.add(rule.id);
    validateRule(rule, policy.name);
  }

  // Ed25519 signature verification
  if (policy.signature) {
    verifySignature(rawYaml, policy.signature);
  }

  return policy;
}

function validateRule(rule: TPSRule, policyName: string): void {
  const loc = `Policy ${policyName}, rule "${rule.id}"`;

  if (rule.id.startsWith("tg_framework_")) {
    throw new PolicyLoadError(
      `${loc}: rule IDs beginning with "tg_framework_" are reserved for compliance framework templates.`,
    );
  }

  if (["redact", "classify"].includes(rule.action) && !rule.targets?.length) {
    throw new PolicyLoadError(`${loc}: action "${rule.action}" requires at least one target.`);
  }

  if (rule.action === "classify" && (rule.classifier === undefined || rule.threshold === undefined)) {
    throw new PolicyLoadError(`${loc}: action "classify" requires classifier and threshold.`);
  }

  if (rule.action === "enforce" && !rule.enforce_type) {
    throw new PolicyLoadError(`${loc}: action "enforce" requires enforce_type.`);
  }

  if (rule.enforce_type === "provider_allowlist" && !rule.allowed_providers?.length) {
    throw new PolicyLoadError(`${loc}: enforce_type "provider_allowlist" requires allowed_providers.`);
  }

  if (rule.enforce_type === "data_residency" && !rule.allowed_regions?.length) {
    throw new PolicyLoadError(`${loc}: enforce_type "data_residency" requires allowed_regions.`);
  }

  if (rule.enforce_type === "schema_validation" && !rule.expected_schema) {
    throw new PolicyLoadError(`${loc}: enforce_type "schema_validation" requires expected_schema.`);
  }

  if (rule.enforce_type === "tool_allowlist") {
    if (!rule.allowed_tools?.length && !rule.blocked_tools?.length) {
      throw new PolicyLoadError(
        `${loc}: enforce_type "tool_allowlist" requires allowed_tools and/or blocked_tools.`,
      );
    }
  }

  if (["tag", "block", "log"].includes(rule.action) && rule.on_violation !== undefined) {
    throw new PolicyLoadError(
      `${loc}: on_violation must not be set for action "${rule.action}".`,
    );
  }

  if (["redact", "classify", "enforce"].includes(rule.action) && !rule.on_violation) {
    throw new PolicyLoadError(
      `${loc}: on_violation is required for action "${rule.action}".`,
    );
  }

  if (rule.stage === "tool-call" && !["enforce", "tag", "log", "block"].includes(rule.action)) {
    throw new PolicyLoadError(
      `${loc}: stage "tool-call" only supports enforce, tag, log, and block actions.`,
    );
  }

  if (rule.sample_rate !== undefined && (rule.sample_rate <= 0 || rule.sample_rate > 1)) {
    throw new PolicyLoadError(`${loc}: sample_rate must be between 0 (exclusive) and 1 (inclusive).`);
  }
}

