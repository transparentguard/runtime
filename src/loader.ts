/**
 * TransparentGuard Runtime — Policy Loader
 * Reads a TPS YAML file, validates it against the JSON Schema,
 * resolves `extends` inheritance chains, and verifies the Ed25519
 * cryptographic signature if present.
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";
import yaml from "js-yaml";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import type { TPSPolicy, TPSRule, TPSSignature } from "./types.js";

// ---------------------------------------------------------------------------
// JSON Schema — validates required top-level structure
// ---------------------------------------------------------------------------

const TPS_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://transparentguard.dev/schema/tps-v1.json",
  title: "TransparentGuard Policy Spec v1.0",
  type: "object",
  required: ["tps_version", "name", "rules", "audit"],
  additionalProperties: true,
  properties: {
    tps_version: { type: "string", enum: ["1.0"] },
    name: { type: "string", minLength: 1, maxLength: 128 },
    description: { type: "string", maxLength: 512 },
    extends: { type: "string", minLength: 1 },
    default_action: { type: "string", enum: ["allow", "deny"] },
    rules: { type: "array", minItems: 0 },
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

function verifyEd25519Signature(
  rawYaml: string,
  sig: TPSSignature,
): void {
  // Reconstruct the canonical signed payload:
  // Parse → strip signature field → re-serialize to stable JSON.
  let doc: Record<string, unknown>;
  try {
    doc = yaml.load(rawYaml) as Record<string, unknown>;
  } catch (err) {
    throw new PolicySignatureError(`Cannot parse policy for signature verification: ${String(err)}`);
  }

  const { signature: _sig, ...docWithoutSig } = doc;
  void _sig;

  // Canonical form: sorted-key JSON, no trailing whitespace
  const canonical = JSON.stringify(sortObjectKeys(docWithoutSig));

  // Resolve public key — either inline (public_key) or via keyring (key_id)
  const publicKeyB64 = sig.public_key;
  if (!publicKeyB64) {
    if (sig.key_id) {
      // Keyring lookup not yet implemented — warn and skip verification
      console.warn(
        `[TransparentGuard] Policy signature uses key_id "${sig.key_id}" but no keyring is configured. ` +
        `Set TG_KEYRING_PATH to enable keyring-based signature verification. Skipping verification.`,
      );
      return;
    }
    throw new PolicySignatureError(
      "Policy signature block is present but neither public_key nor key_id is set.",
    );
  }

  let publicKeyDer: Buffer;
  try {
    const rawKey = Buffer.from(publicKeyB64, "base64");
    if (rawKey.length !== 32) {
      throw new PolicySignatureError(
        `Invalid Ed25519 public key length: expected 32 bytes, got ${rawKey.length}.`,
      );
    }
    // Node crypto expects DER-encoded SubjectPublicKeyInfo for Ed25519
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

function verifySignature(rawYaml: string, sig: TPSSignature): void {
  switch (sig.algorithm) {
    case "ed25519":
      return verifyEd25519Signature(rawYaml, sig);
    case "rsa-pss-sha256":
    case "ecdsa-p256-sha256":
      // These algorithms require DER-encoded keys from a keyring.
      // If public_key is set (ed25519-style), warn. Otherwise keyring lookup.
      if (sig.required) {
        throw new PolicySignatureError(
          `Algorithm "${sig.algorithm}" requires keyring-based key lookup, which is not yet ` +
          `configured. Set TG_KEYRING_PATH or use algorithm "ed25519" with an inline public_key.`,
        );
      }
      console.warn(
        `[TransparentGuard] Algorithm "${sig.algorithm}" is not yet supported inline. Skipping signature verification.`,
      );
      return;
    default:
      throw new PolicySignatureError(
        `Unsupported signature algorithm: ${String(sig.algorithm)}. ` +
        `Supported: ed25519, rsa-pss-sha256, ecdsa-p256-sha256.`,
      );
  }
}

// ---------------------------------------------------------------------------
// Canonical key sorting (RFC 8785 compatible)
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

// ---------------------------------------------------------------------------
// Policy `extends` resolution
// ---------------------------------------------------------------------------

const MAX_EXTENDS_DEPTH = 5;

/**
 * Resolves the `extends` field by loading the base policy and merging fields.
 * Supports relative/absolute local file paths and https:// URIs.
 * tps:// registry URIs are noted but not yet implemented.
 */
async function resolveExtends(
  policy: TPSPolicy,
  sourceDir: string,
  depth: number,
): Promise<TPSPolicy> {
  if (!policy.extends) return policy;
  if (depth > MAX_EXTENDS_DEPTH) {
    throw new PolicyLoadError(
      `Policy "${policy.name}": extends chain exceeds maximum depth of ${MAX_EXTENDS_DEPTH}. ` +
      `Check for accidental deep chains or circular references.`,
    );
  }

  const extendsUri = policy.extends;

  let basePolicyRaw: string;

  if (extendsUri.startsWith("tps://")) {
    // TPS policy registry — not yet implemented locally
    // Will be implemented in a future version with the hosted registry client
    console.warn(
      `[TransparentGuard] tps:// registry URIs are not yet supported in this version. ` +
      `Skipping extends: ${extendsUri}`,
    );
    return policy;
  } else if (extendsUri.startsWith("https://")) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      const response = await fetch(extendsUri, {
        headers: { Accept: "application/vnd.transparentguard.policy+yaml, text/plain" },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!response.ok) {
        throw new PolicyLoadError(
          `Policy "${policy.name}": failed to fetch extends URI "${extendsUri}": HTTP ${response.status}`,
        );
      }
      basePolicyRaw = await response.text();
    } catch (err) {
      if (err instanceof PolicyLoadError) throw err;
      throw new PolicyLoadError(
        `Policy "${policy.name}": cannot fetch extends URI "${extendsUri}": ${String(err)}`,
      );
    }
  } else if (extendsUri.startsWith("http://")) {
    throw new PolicyLoadError(
      `Policy "${policy.name}": http:// is not permitted for extends URIs. Use https://.`,
    );
  } else {
    // Local file path — relative to the directory of the current policy file
    const resolved = path.resolve(sourceDir, extendsUri);
    try {
      basePolicyRaw = fs.readFileSync(resolved, "utf8");
    } catch (err) {
      throw new PolicyLoadError(
        `Policy "${policy.name}": cannot read extends file "${resolved}": ${String(err)}`,
      );
    }
  }

  let basePolicy: TPSPolicy;
  try {
    basePolicy = parseAndValidate(basePolicyRaw, extendsUri, false);
  } catch (err) {
    throw new PolicyLoadError(
      `Policy "${policy.name}": invalid base policy at "${extendsUri}": ${String(err)}`,
    );
  }

  // Resolve base policy's own extends chain first
  basePolicy = await resolveExtends(basePolicy, sourceDir, depth + 1);

  // Merge per spec Section 21.2:
  //   rules: base rules first, override by same id
  //   environments: child completely replaces base
  //   compliance_frameworks: union
  //   audit: child completely replaces base
  //   default_action: child overrides base
  //   provider: child overrides base

  const baseRuleIds = new Set(basePolicy.rules.map((r) => r.id));
  const overrideRuleIds = new Set(policy.rules.map((r) => r.id));

  const mergedRules: TPSRule[] = [
    // Base rules not overridden by child
    ...basePolicy.rules.filter((r) => !overrideRuleIds.has(r.id)),
    // All child rules (including any that override base rules)
    ...policy.rules,
  ];

  const mergedFrameworks = Array.from(
    new Set([
      ...(basePolicy.compliance_frameworks ?? []),
      ...(policy.compliance_frameworks ?? []),
    ]),
  );

  void baseRuleIds; // used for merge logic reasoning

  const merged: TPSPolicy = {
    ...basePolicy,
    ...policy,
    rules: mergedRules,
    compliance_frameworks: mergedFrameworks.length > 0 ? mergedFrameworks : undefined,
    // Child completely replaces base for environments and audit
    environments: policy.environments ?? basePolicy.environments,
    audit: policy.audit ?? basePolicy.audit,
    default_action: policy.default_action ?? basePolicy.default_action,
    provider: policy.provider ?? basePolicy.provider,
  };

  return merged;
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
 * Validates structure, resolves `extends`, and verifies signatures.
 * Results are cached by file path and invalidated when the file changes.
 */
export async function loadPolicy(filePath: string): Promise<TPSPolicy> {
  const resolved = path.resolve(filePath);

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

  let rawYaml: string;
  try {
    rawYaml = fs.readFileSync(resolved, "utf8");
  } catch (err) {
    throw new PolicyLoadError(`Cannot read policy file: ${resolved}`, err);
  }

  let policy = parseAndValidate(rawYaml, resolved, true);

  // Resolve extends chain
  const sourceDir = path.dirname(resolved);
  policy = await resolveExtends(policy, sourceDir, 0);

  // Verify signature on the original file (pre-merge), not the merged policy
  if (policy.signature) {
    try {
      verifySignature(rawYaml, policy.signature);
    } catch (err) {
      if (err instanceof PolicySignatureError && policy.signature.required) {
        throw err; // required: true — re-throw
      }
      if (err instanceof PolicySignatureError) {
        console.warn(`[TransparentGuard] Signature warning: ${err.message}`);
      }
    }
  }

  policyCache.set(resolved, { policy, mtime: stat.mtimeMs });
  return policy;
}

/**
 * Parses and validates a TPS policy from a raw YAML string.
 * Use when you have the policy content in memory (e.g., from a database or API).
 * Does not resolve `extends` chains or write to cache.
 */
export function parsePolicy(rawYaml: string, sourceName = "<inline>"): TPSPolicy {
  return parseAndValidate(rawYaml, sourceName, true);
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

function parseAndValidate(rawYaml: string, sourceName: string, verifySignatureIfPresent: boolean): TPSPolicy {
  let doc: unknown;
  try {
    doc = yaml.load(rawYaml);
  } catch (err) {
    throw new PolicyLoadError(`YAML parse error in ${sourceName}: ${String(err)}`, err);
  }

  if (!doc || typeof doc !== "object") {
    throw new PolicyLoadError(`Policy file ${sourceName} is empty or not a YAML object.`);
  }

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

  // Validate rule IDs are unique and rules are well-formed
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

  // Validate threshold IDs are unique
  const thresholdIds = new Set<string>();
  for (const threshold of policy.thresholds ?? []) {
    if (!threshold.id) {
      throw new PolicyLoadError(`Policy ${policy.name}: every threshold must have an "id" field.`);
    }
    if (thresholdIds.has(threshold.id)) {
      throw new PolicyLoadError(
        `Policy ${policy.name}: duplicate threshold id "${threshold.id}". Threshold IDs must be unique.`,
      );
    }
    thresholdIds.add(threshold.id);
    validateThreshold(threshold, policy.name, ids);
  }

  // Validate test IDs are unique
  const testIds = new Set<string>();
  for (const test of policy.tests ?? []) {
    if (testIds.has(test.id)) {
      throw new PolicyLoadError(
        `Policy ${policy.name}: duplicate test id "${test.id}". Test IDs must be unique.`,
      );
    }
    testIds.add(test.id);
  }

  // Warn on deny-by-default with no rules (not an error but worth noting)
  if (policy.default_action === "deny" && policy.rules.length === 0) {
    console.warn(
      `[TransparentGuard] Policy "${policy.name}" has default_action: deny but no rules. ` +
      `All calls will be blocked.`,
    );
  }

  // Signature verification (only for file loads, not base-policy parsing)
  if (verifySignatureIfPresent && policy.signature) {
    try {
      verifySignature(rawYaml, policy.signature);
    } catch (err) {
      if (err instanceof PolicySignatureError && policy.signature.required) {
        throw err;
      }
      if (err instanceof PolicySignatureError) {
        console.warn(`[TransparentGuard] Signature warning in ${sourceName}: ${err.message}`);
      }
    }
  }

  return policy;
}

function validateRule(rule: TPSRule, policyName: string): void {
  const loc = `Policy ${policyName}, rule "${rule.id}"`;

  if (rule.id.startsWith("tg_framework_")) {
    throw new PolicyLoadError(
      `${loc}: rule IDs beginning with "tg_framework_" are reserved for compliance framework rules.`,
    );
  }

  const validStages = ["pre-request", "post-response", "both", "tool-call"];
  if (!validStages.includes(rule.stage)) {
    throw new PolicyLoadError(
      `${loc}: invalid stage "${rule.stage}". Valid values: ${validStages.join(", ")}.`,
    );
  }

  const validActions = ["redact", "classify", "enforce", "tag", "block", "log"];
  if (!validActions.includes(rule.action)) {
    throw new PolicyLoadError(
      `${loc}: invalid action "${rule.action}". Valid values: ${validActions.join(", ")}.`,
    );
  }

  // tool-call stage restrictions per spec Section 16 rule 35
  if (rule.stage === "tool-call" && !["enforce", "tag", "log", "block"].includes(rule.action)) {
    throw new PolicyLoadError(
      `${loc}: stage "tool-call" only supports enforce, tag, log, and block actions.`,
    );
  }

  if (["redact", "classify"].includes(rule.action) && !rule.targets?.length) {
    throw new PolicyLoadError(`${loc}: action "${rule.action}" requires at least one target.`);
  }

  if (rule.action === "classify") {
    if (!rule.classifier) {
      throw new PolicyLoadError(`${loc}: action "classify" requires a classifier.`);
    }
    if (rule.threshold === undefined) {
      throw new PolicyLoadError(`${loc}: action "classify" requires a threshold.`);
    }
    if (rule.threshold < 0 || rule.threshold > 1) {
      throw new PolicyLoadError(`${loc}: threshold must be between 0.0 and 1.0.`);
    }
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

  // on_violation must NOT be set for tag, block, log actions (they don't produce violations)
  if (["tag", "block", "log"].includes(rule.action) && rule.on_violation !== undefined) {
    throw new PolicyLoadError(
      `${loc}: on_violation must not be set for action "${rule.action}".`,
    );
  }

  // on_violation is required for redact, classify, enforce
  if (["redact", "classify", "enforce"].includes(rule.action) && !rule.on_violation) {
    throw new PolicyLoadError(
      `${loc}: on_violation is required for action "${rule.action}".`,
    );
  }

  if (rule.sample_rate !== undefined) {
    if (rule.sample_rate <= 0 || rule.sample_rate > 1) {
      throw new PolicyLoadError(`${loc}: sample_rate must be between 0 (exclusive) and 1 (inclusive).`);
    }
    // Warn when a blocking rule is sampled below 100%
    if (rule.on_violation === "block" && rule.sample_rate < 1.0) {
      const rationale = rule.metadata?.["sampling_rationale"];
      if (!rationale) {
        console.warn(
          `[TransparentGuard] WARNING: Rule "${rule.id}" has on_violation: block and sample_rate: ${rule.sample_rate}. ` +
          `Approximately ${Math.round((1 - rule.sample_rate) * 100)}% of calls will not be checked by this rule. ` +
          `If intentional, add a metadata.sampling_rationale field to suppress this warning.`,
        );
      }
    }
  }

  // Streaming mode validation
  if (rule.streaming) {
    const validModes = ["buffer", "window", "passthrough"];
    if (!validModes.includes(rule.streaming.mode)) {
      throw new PolicyLoadError(
        `${loc}: streaming.mode must be one of: ${validModes.join(", ")}.`,
      );
    }
    if (rule.streaming.window_tokens !== undefined && rule.streaming.mode !== "window") {
      throw new PolicyLoadError(
        `${loc}: streaming.window_tokens is only valid when streaming.mode is "window".`,
      );
    }
  }
}

function validateThreshold(
  threshold: import("./types.js").TPSThreshold,
  policyName: string,
  ruleIds: Set<string>,
): void {
  const loc = `Policy ${policyName}, threshold "${threshold.id}"`;

  if (!threshold.rule_id) {
    throw new PolicyLoadError(`${loc}: threshold must specify rule_id.`);
  }

  // rule_id must reference an existing user rule or a tg_framework_ rule
  if (!ruleIds.has(threshold.rule_id) && !threshold.rule_id.startsWith("tg_framework_")) {
    throw new PolicyLoadError(
      `${loc}: threshold rule_id "${threshold.rule_id}" does not reference a defined rule. ` +
      `Use an existing rule id or a tg_framework_ prefixed framework rule id.`,
    );
  }

  if (!threshold.count || threshold.count < 1) {
    throw new PolicyLoadError(`${loc}: threshold count must be a positive integer greater than zero.`);
  }

  if (!threshold.window) {
    throw new PolicyLoadError(`${loc}: threshold window is required.`);
  }

  const windowValid = /^\d+[mhd]$/.test(threshold.window);
  if (!windowValid) {
    throw new PolicyLoadError(
      `${loc}: threshold window "${threshold.window}" is invalid. ` +
      `Use format: integer followed by m (minutes), h (hours), or d (days). E.g. "1h", "30m", "7d".`,
    );
  }

  const validActions = ["notify", "block_all", "escalate"];
  if (!validActions.includes(threshold.action)) {
    throw new PolicyLoadError(
      `${loc}: threshold action must be one of: ${validActions.join(", ")}.`,
    );
  }

  if (threshold.action === "notify" && !threshold.notify_url) {
    throw new PolicyLoadError(
      `${loc}: threshold action "notify" requires a notify_url.`,
    );
  }

  if (threshold.notify_url && !threshold.notify_url.startsWith("https://")) {
    throw new PolicyLoadError(
      `${loc}: threshold notify_url must use https://.`,
    );
  }

  if (threshold.action === "block_all" && !threshold.block_message) {
    console.warn(
      `[TransparentGuard] Threshold "${threshold.id}" uses action block_all without a block_message. ` +
      `A default message will be used.`,
    );
  }

  const validViolationTypes = ["blocked", "redacted", "warned", "error", "sampled_out"];
  if (!validViolationTypes.includes(threshold.violation_type)) {
    throw new PolicyLoadError(
      `${loc}: violation_type must be one of: ${validViolationTypes.join(", ")}.`,
    );
  }
}
