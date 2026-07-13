/**
 * TransparentGuard Runtime — Evaluation Receipt (Cryptographic Trust Chain)
 * Generates ECDSA-P256 signed receipts for every policy evaluation.
 * Receipts are tamper-evident, auditor-verifiable, and vendor-independent.
 *
 * Signing key precedence:
 *   1. TG_SIGNING_KEY env — base64-encoded PKCS#8 PEM private key (stable, cross-process)
 *   2. Ephemeral — P-256 key generated at module load (rotates on restart)
 */

import crypto from "crypto";
import type { EvaluationReceipt, RequestPayload, ResponsePayload, TPSPolicy } from "../types.js";

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

interface SigningKey {
  privateKey: crypto.KeyObject;
  publicKeySpki: string; // base64url DER
  publicKeyId: string;   // sha256:first32hex
}

let _signingKey: SigningKey | null = null;

function loadOrGenerateKey(): SigningKey {
  if (_signingKey) return _signingKey;

  const envKey = process.env["TG_SIGNING_KEY"];
  if (envKey) {
    try {
      const pem = Buffer.from(envKey, "base64").toString("utf8");
      const privateKey = crypto.createPrivateKey({ key: pem, format: "pem" });
      const publicKey = crypto.createPublicKey(privateKey);
      const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
      const spkiB64 = spkiDer.toString("base64url");
      const fp = crypto.createHash("sha256").update(spkiDer).digest("hex");
      _signingKey = {
        privateKey,
        publicKeySpki: spkiB64,
        publicKeyId: `sha256:${fp.slice(0, 32)}`,
      };
      return _signingKey;
    } catch (err) {
      console.warn(`[TransparentGuard] TG_SIGNING_KEY is set but could not be loaded: ${String(err)}. Using ephemeral key.`);
    }
  }

  // Ephemeral P-256 key
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const spkiB64 = spkiDer.toString("base64url");
  const fp = crypto.createHash("sha256").update(spkiDer).digest("hex");

  _signingKey = {
    privateKey,
    publicKeySpki: spkiB64,
    publicKeyId: `sha256:${fp.slice(0, 32)}`,
  };
  return _signingKey;
}

// ---------------------------------------------------------------------------
// Receipt generation
// ---------------------------------------------------------------------------

function canonicalize(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalize).join(",") + "]";
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(obj as object).sort()) {
    sorted[k] = (obj as Record<string, unknown>)[k];
  }
  return "{" + Object.entries(sorted).map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",") + "}";
}

function makeReceiptId(): string {
  return `tgr_${crypto.randomBytes(12).toString("hex")}`;
}

/**
 * Generates a signed evaluation receipt for the completed policy evaluation.
 * Returns null if signing fails — receipt failure must never block evaluation.
 */
export function generateReceipt(
  payload: RequestPayload | ResponsePayload,
  policy: TPSPolicy,
  allowed: boolean,
  violationCount: number,
): EvaluationReceipt | null {
  try {
    const key = loadOrGenerateKey();
    const evaluatedAt = new Date().toISOString();
    const id = makeReceiptId();

    // Hash the payload (excluding any previously-redacted spans)
    const payloadCanon = canonicalize(payload);
    const requestHash = crypto.createHash("sha256").update(payloadCanon, "utf8").digest("hex");

    // Policy digest
    const policyDigest = crypto
      .createHash("sha256")
      .update(`${policy.name}:${policy.tps_version}`, "utf8")
      .digest("hex");

    const outcome: EvaluationReceipt["outcome"] =
      !allowed ? "blocked" : violationCount > 0 ? "redacted" : "allowed";

    // Body to sign — deterministically serialized
    const body = canonicalize({
      id,
      request_hash: requestHash,
      policy_digest: policyDigest,
      outcome,
      violation_count: violationCount,
      evaluated_at: evaluatedAt,
    });

    const signature = crypto
      .createSign("SHA256")
      .update(body, "utf8")
      .sign(key.privateKey, "base64url");

    return {
      id,
      request_hash: requestHash,
      policy_digest: policyDigest,
      outcome,
      violation_count: violationCount,
      evaluated_at: evaluatedAt,
      signature,
      public_key_id: key.publicKeyId,
      public_key_spki: key.publicKeySpki,
    };
  } catch {
    return null;
  }
}

/**
 * Verifies an evaluation receipt using the public key embedded in the receipt.
 * Returns true if the signature is valid.
 */
export function verifyReceipt(receipt: EvaluationReceipt): boolean {
  try {
    const spkiDer = Buffer.from(receipt.public_key_spki, "base64url");
    const publicKey = crypto.createPublicKey({ key: spkiDer, type: "spki", format: "der" });

    const body = canonicalize({
      id: receipt.id,
      request_hash: receipt.request_hash,
      policy_digest: receipt.policy_digest,
      outcome: receipt.outcome,
      violation_count: receipt.violation_count,
      evaluated_at: receipt.evaluated_at,
    });

    return crypto
      .createVerify("SHA256")
      .update(body, "utf8")
      .verify(publicKey, receipt.signature, "base64url");
  } catch {
    return false;
  }
}

/**
 * Returns the public key ID and SPKI of the active signing key.
 * Use this to pre-register the public key with your auditor.
 */
export function getSigningPublicKey(): { public_key_id: string; public_key_spki: string } {
  const key = loadOrGenerateKey();
  return {
    public_key_id: key.publicKeyId,
    public_key_spki: key.publicKeySpki,
  };
}
