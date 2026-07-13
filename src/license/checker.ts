/**
 * TransparentGuard Runtime — License Checker
 * Verifies API keys against the TransparentGuard API and enforces trial expiry.
 * Results are cached for 5 minutes to avoid per-call API overhead.
 */

const DEFAULT_API_BASE = "https://api.transparentguard.com";
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const CHECK_TIMEOUT_MS = 5_000;

export class TransparentGuardError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "trial_expired"
      | "invalid_key"
      | "rate_limited"
      | "api_unreachable"
      | "feature_requires_paid_tier"
      | "policy_violation",
    public readonly detail?: string,
  ) {
    super(message);
    this.name = "TransparentGuardError";
  }
}

export type LicenseTier = "free" | "startup" | "growth" | "enterprise" | "oem";

export interface LicenseStatus {
  valid: boolean;
  tier: LicenseTier;
  trialActive: boolean;
  trialExpiresAt?: Date;
  features: LicenseFeature[];
  checkedAt: Date;
}

export type LicenseFeature =
  | "ml_classifiers"
  | "semantic_targets"
  | "confidentiality_check"
  | "compliance_frameworks"
  | "audit_s3"
  | "audit_postgres"
  | "audit_gcs"
  | "audit_azure"
  | "policy_registry"
  | "oem_embed"
  | "fedramp"
  | "trust_chain"
  | "pie"
  | "audit_chain_integrity"
  | "threshold_notifications";

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

interface CacheEntry {
  status: LicenseStatus;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();

// Grace cache — stores the last *valid* license status for up to 1 hour.
// Used when the license API is temporarily unreachable: prevents silent fallback
// to free tier (fail-closed rather than fail-open).
const GRACE_TTL_MS = 60 * 60 * 1000; // 1 hour
const graceCache = new Map<string, CacheEntry>();

function getGraceCached(apiKey: string): LicenseStatus | null {
  const entry = graceCache.get(apiKey);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    graceCache.delete(apiKey);
    return null;
  }
  return entry.status;
}

function setGraceCached(apiKey: string, status: LicenseStatus): void {
  graceCache.set(apiKey, { status, expiresAt: Date.now() + GRACE_TTL_MS });
}

function getCached(apiKey: string): LicenseStatus | null {
  const entry = cache.get(apiKey);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(apiKey);
    return null;
  }
  return entry.status;
}

function setCached(apiKey: string, status: LicenseStatus): void {
  cache.set(apiKey, {
    status,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });
  // Extend grace window every time we get a successful response
  setGraceCached(apiKey, status);
}

// ---------------------------------------------------------------------------
// Free tier feature set
// ---------------------------------------------------------------------------

const FREE_TIER_STATUS: LicenseStatus = {
  valid: true,
  tier: "free",
  trialActive: false,
  features: [], // No paid features
  checkedAt: new Date(),
};

// ---------------------------------------------------------------------------
// API check
// ---------------------------------------------------------------------------

interface LicenseApiResponse {
  valid: boolean;
  tier: LicenseTier;
  trial_active: boolean;
  trial_expires_at?: string;
  features: LicenseFeature[];
}

async function checkApiKey(
  apiKey: string,
  apiBaseUrl: string,
): Promise<LicenseStatus> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CHECK_TIMEOUT_MS);

  try {
    const response = await fetch(`${apiBaseUrl}/v1/license/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        "User-Agent": "transparentguard-runtime/0.1.0",
      },
      body: JSON.stringify({ runtime_version: "0.1.0" }),
      signal: controller.signal,
    });

    if (response.status === 401 || response.status === 403) {
      const body = await response.json().catch(() => ({})) as Record<string, unknown>;
      const code = String(body["code"] ?? "");

      if (code === "trial_expired") {
        throw new TransparentGuardError(
          "Your TransparentGuard trial has ended. Upgrade at transparentguard.com to continue.",
          "trial_expired",
        );
      }

      throw new TransparentGuardError(
        "Invalid TransparentGuard API key. Check your key at transparentguard.com.",
        "invalid_key",
      );
    }

    if (response.status === 429) {
      throw new TransparentGuardError(
        "TransparentGuard license check rate limited. Retrying with cached status.",
        "rate_limited",
      );
    }

    if (!response.ok) {
      throw new TransparentGuardError(
        `TransparentGuard API returned ${response.status}.`,
        "api_unreachable",
      );
    }

    const data = await response.json() as LicenseApiResponse;

    const status: LicenseStatus = {
      valid: data.valid,
      tier: data.tier,
      trialActive: data.trial_active,
      trialExpiresAt: data.trial_expires_at ? new Date(data.trial_expires_at) : undefined,
      features: data.features,
      checkedAt: new Date(),
    };

    // Trial expired — hard block
    if (status.trialActive === false && status.tier === "free" && !data.valid) {
      throw new TransparentGuardError(
        "Your TransparentGuard trial has ended. Upgrade at transparentguard.com to continue.",
        "trial_expired",
      );
    }

    return status;
  } catch (err) {
    if (err instanceof TransparentGuardError) throw err;
    // Network failures — fall through to free tier with a warning
    throw new TransparentGuardError(
      `Cannot reach TransparentGuard API: ${String(err)}`,
      "api_unreachable",
    );
  } finally {
    clearTimeout(timeout);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Checks the license status for the given API key.
 * Returns cached results when available.
 * Falls back to free tier on network failures (non-blocking).
 * Throws TransparentGuardError on trial expiry or invalid keys.
 */
export async function checkLicense(
  apiKey: string | undefined,
  apiBaseUrl: string = DEFAULT_API_BASE,
  offlineMode = false,
): Promise<LicenseStatus> {
  // No key provided — free tier
  if (!apiKey) return { ...FREE_TIER_STATUS, checkedAt: new Date() };

  // Offline mode — skip the API check
  if (offlineMode) {
    return {
      ...FREE_TIER_STATUS,
      tier: "enterprise",
      features: [
        "ml_classifiers",
        "semantic_targets",
        "confidentiality_check",
        "compliance_frameworks",
        "audit_s3",
        "audit_postgres",
        "audit_gcs",
        "audit_azure",
        "policy_registry",
      ],
      checkedAt: new Date(),
    };
  }

  // Cache hit
  const cached = getCached(apiKey);
  if (cached) return cached;

  try {
    const status = await checkApiKey(apiKey, apiBaseUrl);
    setCached(apiKey, status);
    return status;
  } catch (err) {
    if (err instanceof TransparentGuardError) {
      if (err.code === "api_unreachable" || err.code === "rate_limited") {
        // Fail-closed: use last known valid status if within the 1-hour grace window.
        // Never silently downgrade to free tier — that would let callers bypass paid gates.
        const graceStatus = getGraceCached(apiKey);
        if (graceStatus) {
          console.warn(
            `[TransparentGuard] ${err.message} Using cached license status (grace window active, expires in <1h).`,
          );
          return graceStatus;
        }
        // Grace window expired or no prior successful check — hard fail.
        throw new TransparentGuardError(
          `TransparentGuard license server unreachable and no cached status is available. ` +
            `Verify network connectivity to api.transparentguard.com. Original error: ${err.message}`,
          "api_unreachable",
        );
      }
      // Hard failures (trial_expired, invalid_key) — re-throw
      throw err;
    }
    throw err;
  }
}

/**
 * Asserts that the current license includes the requested feature.
 * Throws TransparentGuardError with code "feature_requires_paid_tier" if not.
 */
export function assertFeature(
  status: LicenseStatus,
  feature: LicenseFeature,
  featureDescription: string,
): void {
  if (!status.features.includes(feature)) {
    throw new TransparentGuardError(
      `${featureDescription} requires a paid TransparentGuard plan. Upgrade at transparentguard.com.`,
      "feature_requires_paid_tier",
      feature,
    );
  }
}
