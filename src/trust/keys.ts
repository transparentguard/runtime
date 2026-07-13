/**
 * TransparentGuard Runtime — Key Rotation Watcher
 * Polls a /.well-known/tg-keys.json endpoint for published signing key updates.
 * Allows operators to rotate signing keys without redeployment.
 *
 * Key set format (published at the well-known URL):
 * {
 *   "keys": [
 *     { "kid": "sha256:abc123...", "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "sig" }
 *   ],
 *   "published_at": "2025-01-01T00:00:00Z"
 * }
 */

const DEFAULT_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
const FETCH_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface JwkPublicKey {
  kid: string;
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  use: "sig";
}

export interface KeySet {
  keys: JwkPublicKey[];
  published_at: string;
  fetched_at: string;
  source_url: string;
}

// ---------------------------------------------------------------------------
// In-process state
// ---------------------------------------------------------------------------

let _activeKeySet: KeySet | null = null;
let _watcherTimer: ReturnType<typeof setInterval> | null = null;
let _watcherUrl: string | null = null;

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

async function fetchKeySet(url: string): Promise<KeySet | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { "Accept": "application/json", "User-Agent": "transparentguard-runtime/0.1.0" },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { keys?: JwkPublicKey[]; published_at?: string };
    if (!Array.isArray(data.keys)) return null;
    return {
      keys: data.keys,
      published_at: data.published_at ?? new Date().toISOString(),
      fetched_at: new Date().toISOString(),
      source_url: url,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Starts polling the given endpoint for key set updates.
 * Safe to call multiple times — subsequent calls with the same URL are no-ops.
 * Fetches immediately on first call, then on the configured interval.
 */
export function startKeyRotationWatcher(
  wellKnownUrl: string,
  intervalMs: number = DEFAULT_INTERVAL_MS,
): void {
  if (_watcherTimer && _watcherUrl === wellKnownUrl) return;

  stopKeyRotationWatcher();
  _watcherUrl = wellKnownUrl;

  const poll = (): void => {
    fetchKeySet(wellKnownUrl).then((ks) => {
      if (ks) {
        _activeKeySet = ks;
      }
    }).catch(() => { /* silent — key rotation failures are non-fatal */ });
  };

  // Immediate first fetch
  poll();

  _watcherTimer = setInterval(poll, intervalMs);
  // Don't hold the event loop open
  if (_watcherTimer.unref) _watcherTimer.unref();
}

/**
 * Stops the key rotation watcher.
 */
export function stopKeyRotationWatcher(): void {
  if (_watcherTimer) {
    clearInterval(_watcherTimer);
    _watcherTimer = null;
  }
  _watcherUrl = null;
}

/**
 * Returns the currently active key set, or null if no watcher is running
 * or the initial fetch has not yet completed.
 */
export function getActiveKeySet(): KeySet | null {
  return _activeKeySet;
}

/**
 * Returns the public keys from the active key set as JWK objects.
 * Returns an empty array when no key set is available.
 */
export function getActivePublicKeys(): JwkPublicKey[] {
  return _activeKeySet?.keys ?? [];
}

/**
 * Looks up a key by its kid (key ID) from the active key set.
 */
export function findPublicKey(kid: string): JwkPublicKey | undefined {
  return _activeKeySet?.keys.find((k) => k.kid === kid);
}
