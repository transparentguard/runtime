/**
 * TransparentGuard Runtime — Custom Classifier Registry
 * Allows OEM customers to register domain-specific classifiers via TPS policy files.
 * Supports pattern-based, keyword-based, and webhook-backed classifiers.
 */

import type { ClassifierResponse } from "./classifier-api.js";

const CLASSIFIER_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// Public types (mirrored in types.ts as CustomClassifierSpec)
// ---------------------------------------------------------------------------

export interface CustomClassifierDef {
  /** Unique name, typically prefixed "custom/<name>" */
  name: string;
  description?: string;
  /** Regex patterns — any match triggers the classifier */
  patterns?: string[];
  pattern_flags?: string;
  /** Keywords — matched whole-word (case-insensitive by default) */
  keywords?: string[];
  keyword_match?: "any" | "all";
  keyword_case_sensitive?: boolean;
  /** Score to return on a match (default: 1.0) */
  score_on_match?: number;
  /** External scoring endpoint — POST {text, classifier} → {score, label} */
  webhook_url?: string;
  webhook_headers?: Record<string, string>;
  /** Semantic concept hints (logged for PIE shadow mode; not scored locally) */
  concepts?: string[];
}

// ---------------------------------------------------------------------------
// In-process registry
// ---------------------------------------------------------------------------

const registry = new Map<string, CustomClassifierDef>();

/** Register a custom classifier for this process lifetime. */
export function registerClassifier(def: CustomClassifierDef): void {
  if (!def.name) throw new Error("CustomClassifier: name is required.");
  registry.set(def.name, def);
}

/** Retrieve a registered custom classifier by name. */
export function getClassifier(name: string): CustomClassifierDef | undefined {
  return registry.get(name);
}

/** Returns all registered custom classifier names. */
export function listClassifiers(): string[] {
  return [...registry.keys()];
}

/**
 * Resolve a custom classifier from either the registry or an inline spec
 * (passed from TPSPolicy.custom_classifiers at evaluation time).
 * Returns null when the classifier is unknown.
 */
export async function resolveCustomClassifier(
  text: string,
  spec: CustomClassifierDef,
): Promise<ClassifierResponse> {
  const scoreOnMatch = spec.score_on_match ?? 1.0;

  // 1. Pattern-based scoring
  if (spec.patterns && spec.patterns.length > 0) {
    const flags = spec.pattern_flags ?? "gi";
    for (const raw of spec.patterns) {
      try {
        const re = new RegExp(raw, flags);
        if (re.test(text)) {
          return {
            score: scoreOnMatch,
            label: spec.name,
            source: "heuristic",
            detail: `Pattern match: ${raw.slice(0, 60)}`,
          };
        }
      } catch {
        // Invalid regex — skip silently
      }
    }
  }

  // 2. Keyword-based scoring
  if (spec.keywords && spec.keywords.length > 0) {
    const caseSensitive = spec.keyword_case_sensitive === true;
    const haystack = caseSensitive ? text : text.toLowerCase();

    const matchKw = (kw: string): boolean => {
      const needle = caseSensitive ? kw : kw.toLowerCase();
      const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp(`\\b${escaped}\\b`).test(haystack);
    };

    const matchMode = spec.keyword_match ?? "any";
    const triggered =
      matchMode === "all"
        ? spec.keywords.every(matchKw)
        : spec.keywords.some(matchKw);

    if (triggered) {
      return {
        score: scoreOnMatch,
        label: spec.name,
        source: "heuristic",
        detail: `Keyword match (mode=${matchMode})`,
      };
    }
  }

  // 3. Webhook-based scoring
  if (spec.webhook_url) {
    const result = await callClassifierWebhook(spec, text);
    if (result !== null) return result;
  }

  // No match
  return { score: 0, label: "clean", source: "heuristic" };
}

// ---------------------------------------------------------------------------
// Webhook helper
// ---------------------------------------------------------------------------

async function callClassifierWebhook(
  spec: CustomClassifierDef,
  text: string,
): Promise<ClassifierResponse | null> {
  const url = spec.webhook_url!;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CLASSIFIER_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "transparentguard-runtime/0.1.0",
        ...(spec.webhook_headers ?? {}),
      },
      body: JSON.stringify({ text, classifier: spec.name }),
      signal: controller.signal,
    });

    if (!res.ok) return null;

    const data = (await res.json()) as { score?: number; label?: string; detail?: string };
    const score = typeof data.score === "number" ? Math.min(Math.max(data.score, 0), 1) : 0;
    return {
      score,
      label: data.label ?? (score >= 0.5 ? "match" : "clean"),
      source: "api",
      detail: data.detail,
    };
  } catch {
    return null; // webhook failures are non-fatal — classifier returns no match
  } finally {
    clearTimeout(timer);
  }
}
