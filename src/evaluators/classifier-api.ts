/**
 * TransparentGuard Runtime — Classifier API Client
 * Calls the TransparentGuard hosted classifier API for paid-tier ML evaluations.
 * Free-tier fallback uses local heuristics when the API is unavailable or no key is set.
 */

import type { RuleStage } from "../types.js";
import { classifyMedicalPii } from "./built-in/pii-medical-v1.js";
import { classifyFinancialPii } from "./built-in/pii-financial-v1.js";

const DEFAULT_API_BASE = "https://api.transparentguard.com";
const CLASSIFIER_TIMEOUT_MS = 8000;

export interface ClassifierRequest {
  classifier: string;
  text: string;
  stage: RuleStage;
  context?: {
    systemPrompt?: string;
    contextDocuments?: string[];
  };
}

export interface ClassifierResponse {
  score: number;
  label: string;
  detail?: string;
  source: "api" | "heuristic";
}

export class ClassifierApiError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "ClassifierApiError";
  }
}

/**
 * Calls the TG classifier API with the provided request.
 * Returns a score between 0.0 and 1.0.
 * Throws ClassifierApiError on non-retryable failures.
 */
export async function callClassifierApi(
  req: ClassifierRequest,
  apiKey: string,
  apiBaseUrl: string = DEFAULT_API_BASE,
): Promise<ClassifierResponse> {
  const url = `${apiBaseUrl}/v1/classify`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CLASSIFIER_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        "User-Agent": "transparentguard-runtime/0.1.0",
      },
      body: JSON.stringify(req),
      signal: controller.signal,
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new ClassifierApiError(
        `Classifier API returned ${response.status}: ${body}`,
        response.status,
      );
    }

    const data = (await response.json()) as ClassifierResponse;
    return { ...data, source: "api" };
  } catch (err) {
    if (err instanceof ClassifierApiError) throw err;
    if (err instanceof Error && err.name === "AbortError") {
      throw new ClassifierApiError(
        `Classifier API timed out after ${CLASSIFIER_TIMEOUT_MS}ms`,
      );
    }
    throw new ClassifierApiError(`Classifier API request failed: ${String(err)}`);
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Heuristic fallback used in free tier when no API key is configured.
 * These are intentionally conservative — they catch obvious cases only
 * and do not replace the ML classifiers.
 */
export function heuristicClassify(
  classifier: string,
  text: string,
): ClassifierResponse {
  const lower = text.toLowerCase();

  switch (classifier) {
    case "built-in/prompt-injection-v2": {
      const injectionPhrases = [
        "ignore previous instructions",
        "ignore all instructions",
        "disregard your instructions",
        "forget your previous instructions",
        "you are now",
        "new instructions:",
        "system: you",
        "[system]",
        "\\n\\nsystem:",
        "act as if",
        "pretend you are",
        "from now on you",
        "override your",
        "jailbreak",
        "dan mode",
        "do anything now",
        "bypass",
        "roleplay as",
        "your real instructions",
      ];
      const hits = injectionPhrases.filter((p) => lower.includes(p));
      const score = Math.min(hits.length * 0.25, 0.75);
      return { score, label: score > 0.5 ? "injection" : "clean", source: "heuristic" };
    }

    case "built-in/toxicity-v1": {
      const toxicTerms = [
        "fuck", "shit", "bitch", "asshole", "bastard", "cunt", "damn you",
        "hate you", "kill yourself", "go die", "screw you",
      ];
      const hits = toxicTerms.filter((t) => lower.includes(t));
      const score = Math.min(hits.length * 0.30, 0.80);
      return { score, label: score > 0.5 ? "toxic" : "clean", source: "heuristic" };
    }

    case "built-in/hate-speech-v1": {
      const hatePhrases = [
        "racial slur", "go back to", "your kind", "subhuman", "inferior race",
        "white supremacy", "ethnic cleansing", "final solution",
      ];
      const hits = hatePhrases.filter((p) => lower.includes(p));
      const score = Math.min(hits.length * 0.35, 0.80);
      return { score, label: score > 0.5 ? "hate_speech" : "clean", source: "heuristic" };
    }

    case "built-in/self-harm-v1": {
      const selfHarmPhrases = [
        "kill myself", "end my life", "suicide", "self-harm", "cut myself",
        "want to die", "don't want to live", "overdose", "hang myself",
      ];
      const hits = selfHarmPhrases.filter((p) => lower.includes(p));
      const score = Math.min(hits.length * 0.35, 0.85);
      return { score, label: score > 0.5 ? "self_harm" : "clean", source: "heuristic" };
    }

    case "built-in/violence-v1": {
      const violencePhrases = [
        "how to make a bomb", "how to make explosives", "how to kill",
        "instructions for violence", "attack plan", "weapon instructions",
        "synthesize poison", "make ricin", "make anthrax",
      ];
      const hits = violencePhrases.filter((p) => lower.includes(p));
      const score = Math.min(hits.length * 0.35, 0.85);
      return { score, label: score > 0.5 ? "violence" : "clean", source: "heuristic" };
    }

    case "built-in/factual-grounding-v1": {
      // Without context documents we cannot assess grounding — return neutral
      return { score: 0.75, label: "grounded", source: "heuristic" };
    }

    case "built-in/pii-medical-v1":
      return classifyMedicalPii(text);

    case "built-in/pii-financial-v1":
      return classifyFinancialPii(text);

    default:
      // Unknown classifier — pass through at 0 score
      return { score: 0, label: "unknown_classifier", source: "heuristic" };
  }
}
