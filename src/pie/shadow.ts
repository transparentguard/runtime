/**
 * TransparentGuard Runtime — PIE Shadow Mode
 * Runs a secondary (shadow) classifier alongside the primary one.
 * Logs structured disagreement records when scores diverge beyond threshold.
 * Never affects the primary evaluation outcome.
 */

export interface PIEShadowModeConfig {
  enabled: boolean;
  /** Classifier names to shadow-run alongside their primary evaluation */
  classifiers: string[];
  /** Log a disagreement when |primary - shadow| exceeds this delta (default: 0.20) */
  log_disagreement_threshold?: number;
}

export interface ShadowDisagreementRecord {
  type: "tg.pie.shadow_disagreement";
  classifier: string;
  primary_score: number;
  shadow_score: number;
  delta: number;
  request_id: string;
  timestamp: string;
}

/**
 * Schedules a non-blocking shadow classifier evaluation.
 * Results are logged to stdout as structured JSON when a disagreement is detected.
 * This function is synchronous and returns immediately — the shadow runs in a microtask.
 *
 * @param classifier   - The classifier name being shadow-evaluated
 * @param text         - The text being classified
 * @param primaryScore - The score returned by the primary classifier
 * @param config       - PIE shadow mode configuration from the policy
 * @param requestId    - The request ID for correlation
 * @param shadowFn     - The shadow scoring function (defaults to heuristic)
 */
export function runShadowClassifier(
  classifier: string,
  text: string,
  primaryScore: number,
  config: PIEShadowModeConfig | undefined,
  requestId: string,
  shadowFn: (classifier: string, text: string) => { score: number },
): void {
  if (!config?.enabled) return;
  if (!config.classifiers.includes(classifier)) return;

  const threshold = config.log_disagreement_threshold ?? 0.20;

  // Fire-and-forget in microtask — never delays the primary result
  queueMicrotask(() => {
    try {
      const shadowResult = shadowFn(classifier, text);
      const delta = Math.abs(shadowResult.score - primaryScore);

      if (delta > threshold) {
        const record: ShadowDisagreementRecord = {
          type: "tg.pie.shadow_disagreement",
          classifier,
          primary_score: primaryScore,
          shadow_score: shadowResult.score,
          delta,
          request_id: requestId,
          timestamp: new Date().toISOString(),
        };
        // Structured log — integrates with any log aggregator
        process.stdout.write(JSON.stringify(record) + "\n");
      }
    } catch {
      // Shadow failures are always silent — never pollute primary flow
    }
  });
}
