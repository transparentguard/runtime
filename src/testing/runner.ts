/**
 * TransparentGuard Runtime — Policy Test Runner
 * Executes inline policy tests declared in the `tests` section of a TPS policy file.
 * No real LLM calls are made — only the policy evaluation engine is exercised.
 * Implements TPS v1.0 Section 27.
 *
 * Usage:
 *   import { runPolicyTests } from "@transparentguard/runtime";
 *   const results = await runPolicyTests(policy, licenseStatus);
 *   const allPassed = results.every(r => r.passed);
 */

import type {
  TPSPolicy,
  TPSPolicyTest,
  TPSPolicyTestExpect,
  RequestPayload,
  ResponsePayload,
  Violation,
  EvaluateResult,
} from "../types.js";
import type { LicenseStatus } from "../license/checker.js";
import { evaluate } from "../engine.js";

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface TestRuleTriggeredResult {
  rule_id: string;
  triggered: boolean;
  action_taken?: string;
  violation_count: number;
}

export interface TestFailureReason {
  field: string;
  expected: unknown;
  actual: unknown;
  message: string;
}

export interface PolicyTestResult {
  id: string;
  description?: string;
  passed: boolean;
  failures: TestFailureReason[];
  outcome: string;
  violations: Violation[];
  duration_ms: number;
}

export interface PolicyTestSuiteResult {
  policy_name: string;
  total: number;
  passed: number;
  failed: number;
  results: PolicyTestResult[];
}

// ---------------------------------------------------------------------------
// Map evaluation result to test outcome string
// ---------------------------------------------------------------------------

function computeOutcome(result: EvaluateResult): string {
  if (!result.allowed) return "blocked";

  const violations = result.violations;
  if (violations.length === 0) return "allowed";

  const hasRedaction = violations.some((v) => v.outcome === "redacted");
  const hasWarn = violations.some((v) => v.outcome === "warned");

  if (hasRedaction) return "allowed_with_modifications";
  if (hasWarn) return "warned";
  return "allowed";
}

// ---------------------------------------------------------------------------
// Individual test assertion
// ---------------------------------------------------------------------------

function assertTest(
  test: TPSPolicyTest,
  result: EvaluateResult,
  expect: TPSPolicyTestExpect,
): TestFailureReason[] {
  const failures: TestFailureReason[] = [];
  const actualOutcome = computeOutcome(result);

  // 1. Check overall outcome
  if (actualOutcome !== expect.outcome) {
    failures.push({
      field: "outcome",
      expected: expect.outcome,
      actual: actualOutcome,
      message: `Expected outcome "${expect.outcome}" but got "${actualOutcome}"`,
    });
  }

  // 2. Check rules_triggered
  for (const expectedRule of expect.rules_triggered ?? []) {
    const matchingViolations = result.violations.filter(
      (v) => v.rule_id === expectedRule.rule_id,
    );
    const triggered = matchingViolations.length > 0;

    if (!triggered) {
      failures.push({
        field: `rules_triggered[${expectedRule.rule_id}]`,
        expected: "triggered",
        actual: "not triggered",
        message: `Expected rule "${expectedRule.rule_id}" to have triggered a violation but it did not`,
      });
      continue;
    }

    // Check action_taken if specified
    if (expectedRule.action_taken) {
      const actionMatch = matchingViolations.some(
        (v) => v.outcome === expectedRule.action_taken,
      );
      if (!actionMatch) {
        const actualActions = matchingViolations.map((v) => v.outcome).join(", ");
        failures.push({
          field: `rules_triggered[${expectedRule.rule_id}].action_taken`,
          expected: expectedRule.action_taken,
          actual: actualActions,
          message: `Rule "${expectedRule.rule_id}" triggered but action was "${actualActions}", expected "${expectedRule.action_taken}"`,
        });
      }
    }

    // Check min_violations if specified
    const minViolations = expectedRule.min_violations ?? 1;
    if (matchingViolations.length < minViolations) {
      failures.push({
        field: `rules_triggered[${expectedRule.rule_id}].min_violations`,
        expected: minViolations,
        actual: matchingViolations.length,
        message: `Rule "${expectedRule.rule_id}" triggered ${matchingViolations.length} violation(s), expected at least ${minViolations}`,
      });
    }
  }

  // 3. Check rules_not_triggered
  for (const ruleId of expect.rules_not_triggered ?? []) {
    const triggered = result.violations.some((v) => v.rule_id === ruleId);
    if (triggered) {
      const violation = result.violations.find((v) => v.rule_id === ruleId);
      failures.push({
        field: `rules_not_triggered[${ruleId}]`,
        expected: "not triggered",
        actual: "triggered",
        message: `Expected rule "${ruleId}" NOT to trigger but it did (outcome: ${violation?.outcome ?? "unknown"}, detail: ${violation?.detail ?? "none"})`,
      });
    }
  }

  // 4. Check redactions
  for (const expectedRedaction of expect.redactions ?? []) {
    const matchingRedactions = result.violations.filter(
      (v) => v.outcome === "redacted" && v.category === expectedRedaction.category,
    );

    if (matchingRedactions.length === 0) {
      failures.push({
        field: `redactions[${expectedRedaction.category}]`,
        expected: `at least 1 redaction of category "${expectedRedaction.category}"`,
        actual: "no redactions of this category",
        message: `Expected at least one redaction of category "${expectedRedaction.category}" but none were found`,
      });
      continue;
    }

    if (expectedRedaction.count !== undefined && matchingRedactions.length < expectedRedaction.count) {
      failures.push({
        field: `redactions[${expectedRedaction.category}].count`,
        expected: expectedRedaction.count,
        actual: matchingRedactions.length,
        message: `Expected ${expectedRedaction.count} redaction(s) of category "${expectedRedaction.category}" but found ${matchingRedactions.length}`,
      });
    }
  }

  return failures;
}

// ---------------------------------------------------------------------------
// Build payloads from test input
// ---------------------------------------------------------------------------

function buildRequestPayload(test: TPSPolicyTest): RequestPayload {
  const messages = (test.input.messages ?? []).map((m) => ({
    role: m.role as "system" | "user" | "assistant" | "tool",
    content: m.content,
  }));
  return {
    messages,
    provider: test.input.provider ?? "openai/gpt-4o",
  };
}

function buildResponsePayload(test: TPSPolicyTest): ResponsePayload {
  const response = test.input.response;
  const messages = (test.input.messages ?? []).map((m) => ({
    role: m.role as "system" | "user" | "assistant" | "tool",
    content: m.content,
  }));
  return {
    content: response?.content ?? "",
    provider: test.input.provider ?? "openai/gpt-4o",
    system_prompt: messages.find((m) => m.role === "system")?.content ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

/**
 * Runs all inline tests declared in a TPS policy file.
 * Does not make real LLM calls — only exercises policy evaluation.
 *
 * @param policy - The loaded TPSPolicy object
 * @param licenseStatus - License status for feature gating
 * @returns Full test suite result with pass/fail per test
 */
export async function runPolicyTests(
  policy: TPSPolicy,
  licenseStatus: LicenseStatus,
): Promise<PolicyTestSuiteResult> {
  const tests = policy.tests ?? [];
  const results: PolicyTestResult[] = [];

  for (const test of tests) {
    const start = Date.now();
    let evaluateResult: EvaluateResult;

    try {
      let payload: RequestPayload | ResponsePayload;

      if (test.stage === "pre-request") {
        payload = buildRequestPayload(test);
      } else if (test.stage === "post-response") {
        payload = buildResponsePayload(test);
      } else if (test.stage === "tool-call") {
        // Tool-call tests: create a synthetic pre-request payload with tool info in metadata
        const toolCall = test.input.tool_call;
        payload = {
          messages: [{
            role: "user",
            content: `tool_call:${toolCall?.tool_name ?? "unknown"} args:${JSON.stringify(toolCall?.arguments ?? {})}`,
          }],
          provider: "openai/gpt-4o",
          metadata: {
            tg_test_tool_name: toolCall?.tool_name ?? "",
          },
        } as RequestPayload;
      } else {
        payload = buildRequestPayload(test);
      }

      const evalStage = test.stage === "tool-call" ? "pre-request" : test.stage;
      evaluateResult = await evaluate(
        evalStage,
        payload,
        policy,
        licenseStatus,
        { requestId: `test_${test.id}` },
      );
    } catch (err) {
      const duration = Date.now() - start;
      results.push({
        id: test.id,
        description: test.description,
        passed: false,
        failures: [{
          field: "evaluation",
          expected: "no error",
          actual: String(err),
          message: `Evaluation threw an error: ${String(err)}`,
        }],
        outcome: "error",
        violations: [],
        duration_ms: duration,
      });
      continue;
    }

    const duration = Date.now() - start;
    const failures = assertTest(test, evaluateResult, test.expect);
    const outcome = computeOutcome(evaluateResult);

    results.push({
      id: test.id,
      description: test.description,
      passed: failures.length === 0,
      failures,
      outcome,
      violations: evaluateResult.violations,
      duration_ms: duration,
    });
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;

  return {
    policy_name: policy.name,
    total: results.length,
    passed,
    failed,
    results,
  };
}

/**
 * Formats test results as a human-readable CLI output string.
 * Exit code should be 0 if all passed, 1 if any failed.
 */
export function formatTestResults(suite: PolicyTestSuiteResult): string {
  const lines: string[] = [];
  lines.push(`\nRunning ${suite.total} test(s) against policy "${suite.policy_name}"...\n`);

  for (const result of suite.results) {
    const icon = result.passed ? "  PASS" : "  FAIL";
    lines.push(`${icon}  ${result.id}${result.description ? ` — ${result.description}` : ""}`);
    if (!result.passed) {
      for (const failure of result.failures) {
        lines.push(`        ${failure.message}`);
      }
    }
  }

  lines.push("");
  if (suite.failed === 0) {
    lines.push(`${suite.passed} passed, 0 failed.`);
    lines.push(`Policy "${suite.policy_name}" passed all declared tests.`);
  } else {
    lines.push(`${suite.failed} failed, ${suite.passed} passed.`);
  }
  lines.push("");

  return lines.join("\n");
}
