/**
 * TransparentGuard Runtime — Financial PII Classifier (built-in/pii-financial-v1)
 * Vocabulary-aware detection of financial PII not caught by generic regex patterns.
 * Catches: ABA routing numbers, CUSIP, ISIN, LEI codes, MICR lines,
 * loan identifiers in context, FINRA CRD numbers, ACH trace numbers.
 *
 * Returns a score 0.0–1.0 representing financial PII risk in the text.
 * Designed for use as a classify rule: classifier: "built-in/pii-financial-v1"
 */

import type { ClassifierResponse } from "../classifier-api.js";

// ---------------------------------------------------------------------------
// ABA Routing Number — 9 digits, first 4 in range 0100–3299 (Fed routing range)
// Luhn-like checksum: (3*(d0+d3+d6) + 7*(d1+d4+d7) + (d2+d5+d8)) % 10 === 0
// ---------------------------------------------------------------------------

const ABA_LABELLED = /\b(?:routing\s*(?:number|#|no)|ABA\s*(?:number|#)?|RTN)\s*:?\s*(\d{9})\b/gi;
const ABA_MICR = /\[?:(\d{9})\]?\s*\[?:(\d{4,17})\]?/g; // MICR E-13B format

function isValidAba(digits: string): boolean {
  if (digits.length !== 9) return false;
  const d = digits.split("").map(Number);
  if (d.some((n) => isNaN(n))) return false;
  const sum =
    3 * (d[0]! + d[3]! + d[6]!) +
    7 * (d[1]! + d[4]! + d[7]!) +
    (d[2]! + d[5]! + d[8]!);
  return sum % 10 === 0;
}

function detectAbaRouting(text: string): number {
  let count = 0;
  // Labelled — always high confidence
  const labelled = [...text.matchAll(ABA_LABELLED)];
  count += labelled.length;
  // Unlabelled 9-digit with ABA checksum
  const nineDigit = [...text.matchAll(/\b(\d{9})\b/g)];
  for (const m of nineDigit) {
    if (m[1] && isValidAba(m[1])) count++;
  }
  return count;
}

// ---------------------------------------------------------------------------
// CUSIP — 9 characters: 6 alphanumeric (issuer) + 2 alphanumeric (issue) + 1 check
// ---------------------------------------------------------------------------

const CUSIP_LABELLED = /\bCUSIP\s*:?\s*([A-Z0-9]{9})\b/gi;
const CUSIP_PATTERN = /\b[A-Z0-9]{6}[A-Z0-9]{2}[0-9]\b/g;

// ---------------------------------------------------------------------------
// ISIN — 2-letter country code + 9 alphanumeric + 1 check digit
// ---------------------------------------------------------------------------

const ISIN_LABELLED = /\bISIN\s*:?\s*([A-Z]{2}[A-Z0-9]{9}[0-9])\b/gi;
const ISIN_PATTERN = /\b[A-Z]{2}[A-Z0-9]{9}[0-9]\b/g;

// ---------------------------------------------------------------------------
// LEI — Legal Entity Identifier: 20 characters (4 alpha institution + 14 alphanum + 2 check)
// ---------------------------------------------------------------------------

const LEI_LABELLED = /\bLEI\s*:?\s*([A-Z0-9]{20})\b/gi;
const LEI_PATTERN = /\b[A-Z]{4}[A-Z0-9]{14}[0-9]{2}\b/g;

// ---------------------------------------------------------------------------
// FINRA CRD Number — 5–7 digit identifier for registered broker-dealers / reps
// ---------------------------------------------------------------------------

const FINRA_CRD = /\b(?:FINRA\s*CRD|CRD\s*(?:number|#|no))\s*:?\s*(\d{5,7})\b/gi;

// ---------------------------------------------------------------------------
// ACH Trace Number — 15-digit identifier for ACH transactions
// ---------------------------------------------------------------------------

const ACH_TRACE = /\b(?:ACH\s*trace|trace\s*(?:number|#))\s*:?\s*(\d{15})\b/gi;

// ---------------------------------------------------------------------------
// Loan / Account identifiers in context
// ---------------------------------------------------------------------------

const LOAN_CONTEXT = [
  /\bloan\s*(?:number|#|id|account)\s*:?\s*[A-Z0-9]{6,20}\b/gi,
  /\bmortgage\s*(?:number|#|id|loan)\s*:?\s*[A-Z0-9]{6,20}\b/gi,
  /\baccount\s*(?:number|#|id)\s*:?\s*\d{8,17}\b/gi,
  /\bline\s*of\s*credit\s*(?:number|#|account)\s*:?\s*[A-Z0-9]{6,20}\b/gi,
];

// ---------------------------------------------------------------------------
// Wire transfer context
// ---------------------------------------------------------------------------

const WIRE_CONTEXT = [
  /\bwire\s*(?:transfer|instruction)\s*(?:to|from)\s*(?:account\s*)?\d{8,17}\b/gi,
  /\bbeneficiary\s*account\s*:?\s*\d{8,17}\b/gi,
  /\bcorrespondent\s*bank\s*(?:code|ABA|routing)\s*:?\s*\d{9}\b/gi,
];

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

function countMatches(text: string, patterns: RegExp[]): number {
  let total = 0;
  for (const p of patterns) {
    const re = new RegExp(p.source, p.flags);
    const m = text.match(re);
    if (m) total += m.length;
  }
  return total;
}

interface FinancialHit {
  type: string;
  count: number;
  weight: number;
}

/**
 * Classifies text for financial PII risk.
 * Returns a ClassifierResponse with score 0.0–1.0.
 */
export function classifyFinancialPii(text: string): ClassifierResponse {
  const hits: FinancialHit[] = [];

  const abaCount = detectAbaRouting(text);
  if (abaCount > 0) hits.push({ type: "aba_routing", count: abaCount, weight: 0.50 });

  const cusipLabelled = countMatches(text, [CUSIP_LABELLED]);
  const cusipUnlabelled = countMatches(text, [CUSIP_PATTERN]);
  const cusipTotal = cusipLabelled > 0 ? cusipLabelled : Math.floor(cusipUnlabelled / 2); // unlabelled has false positives
  if (cusipTotal > 0) hits.push({ type: "cusip", count: cusipTotal, weight: cusipLabelled > 0 ? 0.40 : 0.20 });

  const isinLabelled = countMatches(text, [ISIN_LABELLED]);
  const isinUnlabelled = countMatches(text, [ISIN_PATTERN]);
  const isinTotal = isinLabelled > 0 ? isinLabelled : Math.floor(isinUnlabelled / 2);
  if (isinTotal > 0) hits.push({ type: "isin", count: isinTotal, weight: isinLabelled > 0 ? 0.40 : 0.20 });

  const leiLabelled = countMatches(text, [LEI_LABELLED]);
  if (leiLabelled > 0) hits.push({ type: "lei", count: leiLabelled, weight: 0.35 });

  const micrCount = countMatches(text, [ABA_MICR]);
  if (micrCount > 0) hits.push({ type: "micr_line", count: micrCount, weight: 0.60 });

  const finraCount = countMatches(text, [FINRA_CRD]);
  if (finraCount > 0) hits.push({ type: "finra_crd", count: finraCount, weight: 0.38 });

  const achCount = countMatches(text, [ACH_TRACE]);
  if (achCount > 0) hits.push({ type: "ach_trace", count: achCount, weight: 0.45 });

  const loanCount = countMatches(text, LOAN_CONTEXT);
  if (loanCount > 0) hits.push({ type: "loan_account_context", count: loanCount, weight: 0.30 });

  const wireCount = countMatches(text, WIRE_CONTEXT);
  if (wireCount > 0) hits.push({ type: "wire_transfer_context", count: wireCount, weight: 0.40 });

  if (hits.length === 0) {
    return { score: 0, label: "clean", source: "heuristic" };
  }

  const raw = hits.reduce((acc, h) => acc + h.weight * Math.min(h.count, 3), 0);
  const score = Math.min(raw, 1.0);
  const label = score >= 0.5 ? "financial_pii" : "low_risk_financial";
  const detail = hits.map((h) => `${h.type}:${h.count}`).join(", ");

  return { score, label, source: "heuristic", detail };
}
