/**
 * TransparentGuard Runtime — Medical PII Classifier (built-in/pii-medical-v1)
 * Vocabulary-aware detection of medical PII not caught by generic regex patterns.
 * Catches: CPT codes, ICD-10 codes, NDC drug codes, NPI in context, clinical
 * drug names used in patient context, lab values tied to a named patient.
 *
 * Returns a score 0.0–1.0 representing medical PII risk in the text.
 * Designed for use as a classify rule: classifier: "built-in/pii-medical-v1"
 */

import type { ClassifierResponse } from "../classifier-api.js";

// ---------------------------------------------------------------------------
// CPT code detection — 5-digit procedure codes, optionally labelled
// ---------------------------------------------------------------------------

const CPT_PATTERNS = [
  // Labelled: "CPT 99213", "CPT code 36415"
  /\bCPT\s*(?:code\s*)?(\d{5})\b/gi,
  // Common E&M code range in patient context (99201–99499)
  /\b9[12]\d{3}\b/g,
  // Common surgical/radiology codes in clinical context
  /\bprocedure\s*(?:code\s*)?\d{5}\b/gi,
];

// ---------------------------------------------------------------------------
// ICD-10 code detection — e.g. M54.5, J45.41, Z87.891
// ---------------------------------------------------------------------------

const ICD10_PATTERN = /\b[A-Z]\d{2}(?:\.\d{1,4})?\b/g;
const ICD10_LABELLED = /\b(?:ICD-10|diagnosis\s*code|DX\s*code)\s*:?\s*[A-Z]\d{2}(?:\.\d{1,4})?\b/gi;

// ---------------------------------------------------------------------------
// NDC (National Drug Code) — 10/11-digit in formats 5-4-2, 5-3-2, 4-4-2
// ---------------------------------------------------------------------------

const NDC_PATTERNS = [
  // Labelled
  /\bNDC\s*:?\s*\d{4,5}-\d{3,4}-\d{2}\b/gi,
  // Unlabelled formatted
  /\b\d{5}-\d{4}-\d{2}\b/g,
  /\b\d{5}-\d{3}-\d{2}\b/g,
  /\b\d{4}-\d{4}-\d{2}\b/g,
];

// ---------------------------------------------------------------------------
// NPI in clinical context (beyond the generic pattern in pii.ts)
// ---------------------------------------------------------------------------

const NPI_CONTEXT_PATTERN = /\b(?:provider|physician|prescriber|ordering\s*provider)\s*(?:NPI|ID)\s*:?\s*[12]\d{9}\b/gi;

// ---------------------------------------------------------------------------
// Clinical drug names in patient context
// These are the top 50 most-prescribed drugs in the US — presence in combination
// with patient identifiers (name, DOB, MRN) significantly raises PII risk.
// ---------------------------------------------------------------------------

const HIGH_RISK_DRUGS = new Set([
  "metformin", "lisinopril", "atorvastatin", "amlodipine", "omeprazole",
  "metoprolol", "losartan", "albuterol", "gabapentin", "hydrocodone",
  "sertraline", "escitalopram", "levothyroxine", "amoxicillin", "prednisone",
  "furosemide", "pantoprazole", "bupropion", "duloxetine", "trazodone",
  "carvedilol", "tamsulosin", "rosuvastatin", "clopidogrel", "warfarin",
  "insulin", "lantus", "humalog", "ozempic", "wegovy", "mounjaro",
  "jardiance", "eliquis", "xarelto", "entresto", "keytruda",
  "humira", "adalimumab", "pembrolizumab", "apixaban", "rivaroxaban",
  "oxycodone", "tramadol", "morphine", "fentanyl", "buprenorphine",
  "clonazepam", "lorazepam", "alprazolam", "zolpidem", "quetiapine",
]);

// Patient-context trigger words — drug name is high-risk only when near these
const PATIENT_CONTEXT_WORDS = [
  "patient", "prescribed", "diagnosis", "treatment", "dosage", "dose",
  "mg", "mcg", "units", "daily", "twice", "medication", "rx", "refill",
  "allerg", "contraindic", "side effect", "adverse",
];

// ---------------------------------------------------------------------------
// Lab values in patient context
// ---------------------------------------------------------------------------

const LAB_VALUE_PATTERNS = [
  // HbA1c: 8.2%, A1c: 9.1
  /\bHbA1c\s*:?\s*[\d.]+\s*%?/gi,
  /\bA1c\s*:?\s*[\d.]+\s*%?/gi,
  // Creatinine: 1.4 mg/dL
  /\bcreatinine\s*:?\s*[\d.]+\s*(?:mg\/dL|mg\/dl|umol\/L)?/gi,
  // eGFR
  /\beGFR\s*:?\s*[\d.]+/gi,
  // PSA
  /\bPSA\s*:?\s*[\d.]+\s*(?:ng\/mL|ng\/ml)?/gi,
  // INR / PT
  /\bINR\s*:?\s*[\d.]+/gi,
  // LDL/HDL/Total cholesterol in patient context
  /\b(?:LDL|HDL|cholesterol)\s*:?\s*[\d.]+\s*(?:mg\/dL|mg\/dl)?/gi,
  // Blood glucose
  /\b(?:glucose|blood\s*sugar|BG)\s*:?\s*[\d.]+\s*(?:mg\/dL|mg\/dl|mmol\/L)?/gi,
  // Lab result label
  /\b(?:result|lab\s*result|test\s*result)\s*:?\s*(?:positive|negative|reactive|non-reactive|detected|not\s*detected)/gi,
];

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

interface MedicalHit {
  type: string;
  count: number;
  weight: number;
}

function countMatches(text: string, patterns: RegExp[]): number {
  let total = 0;
  for (const pattern of patterns) {
    // Always use a fresh regex to reset lastIndex
    const re = new RegExp(pattern.source, pattern.flags);
    const matches = text.match(re);
    if (matches) total += matches.length;
  }
  return total;
}

function hasDrugInPatientContext(text: string): boolean {
  const lower = text.toLowerCase();
  const hasContext = PATIENT_CONTEXT_WORDS.some((w) => lower.includes(w));
  if (!hasContext) return false;
  for (const drug of HIGH_RISK_DRUGS) {
    if (lower.includes(drug)) return true;
  }
  return false;
}

/**
 * Classifies text for medical PII risk.
 * Returns a ClassifierResponse with score 0.0–1.0.
 */
export function classifyMedicalPii(text: string): ClassifierResponse {
  const hits: MedicalHit[] = [];

  const cptCount = countMatches(text, CPT_PATTERNS);
  if (cptCount > 0) hits.push({ type: "cpt_code", count: cptCount, weight: 0.35 });

  const icd10LabelledCount = countMatches(text, [ICD10_LABELLED]);
  if (icd10LabelledCount > 0) hits.push({ type: "icd10_labelled", count: icd10LabelledCount, weight: 0.40 });
  else {
    // Unlabelled ICD-10 codes are lower confidence
    const icd10Count = countMatches(text, [ICD10_PATTERN]);
    if (icd10Count > 0) hits.push({ type: "icd10_code", count: icd10Count, weight: 0.20 });
  }

  const ndcCount = countMatches(text, NDC_PATTERNS);
  if (ndcCount > 0) hits.push({ type: "ndc_code", count: ndcCount, weight: 0.45 });

  const npiContextCount = countMatches(text, [NPI_CONTEXT_PATTERN]);
  if (npiContextCount > 0) hits.push({ type: "npi_context", count: npiContextCount, weight: 0.40 });

  const labCount = countMatches(text, LAB_VALUE_PATTERNS);
  if (labCount > 0) hits.push({ type: "lab_value", count: labCount, weight: 0.25 });

  if (hasDrugInPatientContext(text)) hits.push({ type: "drug_in_patient_context", count: 1, weight: 0.30 });

  if (hits.length === 0) {
    return { score: 0, label: "clean", source: "heuristic" };
  }

  // Weighted sum, capped at 1.0
  const raw = hits.reduce((acc, h) => acc + h.weight * Math.min(h.count, 3), 0);
  const score = Math.min(raw, 1.0);
  const label = score >= 0.5 ? "medical_pii" : "low_risk_medical";
  const detail = hits.map((h) => `${h.type}:${h.count}`).join(", ");

  return { score, label, source: "heuristic", detail };
}
