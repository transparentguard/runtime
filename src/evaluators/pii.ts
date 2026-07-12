/**
 * TransparentGuard Runtime — PII Evaluator (Free Tier)
 * Pure regex-based detection covering all TPS v1.0 PII categories.
 * No external dependencies — runs entirely offline.
 */

import type { PiiCategory, PiiTarget } from "../types.js";

// ---------------------------------------------------------------------------
// PII category expansion — shortcut aliases
// ---------------------------------------------------------------------------

const PHI_CATEGORIES: PiiCategory[] = [
  "name", "email", "phone", "address", "ssn", "mrn", "dob", "age",
  "health_condition", "insurance_id", "npi", "dea", "ip_address",
  "device_id", "url", "biometric", "genetic",
];

const PII_STANDARD_CATEGORIES: PiiCategory[] = [
  "name", "email", "phone", "address", "ip_address", "username", "url",
];

const PII_FINANCIAL_CATEGORIES: PiiCategory[] = [
  "credit_card", "bank_account", "iban", "swift", "crypto_address", "tax_id",
];

const PII_SENSITIVE_CATEGORIES: PiiCategory[] = [
  "ssn", "passport", "driver_license", "national_id", "tax_id", "voter_id",
  "race", "religion", "political_opinion", "sexual_orientation",
  "biometric", "genetic", "union_membership",
];

const PII_ALL_CATEGORIES: PiiCategory[] = [
  "name", "email", "phone", "address", "ip_address", "username", "device_id", "url",
  "ssn", "passport", "driver_license", "national_id", "tax_id", "voter_id",
  "credit_card", "bank_account", "iban", "swift", "crypto_address",
  "mrn", "dob", "age", "health_condition", "insurance_id", "npi", "dea",
  "race", "religion", "political_opinion", "sexual_orientation",
  "biometric", "genetic", "union_membership",
];

export function expandCategories(categories: PiiCategory[]): PiiCategory[] {
  const expanded = new Set<PiiCategory>();
  for (const cat of categories) {
    switch (cat) {
      case "phi":
        PHI_CATEGORIES.forEach((c) => expanded.add(c));
        break;
      case "pii_standard":
        PII_STANDARD_CATEGORIES.forEach((c) => expanded.add(c));
        break;
      case "pii_financial":
        PII_FINANCIAL_CATEGORIES.forEach((c) => expanded.add(c));
        break;
      case "pii_sensitive":
        PII_SENSITIVE_CATEGORIES.forEach((c) => expanded.add(c));
        break;
      case "pii_all":
        PII_ALL_CATEGORIES.forEach((c) => expanded.add(c));
        break;
      default:
        expanded.add(cat);
    }
  }
  return [...expanded];
}

// ---------------------------------------------------------------------------
// Detection result
// ---------------------------------------------------------------------------

export interface PiiMatch {
  category: PiiCategory;
  start: number;
  end: number;
  original: string;
  confidence: number;
}

// ---------------------------------------------------------------------------
// Regex patterns per category
// Each entry is an array of patterns — first match wins per position.
// All patterns are constructed fresh per call (stateless, no lastIndex issues).
// ---------------------------------------------------------------------------

type PatternEntry = { pattern: string; flags: string; confidence: number };

const PATTERNS: Partial<Record<PiiCategory, PatternEntry[]>> = {
  email: [
    {
      pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}",
      flags: "gi",
      confidence: 0.98,
    },
  ],

  phone: [
    // +1 (555) 555-5555 or +1-555-555-5555 or (555) 555-5555 etc.
    {
      pattern:
        "(?:\\+?1[\\s\\-.]?)?(?:\\(?\\d{3}\\)?[\\s\\-.]?)\\d{3}[\\s\\-.]\\d{4}",
      flags: "g",
      confidence: 0.90,
    },
    // International formats +44 20 7946 0958
    {
      pattern: "\\+\\d{1,3}[\\s\\-.]\\d{1,4}[\\s\\-.]\\d{3,4}[\\s\\-.]\\d{3,4}",
      flags: "g",
      confidence: 0.85,
    },
  ],

  ssn: [
    // 123-45-6789 (not 000, 666, or 900-999 in first segment — real validation)
    {
      pattern: "(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}",
      flags: "g",
      confidence: 0.97,
    },
    // 123456789 (9 consecutive digits — lower confidence)
    {
      pattern: "\\b(?!000000000)(?!111111111)\\d{9}\\b",
      flags: "g",
      confidence: 0.65,
    },
  ],

  credit_card: [
    // Visa, MC, Amex, Discover — with optional separators
    {
      pattern:
        "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\\b",
      flags: "g",
      confidence: 0.95,
    },
    // Same with dashes/spaces
    {
      pattern:
        "\\b(?:4[0-9]{3}[\\s\\-]){3}[0-9]{4}|(?:5[1-5][0-9]{2}|2[2-7][0-9]{2})[\\s\\-][0-9]{4}[\\s\\-][0-9]{4}[\\s\\-][0-9]{4}\\b",
      flags: "g",
      confidence: 0.92,
    },
  ],

  bank_account: [
    // Generic US bank account: 6–17 digits
    { pattern: "\\b\\d{6,17}\\b", flags: "g", confidence: 0.60 },
  ],

  iban: [
    {
      pattern: "\\b[A-Z]{2}\\d{2}[A-Z0-9]{4,30}\\b",
      flags: "g",
      confidence: 0.92,
    },
  ],

  swift: [
    // SWIFT/BIC: 8 or 11 characters
    { pattern: "\\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\\b", flags: "g", confidence: 0.85 },
  ],

  crypto_address: [
    // Bitcoin P2PKH/P2SH
    { pattern: "\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b", flags: "g", confidence: 0.88 },
    // Ethereum
    { pattern: "\\b0x[a-fA-F0-9]{40}\\b", flags: "g", confidence: 0.96 },
    // Bech32 (bc1...)
    { pattern: "\\bbc1[a-zA-HJ-NP-Z0-9]{25,39}\\b", flags: "g", confidence: 0.93 },
  ],

  ip_address: [
    // IPv4
    {
      pattern:
        "\\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
      flags: "g",
      confidence: 0.95,
    },
    // IPv6
    {
      pattern:
        "\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b",
      flags: "gi",
      confidence: 0.95,
    },
  ],

  mrn: [
    // Medical Record Number — typically 6–10 digits, sometimes prefixed
    { pattern: "\\bMRN[:\\s#]*[0-9]{5,10}\\b", flags: "gi", confidence: 0.90 },
    { pattern: "\\bMed(?:ical)?\\s*Record\\s*(?:Number|#|No)[:\\s]*[0-9]{5,10}\\b", flags: "gi", confidence: 0.88 },
  ],

  npi: [
    // National Provider Identifier — 10 digits starting with 1 or 2
    { pattern: "\\bNPI[:\\s#]*[12][0-9]{9}\\b", flags: "gi", confidence: 0.92 },
    { pattern: "\\b[12]\\d{9}\\b", flags: "g", confidence: 0.60 },
  ],

  dea: [
    // DEA Registration Number: 2 letters + 7 digits
    { pattern: "\\b[A-Za-z]{2}[0-9]{7}\\b", flags: "g", confidence: 0.75 },
    { pattern: "\\bDEA[:\\s#]*[A-Za-z]{2}[0-9]{7}\\b", flags: "gi", confidence: 0.95 },
  ],

  passport: [
    // US passport: letter + 8 digits
    { pattern: "\\b[A-Z][0-9]{8}\\b", flags: "g", confidence: 0.72 },
    { pattern: "\\bPassport[:\\s#]*[A-Z0-9]{6,12}\\b", flags: "gi", confidence: 0.88 },
  ],

  driver_license: [
    { pattern: "\\bDL[:\\s#]*[A-Z0-9]{6,12}\\b", flags: "gi", confidence: 0.88 },
    { pattern: "\\bDriver(?:'?s)?\\s*Licen[sc]e[:\\s#]*[A-Z0-9]{6,12}\\b", flags: "gi", confidence: 0.87 },
  ],

  national_id: [
    { pattern: "\\bNational\\s*ID[:\\s#]*[A-Z0-9]{6,20}\\b", flags: "gi", confidence: 0.85 },
  ],

  tax_id: [
    // EIN: XX-XXXXXXX
    { pattern: "\\b\\d{2}-\\d{7}\\b", flags: "g", confidence: 0.88 },
    { pattern: "\\b(?:EIN|TIN|ITIN)[:\\s#]*\\d{2}-?\\d{7}\\b", flags: "gi", confidence: 0.95 },
  ],

  insurance_id: [
    { pattern: "\\bInsurance\\s*(?:ID|Number|#)[:\\s]*[A-Z0-9]{6,20}\\b", flags: "gi", confidence: 0.85 },
    { pattern: "\\bMember\\s*ID[:\\s]*[A-Z0-9]{6,15}\\b", flags: "gi", confidence: 0.78 },
  ],

  dob: [
    // MM/DD/YYYY or MM-DD-YYYY or YYYY-MM-DD
    {
      pattern:
        "\\b(?:0?[1-9]|1[0-2])[/\\-](?:0?[1-9]|[12][0-9]|3[01])[/\\-](?:19|20)\\d{2}\\b",
      flags: "g",
      confidence: 0.88,
    },
    {
      pattern: "\\b(?:19|20)\\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])\\b",
      flags: "g",
      confidence: 0.92,
    },
    // "Date of Birth" label near a date
    {
      pattern:
        "(?:Date\\s*of\\s*Birth|DOB|D\\.O\\.B)[:\\s]*(?:0?[1-9]|1[0-2])[/\\-](?:0?[1-9]|[12][0-9]|3[01])[/\\-](?:19|20)\\d{2}",
      flags: "gi",
      confidence: 0.97,
    },
  ],

  age: [
    { pattern: "\\bage[:\\s]+(?:is\\s+)?([0-9]{1,3})\\s*(?:years?\\s*old)?\\b", flags: "gi", confidence: 0.75 },
    { pattern: "\\b([0-9]{1,3})\\s*(?:yr|year)s?(?:\\s*old)?\\b", flags: "gi", confidence: 0.65 },
  ],

  url: [
    {
      pattern: "https?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
      flags: "gi",
      confidence: 0.98,
    },
  ],

  username: [
    { pattern: "\\b@[a-zA-Z0-9_]{2,30}\\b", flags: "g", confidence: 0.80 },
    { pattern: "\\busername[:\\s]+[a-zA-Z0-9_.\\-]{2,30}\\b", flags: "gi", confidence: 0.88 },
  ],

  address: [
    // Street address: number + street name
    {
      pattern:
        "\\b\\d{1,5}\\s+(?:[A-Z][a-z]+\\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir)(?:\\s*,\\s*[A-Z][a-z]+(?:\\s+[A-Z][a-z]+)*)?(?:\\s*,\\s*[A-Z]{2})?(?:\\s+\\d{5}(?:-\\d{4})?)?\\b",
      flags: "g",
      confidence: 0.85,
    },
  ],

  name: [
    // "Name: John Doe" patterns — low confidence standalone, higher with label
    { pattern: "(?:Name|Patient|Customer|User)[:\\s]+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+){1,2})", flags: "g", confidence: 0.80 },
  ],

  health_condition: [
    // Diagnosis / condition labels
    { pattern: "(?:Diagnosis|Condition|Disorder|Disease)[:\\s]+[A-Za-z][A-Za-z\\s\\-]{3,50}", flags: "gi", confidence: 0.78 },
    { pattern: "(?:diagnosed\\s+with|suffers\\s+from|history\\s+of)[:\\s]+[A-Za-z][A-Za-z\\s\\-]{3,50}", flags: "gi", confidence: 0.82 },
  ],

  race: [
    {
      pattern:
        "\\b(?:African[- ]American|Black|White|Caucasian|Asian|Hispanic|Latino|Latina|Pacific Islander|Native American|Indigenous|Multiracial|Mixed[- ]race)\\b",
      flags: "gi",
      confidence: 0.80,
    },
    { pattern: "(?:Race|Ethnicity)[:\\s]+[A-Za-z][A-Za-z\\s\\-]{2,30}", flags: "gi", confidence: 0.85 },
  ],

  religion: [
    {
      pattern:
        "\\b(?:Christian|Catholic|Protestant|Muslim|Jewish|Hindu|Buddhist|Sikh|Atheist|Agnostic|Mormon|LDS|Evangelical)\\b",
      flags: "gi",
      confidence: 0.78,
    },
    { pattern: "(?:Religion|Religious\\s+belief)[:\\s]+[A-Za-z][A-Za-z\\s\\-]{2,30}", flags: "gi", confidence: 0.88 },
  ],

  political_opinion: [
    { pattern: "(?:Political\\s*(?:affiliation|party|opinion|view))[:\\s]+[A-Za-z][A-Za-z\\s\\-]{2,30}", flags: "gi", confidence: 0.87 },
  ],

  sexual_orientation: [
    {
      pattern:
        "\\b(?:gay|lesbian|bisexual|transgender|non-binary|queer|heterosexual|straight|asexual|LGBTQ\\+?)\\b",
      flags: "gi",
      confidence: 0.82,
    },
    { pattern: "(?:Sexual\\s*orientation)[:\\s]+[A-Za-z][A-Za-z\\s\\-]{2,30}", flags: "gi", confidence: 0.90 },
  ],

  biometric: [
    { pattern: "(?:fingerprint|retinal scan|facial recognition|voice print|biometric)[:\\s]+[A-Za-z0-9]{4,64}", flags: "gi", confidence: 0.85 },
  ],

  genetic: [
    { pattern: "(?:genetic|DNA|genomic)[:\\s]+(?:data|sequence|result|variant)[:\\s]+[A-Za-z0-9]{4,64}", flags: "gi", confidence: 0.85 },
    { pattern: "\\b(?:BRCA1|BRCA2|HER2|TP53|APOE)\\b", flags: "gi", confidence: 0.88 },
  ],

  union_membership: [
    { pattern: "(?:Union|Labor\\s*union|Trade\\s*union)\\s*(?:member|membership)[:\\s]+[A-Za-z][A-Za-z\\s\\-]{2,40}", flags: "gi", confidence: 0.85 },
  ],

  device_id: [
    // MAC address
    { pattern: "\\b([0-9A-Fa-f]{2}[:\\-]){5}[0-9A-Fa-f]{2}\\b", flags: "g", confidence: 0.95 },
    // UUID/GUID
    { pattern: "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b", flags: "g", confidence: 0.90 },
  ],

  voter_id: [
    { pattern: "(?:Voter\\s*ID|Voter\\s*Registration)[:\\s#]*[A-Z0-9]{6,20}", flags: "gi", confidence: 0.87 },
  ],
};

// ---------------------------------------------------------------------------
// Detection function
// ---------------------------------------------------------------------------

/**
 * Detects PII in the given text for the specified categories.
 * Returns sorted, non-overlapping matches above the confidence threshold.
 */
export function detectPii(
  text: string,
  target: PiiTarget,
): PiiMatch[] {
  const confidenceThreshold = target.confidence_threshold ?? 0.80;
  const categories = expandCategories(target.categories);
  const allMatches: PiiMatch[] = [];

  for (const category of categories) {
    const entries = PATTERNS[category as keyof typeof PATTERNS];
    if (!entries) continue;

    for (const entry of entries) {
      if (entry.confidence < confidenceThreshold) continue;
      const re = new RegExp(entry.pattern, entry.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(text)) !== null) {
        // Prevent infinite loops on zero-length matches
        if (match[0].length === 0) {
          re.lastIndex++;
          continue;
        }
        allMatches.push({
          category,
          start: match.index,
          end: match.index + match[0].length,
          original: match[0],
          confidence: entry.confidence,
        });
      }
    }
  }

  // Sort by start position, then resolve overlaps (keep highest confidence)
  return resolveOverlaps(allMatches);
}

/**
 * Redacts detected PII spans in text, replacing each with [REDACTED:<category>].
 * Returns the redacted text and the list of applied matches.
 */
export function redactText(text: string, matches: PiiMatch[]): string {
  if (matches.length === 0) return text;
  let result = "";
  let cursor = 0;
  for (const match of matches) {
    result += text.slice(cursor, match.start);
    result += `[REDACTED:${match.category.toUpperCase()}]`;
    cursor = match.end;
  }
  result += text.slice(cursor);
  return result;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Removes overlapping matches, keeping the highest-confidence one per span. */
function resolveOverlaps(matches: PiiMatch[]): PiiMatch[] {
  if (matches.length === 0) return [];

  // Sort by start, then by confidence desc
  const sorted = matches.slice().sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return b.confidence - a.confidence;
  });

  const result: PiiMatch[] = [];
  let lastEnd = -1;

  for (const match of sorted) {
    if (match.start >= lastEnd) {
      result.push(match);
      lastEnd = match.end;
    } else if (match.confidence > (result[result.length - 1]?.confidence ?? 0)) {
      // Higher confidence match that overlaps — replace the last one
      result.pop();
      result.push(match);
      lastEnd = match.end;
    }
  }

  return result;
}
