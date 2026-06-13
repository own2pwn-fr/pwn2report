import type {
  Confidence,
  Evidence,
  Finding,
  FindingKind,
  FindingPatch,
  Mapping,
  NewFinding,
  RetestStatus,
  Severity,
  StructuredPoc,
  TriageStatus,
} from "@/lib/types";

export interface FindingFormState {
  title: string;
  severity: Severity;
  confidence: Confidence;
  kind: FindingKind;
  cwe: string;
  cve: string;
  cvss_vector: string;
  cvss_score: number | null;
  triage_status: TriageStatus;
  triage_note: string;
  // description facets
  summary: string;
  root_cause: string;
  attack_vector: string;
  business_impact: string;
  technical_details: string;
  // remediation
  fix: string;
  code_patch: string;
  references: string[];
  // evidence
  ev_file: string;
  ev_start_line: string;
  ev_end_line: string;
  ev_snippet: string;
  // poc
  poc_scenario: string;
  poc_steps: string[];
  poc_payload: string;
  // misc lists
  refs: string[];
  tags: string[];
  // retest
  retest_status: RetestStatus;
  retest_date: string;
  // compliance mappings + custom fields
  mappings: Mapping[];
  custom_fields: Record<string, string>;
}

export function emptyState(): FindingFormState {
  return {
    title: "",
    severity: "medium",
    confidence: "medium",
    kind: "manual",
    cwe: "",
    cve: "",
    cvss_vector: "",
    cvss_score: null,
    triage_status: "open",
    triage_note: "",
    summary: "",
    root_cause: "",
    attack_vector: "",
    business_impact: "",
    technical_details: "",
    fix: "",
    code_patch: "",
    references: [],
    ev_file: "",
    ev_start_line: "",
    ev_end_line: "",
    ev_snippet: "",
    poc_scenario: "",
    poc_steps: [],
    poc_payload: "",
    refs: [],
    tags: [],
    retest_status: "not_retested",
    retest_date: "",
    mappings: [],
    custom_fields: {},
  };
}

export function stateFromFinding(f: Finding): FindingFormState {
  return {
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    kind: f.kind,
    cwe: f.cwe ?? "",
    cve: f.cve ?? "",
    cvss_vector: f.cvss_vector ?? "",
    cvss_score: f.cvss_score ?? null,
    triage_status: f.triage_status,
    triage_note: f.triage_note ?? "",
    summary: f.description.summary,
    root_cause: f.description.root_cause,
    attack_vector: f.description.attack_vector,
    business_impact: f.description.business_impact,
    technical_details: f.description.technical_details,
    fix: f.remediation.fix,
    code_patch: f.remediation.code_patch ?? "",
    references: [...f.remediation.references],
    ev_file: f.evidence?.file ?? "",
    ev_start_line: f.evidence?.start_line != null ? String(f.evidence.start_line) : "",
    ev_end_line: f.evidence?.end_line != null ? String(f.evidence.end_line) : "",
    ev_snippet: f.evidence?.snippet ?? "",
    poc_scenario: f.poc?.scenario ?? "",
    poc_steps: f.poc ? [...f.poc.exploitation_steps] : [],
    poc_payload: f.poc?.payload ?? "",
    refs: [...f.refs],
    tags: [...f.tags],
    retest_status: f.retest_status ?? "not_retested",
    retest_date: f.retest_date ?? "",
    mappings: f.mappings ? f.mappings.map((m) => ({ ...m })) : [],
    custom_fields: { ...(f.custom_fields ?? {}) },
  };
}

function parseLineNumber(value: string): number | null {
  const n = parseInt(value.trim(), 10);
  return Number.isFinite(n) ? n : null;
}

/** Build an Evidence object, or null when every field is empty. */
function buildEvidence(s: FindingFormState): Evidence | null {
  const file = s.ev_file.trim() || null;
  const start = parseLineNumber(s.ev_start_line);
  const end = parseLineNumber(s.ev_end_line);
  const snippet = s.ev_snippet.trim() || null;
  if (!file && start == null && end == null && !snippet) return null;
  return { file, start_line: start, end_line: end, snippet };
}

/** Build a StructuredPoc, or null when empty. */
function buildPoc(s: FindingFormState): StructuredPoc | null {
  const scenario = s.poc_scenario.trim();
  const steps = s.poc_steps.map((x) => x.trim()).filter(Boolean);
  const payload = s.poc_payload.trim() || null;
  if (!scenario && steps.length === 0 && !payload) return null;
  return { scenario, exploitation_steps: steps, payload };
}

function cleanList(items: string[]): string[] {
  return items.map((x) => x.trim()).filter(Boolean);
}

/** Drop incomplete mappings and trim their fields. */
function cleanMappings(mappings: Mapping[]): Mapping[] {
  return mappings
    .filter((m) => m.framework.trim() && m.id.trim())
    .map((m) => ({
      framework: m.framework.trim(),
      id: m.id.trim(),
      name: m.name?.trim() ? m.name.trim() : null,
    }));
}

/** Drop entries with an empty key and trim their keys. */
function cleanRecord(record: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(record)) {
    const key = k.trim();
    if (key) out[key] = v;
  }
  return out;
}

function commonFields(s: FindingFormState) {
  return {
    severity: s.severity,
    confidence: s.confidence,
    kind: s.kind,
    cwe: s.cwe.trim() || null,
    cve: s.cve.trim() || null,
    cvss_vector: s.cvss_vector.trim() || null,
    cvss_score: s.cvss_vector.trim() ? s.cvss_score : null,
    triage_status: s.triage_status,
    triage_note: s.triage_note.trim() || null,
    description: {
      summary: s.summary,
      root_cause: s.root_cause,
      attack_vector: s.attack_vector,
      business_impact: s.business_impact,
      technical_details: s.technical_details,
    },
    remediation: {
      fix: s.fix,
      code_patch: s.code_patch.trim() || null,
      references: cleanList(s.references),
    },
    evidence: buildEvidence(s),
    poc: buildPoc(s),
    refs: cleanList(s.refs),
    tags: cleanList(s.tags),
    retest_status: s.retest_status,
    // Only carry a date when a retest outcome has actually been recorded.
    retest_date:
      s.retest_status !== "not_retested" && s.retest_date.trim() ? s.retest_date.trim() : null,
    mappings: cleanMappings(s.mappings),
    custom_fields: cleanRecord(s.custom_fields),
  };
}

export function toNewFinding(s: FindingFormState): NewFinding {
  return { title: s.title.trim(), ...commonFields(s) };
}

export function toPatch(s: FindingFormState): FindingPatch {
  return { title: s.title.trim(), ...commonFields(s) };
}
