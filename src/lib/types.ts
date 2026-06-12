// Canonical TypeScript types — mirror the Rust backend serde models.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type TriageStatus = "open" | "acknowledged" | "false_positive" | "resolved";
export type ReportType = "web_pentest" | "code_audit" | "red_team";
export type FindingKind = "manual" | "sast" | "iac" | "sca" | "secret";

export interface FindingDescription {
  summary: string;
  root_cause: string;
  attack_vector: string;
  business_impact: string;
  technical_details: string;
}

export interface FindingRemediation {
  fix: string;
  code_patch: string | null;
  references: string[];
}

export interface Evidence {
  file: string | null;
  start_line: number | null;
  end_line: number | null;
  snippet: string | null;
}

export interface StructuredPoc {
  scenario: string;
  exploitation_steps: string[];
  payload: string | null;
}

export interface Finding {
  id: string;
  report_id: string;
  sort_order: number;
  title: string;
  severity: Severity;
  confidence: Confidence;
  kind: FindingKind;
  cwe: string | null;
  cve: string | null;
  cvss_vector: string | null;
  cvss_score: number | null;
  triage_status: TriageStatus;
  triage_note: string | null;
  description: FindingDescription;
  remediation: FindingRemediation;
  evidence: Evidence | null;
  poc: StructuredPoc | null;
  refs: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface Report {
  id: string;
  title: string;
  client: string;
  report_type: ReportType;
  status: string;
  exec_summary: string;
  scope: string;
  methodology: string;
  created_at: string;
  updated_at: string;
}

export interface ReportSummary {
  id: string;
  title: string;
  client: string;
  report_type: ReportType;
  status: string;
  finding_count: number;
  updated_at: string;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  keychain_available: boolean;
}

export interface NewReport {
  title: string;
  client: string;
  report_type: ReportType;
}

export interface NewFinding {
  title: string;
  severity: Severity;
  confidence?: Confidence;
  kind?: FindingKind;
  cwe?: string | null;
  cve?: string | null;
  cvss_vector?: string | null;
  cvss_score?: number | null;
  triage_status?: TriageStatus;
  triage_note?: string | null;
  description?: Partial<FindingDescription>;
  remediation?: Partial<FindingRemediation>;
  evidence?: Evidence | null;
  poc?: StructuredPoc | null;
  refs?: string[];
  tags?: string[];
}

/** Template metadata returned by `list_templates`. */
export interface TemplateInfo {
  report_type: ReportType;
  is_custom: boolean;
}

// Partial patch payloads for update commands. Backend treats omitted fields
// as "leave unchanged".
export type ReportPatch = Partial<
  Pick<
    Report,
    "title" | "client" | "report_type" | "status" | "exec_summary" | "scope" | "methodology"
  >
>;

export type FindingPatch = Partial<
  Pick<
    Finding,
    | "title"
    | "severity"
    | "confidence"
    | "kind"
    | "cwe"
    | "cve"
    | "cvss_vector"
    | "cvss_score"
    | "triage_status"
    | "triage_note"
    | "description"
    | "remediation"
    | "evidence"
    | "poc"
    | "refs"
    | "tags"
  >
>;

// ── Knowledge base ───────────────────────────────────────────────────────────

export interface KbEntry {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  kind: FindingKind;
  cwe: string | null;
  cve: string | null;
  cvss_vector: string | null;
  cvss_score: number | null;
  description: FindingDescription;
  remediation: FindingRemediation;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export type NewKbEntry = Omit<KbEntry, "id" | "created_at" | "updated_at">;

export type KbPatch = Partial<NewKbEntry>;

// ── Evidence images ──────────────────────────────────────────────────────────

export interface EvidenceImage {
  id: string;
  finding_id: string;
  caption: string;
  mime: string;
  sort_order: number;
  created_at: string;
}

// Supported scanner import formats for `import_findings`.
export type ImportFormat = "sarif" | "nuclei" | "zap" | "burp" | "nessus" | "secai";

// Shape the Rust layer serializes its errors into.
export interface IpcError {
  kind: string;
  message: string;
}
