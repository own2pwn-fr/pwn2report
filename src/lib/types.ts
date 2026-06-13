// Canonical TypeScript types — mirror the Rust backend serde models.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type TriageStatus = "open" | "acknowledged" | "false_positive" | "resolved";
export type ReportType = "web_pentest" | "code_audit" | "red_team";
export type FindingKind = "manual" | "sast" | "iac" | "sca" | "secret";

/** Outcome of a retest pass over a previously reported finding. */
export type RetestStatus =
  | "not_retested"
  | "fixed"
  | "partially_fixed"
  | "not_fixed"
  | "risk_accepted";

/** A compliance/framework mapping attached to a finding (e.g. OWASP A03:2021). */
export interface Mapping {
  framework: string;
  id: string;
  name?: string | null;
}

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
  /** Retest outcome for this finding. `null` / `"not_retested"` when never retested. */
  retest_status?: RetestStatus | null;
  /** ISO date (YYYY-MM-DD) the retest was performed. */
  retest_date?: string | null;
  /** Free-form key/value metadata. */
  custom_fields: Record<string, string>;
  /** Compliance / framework mappings. */
  mappings: Mapping[];
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
  /** Delivery language of the *exported* report (section titles etc.), independent
   * of the app UI language. Backend default is "en". */
  language: string;
  /** Engagement metadata (aggregate report layer). */
  engagement_start?: string;
  engagement_end?: string;
  authors: string[];
  reviewer?: string;
  engagement_ref?: string;
  confidentiality?: string;
  /** Whether a branding logo has been uploaded for this report's cover. */
  has_logo: boolean;
  /** Free-form key/value metadata for the report. */
  custom_fields: Record<string, string>;
  created_at: string;
  updated_at: string;
}

// ── Affected assets ──────────────────────────────────────────────────────────

export type AssetKind = "host" | "ip" | "url" | "domain" | "credential" | "other";

export interface Asset {
  id: string;
  report_id: string;
  kind: AssetKind;
  identifier: string;
  description: string;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

export interface NewAsset {
  kind: AssetKind;
  identifier: string;
  description?: string;
}

export type AssetPatch = Partial<Pick<Asset, "kind" | "identifier" | "description">>;

// ── Structured scope ─────────────────────────────────────────────────────────

export interface ScopeItem {
  id: string;
  report_id: string;
  kind: string;
  value: string;
  in_scope: boolean;
  note: string;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

export interface NewScopeItem {
  kind: string;
  value: string;
  in_scope: boolean;
  note?: string;
}

export type ScopeItemPatch = Partial<
  Pick<ScopeItem, "kind" | "value" | "in_scope" | "note">
>;

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
  /** Optional delivery language for the exported report; backend defaults to "en". */
  language?: string;
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
  retest_status?: RetestStatus | null;
  retest_date?: string | null;
  custom_fields?: Record<string, string>;
  mappings?: Mapping[];
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
    | "title"
    | "client"
    | "report_type"
    | "status"
    | "exec_summary"
    | "scope"
    | "methodology"
    | "language"
    | "engagement_start"
    | "engagement_end"
    | "authors"
    | "reviewer"
    | "engagement_ref"
    | "confidentiality"
    | "custom_fields"
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
    | "retest_status"
    | "retest_date"
    | "custom_fields"
    | "mappings"
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
export type ImportFormat = "sarif" | "nuclei" | "zap" | "burp" | "nessus" | "secai" | "csv";

// Outcome of a scanner import, returned by `import_findings`.
export interface ImportSummary {
  imported: number;
  skipped: number;
  deduped: number;
  warnings: string[];
}

// Shape the Rust layer serializes its errors into.
export interface IpcError {
  kind: string;
  message: string;
}

// ── Encrypted sync bundle ─────────────────────────────────────────────────────

// Counts returned after merging an imported sync bundle into the local vault.
export interface SyncSummary {
  reports_added: number;
  reports_updated: number;
  findings_added: number;
  findings_updated: number;
  kb_added: number;
  kb_updated: number;
  images_added: number;
  skipped: number;
}

// ── AI assistance ─────────────────────────────────────────────────────────────

export type AiProvider = "ollama" | "openai" | "anthropic" | "azure" | "gemini";

export interface AiConfig {
  enabled: boolean;
  provider: AiProvider;
  base_url: string;
  model: string;
  /** Upper bound on tokens generated per completion. Backend default is 1024. */
  max_tokens: number;
  /** Azure OpenAI API version (e.g. "2024-06-01"). Only used by the azure provider. */
  api_version?: string;
}

export interface AiConfigView extends AiConfig {
  has_key: boolean;
}
