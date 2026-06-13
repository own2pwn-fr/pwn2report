import type { FindingFormState } from "@/components/findings/finding-form-state";

/**
 * Field-level validation for the finding form.
 *
 * Two tiers:
 *  - "hard" errors block submit (currently only the required title).
 *  - "soft" warnings flag malformed-but-tolerated input (CWE/CVE format,
 *    evidence line numbers). They surface inline and via `aria-invalid` but do
 *    NOT block saving — a half-typed CWE shouldn't trap the user's data.
 *
 * Each entry is keyed by a stable field id (matching the input's `id`) and
 * carries an i18n message key resolved by the form at render time.
 */
export type ValidationSeverity = "error" | "warning";

export interface FieldIssue {
  field: string;
  severity: ValidationSeverity;
  /** i18n message key. */
  messageKey: string;
}

const CWE_RE = /^CWE-\d+$/i;
const CVE_RE = /^CVE-\d{4}-\d+$/i;

/** A positive integer (no decimals, no leading sign). */
function isPositiveInt(value: string): boolean {
  return /^\d+$/.test(value) && parseInt(value, 10) > 0;
}

export function validateFindingForm(s: FindingFormState): FieldIssue[] {
  const issues: FieldIssue[] = [];

  // ── Hard error: title required ──────────────────────────────────────────
  if (!s.title.trim()) {
    issues.push({
      field: "f-title",
      severity: "error",
      messageKey: "findings.validation.titleRequired",
    });
  }

  // ── Soft: CWE format (CWE-\d+) ──────────────────────────────────────────
  const cwe = s.cwe.trim();
  if (cwe && !CWE_RE.test(cwe)) {
    issues.push({
      field: "f-cwe",
      severity: "warning",
      messageKey: "findings.validation.cweFormat",
    });
  }

  // ── Soft: CVE format (CVE-\d{4}-\d+) ────────────────────────────────────
  const cve = s.cve.trim();
  if (cve && !CVE_RE.test(cve)) {
    issues.push({
      field: "f-cve",
      severity: "warning",
      messageKey: "findings.validation.cveFormat",
    });
  }

  // ── Soft: evidence line numbers (positive ints, start ≤ end) ────────────
  const startRaw = s.ev_start_line.trim();
  const endRaw = s.ev_end_line.trim();
  const startValid = startRaw === "" || isPositiveInt(startRaw);
  const endValid = endRaw === "" || isPositiveInt(endRaw);

  if (startRaw !== "" && !startValid) {
    issues.push({
      field: "f-ev-start",
      severity: "warning",
      messageKey: "findings.validation.lineNumber",
    });
  }
  if (endRaw !== "" && !endValid) {
    issues.push({
      field: "f-ev-end",
      severity: "warning",
      messageKey: "findings.validation.lineNumber",
    });
  }
  if (
    startValid &&
    endValid &&
    startRaw !== "" &&
    endRaw !== "" &&
    parseInt(startRaw, 10) > parseInt(endRaw, 10)
  ) {
    issues.push({
      field: "f-ev-end",
      severity: "warning",
      messageKey: "findings.validation.lineRange",
    });
  }

  return issues;
}

/** True when there is at least one hard (blocking) error. */
export function hasBlockingError(issues: FieldIssue[]): boolean {
  return issues.some((i) => i.severity === "error");
}

/** Index issues by field id for O(1) lookup during render. */
export function issuesByField(issues: FieldIssue[]): Record<string, FieldIssue> {
  const map: Record<string, FieldIssue> = {};
  for (const issue of issues) {
    // First issue per field wins (errors are pushed before warnings above).
    if (!map[issue.field]) map[issue.field] = issue;
  }
  return map;
}
