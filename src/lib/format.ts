import i18n from "@/i18n";
import type { Confidence, ReportType, Severity, TriageStatus } from "./types";

/** Format an ISO timestamp as a short date, following the active app language. */
export function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(i18n.language, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/** Format an ISO timestamp with time (for "last updated" tooltips), following
 * the active app language. */
export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(i18n.language, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Sort weight so critical findings float to the top. */
export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

// i18n key fragments — components resolve these through t().
export const severityKey = (s: Severity) => `severity.${s}`;
export const confidenceKey = (c: Confidence) => `confidence.${c}`;
export const triageKey = (t: TriageStatus) => `triage.${t}`;
export const reportTypeKey = (r: ReportType) => `reportType.${r}`;
