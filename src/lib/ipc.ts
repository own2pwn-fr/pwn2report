// Typed wrappers around the Tauri `invoke` IPC bridge.
//
// Tauri v2 invoke args are camelCase on the JS side and are mapped to the
// matching snake_case Rust params automatically. Every command returns a
// Result on the Rust side; a rejection surfaces here as a thrown value shaped
// like `IpcError` ({ kind, message }).

import { invoke } from "@tauri-apps/api/core";
import type {
  AiConfig,
  AiConfigView,
  EvidenceImage,
  Finding,
  FindingPatch,
  ImportFormat,
  IpcError,
  KbEntry,
  KbPatch,
  NewFinding,
  NewKbEntry,
  NewReport,
  Report,
  ReportPatch,
  ReportSummary,
  ReportType,
  SyncSummary,
  TemplateInfo,
  VaultStatus,
} from "./types";

/** Narrow an unknown thrown value into an IpcError for toast display. */
export function asIpcError(err: unknown): IpcError {
  if (
    typeof err === "object" &&
    err !== null &&
    "message" in err &&
    typeof (err as Record<string, unknown>).message === "string"
  ) {
    const e = err as Record<string, unknown>;
    return { kind: typeof e.kind === "string" ? e.kind : "error", message: e.message as string };
  }
  if (typeof err === "string") return { kind: "error", message: err };
  return { kind: "error", message: "Unknown error" };
}

// ── Vault ──────────────────────────────────────────────────────────────────

export const vaultStatus = () => invoke<VaultStatus>("vault_status");

export const createVault = (passphrase: string, remember: boolean) =>
  invoke<void>("create_vault", { passphrase, remember });

export const unlockVault = (passphrase: string, remember: boolean) =>
  invoke<void>("unlock_vault", { passphrase, remember });

export const unlockWithKeychain = () => invoke<boolean>("unlock_with_keychain");

export const lockVault = () => invoke<void>("lock_vault");

export const forgetKeychain = () => invoke<void>("forget_keychain");

// ── Reports ────────────────────────────────────────────────────────────────

export const listReports = () => invoke<ReportSummary[]>("list_reports");

export const createReport = (input: NewReport) => invoke<Report>("create_report", { input });

export const getReport = (id: string) => invoke<Report>("get_report", { id });

export const updateReport = (id: string, patch: ReportPatch) =>
  invoke<Report>("update_report", { id, patch });

export const deleteReport = (id: string) => invoke<void>("delete_report", { id });

// ── Findings ───────────────────────────────────────────────────────────────

export const listFindings = (reportId: string) =>
  invoke<Finding[]>("list_findings", { reportId });

export const createFinding = (reportId: string, input: NewFinding) =>
  invoke<Finding>("create_finding", { reportId, input });

export const updateFinding = (id: string, patch: FindingPatch) =>
  invoke<Finding>("update_finding", { id, patch });

export const deleteFinding = (id: string) => invoke<void>("delete_finding", { id });

export const reorderFindings = (reportId: string, orderedIds: string[]) =>
  invoke<void>("reorder_findings", { reportId, orderedIds });

// ── Export ─────────────────────────────────────────────────────────────────

export const exportPdf = (reportId: string) => invoke<number[]>("export_pdf", { reportId });

export const exportDocx = (reportId: string) => invoke<number[]>("export_docx", { reportId });

export const exportMarkdown = (reportId: string) =>
  invoke<string>("export_markdown", { reportId });

export const exportHtml = (reportId: string) => invoke<string>("export_html", { reportId });

// ── Security ───────────────────────────────────────────────────────────────

export const changePassphrase = (oldPassphrase: string, newPassphrase: string) =>
  invoke<void>("change_passphrase", { oldPassphrase, newPassphrase });

export const backupVault = (destPath: string) => invoke<void>("backup_vault", { destPath });

// ── Encrypted sync bundle ──────────────────────────────────────────────────────

/** Write an end-to-end encrypted sync bundle, protected by `passphrase`, to `destPath`. */
export const exportSyncBundle = (passphrase: string, destPath: string) =>
  invoke<void>("export_sync_bundle", { passphrase, destPath });

/** Decrypt and merge a sync bundle from `srcPath` into the local vault (last edit wins). */
export const importSyncBundle = (passphrase: string, srcPath: string) =>
  invoke<SyncSummary>("import_sync_bundle", { passphrase, srcPath });

// ── Templates ──────────────────────────────────────────────────────────────

export const listTemplates = () => invoke<TemplateInfo[]>("list_templates");

export const getTemplate = (reportType: ReportType) =>
  invoke<string>("get_template", { reportType });

export const saveTemplate = (reportType: ReportType, content: string) =>
  invoke<void>("save_template", { reportType, content });

export const resetTemplate = (reportType: ReportType) =>
  invoke<void>("reset_template", { reportType });

// ── Knowledge base ───────────────────────────────────────────────────────────

export const kbList = () => invoke<KbEntry[]>("kb_list");

export const kbGet = (id: string) => invoke<KbEntry>("kb_get", { id });

export const kbCreate = (input: NewKbEntry) => invoke<KbEntry>("kb_create", { input });

export const kbUpdate = (id: string, patch: KbPatch) =>
  invoke<KbEntry>("kb_update", { id, patch });

export const kbDelete = (id: string) => invoke<void>("kb_delete", { id });

/** Import the catalog shipped with the app. Resolves to the inserted count. */
export const kbImportBundled = () => invoke<number>("kb_import_bundled");

// ── KB → report ──────────────────────────────────────────────────────────────

export const createFindingFromKb = (reportId: string, kbId: string) =>
  invoke<Finding>("create_finding_from_kb", { reportId, kbId });

// ── Evidence images ──────────────────────────────────────────────────────────

export const addEvidenceImage = (
  findingId: string,
  caption: string,
  mime: string,
  data: number[],
) => invoke<EvidenceImage>("add_evidence_image", { findingId, caption, mime, data });

export const listEvidenceImages = (findingId: string) =>
  invoke<EvidenceImage[]>("list_evidence_images", { findingId });

export const getEvidenceImage = (id: string) => invoke<number[]>("get_evidence_image", { id });

export const updateEvidenceCaption = (id: string, caption: string) =>
  invoke<EvidenceImage>("update_evidence_caption", { id, caption });

export const deleteEvidenceImage = (id: string) =>
  invoke<void>("delete_evidence_image", { id });

export const reorderEvidenceImages = (findingId: string, orderedIds: string[]) =>
  invoke<void>("reorder_evidence_images", { findingId, orderedIds });

// ── Scanner import ───────────────────────────────────────────────────────────

/** Import scanner output into a report. Resolves to the imported finding count. */
export const importFindings = (reportId: string, format: ImportFormat, content: string) =>
  invoke<number>("import_findings", { reportId, format, content });

// ── AI assistance ──────────────────────────────────────────────────────────────

export const aiGetConfig = () => invoke<AiConfigView>("ai_get_config");

/**
 * Persist the AI configuration. Pass `apiKey: undefined`/`null` to keep the
 * existing key untouched; pass an empty string to clear it.
 */
export const aiSetConfig = (config: AiConfig, apiKey?: string | null) =>
  invoke<void>("ai_set_config", { config, apiKey: apiKey ?? null });

export const aiTestConnection = () => invoke<string>("ai_test_connection");

export const aiComplete = (prompt: string, system?: string | null) =>
  invoke<string>("ai_complete", { system: system ?? null, prompt });
