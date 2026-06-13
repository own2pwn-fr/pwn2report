import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import {
  ArrowLeft,
  BookMarked,
  Bug,
  FileUp,
  Image,
  ListChecks,
  Plus,
  Server,
  SlidersHorizontal,
  Users,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Check, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ExportMenu } from "@/components/export-menu";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CollapsibleSection } from "@/components/ui/collapsible-section";
import { ReportLanguageSelect } from "@/components/report-language-select";
import { ReportTypeBadge } from "@/components/report-type-badge";
import { EmptyState } from "@/components/empty-state";
import { FindingCard } from "@/components/findings/finding-card";
import { FindingForm } from "@/components/findings/finding-form";
import { KbPicker } from "@/components/findings/kb-picker";
import { ImportFindingsDialog } from "@/components/findings/import-findings-dialog";
import { AssetsManager } from "@/components/report/assets-manager";
import { ScopeManager } from "@/components/report/scope-manager";
import { KeyValueEditor } from "@/components/ui/key-value-editor";
import { EngagementMetadata } from "@/components/report/engagement-metadata";
import { LogoBranding } from "@/components/report/logo-branding";
import { AiAssistButton } from "@/components/ai/ai-assist-button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useReport, useUpdateReport } from "@/lib/queries/use-reports";
import {
  useCloneFinding,
  useCreateFinding,
  useCreateFindingFromKb,
  useDeleteFinding,
  useFindings,
  useImportFindings,
  useUpdateFinding,
} from "@/lib/queries/use-findings";
import { useAssets } from "@/lib/queries/use-assets";
import { useScopeItems } from "@/lib/queries/use-scope";
import { useSetFindingAssets } from "@/lib/queries/use-finding-assets";
import { errorMessage } from "@/lib/ipc";
import { useDebouncedCallback } from "@/lib/use-debounced-callback";
import { useUndoableDelete } from "@/lib/use-undoable-delete";
import { severityRank } from "@/lib/format";
import type {
  Finding,
  FindingPatch,
  ImportFormat,
  NewFinding,
  ReportPatch,
} from "@/lib/types";

/** Subtle "Saving…/Saved ✓" status, shown only after the user has edited. */
function SaveStatus({ status }: { status: "idle" | "saving" | "saved" }) {
  const { t } = useTranslation();
  if (status === "idle") return null;
  if (status === "saving") {
    return (
      <span className="flex items-center gap-1 text-xs text-muted-foreground">
        <Loader2 className="size-3 animate-spin" />
        {t("common.saving")}
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1 text-xs text-muted-foreground">
      <Check className="size-3 text-emerald-600 dark:text-emerald-500" />
      {t("common.saved")}
    </span>
  );
}

/** A textarea that debounces updates back to the report on change. */
function DebouncedField({
  label,
  value,
  placeholder,
  onCommit,
  rows = 4,
  aiAssist = false,
  isPending = false,
  isSuccess = false,
}: {
  label: string;
  value: string;
  placeholder?: string;
  onCommit: (value: string) => void;
  rows?: number;
  /** Show an AI assist button next to the label (gated on AI being enabled). */
  aiAssist?: boolean;
  /** The report update mutation is in flight. */
  isPending?: boolean;
  /** The last report update succeeded. */
  isSuccess?: boolean;
}) {
  const [local, setLocal] = useState(value);
  // Whether THIS field initiated the most recent edit (so we only show its status).
  const [touched, setTouched] = useState(false);
  // Re-sync when the upstream value changes (e.g. switching reports).
  useEffect(() => setLocal(value), [value]);
  const debounced = useDebouncedCallback((v: string) => onCommit(v), 600);

  // Replace the field with AI output and commit immediately (no debounce wait).
  const applyAi = (text: string) => {
    setTouched(true);
    setLocal(text);
    onCommit(text);
  };

  const status: "idle" | "saving" | "saved" = !touched
    ? "idle"
    : isPending
      ? "saving"
      : isSuccess
        ? "saved"
        : "idle";

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <Label>{label}</Label>
        <div className="flex items-center gap-2">
          <SaveStatus status={status} />
          {aiAssist && (
            <AiAssistButton
              value={local}
              fieldLabel={label}
              onResult={applyAi}
              className="-my-2 size-7"
            />
          )}
        </div>
      </div>
      <Textarea
        value={local}
        rows={rows}
        placeholder={placeholder}
        onChange={(e) => {
          setTouched(true);
          setLocal(e.target.value);
          debounced(e.target.value);
        }}
      />
    </div>
  );
}

export function ReportDetail() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();

  const { data: report, isLoading, isError } = useReport(id);
  const { data: findings } = useFindings(id);
  const { data: assets } = useAssets(id);
  const { data: scopeItems } = useScopeItems(id);
  const updateReport = useUpdateReport(id ?? "");
  const createFinding = useCreateFinding(id ?? "");
  const updateFinding = useUpdateFinding(id ?? "");
  const deleteFinding = useDeleteFinding(id ?? "");
  const cloneFinding = useCloneFinding(id ?? "");
  const createFromKb = useCreateFindingFromKb(id ?? "");
  const importFindingsM = useImportFindings(id ?? "");
  const setFindingAssets = useSetFindingAssets();

  const undoableDelete = useUndoableDelete();

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Finding | undefined>(undefined);
  const [kbPickerOpen, setKbPickerOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<Finding | null>(null);

  const commit = (patch: ReportPatch) =>
    updateReport.mutate(patch, {
      onError: (err) => toast.error(errorMessage(err)),
    });

  const openCreate = () => {
    setEditing(undefined);
    setFormOpen(true);
  };

  const openEdit = (f: Finding) => {
    setEditing(f);
    setFormOpen(true);
  };

  const handleCreate = (input: NewFinding, assetIds: string[]) =>
    createFinding.mutate(input, {
      onSuccess: (created) => {
        setFormOpen(false);
        if (assetIds.length > 0) {
          setFindingAssets.mutate(
            { findingId: created.id, assetIds },
            { onError: (err) => toast.error(errorMessage(err)) },
          );
        }
      },
      onError: (err) => toast.error(errorMessage(err, "findings.createError")),
    });

  const handleUpdate = (findingId: string, patch: FindingPatch, assetIds: string[]) =>
    updateFinding.mutate(
      { id: findingId, patch },
      {
        onSuccess: () => {
          setFormOpen(false);
          setFindingAssets.mutate(
            { findingId, assetIds },
            { onError: (err) => toast.error(errorMessage(err)) },
          );
        },
        onError: (err) => toast.error(errorMessage(err)),
      },
    );

  const handleDuplicate = (f: Finding) =>
    cloneFinding.mutate(f.id, {
      onSuccess: () => toast.success(t("findings.duplicated", { title: f.title })),
      onError: (err) => toast.error(errorMessage(err, "findings.duplicateError")),
    });

  const confirmDelete = () => {
    const f = pendingDelete;
    setPendingDelete(null);
    if (!f) return;
    undoableDelete({
      id: f.id,
      message: t("findings.deleted", { title: f.title }),
      undoLabel: t("common.undo"),
      perform: () =>
        deleteFinding.mutate(f.id, {
          onError: (err) => toast.error(errorMessage(err)),
        }),
    });
  };

  const handlePickFromKb = (kbId: string) =>
    createFromKb.mutate(kbId, {
      onSuccess: () => {
        setKbPickerOpen(false);
        toast.success(t("findings.kbPicker.added"));
      },
      onError: (err) => toast.error(errorMessage(err, "findings.kbPicker.error")),
    });

  const handleImport = (format: ImportFormat, content: string) =>
    importFindingsM.mutate(
      { format, content },
      {
        onSuccess: (count) => {
          setImportOpen(false);
          toast.success(t("findings.import.success", { count }));
        },
        onError: (err) => toast.error(errorMessage(err, "findings.import.error")),
      },
    );

  if (isLoading) {
    return <p className="px-6 py-10 text-sm text-muted-foreground">{t("common.loading")}</p>;
  }
  if (isError || !report) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-10">
        <Button variant="ghost" onClick={() => navigate("/")}>
          <ArrowLeft />
          {t("common.back")}
        </Button>
        <p className="mt-6 text-sm text-muted-foreground">{t("report.notFound")}</p>
      </div>
    );
  }

  const sortedFindings = [...(findings ?? [])].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || a.sort_order - b.sort_order,
  );

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2 }}
      className="mx-auto max-w-4xl px-6 py-8"
    >
      <div className="mb-6 flex items-center justify-between gap-4">
        <Button variant="ghost" onClick={() => navigate("/")}>
          <ArrowLeft />
          {t("common.back")}
        </Button>
        <ExportMenu report={report} />
      </div>

      <header className="mb-8 space-y-2">
        <ReportTypeBadge type={report.report_type} />
        <h1 className="text-3xl font-bold tracking-tight">{report.title}</h1>
        <p className="text-muted-foreground">{report.client}</p>
      </header>

      <div className="space-y-4">
        {/* ── Details ──────────────────────────────────────────────────────── */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("report.details")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            <ReportLanguageSelect
              value={report.language}
              onChange={(language) => commit({ language })}
              className="max-w-xs"
            />
            <DebouncedField
              label={t("report.execSummary")}
              value={report.exec_summary}
              placeholder={t("report.execSummaryPlaceholder")}
              onCommit={(v) => commit({ exec_summary: v })}
              rows={4}
              aiAssist
              isPending={updateReport.isPending}
              isSuccess={updateReport.isSuccess}
            />
            <DebouncedField
              label={t("report.scope")}
              value={report.scope}
              placeholder={t("report.scopePlaceholder")}
              onCommit={(v) => commit({ scope: v })}
              rows={3}
              isPending={updateReport.isPending}
              isSuccess={updateReport.isSuccess}
            />
            <DebouncedField
              label={t("report.methodology")}
              value={report.methodology}
              placeholder={t("report.methodologyPlaceholder")}
              onCommit={(v) => commit({ methodology: v })}
              rows={3}
              isPending={updateReport.isPending}
              isSuccess={updateReport.isSuccess}
            />
          </CardContent>
        </Card>

        {/* ── Engagement metadata ──────────────────────────────────────────── */}
        <CollapsibleSection
          title={t("engagement.title")}
          icon={Users}
          defaultOpen={false}
        >
          <EngagementMetadata
            report={report}
            onCommit={commit}
            isPending={updateReport.isPending}
            isSuccess={updateReport.isSuccess}
          />
        </CollapsibleSection>

        {/* ── Structured scope ─────────────────────────────────────────────── */}
        <CollapsibleSection
          title={t("scope.title")}
          icon={ListChecks}
          count={scopeItems?.length}
          defaultOpen={false}
        >
          <ScopeManager reportId={report.id} />
        </CollapsibleSection>

        {/* ── Affected assets ──────────────────────────────────────────────── */}
        <CollapsibleSection
          title={t("assets.title")}
          icon={Server}
          count={assets?.length}
          defaultOpen={false}
        >
          <AssetsManager reportId={report.id} />
        </CollapsibleSection>

        {/* ── Branding / logo ──────────────────────────────────────────────── */}
        <CollapsibleSection
          title={t("branding.title")}
          icon={Image}
          defaultOpen={false}
        >
          <LogoBranding reportId={report.id} hasLogo={report.has_logo} />
        </CollapsibleSection>

        {/* ── Custom fields ────────────────────────────────────────────────── */}
        <CollapsibleSection
          title={t("customFields.title")}
          icon={SlidersHorizontal}
          count={Object.keys(report.custom_fields ?? {}).length || undefined}
          defaultOpen={false}
        >
          <p className="mb-3 text-sm text-muted-foreground">{t("customFields.reportHint")}</p>
          <KeyValueEditor
            value={report.custom_fields ?? {}}
            onChange={(custom_fields) => commit({ custom_fields })}
          />
        </CollapsibleSection>
      </div>

      <Separator className="my-8" />

      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-xl font-semibold tracking-tight">{t("findings.title")}</h2>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" onClick={() => setKbPickerOpen(true)}>
            <BookMarked />
            {t("findings.addFromKb")}
          </Button>
          <Button variant="outline" onClick={() => setImportOpen(true)}>
            <FileUp />
            {t("findings.importCta")}
          </Button>
          {sortedFindings.length > 0 && (
            <Button variant="brand" onClick={openCreate}>
              <Plus />
              {t("findings.new")}
            </Button>
          )}
        </div>
      </div>

      {sortedFindings.length === 0 ? (
        <EmptyState
          icon={Bug}
          title={t("findings.empty.title")}
          body={t("findings.empty.body")}
          ctaLabel={t("findings.empty.cta")}
          onCta={openCreate}
        />
      ) : (
        <motion.div layout className="space-y-3">
          <AnimatePresence>
            {sortedFindings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                onEdit={openEdit}
                onDuplicate={handleDuplicate}
                onDelete={setPendingDelete}
              />
            ))}
          </AnimatePresence>
        </motion.div>
      )}

      {/* Keyed so the form re-initializes its state per target finding. */}
      <FindingForm
        key={editing?.id ?? "new"}
        open={formOpen}
        onOpenChange={setFormOpen}
        reportId={id ?? ""}
        finding={editing}
        onCreate={handleCreate}
        onUpdate={handleUpdate}
        pending={createFinding.isPending || updateFinding.isPending}
      />

      <KbPicker
        open={kbPickerOpen}
        onOpenChange={setKbPickerOpen}
        onPick={handlePickFromKb}
        pending={createFromKb.isPending}
      />

      <ImportFindingsDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        onImport={handleImport}
        pending={importFindingsM.isPending}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t("findings.deleteTitle")}
        description={t("findings.deleteConfirm")}
        itemName={pendingDelete?.title}
        onConfirm={confirmDelete}
      />
    </motion.div>
  );
}
