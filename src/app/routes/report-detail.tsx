import { useEffect, useMemo, useState } from "react";
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
  Trash2,
  Users,
  X,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ReportLanguageSelect } from "@/components/report-language-select";
import { ReportTypeBadge } from "@/components/report-type-badge";
import { EmptyState } from "@/components/empty-state";
import { StackSkeleton } from "@/components/ui/skeleton";
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
  useReorderFindings,
  useUpdateFinding,
} from "@/lib/queries/use-findings";
import { useAssets } from "@/lib/queries/use-assets";
import { useScopeItems } from "@/lib/queries/use-scope";
import { useSetFindingAssets } from "@/lib/queries/use-finding-assets";
import { errorMessage } from "@/lib/ipc";
import { useDebouncedCallback } from "@/lib/use-debounced-callback";
import { useUndoableDelete } from "@/lib/use-undoable-delete";
import { useHotkey } from "@/lib/use-hotkeys";
import { severityRank } from "@/lib/format";
import type {
  Finding,
  FindingPatch,
  ImportFormat,
  NewFinding,
  ReportPatch,
  TriageStatus,
} from "@/lib/types";

type OrderMode = "severity" | "manual";
const TRIAGE_STATUSES: TriageStatus[] = [
  "open",
  "acknowledged",
  "false_positive",
  "resolved",
];

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
  const reorderFindings = useReorderFindings(id ?? "");
  const setFindingAssets = useSetFindingAssets();

  const undoableDelete = useUndoableDelete();

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Finding | undefined>(undefined);
  const [kbPickerOpen, setKbPickerOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importWarnings, setImportWarnings] = useState<string[]>([]);
  const [pendingDelete, setPendingDelete] = useState<Finding | null>(null);

  // Findings ordering + bulk selection.
  const [orderMode, setOrderMode] = useState<OrderMode>("severity");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [pendingBulkDelete, setPendingBulkDelete] = useState(false);

  // `n` adds a finding from anywhere on the page.
  useHotkey("n", () => {
    setEditing(undefined);
    setFormOpen(true);
  });

  // Drop selection entries for findings that no longer exist (after delete/sync).
  useEffect(() => {
    if (!findings) return;
    setSelected((prev) => {
      if (prev.size === 0) return prev;
      const live = new Set(findings.map((f) => f.id));
      const next = new Set([...prev].filter((idv) => live.has(idv)));
      return next.size === prev.size ? prev : next;
    });
  }, [findings]);

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
        onSuccess: (summary) => {
          setImportWarnings(summary.warnings);
          toast.success(
            t("findings.import.summary", {
              imported: summary.imported,
              skipped: summary.skipped,
              deduped: summary.deduped,
            }),
          );
          // Keep the dialog open when there are warnings to review; otherwise close.
          if (summary.warnings.length === 0) setImportOpen(false);
        },
        onError: (err) => toast.error(errorMessage(err, "findings.import.error")),
      },
    );

  // Ordered findings for display. "severity" sorts by severity then stored order;
  // "manual" honours the persisted sort_order so drag/up-down ordering sticks.
  const displayFindings = useMemo(() => {
    const list = [...(findings ?? [])];
    if (orderMode === "manual") {
      return list.sort((a, b) => a.sort_order - b.sort_order);
    }
    return list.sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) || a.sort_order - b.sort_order,
    );
  }, [findings, orderMode]);

  const toggleSelect = (f: Finding) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(f.id)) next.delete(f.id);
      else next.add(f.id);
      return next;
    });

  const clearSelection = () => setSelected(new Set());

  const selectAll = () => setSelected(new Set(displayFindings.map((f) => f.id)));

  // Persist a manual move by swapping with the neighbour and reordering.
  const move = (f: Finding, dir: -1 | 1) => {
    const ids = displayFindings.map((x) => x.id);
    const idx = ids.indexOf(f.id);
    const target = idx + dir;
    if (target < 0 || target >= ids.length) return;
    [ids[idx], ids[target]] = [ids[target], ids[idx]];
    // Manual ordering only makes sense when displayed in manual order.
    setOrderMode("manual");
    reorderFindings.mutate(ids, {
      onError: (err) => toast.error(errorMessage(err, "findings.reorderError")),
    });
  };

  const handleBulkDelete = () => {
    const ids = [...selected];
    setPendingBulkDelete(false);
    if (ids.length === 0) return;
    clearSelection();
    undoableDelete({
      id: `bulk:${ids.join(",")}`,
      message: t("findings.select.bulkDeleted", { count: ids.length }),
      undoLabel: t("common.undo"),
      perform: () => {
        for (const fid of ids) {
          deleteFinding.mutate(fid, {
            onError: (err) => toast.error(errorMessage(err)),
          });
        }
      },
    });
  };

  const handleBulkTriage = (status: TriageStatus) => {
    const ids = [...selected];
    if (ids.length === 0) return;
    clearSelection();
    let failed = false;
    for (const fid of ids) {
      updateFinding.mutate(
        { id: fid, patch: { triage_status: status } },
        {
          onError: () => {
            if (!failed) {
              failed = true;
              toast.error(t("findings.select.bulkError"));
            }
          },
        },
      );
    }
    toast.success(t("findings.select.bulkTriageDone", { count: ids.length }));
  };

  // History-aware back: pop the history stack when there is one, else go home.
  const goBack = () => {
    if (window.history.length > 1) navigate(-1);
    else navigate("/");
  };

  if (isLoading) {
    return (
      <div className="mx-auto max-w-4xl px-6 py-8">
        <StackSkeleton count={5} />
      </div>
    );
  }
  if (isError || !report) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-10">
        <Button variant="ghost" onClick={goBack}>
          <ArrowLeft />
          {t("common.back")}
        </Button>
        <p className="mt-6 text-sm text-muted-foreground">{t("report.notFound")}</p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-6 py-8">
      <nav aria-label={t("nav.breadcrumb")} className="mb-4">
        <ol className="flex flex-wrap items-center gap-1.5 text-sm text-muted-foreground">
          <li>
            <button
              type="button"
              onClick={() => navigate("/")}
              className="rounded hover:text-foreground hover:underline"
            >
              {t("reports.title")}
            </button>
          </li>
          <li aria-hidden>/</li>
          <li className="truncate font-medium text-foreground" aria-current="page">
            {t("report.breadcrumb", { client: report.client, title: report.title })}
          </li>
        </ol>
      </nav>

      <div className="mb-6 flex items-center justify-between gap-4">
        <Button variant="ghost" onClick={goBack}>
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
          {displayFindings.length > 1 && (
            <Select value={orderMode} onValueChange={(v) => setOrderMode(v as OrderMode)}>
              <SelectTrigger className="w-44" aria-label={t("findings.order.label")}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="severity">{t("findings.order.severity")}</SelectItem>
                <SelectItem value="manual">{t("findings.order.manual")}</SelectItem>
              </SelectContent>
            </Select>
          )}
          <Button variant="outline" onClick={() => setKbPickerOpen(true)}>
            <BookMarked />
            {t("findings.addFromKb")}
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              setImportWarnings([]);
              setImportOpen(true);
            }}
          >
            <FileUp />
            {t("findings.importCta")}
          </Button>
          {displayFindings.length > 0 && (
            <Button variant="brand" onClick={openCreate}>
              <Plus />
              {t("findings.new")}
            </Button>
          )}
        </div>
      </div>

      {orderMode === "manual" && displayFindings.length > 1 && (
        <p className="mb-3 text-xs text-muted-foreground">{t("findings.order.manualHint")}</p>
      )}

      {/* Bulk-selection toolbar — appears once one or more findings are picked. */}
      <AnimatePresence>
        {selected.size > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.15 }}
            className="mb-3 overflow-hidden"
          >
            <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 p-2">
              <span className="px-1 text-sm font-medium">
                {t("findings.select.count", { count: selected.size })}
              </span>
              <Select onValueChange={(v) => handleBulkTriage(v as TriageStatus)}>
                <SelectTrigger className="h-8 w-44" aria-label={t("findings.select.setTriage")}>
                  <SelectValue placeholder={t("findings.select.setTriage")} />
                </SelectTrigger>
                <SelectContent>
                  {TRIAGE_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {t(`triage.${s}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setPendingBulkDelete(true)}
              >
                <Trash2 />
                {t("findings.select.bulkDelete")}
              </Button>
              <Button variant="ghost" size="sm" onClick={selectAll}>
                {t("findings.select.selectAll")}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={clearSelection}
                aria-label={t("findings.select.clear")}
              >
                <X />
                {t("findings.select.clear")}
              </Button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {displayFindings.length === 0 ? (
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
            {displayFindings.map((f, i) => (
              <FindingCard
                key={f.id}
                finding={f}
                onEdit={openEdit}
                onDuplicate={handleDuplicate}
                onDelete={setPendingDelete}
                selectable
                selected={selected.has(f.id)}
                onToggleSelect={toggleSelect}
                reorderable={orderMode === "manual"}
                onMoveUp={(x) => move(x, -1)}
                onMoveDown={(x) => move(x, 1)}
                canMoveUp={i > 0}
                canMoveDown={i < displayFindings.length - 1}
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
        onOpenChange={(o) => {
          setImportOpen(o);
          if (!o) setImportWarnings([]);
        }}
        onImport={handleImport}
        pending={importFindingsM.isPending}
        warnings={importWarnings}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t("findings.deleteTitle")}
        description={t("findings.deleteConfirm")}
        itemName={pendingDelete?.title}
        onConfirm={confirmDelete}
      />

      <ConfirmDialog
        open={pendingBulkDelete}
        onOpenChange={setPendingBulkDelete}
        title={t("findings.select.bulkDeleteTitle")}
        description={t("findings.select.bulkDeleteConfirm", { count: selected.size })}
        onConfirm={handleBulkDelete}
      />
    </div>
  );
}
