import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";
import { Copy, FileText, Plus, Trash2, Search } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { CardGridSkeleton } from "@/components/ui/skeleton";
import { ReportLanguageSelect } from "@/components/report-language-select";
import { ReportTypeBadge } from "@/components/report-type-badge";
import { EmptyState } from "@/components/empty-state";
import { SUPPORTED_LANGUAGES } from "@/i18n";
import {
  useCloneReport,
  useCreateReport,
  useDeleteReport,
  useReports,
} from "@/lib/queries/use-reports";
import { useUndoableDelete } from "@/lib/use-undoable-delete";
import { useHotkey, useSubmitShortcut } from "@/lib/use-hotkeys";
import { errorMessage } from "@/lib/ipc";
import { formatDate } from "@/lib/format";
import type { ReportSummary, ReportType } from "@/lib/types";

const REPORT_TYPES: ReportType[] = ["web_pentest", "code_audit", "red_team"];
type SortKey = "updated" | "created" | "findings";
type TypeFilter = "all" | ReportType;

/** Resolve the active UI language down to a supported short code (default "en"). */
function uiLanguage(raw: string): string {
  const short = raw.split("-")[0];
  return (SUPPORTED_LANGUAGES as readonly string[]).includes(short) ? short : "en";
}

function NewReportDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (id: string) => void;
}) {
  const { t, i18n } = useTranslation();
  const [title, setTitle] = useState("");
  const [client, setClient] = useState("");
  const [type, setType] = useState<ReportType>("web_pentest");
  // Default the report's delivery language to the current UI language.
  const [language, setLanguage] = useState<string>(() => uiLanguage(i18n.language));
  const createReport = useCreateReport();

  const reset = () => {
    setTitle("");
    setClient("");
    setType("web_pentest");
    setLanguage(uiLanguage(i18n.language));
  };

  const submit = () => {
    if (!title.trim() || !client.trim() || createReport.isPending) return;
    createReport.mutate(
      { title: title.trim(), client: client.trim(), report_type: type, language },
      {
        onSuccess: (report) => {
          onOpenChange(false);
          reset();
          onCreated(report.id);
        },
        onError: (err) => toast.error(errorMessage(err, "reports.createError")),
      },
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    submit();
  };

  // Cmd/Ctrl+Enter submits even when focus is on a non-input control.
  useSubmitShortcut(open, submit);

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o);
        if (!o) reset();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("reports.newTitle")}</DialogTitle>
          <DialogDescription>{t("reports.subtitle")}</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="r-title">{t("reports.fieldTitle")}</Label>
            <Input
              id="r-title"
              autoFocus
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder={t("reports.fieldTitlePlaceholder")}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="r-client">{t("reports.fieldClient")}</Label>
            <Input
              id="r-client"
              value={client}
              onChange={(e) => setClient(e.target.value)}
              placeholder={t("reports.fieldClientPlaceholder")}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label>{t("reports.fieldType")}</Label>
            <Select value={type} onValueChange={(v) => setType(v as ReportType)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REPORT_TYPES.map((rt) => (
                  <SelectItem key={rt} value={rt}>
                    {t(`reportType.${rt}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <ReportLanguageSelect value={language} onChange={setLanguage} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              type="submit"
              variant="brand"
              disabled={createReport.isPending || !title.trim() || !client.trim()}
            >
              {createReport.isPending ? t("common.saving") : t("common.create")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function ReportsList() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { data: reports, isLoading } = useReports();
  const deleteReport = useDeleteReport();
  const cloneReport = useCloneReport();
  const undoableDelete = useUndoableDelete();

  const [pendingDelete, setPendingDelete] = useState<ReportSummary | null>(null);
  const [newOpen, setNewOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortKey>("updated");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");

  // `/` focuses the search box; `n` opens the new-report dialog.
  useHotkey("/", () => document.getElementById("reports-search")?.focus());
  useHotkey("n", () => setNewOpen(true));

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...(reports ?? [])]
      .filter((r) => typeFilter === "all" || r.report_type === typeFilter)
      .filter((r) => {
        if (!q) return true;
        return r.title.toLowerCase().includes(q) || r.client.toLowerCase().includes(q);
      })
      .sort((a, b) => {
        if (sort === "findings") return b.finding_count - a.finding_count;
        // `created` and `updated` both sort newest-first; the summary only carries
        // updated_at, so `created` falls back to id (monotonic create order).
        if (sort === "created") return b.id.localeCompare(a.id);
        return b.updated_at.localeCompare(a.updated_at);
      });
  }, [reports, query, typeFilter, sort]);

  const handleDuplicate = (report: ReportSummary, e: React.MouseEvent) => {
    e.stopPropagation();
    cloneReport.mutate(report.id, {
      onSuccess: (copy) => {
        toast.success(t("reports.duplicated", { title: report.title }));
        navigate(`/reports/${copy.id}`);
      },
      onError: (err) => toast.error(errorMessage(err, "reports.duplicateError")),
    });
  };

  const requestDelete = (report: ReportSummary, e: React.MouseEvent) => {
    e.stopPropagation();
    setPendingDelete(report);
  };

  const confirmDelete = () => {
    const report = pendingDelete;
    setPendingDelete(null);
    if (!report) return;
    undoableDelete({
      id: report.id,
      message: t("reports.deleted", { title: report.title }),
      undoLabel: t("common.undo"),
      perform: () =>
        deleteReport.mutate(report.id, {
          onError: (err) => toast.error(errorMessage(err)),
        }),
    });
  };

  const hasReports = reports && reports.length > 0;

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <header className="mb-8 flex items-start justify-between gap-4">
        <div>
          <h1 className="display-xl">{t("reports.title")}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t("reports.subtitle")}</p>
        </div>
        <Button variant="brand" onClick={() => setNewOpen(true)}>
          <Plus />
          {t("reports.new")}
        </Button>
      </header>

      {hasReports && (
        <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative sm:max-w-xs sm:flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id="reports-search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t("reports.searchPlaceholder")}
              className="pl-9"
            />
          </div>
          <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as TypeFilter)}>
            <SelectTrigger className="sm:w-44" aria-label={t("reports.fieldType")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t("reports.filterAllTypes")}</SelectItem>
              {REPORT_TYPES.map((rt) => (
                <SelectItem key={rt} value={rt}>
                  {t(`reportType.${rt}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={sort} onValueChange={(v) => setSort(v as SortKey)}>
            <SelectTrigger className="sm:w-48" aria-label={t("reports.sortLabel")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="updated">{t("reports.sort.updated")}</SelectItem>
              <SelectItem value="created">{t("reports.sort.created")}</SelectItem>
              <SelectItem value="findings">{t("reports.sort.findings")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}

      {isLoading ? (
        <CardGridSkeleton />
      ) : !hasReports ? (
        <EmptyState
          icon={FileText}
          title={t("reports.empty.title")}
          body={t("reports.empty.body")}
          ctaLabel={t("reports.empty.cta")}
          onCta={() => setNewOpen(true)}
        />
      ) : visible.length === 0 ? (
        <p className="py-12 text-center text-sm text-muted-foreground">
          {t("reports.noMatches")}
        </p>
      ) : (
        <motion.div layout className="grid gap-4 sm:grid-cols-2">
          <AnimatePresence>
            {visible.map((r) => (
              <motion.div
                key={r.id}
                layout
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.97 }}
                transition={{ duration: 0.18 }}
                whileHover={{ y: -2 }}
              >
                <Card
                  className="group cursor-pointer transition-colors hover:border-[hsl(var(--accent-brand)/0.5)]"
                  onClick={() => navigate(`/reports/${r.id}`)}
                >
                  <CardContent className="space-y-3 p-5">
                    <div className="flex items-start justify-between gap-2">
                      <ReportTypeBadge type={r.report_type} />
                      <div className="flex shrink-0 gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t("common.duplicate")}
                          aria-label={t("common.duplicate")}
                          disabled={cloneReport.isPending}
                          onClick={(e) => handleDuplicate(r, e)}
                        >
                          <Copy />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t("common.delete")}
                          aria-label={t("common.delete")}
                          onClick={(e) => requestDelete(r, e)}
                        >
                          <Trash2 />
                        </Button>
                      </div>
                    </div>
                    <div>
                      <h3 className="font-semibold leading-snug">{r.title}</h3>
                      <p className="text-sm text-muted-foreground">{r.client}</p>
                    </div>
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span className="font-mono">
                        {t("reports.findingCount", { count: r.finding_count })}
                      </span>
                      <span>{t("reports.updated", { date: formatDate(r.updated_at) })}</span>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </AnimatePresence>
        </motion.div>
      )}

      <NewReportDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        onCreated={(id) => navigate(`/reports/${id}`)}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t("reports.deleteTitle")}
        description={t("reports.deleteConfirm")}
        itemName={pendingDelete?.title}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
