import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { FileText, Plus, Trash2, Lock, Settings as SettingsIcon } from "lucide-react";
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { ThemeToggle } from "@/components/theme-toggle";
import { ReportTypeBadge } from "@/components/report-type-badge";
import { EmptyState } from "@/components/empty-state";
import { useCreateReport, useDeleteReport, useReports } from "@/lib/queries/use-reports";
import { useLockVault } from "@/lib/queries/use-vault";
import { asIpcError } from "@/lib/ipc";
import { formatDate } from "@/lib/format";
import type { ReportType } from "@/lib/types";

const REPORT_TYPES: ReportType[] = ["web_pentest", "code_audit", "red_team"];

function NewReportDialog({ onCreated }: { onCreated: (id: string) => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [client, setClient] = useState("");
  const [type, setType] = useState<ReportType>("web_pentest");
  const createReport = useCreateReport();

  const reset = () => {
    setTitle("");
    setClient("");
    setType("web_pentest");
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !client.trim()) return;
    createReport.mutate(
      { title: title.trim(), client: client.trim(), report_type: type },
      {
        onSuccess: (report) => {
          setOpen(false);
          reset();
          onCreated(report.id);
        },
        onError: (err) => toast.error(asIpcError(err).message || t("reports.createError")),
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button variant="brand">
          <Plus />
          {t("reports.new")}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("reports.newTitle")}</DialogTitle>
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
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
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
  const lockVault = useLockVault();

  const handleDelete = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(t("reports.deleteConfirm"))) return;
    deleteReport.mutate(id, {
      onError: (err) => toast.error(asIpcError(err).message),
    });
  };

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <header className="mb-8 flex items-start justify-between gap-4">
        <div>
          <h1 className="display-xl">{t("reports.title")}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t("reports.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <ThemeToggle />
          <Button
            variant="ghost"
            size="icon"
            title={t("settings.title")}
            aria-label={t("settings.title")}
            onClick={() => navigate("/settings")}
          >
            <SettingsIcon />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            title={t("vault.lock")}
            aria-label={t("vault.lock")}
            onClick={() =>
              lockVault.mutate(undefined, {
                onSuccess: () => toast.success(t("vault.locked")),
              })
            }
          >
            <Lock />
          </Button>
          <NewReportDialog onCreated={(id) => navigate(`/reports/${id}`)} />
        </div>
      </header>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
      ) : !reports || reports.length === 0 ? (
        <EmptyState
          icon={FileText}
          title={t("reports.empty.title")}
          body={t("reports.empty.body")}
          ctaLabel={t("reports.empty.cta")}
          onCta={() => {
            // Trigger the new-report dialog by focusing — simplest is to scroll
            // the user to the header button; we rely on the header CTA instead.
            document
              .querySelector<HTMLButtonElement>("header button:last-of-type")
              ?.click();
          }}
        />
      ) : (
        <motion.div layout className="grid gap-4 sm:grid-cols-2">
          <AnimatePresence>
            {reports.map((r) => (
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
                      <Button
                        variant="ghost"
                        size="icon"
                        className="opacity-0 transition-opacity group-hover:opacity-100"
                        title={t("common.delete")}
                        aria-label={t("common.delete")}
                        onClick={(e) => handleDelete(r.id, e)}
                      >
                        <Trash2 />
                      </Button>
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
    </div>
  );
}
