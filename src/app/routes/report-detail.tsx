import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { ArrowLeft, Bug, Plus } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { ExportMenu } from "@/components/export-menu";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ReportTypeBadge } from "@/components/report-type-badge";
import { EmptyState } from "@/components/empty-state";
import { FindingCard } from "@/components/findings/finding-card";
import { FindingForm } from "@/components/findings/finding-form";
import { useReport, useUpdateReport } from "@/lib/queries/use-reports";
import {
  useCreateFinding,
  useDeleteFinding,
  useFindings,
  useUpdateFinding,
} from "@/lib/queries/use-findings";
import { asIpcError } from "@/lib/ipc";
import { useDebouncedCallback } from "@/lib/use-debounced-callback";
import { severityRank } from "@/lib/format";
import type { Finding, FindingPatch, NewFinding, ReportPatch } from "@/lib/types";

/** A textarea that debounces updates back to the report on change. */
function DebouncedField({
  label,
  value,
  placeholder,
  onCommit,
  rows = 4,
}: {
  label: string;
  value: string;
  placeholder?: string;
  onCommit: (value: string) => void;
  rows?: number;
}) {
  const [local, setLocal] = useState(value);
  // Re-sync when the upstream value changes (e.g. switching reports).
  useEffect(() => setLocal(value), [value]);
  const debounced = useDebouncedCallback((v: string) => onCommit(v), 600);

  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <Textarea
        value={local}
        rows={rows}
        placeholder={placeholder}
        onChange={(e) => {
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
  const updateReport = useUpdateReport(id ?? "");
  const createFinding = useCreateFinding(id ?? "");
  const updateFinding = useUpdateFinding(id ?? "");
  const deleteFinding = useDeleteFinding(id ?? "");

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Finding | undefined>(undefined);

  const commit = (patch: ReportPatch) =>
    updateReport.mutate(patch, {
      onError: (err) => toast.error(asIpcError(err).message),
    });

  const openCreate = () => {
    setEditing(undefined);
    setFormOpen(true);
  };

  const openEdit = (f: Finding) => {
    setEditing(f);
    setFormOpen(true);
  };

  const handleCreate = (input: NewFinding) =>
    createFinding.mutate(input, {
      onSuccess: () => setFormOpen(false),
      onError: (err) => toast.error(asIpcError(err).message || t("findings.createError")),
    });

  const handleUpdate = (findingId: string, patch: FindingPatch) =>
    updateFinding.mutate(
      { id: findingId, patch },
      {
        onSuccess: () => setFormOpen(false),
        onError: (err) => toast.error(asIpcError(err).message),
      },
    );

  const handleDelete = (f: Finding) => {
    if (!window.confirm(t("findings.deleteConfirm"))) return;
    deleteFinding.mutate(f.id, {
      onError: (err) => toast.error(asIpcError(err).message),
    });
  };

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

      <Card className="mb-8">
        <CardHeader>
          <CardTitle className="text-base">{t("report.details")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <DebouncedField
            label={t("report.execSummary")}
            value={report.exec_summary}
            placeholder={t("report.execSummaryPlaceholder")}
            onCommit={(v) => commit({ exec_summary: v })}
            rows={4}
          />
          <DebouncedField
            label={t("report.scope")}
            value={report.scope}
            placeholder={t("report.scopePlaceholder")}
            onCommit={(v) => commit({ scope: v })}
            rows={3}
          />
          <DebouncedField
            label={t("report.methodology")}
            value={report.methodology}
            placeholder={t("report.methodologyPlaceholder")}
            onCommit={(v) => commit({ methodology: v })}
            rows={3}
          />
        </CardContent>
      </Card>

      <Separator className="my-8" />

      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-xl font-semibold tracking-tight">{t("findings.title")}</h2>
        {sortedFindings.length > 0 && (
          <Button variant="brand" onClick={openCreate}>
            <Plus />
            {t("findings.new")}
          </Button>
        )}
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
              <FindingCard key={f.id} finding={f} onEdit={openEdit} onDelete={handleDelete} />
            ))}
          </AnimatePresence>
        </motion.div>
      )}

      {/* Keyed so the form re-initializes its state per target finding. */}
      <FindingForm
        key={editing?.id ?? "new"}
        open={formOpen}
        onOpenChange={setFormOpen}
        finding={editing}
        onCreate={handleCreate}
        onUpdate={handleUpdate}
        pending={createFinding.isPending || updateFinding.isPending}
      />
    </motion.div>
  );
}
