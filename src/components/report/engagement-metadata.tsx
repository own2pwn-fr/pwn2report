import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Check, Loader2, Plus, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useDebouncedCallback } from "@/lib/use-debounced-callback";
import type { Report, ReportPatch } from "@/lib/types";

/** Subtle "Saving…/Saved" status, shown only after the user has edited. */
function SaveStatus({
  status,
}: {
  status: "idle" | "saving" | "saved";
}) {
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

/** A debounced single-line input committing one report field on change. */
function DebouncedInput({
  label,
  value,
  placeholder,
  type = "text",
  onCommit,
  isPending,
  isSuccess,
}: {
  label: string;
  value: string;
  placeholder?: string;
  type?: "text" | "date";
  onCommit: (value: string) => void;
  isPending: boolean;
  isSuccess: boolean;
}) {
  const [local, setLocal] = useState(value);
  const [touched, setTouched] = useState(false);
  useEffect(() => setLocal(value), [value]);
  const debounced = useDebouncedCallback((v: string) => onCommit(v), 600);

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
        <SaveStatus status={status} />
      </div>
      <Input
        type={type}
        value={local}
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

/** A stable id for author rows so reorders/removals keep focus correct. */
function newRowId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `row-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

interface AuthorRow {
  id: string;
  value: string;
}

/** Add/remove editor for the report's authors (string[]), committed on change. */
function AuthorsEditor({
  authors,
  onCommit,
}: {
  authors: string[];
  onCommit: (next: string[]) => void;
}) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<AuthorRow[]>(() =>
    authors.map((value) => ({ id: newRowId(), value })),
  );

  // Reconcile when authors change from outside (e.g. switching reports).
  useEffect(() => {
    setRows((prev) => {
      const sameLength = prev.length === authors.length;
      const sameValues = sameLength && prev.every((r, i) => r.value === authors[i]);
      if (sameValues) return prev;
      return authors.map((value, i) => ({ id: prev[i]?.id ?? newRowId(), value }));
    });
  }, [authors]);

  const commit = (next: AuthorRow[]) => {
    setRows(next);
    onCommit(next.map((r) => r.value).filter((v) => v.trim().length > 0));
  };

  const update = (id: string, value: string) =>
    commit(rows.map((r) => (r.id === id ? { ...r, value } : r)));
  const remove = (id: string) => commit(rows.filter((r) => r.id !== id));
  const add = () => setRows((prev) => [...prev, { id: newRowId(), value: "" }]);

  return (
    <div className="space-y-1.5">
      <Label>{t("engagement.authors")}</Label>
      <div className="space-y-2">
        <AnimatePresence initial={false}>
          {rows.map((row) => (
            <motion.div
              key={row.id}
              layout
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, x: -8 }}
              transition={{ duration: 0.15 }}
              className="flex items-center gap-2"
            >
              <Input
                value={row.value}
                placeholder={t("engagement.authorPlaceholder")}
                onChange={(e) => update(row.id, e.target.value)}
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                onClick={() => remove(row.id)}
                aria-label={t("common.delete")}
              >
                <X />
              </Button>
            </motion.div>
          ))}
        </AnimatePresence>
        <Button type="button" variant="outline" size="sm" onClick={add}>
          <Plus />
          {t("engagement.addAuthor")}
        </Button>
      </div>
    </div>
  );
}

export function EngagementMetadata({
  report,
  onCommit,
  isPending,
  isSuccess,
}: {
  report: Report;
  onCommit: (patch: ReportPatch) => void;
  isPending: boolean;
  isSuccess: boolean;
}) {
  const { t } = useTranslation();

  return (
    <div className="space-y-5">
      <AuthorsEditor
        authors={report.authors ?? []}
        onCommit={(authors) => onCommit({ authors })}
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <DebouncedInput
          label={t("engagement.reviewer")}
          value={report.reviewer ?? ""}
          placeholder={t("engagement.reviewerPlaceholder")}
          onCommit={(v) => onCommit({ reviewer: v })}
          isPending={isPending}
          isSuccess={isSuccess}
        />
        <DebouncedInput
          label={t("engagement.ref")}
          value={report.engagement_ref ?? ""}
          placeholder={t("engagement.refPlaceholder")}
          onCommit={(v) => onCommit({ engagement_ref: v })}
          isPending={isPending}
          isSuccess={isSuccess}
        />
        <DebouncedInput
          label={t("engagement.start")}
          value={report.engagement_start ?? ""}
          type="date"
          onCommit={(v) => onCommit({ engagement_start: v })}
          isPending={isPending}
          isSuccess={isSuccess}
        />
        <DebouncedInput
          label={t("engagement.end")}
          value={report.engagement_end ?? ""}
          type="date"
          onCommit={(v) => onCommit({ engagement_end: v })}
          isPending={isPending}
          isSuccess={isSuccess}
        />
        <DebouncedInput
          label={t("engagement.confidentiality")}
          value={report.confidentiality ?? ""}
          placeholder={t("engagement.confidentialityPlaceholder")}
          onCommit={(v) => onCommit({ confidentiality: v })}
          isPending={isPending}
          isSuccess={isSuccess}
        />
      </div>
    </div>
  );
}
