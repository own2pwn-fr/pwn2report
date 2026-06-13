import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { ArrowLeft, BookMarked, Pencil, Plus, Trash2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState } from "@/components/empty-state";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { KbForm } from "@/components/kb/kb-form";
import {
  useCreateKbEntry,
  useDeleteKbEntry,
  useImportBundledKb,
  useKbEntries,
  useUpdateKbEntry,
} from "@/lib/queries/use-kb";
import { errorMessage } from "@/lib/ipc";
import { SEVERITY_ORDER, severityRank } from "@/lib/format";
import type { KbEntry, KbPatch, NewKbEntry, Severity } from "@/lib/types";

type SeverityFilter = "all" | Severity;

export function KnowledgeBase() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { data: entries, isLoading } = useKbEntries();
  const createEntry = useCreateKbEntry();
  const updateEntry = useUpdateKbEntry();
  const deleteEntry = useDeleteKbEntry();
  const importBundled = useImportBundledKb();

  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<KbEntry | undefined>(undefined);
  const [pendingDelete, setPendingDelete] = useState<KbEntry | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...(entries ?? [])]
      .filter((e) => severityFilter === "all" || e.severity === severityFilter)
      .filter((e) => {
        if (!q) return true;
        return (
          e.title.toLowerCase().includes(q) ||
          e.tags.some((tag) => tag.toLowerCase().includes(q))
        );
      })
      .sort(
        (a, b) =>
          severityRank(a.severity) - severityRank(b.severity) ||
          a.title.localeCompare(b.title),
      );
  }, [entries, query, severityFilter]);

  const openCreate = () => {
    setEditing(undefined);
    setFormOpen(true);
  };

  const openEdit = (e: KbEntry) => {
    setEditing(e);
    setFormOpen(true);
  };

  const handleCreate = (input: NewKbEntry) =>
    createEntry.mutate(input, {
      onSuccess: () => setFormOpen(false),
      onError: (err) => toast.error(errorMessage(err, "kb.createError")),
    });

  const handleUpdate = (id: string, patch: KbPatch) =>
    updateEntry.mutate(
      { id, patch },
      {
        onSuccess: () => setFormOpen(false),
        onError: (err) => toast.error(errorMessage(err)),
      },
    );

  const requestDelete = (e: KbEntry, ev: React.MouseEvent) => {
    ev.stopPropagation();
    setPendingDelete(e);
  };

  const confirmDelete = () => {
    const entry = pendingDelete;
    setPendingDelete(null);
    if (!entry) return;
    deleteEntry.mutate(entry.id, {
      onError: (err) => toast.error(errorMessage(err)),
    });
  };

  const handleImport = () =>
    importBundled.mutate(undefined, {
      onSuccess: (count) => toast.success(t("kb.importSuccess", { count })),
      onError: (err) => toast.error(errorMessage(err, "kb.importError")),
    });

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <div className="mb-6">
        <Button variant="ghost" onClick={() => navigate("/")}>
          <ArrowLeft />
          {t("common.back")}
        </Button>
      </div>

      <header className="mb-8 flex items-start justify-between gap-4">
        <div>
          <h1 className="display-xl">{t("kb.title")}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t("kb.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={handleImport}
            disabled={importBundled.isPending}
          >
            {importBundled.isPending ? t("common.loading") : t("kb.importBundled")}
          </Button>
          <Button variant="brand" onClick={openCreate}>
            <Plus />
            {t("kb.new")}
          </Button>
        </div>
      </header>

      {entries && entries.length > 0 && (
        <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("kb.searchPlaceholder")}
            className="sm:max-w-xs"
          />
          <Select
            value={severityFilter}
            onValueChange={(v) => setSeverityFilter(v as SeverityFilter)}
          >
            <SelectTrigger className="sm:w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t("kb.filterAllSeverities")}</SelectItem>
              {SEVERITY_ORDER.map((s) => (
                <SelectItem key={s} value={s}>
                  {t(`severity.${s}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
      ) : !entries || entries.length === 0 ? (
        <EmptyState
          icon={BookMarked}
          title={t("kb.empty.title")}
          body={t("kb.empty.body")}
          ctaLabel={importBundled.isPending ? t("common.loading") : t("kb.empty.cta")}
          onCta={handleImport}
        />
      ) : filtered.length === 0 ? (
        <p className="py-12 text-center text-sm text-muted-foreground">
          {t("kb.noMatches")}
        </p>
      ) : (
        <motion.div layout className="grid gap-4 sm:grid-cols-2">
          <AnimatePresence>
            {filtered.map((e) => (
              <motion.div
                key={e.id}
                layout
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.97 }}
                transition={{ duration: 0.18 }}
                whileHover={{ y: -2 }}
              >
                <Card
                  className="group cursor-pointer transition-colors hover:border-[hsl(var(--accent-brand)/0.5)]"
                  onClick={() => openEdit(e)}
                >
                  <CardContent className="space-y-3 p-5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={e.severity} />
                        {e.cwe && (
                          <Badge variant="outline" className="font-mono text-[10px]">
                            {e.cwe}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t("common.edit")}
                          aria-label={t("common.edit")}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            openEdit(e);
                          }}
                        >
                          <Pencil />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t("common.delete")}
                          aria-label={t("common.delete")}
                          onClick={(ev) => requestDelete(e, ev)}
                        >
                          <Trash2 />
                        </Button>
                      </div>
                    </div>
                    <h3 className="font-semibold leading-snug">{e.title}</h3>
                    {e.description.summary && (
                      <p className="line-clamp-2 text-sm text-muted-foreground">
                        {e.description.summary}
                      </p>
                    )}
                    {e.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {e.tags.map((tag) => (
                          <Badge key={tag} variant="secondary" className="text-[10px]">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </AnimatePresence>
        </motion.div>
      )}

      {/* Keyed so the form re-initializes its state per target entry. */}
      <KbForm
        key={editing?.id ?? "new"}
        open={formOpen}
        onOpenChange={setFormOpen}
        entry={editing}
        onCreate={handleCreate}
        onUpdate={handleUpdate}
        pending={createEntry.isPending || updateEntry.isPending}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t("kb.deleteTitle")}
        description={t("kb.deleteConfirm")}
        itemName={pendingDelete?.title}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
