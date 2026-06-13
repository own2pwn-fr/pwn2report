import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/severity-badge";
import { useKbEntries } from "@/lib/queries/use-kb";
import { severityRank } from "@/lib/format";

export function KbPicker({
  open,
  onOpenChange,
  onPick,
  pending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onPick: (kbId: string) => void;
  pending: boolean;
}) {
  const { t } = useTranslation();
  // Only fetch the catalog while the picker is open.
  const { data: entries, isLoading } = useKbEntries(open);
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...(entries ?? [])]
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
  }, [entries, query]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-hidden">
        <DialogHeader>
          <DialogTitle>{t("findings.kbPicker.title")}</DialogTitle>
          <DialogDescription>{t("kb.subtitle")}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("kb.searchPlaceholder")}
          />
          <div className="max-h-[55vh] space-y-2 overflow-y-auto pr-1">
            {isLoading ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                {t("common.loading")}
              </p>
            ) : filtered.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                {entries && entries.length === 0
                  ? t("findings.kbPicker.empty")
                  : t("kb.noMatches")}
              </p>
            ) : (
              filtered.map((e) => (
                <button
                  key={e.id}
                  type="button"
                  disabled={pending}
                  onClick={() => onPick(e.id)}
                  className="flex w-full flex-col gap-1.5 rounded-lg border p-3 text-left transition-colors hover:border-[hsl(var(--accent-brand)/0.5)] hover:bg-muted/50 disabled:opacity-50"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={e.severity} />
                    {e.cwe && (
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {e.cwe}
                      </Badge>
                    )}
                    <span className="font-medium">{e.title}</span>
                  </div>
                  {e.description.summary && (
                    <p className="line-clamp-2 text-sm text-muted-foreground">
                      {e.description.summary}
                    </p>
                  )}
                </button>
              ))
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
