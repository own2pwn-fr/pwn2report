import { motion } from "motion/react";
import { Copy, Pencil, Trash2, ChevronUp, ChevronDown } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import { RetestBadge } from "@/components/findings/retest-badge";
import { CvssVector } from "@/components/cvss-vector";
import { cn } from "@/lib/utils";
import type { Finding } from "@/lib/types";

export function FindingCard({
  finding,
  onEdit,
  onDuplicate,
  onDelete,
  // Selection (bulk ops). When `selectable`, a checkbox is shown.
  selectable = false,
  selected = false,
  onToggleSelect,
  // Manual reorder controls. When `reorderable`, a drag handle + up/down show.
  reorderable = false,
  onMoveUp,
  onMoveDown,
  canMoveUp = false,
  canMoveDown = false,
}: {
  finding: Finding;
  onEdit: (f: Finding) => void;
  onDuplicate: (f: Finding) => void;
  onDelete: (f: Finding) => void;
  selectable?: boolean;
  selected?: boolean;
  onToggleSelect?: (f: Finding) => void;
  reorderable?: boolean;
  onMoveUp?: (f: Finding) => void;
  onMoveDown?: (f: Finding) => void;
  canMoveUp?: boolean;
  canMoveDown?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.18 }}
    >
      <Card className={cn(selected && "border-[hsl(var(--accent-brand)/0.6)] bg-[hsl(var(--accent-brand)/0.04)]")}>
        <CardContent className="flex gap-3 p-4">
          {(selectable || reorderable) && (
            <div className="flex shrink-0 flex-col items-center gap-1 pt-0.5">
              {selectable && (
                <input
                  type="checkbox"
                  className="size-4 accent-[hsl(var(--accent-brand-solid))]"
                  checked={selected}
                  onChange={() => onToggleSelect?.(finding)}
                  aria-label={t("findings.select.toggle")}
                />
              )}
              {reorderable && (
                <>
                  <button
                    type="button"
                    aria-label={t("findings.order.moveUp")}
                    title={t("findings.order.moveUp")}
                    disabled={!canMoveUp}
                    onClick={() => onMoveUp?.(finding)}
                    className="text-muted-foreground hover:text-foreground disabled:opacity-30"
                  >
                    <ChevronUp className="size-4" />
                  </button>
                  <button
                    type="button"
                    aria-label={t("findings.order.moveDown")}
                    title={t("findings.order.moveDown")}
                    disabled={!canMoveDown}
                    onClick={() => onMoveDown?.(finding)}
                    className="text-muted-foreground hover:text-foreground disabled:opacity-30"
                  >
                    <ChevronDown className="size-4" />
                  </button>
                </>
              )}
            </div>
          )}
          <div className="min-w-0 flex-1 space-y-3">
            <div className="flex items-start justify-between gap-3">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  {finding.cwe && (
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {finding.cwe}
                    </Badge>
                  )}
                  {finding.cve && (
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {finding.cve}
                    </Badge>
                  )}
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    {t(`confidence.${finding.confidence}`)} · {t(`triage.${finding.triage_status}`)}
                  </span>
                  <RetestBadge status={finding.retest_status} />
                </div>
                <h3 className="font-semibold leading-snug">{finding.title}</h3>
              </div>
              <div className="flex shrink-0 gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => onEdit(finding)}
                  title={t("common.edit")}
                  aria-label={t("common.edit")}
                >
                  <Pencil />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => onDuplicate(finding)}
                  title={t("common.duplicate")}
                  aria-label={t("common.duplicate")}
                >
                  <Copy />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => onDelete(finding)}
                  title={t("common.delete")}
                  aria-label={t("common.delete")}
                >
                  <Trash2 />
                </Button>
              </div>
            </div>

            {finding.description.summary && (
              <p className="text-sm text-muted-foreground">{finding.description.summary}</p>
            )}

            {finding.cvss_vector && (
              <div className="rounded-md border bg-muted/30 p-3">
                <CvssVector vector={finding.cvss_vector} score={finding.cvss_score} />
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
