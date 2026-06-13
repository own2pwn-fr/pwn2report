import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Plus, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/** A single editable pair with a stable id so reorder/delete keeps focus right. */
interface PairRow {
  id: string;
  key: string;
  value: string;
}

function newRowId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `kv-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

/** Serialize rows into a Record, dropping rows with an empty/duplicate key. */
function rowsToRecord(rows: PairRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) {
    const k = r.key.trim();
    if (k) out[k] = r.value;
  }
  return out;
}

function recordToRows(record: Record<string, string>): PairRow[] {
  return Object.entries(record).map(([key, value]) => ({ id: newRowId(), key, value }));
}

/**
 * Reusable add/remove editor for `Record<string, string>` custom-field maps.
 *
 * Mirrors the finding form's `ListEditor`: rows carry stable generated ids so
 * editing/removing a middle row doesn't mis-focus the rest. The parent owns a
 * plain record; we reconcile against it when it changes from outside.
 */
export function KeyValueEditor({
  label,
  value,
  onChange,
}: {
  label?: string;
  value: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
}) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<PairRow[]>(() => recordToRows(value));

  // Reconcile when the external record changes (e.g. switching report/finding).
  useEffect(() => {
    setRows((prev) => {
      const current = rowsToRecord(prev);
      const same =
        Object.keys(current).length === Object.keys(value).length &&
        Object.entries(value).every(([k, v]) => current[k] === v);
      if (same) return prev;
      return recordToRows(value);
    });
  }, [value]);

  const commit = (next: PairRow[]) => {
    setRows(next);
    onChange(rowsToRecord(next));
  };

  const updateKey = (id: string, key: string) =>
    commit(rows.map((r) => (r.id === id ? { ...r, key } : r)));
  const updateValue = (id: string, val: string) =>
    commit(rows.map((r) => (r.id === id ? { ...r, value: val } : r)));
  const remove = (id: string) => commit(rows.filter((r) => r.id !== id));
  const add = () => commit([...rows, { id: newRowId(), key: "", value: "" }]);

  return (
    <div className="space-y-1.5">
      {label && <Label>{label}</Label>}
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
                value={row.key}
                placeholder={t("customFields.keyPlaceholder")}
                onChange={(e) => updateKey(row.id, e.target.value)}
                aria-label={t("customFields.key")}
                className="max-w-[40%]"
              />
              <Input
                value={row.value}
                placeholder={t("customFields.valuePlaceholder")}
                onChange={(e) => updateValue(row.id, e.target.value)}
                aria-label={t("customFields.value")}
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
          {t("customFields.addRow")}
        </Button>
      </div>
    </div>
  );
}
