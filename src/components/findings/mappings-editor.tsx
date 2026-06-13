import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Plus, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { Mapping } from "@/lib/types";

/** Supported compliance frameworks (keys map to `mappingFramework.*` i18n keys). */
export const MAPPING_FRAMEWORKS = [
  "owasp_top10",
  "owasp_asvs",
  "mitre_attack",
  "pci_dss",
  "nist",
  "cwe",
  "custom",
] as const;

interface MappingRow extends Mapping {
  rowId: string;
}

function newRowId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `map-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

function toRows(mappings: Mapping[]): MappingRow[] {
  return mappings.map((m) => ({ rowId: newRowId(), ...m }));
}

/** Strip the local rowId; keep only rows with both a framework and an id. */
function toMappings(rows: MappingRow[]): Mapping[] {
  return rows
    .map(({ rowId: _rowId, ...m }) => m)
    .filter((m) => m.framework.trim() && m.id.trim())
    .map((m) => ({
      framework: m.framework.trim(),
      id: m.id.trim(),
      name: m.name?.trim() ? m.name.trim() : null,
    }));
}

/** Add/remove editor for compliance framework mappings on a finding. */
export function MappingsEditor({
  value,
  onChange,
}: {
  value: Mapping[];
  onChange: (next: Mapping[]) => void;
}) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<MappingRow[]>(() => toRows(value));

  // Reconcile when the external value changes (draft restore / switch finding).
  useEffect(() => {
    setRows((prev) => {
      const current = toMappings(prev);
      const same =
        current.length === value.length &&
        current.every(
          (m, i) =>
            m.framework === value[i]?.framework &&
            m.id === value[i]?.id &&
            (m.name ?? null) === (value[i]?.name ?? null),
        );
      if (same) return prev;
      return toRows(value);
    });
  }, [value]);

  const commit = (next: MappingRow[]) => {
    setRows(next);
    onChange(toMappings(next));
  };

  const patch = (rowId: string, fields: Partial<Mapping>) =>
    commit(rows.map((r) => (r.rowId === rowId ? { ...r, ...fields } : r)));
  const remove = (rowId: string) => commit(rows.filter((r) => r.rowId !== rowId));
  const add = () =>
    commit([...rows, { rowId: newRowId(), framework: "owasp_top10", id: "", name: null }]);

  return (
    <div className="space-y-2">
      <AnimatePresence initial={false}>
        {rows.map((row) => (
          <motion.div
            key={row.rowId}
            layout
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, x: -8 }}
            transition={{ duration: 0.15 }}
            className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_auto] items-center gap-2"
          >
            <Select
              value={row.framework}
              onValueChange={(v) => patch(row.rowId, { framework: v })}
            >
              <SelectTrigger aria-label={t("mappings.framework")}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {MAPPING_FRAMEWORKS.map((f) => (
                  <SelectItem key={f} value={f}>
                    {t(`mappingFramework.${f}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              value={row.id}
              placeholder={t("mappings.idPlaceholder")}
              onChange={(e) => patch(row.rowId, { id: e.target.value })}
              aria-label={t("mappings.id")}
              className="font-mono text-xs"
            />
            <Input
              value={row.name ?? ""}
              placeholder={t("mappings.namePlaceholder")}
              onChange={(e) => patch(row.rowId, { name: e.target.value })}
              aria-label={t("mappings.name")}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={() => remove(row.rowId)}
              aria-label={t("common.delete")}
            >
              <X />
            </Button>
          </motion.div>
        ))}
      </AnimatePresence>
      <Button type="button" variant="outline" size="sm" onClick={add}>
        <Plus />
        {t("mappings.addRow")}
      </Button>
    </div>
  );
}
