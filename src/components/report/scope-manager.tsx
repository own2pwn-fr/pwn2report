import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ArrowDown, ArrowUp, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { errorMessage } from "@/lib/ipc";
import {
  useCreateScopeItem,
  useDeleteScopeItem,
  useReorderScopeItems,
  useScopeItems,
  useUpdateScopeItem,
} from "@/lib/queries/use-scope";
import { useDebouncedCallback } from "@/lib/use-debounced-callback";
import type { ScopeItem } from "@/lib/types";

/** A single editable scope row: in-scope toggle + kind + value + note + reorder. */
function ScopeRow({
  item,
  reportId,
  isFirst,
  isLast,
  onMove,
  onDelete,
}: {
  item: ScopeItem;
  reportId: string;
  isFirst: boolean;
  isLast: boolean;
  onMove: (delta: number) => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const update = useUpdateScopeItem(reportId);

  const [kind, setKind] = useState(item.kind);
  const [value, setValue] = useState(item.value);
  const [note, setNote] = useState(item.note);

  const commit = useDebouncedCallback(
    (patch: { kind?: string; value?: string; note?: string }) =>
      update.mutate(
        { id: item.id, patch },
        { onError: (err) => toast.error(errorMessage(err)) },
      ),
    600,
  );

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border p-3 sm:flex-nowrap">
      <div className="flex shrink-0 items-center gap-2">
        <Switch
          checked={item.in_scope}
          onCheckedChange={(checked) =>
            update.mutate(
              { id: item.id, patch: { in_scope: checked } },
              { onError: (err) => toast.error(errorMessage(err)) },
            )
          }
          aria-label={t("scope.inScope")}
        />
        <span className="w-20 text-xs text-muted-foreground">
          {item.in_scope ? t("scope.inScope") : t("scope.outOfScope")}
        </span>
      </div>
      <Input
        value={kind}
        placeholder={t("scope.kindPlaceholder")}
        className="w-32 shrink-0"
        onChange={(e) => {
          setKind(e.target.value);
          commit({ kind: e.target.value });
        }}
        aria-label={t("scope.kind")}
      />
      <Input
        value={value}
        placeholder={t("scope.valuePlaceholder")}
        className="min-w-40 flex-1 font-mono text-xs"
        onChange={(e) => {
          setValue(e.target.value);
          commit({ value: e.target.value });
        }}
        aria-label={t("scope.value")}
      />
      <Input
        value={note}
        placeholder={t("scope.notePlaceholder")}
        className="min-w-40 flex-1"
        onChange={(e) => {
          setNote(e.target.value);
          commit({ note: e.target.value });
        }}
        aria-label={t("scope.note")}
      />
      <div className="flex shrink-0 items-center">
        <Button
          type="button"
          variant="ghost"
          size="icon"
          disabled={isFirst}
          onClick={() => onMove(-1)}
          aria-label={t("common.moveUp")}
        >
          <ArrowUp />
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          disabled={isLast}
          onClick={() => onMove(1)}
          aria-label={t("common.moveDown")}
        >
          <ArrowDown />
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={onDelete}
          aria-label={t("common.delete")}
        >
          <X />
        </Button>
      </div>
    </div>
  );
}

export function ScopeManager({ reportId }: { reportId: string }) {
  const { t } = useTranslation();
  const { data: items } = useScopeItems(reportId);
  const create = useCreateScopeItem(reportId);
  const remove = useDeleteScopeItem(reportId);
  const reorder = useReorderScopeItems(reportId);

  const [pendingDelete, setPendingDelete] = useState<ScopeItem | null>(null);

  const list = items ?? [];

  const handleAdd = (inScope: boolean) =>
    create.mutate(
      { kind: "", value: "", in_scope: inScope, note: "" },
      { onError: (err) => toast.error(errorMessage(err)) },
    );

  const move = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= list.length) return;
    const ids = list.map((s) => s.id);
    [ids[index], ids[target]] = [ids[target], ids[index]];
    reorder.mutate(ids, { onError: (err) => toast.error(errorMessage(err)) });
  };

  const confirmDelete = () => {
    const item = pendingDelete;
    setPendingDelete(null);
    if (!item) return;
    remove.mutate(item.id, { onError: (err) => toast.error(errorMessage(err)) });
  };

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">{t("scope.hint")}</p>
      {list.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("scope.empty")}</p>
      ) : (
        <div className="space-y-2">
          {list.map((item, index) => (
            <ScopeRow
              key={item.id}
              item={item}
              reportId={reportId}
              isFirst={index === 0}
              isLast={index === list.length - 1}
              onMove={(delta) => move(index, delta)}
              onDelete={() => setPendingDelete(item)}
            />
          ))}
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => handleAdd(true)}
          disabled={create.isPending}
        >
          <Plus />
          {t("scope.addInScope")}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => handleAdd(false)}
          disabled={create.isPending}
        >
          <Plus />
          {t("scope.addOutOfScope")}
        </Button>
      </div>

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t("scope.deleteTitle")}
        description={t("scope.deleteConfirm")}
        itemName={pendingDelete?.value || undefined}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
