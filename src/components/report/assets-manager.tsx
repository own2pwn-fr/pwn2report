import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ArrowDown, ArrowUp, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { errorMessage } from "@/lib/ipc";
import {
  useAssets,
  useCreateAsset,
  useDeleteAsset,
  useReorderAssets,
  useUpdateAsset,
} from "@/lib/queries/use-assets";
import { useDebouncedCallback } from "@/lib/use-debounced-callback";
import type { Asset, AssetKind } from "@/lib/types";

const ASSET_KINDS: AssetKind[] = ["host", "ip", "url", "domain", "credential", "other"];

/** A single editable asset row with inline kind/identifier/description + reorder. */
function AssetRow({
  asset,
  reportId,
  isFirst,
  isLast,
  onMove,
  onDelete,
}: {
  asset: Asset;
  reportId: string;
  isFirst: boolean;
  isLast: boolean;
  onMove: (delta: number) => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const update = useUpdateAsset(reportId);

  const [identifier, setIdentifier] = useState(asset.identifier);
  const [description, setDescription] = useState(asset.description);

  const commit = useDebouncedCallback(
    (patch: { identifier?: string; description?: string }) =>
      update.mutate(
        { id: asset.id, patch },
        { onError: (err) => toast.error(errorMessage(err)) },
      ),
    600,
  );

  return (
    <div className="flex flex-wrap items-start gap-2 rounded-md border p-3 sm:flex-nowrap">
      <Select
        value={asset.kind}
        onValueChange={(v) =>
          update.mutate(
            { id: asset.id, patch: { kind: v as AssetKind } },
            { onError: (err) => toast.error(errorMessage(err)) },
          )
        }
      >
        <SelectTrigger className="w-32 shrink-0">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {ASSET_KINDS.map((k) => (
            <SelectItem key={k} value={k}>
              {t(`assets.kind.${k}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Input
        value={identifier}
        placeholder={t("assets.identifierPlaceholder")}
        className="min-w-40 flex-1 font-mono text-xs"
        onChange={(e) => {
          setIdentifier(e.target.value);
          commit({ identifier: e.target.value });
        }}
        aria-label={t("assets.identifier")}
      />
      <Input
        value={description}
        placeholder={t("assets.descriptionPlaceholder")}
        className="min-w-40 flex-1"
        onChange={(e) => {
          setDescription(e.target.value);
          commit({ description: e.target.value });
        }}
        aria-label={t("assets.description")}
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

export function AssetsManager({ reportId }: { reportId: string }) {
  const { t } = useTranslation();
  const { data: assets } = useAssets(reportId);
  const create = useCreateAsset(reportId);
  const remove = useDeleteAsset(reportId);
  const reorder = useReorderAssets(reportId);

  const [pendingDelete, setPendingDelete] = useState<Asset | null>(null);

  const list = assets ?? [];

  const handleAdd = () =>
    create.mutate(
      { kind: "host", identifier: "", description: "" },
      { onError: (err) => toast.error(errorMessage(err)) },
    );

  const move = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= list.length) return;
    const ids = list.map((a) => a.id);
    [ids[index], ids[target]] = [ids[target], ids[index]];
    reorder.mutate(ids, { onError: (err) => toast.error(errorMessage(err)) });
  };

  const confirmDelete = () => {
    const asset = pendingDelete;
    setPendingDelete(null);
    if (!asset) return;
    remove.mutate(asset.id, { onError: (err) => toast.error(errorMessage(err)) });
  };

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">{t("assets.hint")}</p>
      {list.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("assets.empty")}</p>
      ) : (
        <div className="space-y-2">
          {list.map((asset, index) => (
            <AssetRow
              key={asset.id}
              asset={asset}
              reportId={reportId}
              isFirst={index === 0}
              isLast={index === list.length - 1}
              onMove={(delta) => move(index, delta)}
              onDelete={() => setPendingDelete(asset)}
            />
          ))}
        </div>
      )}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={handleAdd}
        disabled={create.isPending}
      >
        <Plus />
        {t("assets.add")}
      </Button>

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t("assets.deleteTitle")}
        description={t("assets.deleteConfirm")}
        itemName={pendingDelete?.identifier || undefined}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
