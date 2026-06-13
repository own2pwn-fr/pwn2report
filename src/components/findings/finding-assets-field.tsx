import { useTranslation } from "react-i18next";
import { Check, ChevronsUpDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useAssets } from "@/lib/queries/use-assets";
import { cn } from "@/lib/utils";

/**
 * Multi-select of a report's affected assets, used in the finding form to mark
 * which assets a finding affects. Controlled: the parent owns the selected
 * asset-id set and persists it on save via `set_finding_assets`.
 */
export function FindingAssetsField({
  reportId,
  selected,
  onChange,
}: {
  reportId: string;
  selected: string[];
  onChange: (assetIds: string[]) => void;
}) {
  const { t } = useTranslation();
  const { data: assets } = useAssets(reportId);
  const list = assets ?? [];

  const toggle = (id: string) =>
    onChange(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);

  const selectedAssets = list.filter((a) => selected.includes(a.id));

  return (
    <div className="space-y-1.5">
      <Label>{t("findings.affectedAssets")}</Label>
      {list.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("findings.affectedAssetsEmpty")}</p>
      ) : (
        <Popover>
          <PopoverTrigger asChild>
            <Button
              type="button"
              variant="outline"
              className="w-full justify-between font-normal"
            >
              <span className="truncate text-muted-foreground">
                {selected.length === 0
                  ? t("findings.affectedAssetsPlaceholder")
                  : t("findings.affectedAssetsCount", { count: selected.length })}
              </span>
              <ChevronsUpDown className="size-4 shrink-0 opacity-50" />
            </Button>
          </PopoverTrigger>
          <PopoverContent align="start" className="max-h-72 w-80 overflow-y-auto p-1">
            {list.map((asset) => {
              const isSelected = selected.includes(asset.id);
              const label = asset.identifier || t(`assets.kind.${asset.kind}`);
              return (
                <button
                  key={asset.id}
                  type="button"
                  onClick={() => toggle(asset.id)}
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm hover:bg-accent hover:text-accent-foreground"
                >
                  <Check
                    className={cn("size-4 shrink-0", isSelected ? "opacity-100" : "opacity-0")}
                  />
                  <span className="font-mono text-xs">{label}</span>
                  <span className="ml-auto shrink-0 text-xs text-muted-foreground">
                    {t(`assets.kind.${asset.kind}`)}
                  </span>
                </button>
              );
            })}
          </PopoverContent>
        </Popover>
      )}
      {selectedAssets.length > 0 && (
        <div className="flex flex-wrap gap-1.5 pt-1">
          {selectedAssets.map((asset) => (
            <Badge key={asset.id} variant="secondary">
              {asset.identifier || t(`assets.kind.${asset.kind}`)}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}
