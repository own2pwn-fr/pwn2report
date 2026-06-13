import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ArrowDown, ArrowUp, ImageOff, PenLine, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { errorMessage } from "@/lib/ipc";
import { objectUrlFromBytes } from "@/lib/image";
import {
  useEvidenceBytes,
  useUpdateEvidenceCaption,
} from "@/lib/queries/use-evidence";
import type { EvidenceImage } from "@/lib/types";

export function EvidenceThumbnail({
  image,
  findingId,
  isFirst,
  isLast,
  onMoveUp,
  onMoveDown,
  onDelete,
  onAnnotate,
}: {
  image: EvidenceImage;
  findingId: string;
  isFirst: boolean;
  isLast: boolean;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onDelete: () => void;
  onAnnotate: () => void;
}) {
  const { t } = useTranslation();
  const { data: bytes, isLoading, isError } = useEvidenceBytes(image.id);
  const updateCaption = useUpdateEvidenceCaption(findingId);

  const [url, setUrl] = useState<string | null>(null);
  const [caption, setCaption] = useState(image.caption);

  // Keep the local caption in sync if the server value changes elsewhere.
  useEffect(() => setCaption(image.caption), [image.caption]);

  // Build/revoke the object URL for the thumbnail preview.
  useEffect(() => {
    if (!bytes) return;
    const next = objectUrlFromBytes(bytes, image.mime);
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [bytes, image.mime]);

  const commitCaption = () => {
    const next = caption.trim();
    if (next === image.caption) return;
    updateCaption.mutate(
      { id: image.id, caption: next },
      { onError: (err) => toast.error(errorMessage(err, "evidence.captionError")) },
    );
  };

  return (
    <div className="flex flex-col gap-2 rounded-lg border bg-card p-2">
      <div className="relative aspect-video w-full overflow-hidden rounded-md bg-muted/40">
        {isError ? (
          <div className="flex h-full w-full flex-col items-center justify-center gap-1 text-muted-foreground">
            <ImageOff className="size-6" />
            <span className="text-xs">{t("evidence.loadError")}</span>
          </div>
        ) : url ? (
          <img src={url} alt={caption || ""} className="h-full w-full object-contain" />
        ) : (
          <div className="flex h-full w-full items-center justify-center text-xs text-muted-foreground">
            {isLoading ? t("evidence.loading") : null}
          </div>
        )}
      </div>

      <Input
        value={caption}
        placeholder={t("evidence.captionPlaceholder")}
        onChange={(e) => setCaption(e.target.value)}
        onBlur={commitCaption}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            (e.target as HTMLInputElement).blur();
          }
        }}
        className="text-xs"
      />

      <div className="flex items-center justify-between">
        <div className="flex gap-1">
          <Button
            type="button"
            size="icon"
            variant="ghost"
            onClick={onMoveUp}
            disabled={isFirst}
            title={t("evidence.moveUp")}
            aria-label={t("evidence.moveUp")}
          >
            <ArrowUp />
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            onClick={onMoveDown}
            disabled={isLast}
            title={t("evidence.moveDown")}
            aria-label={t("evidence.moveDown")}
          >
            <ArrowDown />
          </Button>
        </div>
        <div className="flex gap-1">
          <Button
            type="button"
            size="icon"
            variant="ghost"
            onClick={onAnnotate}
            title={t("evidence.annotate")}
            aria-label={t("evidence.annotate")}
          >
            <PenLine />
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            onClick={onDelete}
            title={t("common.delete")}
            aria-label={t("common.delete")}
          >
            <Trash2 />
          </Button>
        </div>
      </div>
    </div>
  );
}
