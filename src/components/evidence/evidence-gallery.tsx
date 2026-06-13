import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ClipboardPaste, ImagePlus, Loader2 } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { readFile } from "@tauri-apps/plugin-fs";
import { Button } from "@/components/ui/button";
import { Annotator } from "@/components/evidence/annotator";
import { EvidenceThumbnail } from "@/components/evidence/evidence-thumbnail";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { errorMessage } from "@/lib/ipc";
import { IMAGE_EXTENSIONS, mimeFromPath, stripImageMetadata } from "@/lib/image";
import {
  useAddEvidenceImage,
  useDeleteEvidenceImage,
  useEvidenceImages,
  useReorderEvidenceImages,
} from "@/lib/queries/use-evidence";
import type { EvidenceImage } from "@/lib/types";

/** Read an image from the clipboard, if any, as raw bytes + mime. */
async function readClipboardImage(): Promise<{ data: number[]; mime: string } | null> {
  if (!navigator.clipboard?.read) return null;
  const items = await navigator.clipboard.read();
  for (const item of items) {
    const type = item.types.find((ty) => ty.startsWith("image/"));
    if (!type) continue;
    const blob = await item.getType(type);
    const buf = await blob.arrayBuffer();
    return { data: Array.from(new Uint8Array(buf)), mime: type };
  }
  return null;
}

export function EvidenceGallery({ findingId }: { findingId: string }) {
  const { t } = useTranslation();
  const { data: images } = useEvidenceImages(findingId);
  const addImage = useAddEvidenceImage(findingId);
  const deleteImage = useDeleteEvidenceImage(findingId);
  const reorder = useReorderEvidenceImages(findingId);

  const [annotating, setAnnotating] = useState<EvidenceImage | null>(null);
  const [pendingDelete, setPendingDelete] = useState<EvidenceImage | null>(null);

  const list = images ?? [];

  const handleAddFromFile = async () => {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{ name: t("evidence.filterImages"), extensions: IMAGE_EXTENSIONS }],
      });
      if (!selected || typeof selected !== "string") return;
      const bytes = await readFile(selected);
      const name = selected.split(/[\\/]/).pop() ?? "";
      // Re-encode through a canvas to strip EXIF/GPS/device metadata before it
      // ever enters the vault.
      const clean = await stripImageMetadata(bytes, mimeFromPath(selected));
      await addImage.mutateAsync({
        caption: name,
        mime: clean.mime,
        data: clean.bytes,
      });
    } catch (err) {
      toast.error(errorMessage(err, "evidence.addError"));
    }
  };

  const handlePaste = async () => {
    try {
      const img = await readClipboardImage();
      if (!img) {
        toast.message(t("evidence.pasteEmpty"));
        return;
      }
      // Clipboard images can also carry metadata — strip it on the way in.
      const clean = await stripImageMetadata(img.data, img.mime);
      await addImage.mutateAsync({ caption: "", mime: clean.mime, data: clean.bytes });
    } catch (err) {
      toast.error(errorMessage(err, "evidence.pasteError"));
    }
  };

  const move = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= list.length) return;
    const ids = list.map((i) => i.id);
    [ids[index], ids[target]] = [ids[target], ids[index]];
    reorder.mutate(ids, {
      onError: (err) => toast.error(errorMessage(err)),
    });
  };

  const confirmDelete = () => {
    const image = pendingDelete;
    setPendingDelete(null);
    if (!image) return;
    deleteImage.mutate(image.id, {
      onError: (err) => toast.error(errorMessage(err, "evidence.deleteError")),
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => void handleAddFromFile()}
          disabled={addImage.isPending}
        >
          {addImage.isPending ? <Loader2 className="animate-spin" /> : <ImagePlus />}
          {addImage.isPending ? t("evidence.adding") : t("evidence.add")}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => void handlePaste()}
          disabled={addImage.isPending}
        >
          <ClipboardPaste />
          {t("evidence.paste")}
        </Button>
        <span className="text-xs text-muted-foreground">{t("evidence.pasteHint")}</span>
      </div>

      {list.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("evidence.empty")}</p>
      ) : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {list.map((image, index) => (
            <EvidenceThumbnail
              key={image.id}
              image={image}
              findingId={findingId}
              isFirst={index === 0}
              isLast={index === list.length - 1}
              onMoveUp={() => move(index, -1)}
              onMoveDown={() => move(index, 1)}
              onDelete={() => setPendingDelete(image)}
              onAnnotate={() => setAnnotating(image)}
            />
          ))}
        </div>
      )}

      {annotating && (
        <Annotator
          open={annotating !== null}
          onOpenChange={(o) => !o && setAnnotating(null)}
          source={annotating}
        />
      )}

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t("evidence.deleteTitle")}
        description={t("evidence.deleteConfirm")}
        itemName={pendingDelete?.caption || undefined}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
