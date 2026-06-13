import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ImagePlus, Loader2, Trash2 } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { readFile } from "@tauri-apps/plugin-fs";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { errorMessage } from "@/lib/ipc";
import {
  IMAGE_EXTENSIONS,
  mimeFromPath,
  objectUrlFromBytes,
  stripImageMetadata,
} from "@/lib/image";
import {
  useClearReportLogo,
  useReportLogo,
  useSetReportLogo,
} from "@/lib/queries/use-report-logo";

export function LogoBranding({
  reportId,
  hasLogo,
}: {
  reportId: string;
  hasLogo: boolean;
}) {
  const { t } = useTranslation();
  const { data: bytes } = useReportLogo(reportId, hasLogo);
  const setLogo = useSetReportLogo(reportId);
  const clearLogo = useClearReportLogo(reportId);

  const [confirmClear, setConfirmClear] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);

  // Build (and revoke) an object URL for the logo preview. PNG keeps any
  // transparency; we infer the blob type from the stored bytes' likely format
  // by reusing PNG as a safe default for the <img> blob.
  useEffect(() => {
    if (!bytes || bytes.length === 0) {
      setPreviewUrl(null);
      return;
    }
    const url = objectUrlFromBytes(bytes, "image/png");
    setPreviewUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [bytes]);

  const handlePick = async () => {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{ name: t("branding.filterImages"), extensions: IMAGE_EXTENSIONS }],
      });
      if (!selected || typeof selected !== "string") return;
      const raw = await readFile(selected);
      // Strip any embedded metadata before the logo enters the vault.
      const clean = await stripImageMetadata(raw, mimeFromPath(selected));
      await setLogo.mutateAsync({ mime: clean.mime, data: clean.bytes });
      toast.success(t("branding.uploaded"));
    } catch (err) {
      toast.error(errorMessage(err, "branding.uploadError"));
    }
  };

  const confirmClearLogo = () => {
    setConfirmClear(false);
    clearLogo.mutate(undefined, {
      onError: (err) => toast.error(errorMessage(err, "branding.clearError")),
    });
  };

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">{t("branding.hint")}</p>
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex size-24 items-center justify-center overflow-hidden rounded-md border bg-muted/40">
          {previewUrl ? (
            <img
              src={previewUrl}
              alt={t("branding.previewAlt")}
              className="max-h-full max-w-full object-contain"
            />
          ) : (
            <ImagePlus className="size-6 text-muted-foreground" />
          )}
        </div>
        <div className="flex flex-col gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void handlePick()}
            disabled={setLogo.isPending}
          >
            {setLogo.isPending ? <Loader2 className="animate-spin" /> : <ImagePlus />}
            {hasLogo ? t("branding.replace") : t("branding.upload")}
          </Button>
          {hasLogo && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setConfirmClear(true)}
              disabled={clearLogo.isPending}
            >
              <Trash2 />
              {t("branding.clear")}
            </Button>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={confirmClear}
        onOpenChange={setConfirmClear}
        title={t("branding.clearTitle")}
        description={t("branding.clearConfirm")}
        onConfirm={confirmClearLogo}
      />
    </div>
  );
}
