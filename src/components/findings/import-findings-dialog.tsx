import { useState } from "react";
import { useTranslation } from "react-i18next";
import { FileUp } from "lucide-react";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { ImportFormat } from "@/lib/types";

const FORMATS: ImportFormat[] = ["sarif", "nuclei", "zap", "burp", "nessus", "secai"];

export function ImportFindingsDialog({
  open,
  onOpenChange,
  onImport,
  pending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onImport: (format: ImportFormat, content: string) => void;
  pending: boolean;
}) {
  const { t } = useTranslation();
  const [format, setFormat] = useState<ImportFormat>("sarif");
  const [fileName, setFileName] = useState<string | null>(null);
  const [content, setContent] = useState<string | null>(null);
  const [reading, setReading] = useState(false);

  const handlePickFile = async () => {
    setReading(true);
    try {
      const selected = await openFileDialog({ multiple: false, directory: false });
      if (typeof selected !== "string") return;
      const text = await readTextFile(selected);
      setContent(text);
      setFileName(selected.split(/[/\\]/).pop() ?? selected);
    } finally {
      setReading(false);
    }
  };

  const handleSubmit = () => {
    if (content == null) return;
    onImport(format, content);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("findings.import.title")}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>{t("findings.import.format")}</Label>
            <Select value={format} onValueChange={(v) => setFormat(v as ImportFormat)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FORMATS.map((f) => (
                  <SelectItem key={f} value={f}>
                    {t(`importFormat.${f}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>{t("findings.import.file")}</Label>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={handlePickFile}
                disabled={reading || pending}
              >
                <FileUp />
                {t("findings.import.chooseFile")}
              </Button>
              <span className="truncate text-sm text-muted-foreground">
                {fileName ?? t("findings.import.noFile")}
              </span>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button
            type="button"
            variant="brand"
            onClick={handleSubmit}
            disabled={pending || reading || content == null}
          >
            {pending ? t("findings.import.importing") : t("findings.import.cta")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
