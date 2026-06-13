import { useState } from "react";
import { useTranslation } from "react-i18next";
import { AnimatePresence, motion } from "motion/react";
import { ChevronDown, FileUp, TriangleAlert } from "lucide-react";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useSubmitShortcut } from "@/lib/use-hotkeys";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { sniffImportFormat } from "@/lib/import-sniff";
import { cn } from "@/lib/utils";
import type { ImportFormat } from "@/lib/types";

// Manual format choices, plus an "auto" sentinel that sniffs the file content.
const FORMATS: ImportFormat[] = [
  "sarif",
  "nuclei",
  "zap",
  "burp",
  "nessus",
  "secai",
  "csv",
];

type FormatChoice = ImportFormat | "auto";

export function ImportFindingsDialog({
  open,
  onOpenChange,
  onImport,
  pending,
  warnings,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onImport: (format: ImportFormat, content: string) => void;
  pending: boolean;
  /** Warnings from the most recent import, rendered inline (not just toasted). */
  warnings: string[];
}) {
  const { t } = useTranslation();
  const [choice, setChoice] = useState<FormatChoice>("auto");
  const [fileName, setFileName] = useState<string | null>(null);
  const [content, setContent] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [warningsOpen, setWarningsOpen] = useState(true);
  // Surfaced when "auto" cannot confidently detect the format.
  const [sniffFailed, setSniffFailed] = useState(false);

  const handlePickFile = async () => {
    setReading(true);
    try {
      const selected = await openFileDialog({ multiple: false, directory: false });
      if (typeof selected !== "string") return;
      const text = await readTextFile(selected);
      setContent(text);
      setFileName(selected.split(/[/\\]/).pop() ?? selected);
      setSniffFailed(false);
    } finally {
      setReading(false);
    }
  };

  const handleSubmit = () => {
    if (content == null) return;
    let format: ImportFormat;
    if (choice === "auto") {
      const detected = sniffImportFormat(content, fileName);
      if (detected == null) {
        // Could not detect — ask the user to pick a concrete format.
        setSniffFailed(true);
        return;
      }
      format = detected;
    } else {
      format = choice;
    }
    setSniffFailed(false);
    onImport(format, content);
  };

  // Cmd/Ctrl+Enter triggers the import once a file is loaded.
  useSubmitShortcut(open, () => {
    if (!pending && !reading && content != null) handleSubmit();
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("findings.import.title")}</DialogTitle>
          <DialogDescription>{t("findings.import.description")}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>{t("findings.import.format")}</Label>
            <Select
              value={choice}
              onValueChange={(v) => {
                setChoice(v as FormatChoice);
                setSniffFailed(false);
              }}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">{t("findings.import.auto")}</SelectItem>
                {FORMATS.map((f) => (
                  <SelectItem key={f} value={f}>
                    {t(`importFormat.${f}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {sniffFailed && (
              <p className="text-sm text-destructive">{t("findings.import.autoFailed")}</p>
            )}
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
          {warnings.length > 0 && (
            <div className="rounded-md border border-border">
              <button
                type="button"
                onClick={() => setWarningsOpen((o) => !o)}
                aria-expanded={warningsOpen}
                className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm font-medium"
              >
                <ChevronDown
                  className={cn(
                    "size-4 text-muted-foreground transition-transform",
                    warningsOpen ? "rotate-0" : "-rotate-90",
                  )}
                />
                <TriangleAlert className="size-4 text-amber-500" />
                <span>{t("findings.import.warningsTitle", { count: warnings.length })}</span>
              </button>
              <AnimatePresence initial={false}>
                {warningsOpen && (
                  <motion.div
                    key="warnings"
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <ul className="list-disc space-y-1 pb-3 pl-9 pr-4 text-sm text-muted-foreground">
                      {warnings.map((w, i) => (
                        <li key={i}>{w}</li>
                      ))}
                    </ul>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}
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
