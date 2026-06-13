import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ChevronDown, Download, FileText, FileCode, FileType, Loader2 } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { writeFile, writeTextFile } from "@tauri-apps/plugin-fs";
import { openPath } from "@tauri-apps/plugin-opener";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { errorMessage, exportDocx, exportHtml, exportMarkdown, exportPdf } from "@/lib/ipc";
import type { Report } from "@/lib/types";

type Format = "pdf" | "docx" | "markdown" | "html";

interface FormatSpec {
  ext: string;
  /** i18n key for the save-dialog filter name. */
  filterNameKey: string;
  binary: boolean;
}

const SPECS: Record<Format, FormatSpec> = {
  pdf: { ext: "pdf", filterNameKey: "export.filter.pdf", binary: true },
  docx: { ext: "docx", filterNameKey: "export.filter.docx", binary: true },
  markdown: { ext: "md", filterNameKey: "export.filter.markdown", binary: false },
  html: { ext: "html", filterNameKey: "export.filter.html", binary: false },
};

/** Lowercase, hyphenated slug for a default export filename. */
function slugify(value: string): string {
  return (
    value
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "report"
  );
}

export function ExportMenu({ report }: { report: Report }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState<Format | null>(null);

  const run = async (format: Format) => {
    const spec = SPECS[format];
    setBusy(format);
    try {
      // Run the backend renderer first so any failure (e.g. missing pandoc for
      // DOCX) surfaces before we bother the user with a save dialog.
      const data = spec.binary
        ? format === "pdf"
          ? await exportPdf(report.id)
          : await exportDocx(report.id)
        : format === "markdown"
          ? await exportMarkdown(report.id)
          : await exportHtml(report.id);

      const filterName = t(spec.filterNameKey);
      const defaultName = `${slugify(report.client)}-${slugify(report.title)}.${spec.ext}`;
      const path = await save({
        defaultPath: defaultName,
        filters: [{ name: filterName, extensions: [spec.ext] }],
      });
      if (!path) {
        toast.message(t("report.exportCancelled"));
        return;
      }

      if (spec.binary) {
        await writeFile(path, new Uint8Array(data as number[]));
      } else {
        await writeTextFile(path, data as string);
      }
      await openPath(path);
      toast.success(t("report.exportSuccessFormat", { format: filterName }));
    } catch (err) {
      toast.error(errorMessage(err, "report.exportError"));
    } finally {
      setBusy(null);
    }
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" disabled={busy !== null}>
          {busy ? <Loader2 className="animate-spin" /> : <Download />}
          {busy ? t("report.exporting") : t("report.export")}
          <ChevronDown className="opacity-60" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>{t("report.exportAs")}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void run("pdf")}>
          <FileType />
          {t("report.formatPdf")}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => void run("docx")}>
          <FileText />
          {t("report.formatDocx")}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => void run("markdown")}>
          <FileCode />
          {t("report.formatMarkdown")}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => void run("html")}>
          <FileCode />
          {t("report.formatHtml")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
