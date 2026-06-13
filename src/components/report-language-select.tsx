import { useTranslation } from "react-i18next";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SUPPORTED_LANGUAGES } from "@/i18n";

// Language autonyms (each name written in its own language), shown so the choice
// is recognizable regardless of the active UI language.
const LANGUAGE_AUTONYMS: Record<string, string> = {
  en: "English",
  fr: "Français",
};

/** Resolve a stored report language to a known short code, defaulting to "en". */
function normalize(value: string): string {
  const short = value.split("-")[0];
  return (SUPPORTED_LANGUAGES as readonly string[]).includes(short) ? short : "en";
}

/**
 * Selector for a report's *delivery* language — the language of the exported
 * report's structure (section titles etc.), independent of the app UI language.
 *
 * Renders a labeled <Select> with optional explanatory hint.
 */
export function ReportLanguageSelect({
  value,
  onChange,
  showHint = true,
  className,
}: {
  value: string;
  onChange: (lang: string) => void;
  /** Show the "controls the exported report" explanatory hint below the select. */
  showHint?: boolean;
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <div className={className}>
      <Label>{t("report.language.label")}</Label>
      <Select value={normalize(value)} onValueChange={onChange}>
        <SelectTrigger className="mt-1.5">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {SUPPORTED_LANGUAGES.map((lang) => (
            <SelectItem key={lang} value={lang}>
              {LANGUAGE_AUTONYMS[lang] ?? lang}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {showHint && (
        <p className="mt-1.5 text-xs text-muted-foreground">{t("report.language.hint")}</p>
      )}
    </div>
  );
}
