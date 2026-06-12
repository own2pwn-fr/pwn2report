import { Languages } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { setLanguage, SUPPORTED_LANGUAGES, type Language } from "@/i18n";

/** Resolve the i18next language down to one of the supported short codes. */
function currentLanguage(raw: string): Language {
  const short = raw.split("-")[0];
  return (SUPPORTED_LANGUAGES as readonly string[]).includes(short)
    ? (short as Language)
    : "en";
}

/**
 * Icon button that cycles between the supported locales (en ⇄ fr) and persists
 * the choice. Shows the active code as a small badge over the icon.
 */
export function LanguageToggle() {
  const { t, i18n } = useTranslation();
  const lang = currentLanguage(i18n.language);

  const next = () => {
    const idx = SUPPORTED_LANGUAGES.indexOf(lang);
    const nextLang = SUPPORTED_LANGUAGES[(idx + 1) % SUPPORTED_LANGUAGES.length];
    setLanguage(nextLang);
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          onClick={next}
          aria-label={t("language.toggle")}
          className="relative"
        >
          <Languages />
          <span className="absolute bottom-1 right-1 text-[9px] font-bold uppercase leading-none">
            {lang}
          </span>
        </Button>
      </TooltipTrigger>
      <TooltipContent>{t("language.toggle")}</TooltipContent>
    </Tooltip>
  );
}
