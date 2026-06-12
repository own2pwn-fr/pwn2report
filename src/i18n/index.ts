import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./messages/en.json";
import fr from "./messages/fr.json";

/** Locales the app ships with. Used to validate persisted/detected values. */
export const SUPPORTED_LANGUAGES = ["en", "fr"] as const;
export type Language = (typeof SUPPORTED_LANGUAGES)[number];

const LANG_STORAGE_KEY = "pwn2report.lang";
const DEFAULT_LANGUAGE: Language = "en";

function isLanguage(value: string | null): value is Language {
  return value != null && (SUPPORTED_LANGUAGES as readonly string[]).includes(value);
}

/** Resolve the initial language from localStorage, falling back to the default. */
function detectLanguage(): Language {
  try {
    const saved = localStorage.getItem(LANG_STORAGE_KEY);
    if (isLanguage(saved)) return saved;
  } catch {
    // localStorage may be unavailable (private mode); fall through to default.
  }
  return DEFAULT_LANGUAGE;
}

// All user-facing strings resolve through t(); each locale lives in its own
// messages file with an identical key structure.
void i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    fr: { translation: fr },
  },
  lng: detectLanguage(),
  fallbackLng: DEFAULT_LANGUAGE,
  supportedLngs: SUPPORTED_LANGUAGES,
  interpolation: { escapeValue: false },
  returnNull: false,
});

/** Switch the active language and persist the choice for next launch. */
export function setLanguage(lang: Language): void {
  void i18n.changeLanguage(lang);
  try {
    localStorage.setItem(LANG_STORAGE_KEY, lang);
  } catch {
    // Persisting is best-effort; the in-memory change still applies.
  }
}

export default i18n;
