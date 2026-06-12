import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./messages/en.json";

// Single-locale setup for now ("en"). All user-facing strings resolve through
// t() so adding locales later is a matter of dropping in another messages file.
void i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
  },
  lng: "en",
  fallbackLng: "en",
  interpolation: { escapeValue: false },
  returnNull: false,
});

export default i18n;
