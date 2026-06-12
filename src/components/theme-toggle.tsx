import { Moon, Sun } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { useTheme } from "@/lib/use-theme";

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  const { t } = useTranslation();
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={toggleTheme}
      title={theme === "dark" ? t("theme.light") : t("theme.dark")}
      aria-label={t("theme.toggle")}
    >
      {theme === "dark" ? <Sun /> : <Moon />}
    </Button>
  );
}
