import { useEffect, useRef } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { BookMarked, FileText, Lock, Settings as SettingsIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ThemeToggle } from "@/components/theme-toggle";
import { LanguageToggle } from "@/components/language-toggle";
import { useLockVault } from "@/lib/queries/use-vault";
import { useIdleLock } from "@/lib/use-idle-lock";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { to: "/", icon: FileText, key: "reports.title", end: true },
  { to: "/kb", icon: BookMarked, key: "kb.title", end: false },
  { to: "/settings", icon: SettingsIcon, key: "settings.title", end: false },
] as const;

/**
 * Persistent top bar + animated routed content area shown for all unlocked
 * routes. Owns global navigation, the Lock action, idle auto-lock, and route
 * change focus management (focus moves to <main> so screen-reader / keyboard
 * users land on the new page).
 */
export function AppShell() {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const lockVault = useLockVault();
  const mainRef = useRef<HTMLElement | null>(null);

  const handleLock = () => {
    lockVault.mutate(undefined, {
      onSuccess: () => {
        toast.success(t("vault.locked"));
        navigate("/vault", { replace: true });
      },
    });
  };

  // Auto-lock after inactivity (setting; 0 = off). Active while unlocked.
  useIdleLock(true, handleLock);

  // Move focus to the main region on every route change.
  useEffect(() => {
    mainRef.current?.focus();
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen flex-col">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-popover focus:px-3 focus:py-2 focus:text-sm focus:shadow"
      >
        {t("nav.skipToContent")}
      </a>
      <header className="sticky top-0 z-30 border-b bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-5xl items-center gap-1 px-6">
          <span className="mr-4 select-none text-sm font-semibold tracking-tight">
            {t("app.name")}
          </span>
          <nav aria-label={t("nav.primary")} className="flex items-center gap-1">
            {NAV_ITEMS.map(({ to, icon: Icon, key, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  cn(
                    "inline-flex h-9 items-center gap-2 rounded-md px-3 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-accent text-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground",
                  )
                }
              >
                <Icon className="size-4" />
                <span className="hidden sm:inline">{t(key)}</span>
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-1">
            <ThemeToggle />
            <LanguageToggle />
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={t("vault.lock")}
                  onClick={handleLock}
                >
                  <Lock />
                </Button>
              </TooltipTrigger>
              <TooltipContent>{t("vault.lock")}</TooltipContent>
            </Tooltip>
          </div>
        </div>
      </header>

      <AnimatePresence mode="wait">
        <motion.main
          key={location.pathname}
          id="main-content"
          ref={mainRef}
          tabIndex={-1}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.18, ease: "easeOut" }}
          className="flex-1 outline-none"
        >
          <Outlet />
        </motion.main>
      </AnimatePresence>
    </div>
  );
}
