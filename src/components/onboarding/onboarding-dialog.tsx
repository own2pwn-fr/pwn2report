import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { useTranslation } from "react-i18next";
import {
  ArrowLeft,
  ArrowRight,
  Bug,
  Camera,
  FileText,
  Rocket,
  Sparkles,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";

interface Step {
  key: string;
  icon: LucideIcon;
}

const STEPS: Step[] = [
  { key: "welcome", icon: Rocket },
  { key: "reports", icon: FileText },
  { key: "findings", icon: Bug },
  { key: "evidence", icon: Camera },
  { key: "export", icon: FileText },
  { key: "ai", icon: Sparkles },
];

/**
 * Multi-step first-run welcome tour. Shown after the vault is unlocked when the
 * user has not been onboarded yet. Skipping or finishing both call `onDone`.
 */
export function OnboardingDialog({
  open,
  onDone,
}: {
  open: boolean;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [index, setIndex] = useState(0);

  const step = STEPS[index];
  const Icon = step.icon;
  const isLast = index === STEPS.length - 1;
  const isFirst = index === 0;

  const close = () => {
    setIndex(0);
    onDone();
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && close()}>
      <DialogContent className="max-w-md">
        <DialogTitle className="sr-only">{t(`onboarding.steps.${step.key}.title`)}</DialogTitle>
        <DialogDescription className="sr-only">
          {t(`onboarding.steps.${step.key}.body`)}
        </DialogDescription>
        <div className="flex flex-col items-center gap-5 py-2 text-center">
          <AnimatePresence mode="wait">
            <motion.div
              key={step.key}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
              className="flex flex-col items-center gap-4"
            >
              <div
                className="flex size-14 items-center justify-center rounded-2xl"
                style={{ backgroundColor: "hsl(var(--accent-brand) / 0.14)" }}
              >
                <Icon className="size-7 text-[hsl(var(--accent-brand))]" />
              </div>
              <h2 className="text-xl font-bold tracking-tight">
                {t(`onboarding.steps.${step.key}.title`)}
              </h2>
              <p className="text-sm text-muted-foreground">
                {t(`onboarding.steps.${step.key}.body`)}
              </p>
            </motion.div>
          </AnimatePresence>

          {/* Step dots */}
          <div className="flex items-center gap-1.5" aria-hidden>
            {STEPS.map((s, i) => (
              <span
                key={s.key}
                className="size-1.5 rounded-full transition-colors"
                style={{
                  backgroundColor:
                    i === index
                      ? "hsl(var(--accent-brand))"
                      : "hsl(var(--muted-foreground) / 0.3)",
                }}
              />
            ))}
          </div>

          <p className="text-xs text-muted-foreground">
            {t("onboarding.stepCount", { current: index + 1, total: STEPS.length })}
          </p>
        </div>

        <div className="flex items-center justify-between gap-2">
          {isFirst ? (
            <Button variant="ghost" onClick={close}>
              {t("onboarding.skip")}
            </Button>
          ) : (
            <Button variant="ghost" onClick={() => setIndex((i) => i - 1)}>
              <ArrowLeft />
              {t("onboarding.back")}
            </Button>
          )}
          {isLast ? (
            <Button variant="brand" onClick={close}>
              {t("onboarding.done")}
            </Button>
          ) : (
            <Button variant="brand" onClick={() => setIndex((i) => i + 1)}>
              {t("onboarding.next")}
              <ArrowRight />
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
