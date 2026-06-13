import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import type { RetestStatus } from "@/lib/types";

// Color mapping: fixed=green, not_fixed=red, partial=amber, risk_accepted=muted.
const RETEST_CLASS: Record<Exclude<RetestStatus, "not_retested">, string> = {
  fixed: "border-emerald-600/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  partially_fixed: "border-amber-600/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  not_fixed: "border-destructive/30 bg-destructive/10 text-destructive",
  risk_accepted: "border-border bg-muted text-muted-foreground",
};

/** Small badge surfacing a finding's retest outcome. Renders nothing when unset. */
export function RetestBadge({
  status,
  className,
}: {
  status?: RetestStatus | null;
  className?: string;
}) {
  const { t } = useTranslation();
  if (!status || status === "not_retested") return null;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        RETEST_CLASS[status],
        className,
      )}
    >
      {t(`retest.${status}`)}
    </span>
  );
}
