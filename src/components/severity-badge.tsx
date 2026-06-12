import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { severityKey } from "@/lib/format";
import type { Severity } from "@/lib/types";

const SEV_CLASS: Record<Severity, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wide",
        SEV_CLASS[severity],
        className,
      )}
    >
      {t(severityKey(severity))}
    </span>
  );
}
