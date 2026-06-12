import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { reportTypeKey } from "@/lib/format";
import type { ReportType } from "@/lib/types";

export function ReportTypeBadge({ type }: { type: ReportType }) {
  const { t } = useTranslation();
  return (
    <Badge variant="secondary" className="font-mono text-[10px] uppercase tracking-wide">
      {t(reportTypeKey(type))}
    </Badge>
  );
}
