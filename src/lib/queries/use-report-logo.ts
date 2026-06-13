import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import { queryKeys } from "./query-keys";

/**
 * Fetch a report's branding logo bytes. Returns `null` when no logo is set
 * (the caller passes `hasLogo` so we don't query for nothing).
 */
export function useReportLogo(reportId: string | undefined, hasLogo: boolean) {
  return useQuery({
    queryKey: reportId ? queryKeys.reportLogo(reportId) : ["report-logo", "_none"],
    queryFn: () => ipc.getReportLogo(reportId as string),
    enabled: !!reportId && hasLogo,
  });
}

export function useSetReportLogo(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ mime, data }: { mime: string; data: number[] }) =>
      ipc.setReportLogo(reportId, mime, data),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.reportLogo(reportId) });
      void qc.invalidateQueries({ queryKey: queryKeys.report(reportId) });
    },
  });
}

export function useClearReportLogo(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => ipc.clearReportLogo(reportId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.reportLogo(reportId) });
      void qc.invalidateQueries({ queryKey: queryKeys.report(reportId) });
    },
  });
}
