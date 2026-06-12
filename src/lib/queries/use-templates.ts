import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { ReportType } from "@/lib/types";

const templatesKey = ["templates"] as const;
const templateKey = (rt: ReportType) => ["templates", rt] as const;

export function useTemplates() {
  return useQuery({
    queryKey: templatesKey,
    queryFn: ipc.listTemplates,
  });
}

export function useTemplate(reportType: ReportType | undefined) {
  return useQuery({
    queryKey: reportType ? templateKey(reportType) : ["templates", "_none"],
    queryFn: () => ipc.getTemplate(reportType as ReportType),
    enabled: !!reportType,
  });
}

export function useSaveTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ reportType, content }: { reportType: ReportType; content: string }) =>
      ipc.saveTemplate(reportType, content),
    onSuccess: (_data, { reportType }) => {
      void qc.invalidateQueries({ queryKey: templatesKey });
      void qc.invalidateQueries({ queryKey: templateKey(reportType) });
    },
  });
}

export function useResetTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (reportType: ReportType) => ipc.resetTemplate(reportType),
    onSuccess: (_data, reportType) => {
      void qc.invalidateQueries({ queryKey: templatesKey });
      void qc.invalidateQueries({ queryKey: templateKey(reportType) });
    },
  });
}
