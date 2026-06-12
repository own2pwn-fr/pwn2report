import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { NewReport, ReportPatch } from "@/lib/types";
import { queryKeys } from "./query-keys";

export function useReports(enabled = true) {
  return useQuery({
    queryKey: queryKeys.reports,
    queryFn: ipc.listReports,
    enabled,
  });
}

export function useReport(id: string | undefined) {
  return useQuery({
    queryKey: id ? queryKeys.report(id) : ["reports", "_none"],
    queryFn: () => ipc.getReport(id as string),
    enabled: !!id,
  });
}

export function useCreateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: NewReport) => ipc.createReport(input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.reports }),
  });
}

export function useUpdateReport(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (patch: ReportPatch) => ipc.updateReport(id, patch),
    onSuccess: (updated) => {
      qc.setQueryData(queryKeys.report(id), updated);
      void qc.invalidateQueries({ queryKey: queryKeys.reports });
    },
  });
}

export function useDeleteReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => ipc.deleteReport(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.reports }),
  });
}
