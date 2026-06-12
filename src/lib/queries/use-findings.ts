import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { FindingPatch, NewFinding } from "@/lib/types";
import { queryKeys } from "./query-keys";

export function useFindings(reportId: string | undefined) {
  return useQuery({
    queryKey: reportId ? queryKeys.findings(reportId) : ["findings", "_none"],
    queryFn: () => ipc.listFindings(reportId as string),
    enabled: !!reportId,
  });
}

export function useCreateFinding(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: NewFinding) => ipc.createFinding(reportId, input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.findings(reportId) });
      void qc.invalidateQueries({ queryKey: queryKeys.reports });
    },
  });
}

export function useUpdateFinding(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: FindingPatch }) =>
      ipc.updateFinding(id, patch),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.findings(reportId) }),
  });
}

export function useDeleteFinding(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => ipc.deleteFinding(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.findings(reportId) });
      void qc.invalidateQueries({ queryKey: queryKeys.reports });
    },
  });
}

export function useReorderFindings(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (orderedIds: string[]) => ipc.reorderFindings(reportId, orderedIds),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.findings(reportId) }),
  });
}
