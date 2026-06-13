import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { NewScopeItem, ScopeItem, ScopeItemPatch } from "@/lib/types";
import { queryKeys } from "./query-keys";

/** List a report's structured scope items, ordered by sort_order. */
export function useScopeItems(reportId: string | undefined) {
  return useQuery({
    queryKey: reportId ? queryKeys.scope(reportId) : ["scope", "_none"],
    queryFn: async () => {
      const items = await ipc.listScopeItems(reportId as string);
      return [...items].sort((a, b) => a.sort_order - b.sort_order);
    },
    enabled: !!reportId,
  });
}

export function useCreateScopeItem(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: NewScopeItem) => ipc.createScopeItem(reportId, input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.scope(reportId) }),
  });
}

export function useUpdateScopeItem(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: ScopeItemPatch }) =>
      ipc.updateScopeItem(id, patch),
    onSuccess: (updated: ScopeItem) => {
      qc.setQueryData<ScopeItem[]>(queryKeys.scope(reportId), (prev) =>
        prev?.map((s) => (s.id === updated.id ? updated : s)),
      );
    },
  });
}

export function useDeleteScopeItem(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => ipc.deleteScopeItem(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.scope(reportId) }),
  });
}

export function useReorderScopeItems(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (orderedIds: string[]) => ipc.reorderScopeItems(reportId, orderedIds),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.scope(reportId) }),
  });
}
