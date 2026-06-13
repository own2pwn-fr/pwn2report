import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { Asset, AssetPatch, NewAsset } from "@/lib/types";
import { queryKeys } from "./query-keys";

/** List a report's affected assets, ordered by sort_order. */
export function useAssets(reportId: string | undefined) {
  return useQuery({
    queryKey: reportId ? queryKeys.assets(reportId) : ["assets", "_none"],
    queryFn: async () => {
      const assets = await ipc.listAssets(reportId as string);
      return [...assets].sort((a, b) => a.sort_order - b.sort_order);
    },
    enabled: !!reportId,
  });
}

export function useCreateAsset(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: NewAsset) => ipc.createAsset(reportId, input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.assets(reportId) }),
  });
}

export function useUpdateAsset(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: AssetPatch }) =>
      ipc.updateAsset(id, patch),
    onSuccess: (updated: Asset) => {
      qc.setQueryData<Asset[]>(queryKeys.assets(reportId), (prev) =>
        prev?.map((a) => (a.id === updated.id ? updated : a)),
      );
    },
  });
}

export function useDeleteAsset(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => ipc.deleteAsset(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.assets(reportId) }),
  });
}

export function useReorderAssets(reportId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (orderedIds: string[]) => ipc.reorderAssets(reportId, orderedIds),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.assets(reportId) }),
  });
}
