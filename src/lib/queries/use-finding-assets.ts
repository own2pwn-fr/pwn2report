import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import { queryKeys } from "./query-keys";

/** List the assets a finding is marked as affecting. */
export function useFindingAssets(findingId: string | undefined) {
  return useQuery({
    queryKey: findingId ? queryKeys.findingAssets(findingId) : ["finding-assets", "_none"],
    queryFn: () => ipc.listFindingAssets(findingId as string),
    enabled: !!findingId,
  });
}

/** Replace the full set of assets a finding affects. */
export function useSetFindingAssets() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ findingId, assetIds }: { findingId: string; assetIds: string[] }) =>
      ipc.setFindingAssets(findingId, assetIds),
    onSuccess: (_data, { findingId }) =>
      void qc.invalidateQueries({ queryKey: queryKeys.findingAssets(findingId) }),
  });
}
