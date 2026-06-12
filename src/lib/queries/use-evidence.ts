import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { EvidenceImage } from "@/lib/types";
import { queryKeys } from "./query-keys";

/** List the evidence images attached to a finding, ordered by sort_order. */
export function useEvidenceImages(findingId: string | undefined) {
  return useQuery({
    queryKey: findingId ? queryKeys.evidence(findingId) : ["evidence", "_none"],
    queryFn: async () => {
      const images = await ipc.listEvidenceImages(findingId as string);
      return [...images].sort((a, b) => a.sort_order - b.sort_order);
    },
    enabled: !!findingId,
  });
}

/**
 * Fetch the raw bytes of an evidence image, cached by id. The bytes are
 * immutable for a given id, so they never go stale.
 */
export function useEvidenceBytes(id: string) {
  return useQuery({
    queryKey: queryKeys.evidenceBytes(id),
    queryFn: () => ipc.getEvidenceImage(id),
    staleTime: Infinity,
  });
}

export function useAddEvidenceImage(findingId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ caption, mime, data }: { caption: string; mime: string; data: number[] }) =>
      ipc.addEvidenceImage(findingId, caption, mime, data),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.evidence(findingId) }),
  });
}

export function useUpdateEvidenceCaption(findingId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, caption }: { id: string; caption: string }) =>
      ipc.updateEvidenceCaption(id, caption),
    onSuccess: (updated: EvidenceImage) => {
      qc.setQueryData<EvidenceImage[]>(queryKeys.evidence(findingId), (prev) =>
        prev?.map((img) => (img.id === updated.id ? updated : img)),
      );
    },
  });
}

export function useDeleteEvidenceImage(findingId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => ipc.deleteEvidenceImage(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.evidence(findingId) }),
  });
}

export function useReorderEvidenceImages(findingId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (orderedIds: string[]) => ipc.reorderEvidenceImages(findingId, orderedIds),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.evidence(findingId) }),
  });
}
