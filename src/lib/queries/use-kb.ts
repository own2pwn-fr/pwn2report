import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { KbPatch, NewKbEntry } from "@/lib/types";
import { queryKeys } from "./query-keys";

export function useKbEntries(enabled = true) {
  return useQuery({
    queryKey: queryKeys.kb,
    queryFn: ipc.kbList,
    enabled,
  });
}

export function useKbEntry(id: string | undefined) {
  return useQuery({
    queryKey: id ? queryKeys.kbEntry(id) : ["kb", "_none"],
    queryFn: () => ipc.kbGet(id as string),
    enabled: !!id,
  });
}

export function useCreateKbEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: NewKbEntry) => ipc.kbCreate(input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.kb }),
  });
}

export function useUpdateKbEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: KbPatch }) => ipc.kbUpdate(id, patch),
    onSuccess: (updated) => {
      qc.setQueryData(queryKeys.kbEntry(updated.id), updated);
      void qc.invalidateQueries({ queryKey: queryKeys.kb });
    },
  });
}

export function useDeleteKbEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => ipc.kbDelete(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.kb }),
  });
}

export function useImportBundledKb() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => ipc.kbImportBundled(),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.kb }),
  });
}
