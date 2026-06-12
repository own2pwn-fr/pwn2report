import { useMutation, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { SyncSummary } from "@/lib/types";
import { queryKeys } from "./query-keys";

/** Export an end-to-end encrypted sync bundle to a chosen file path. */
export function useExportSyncBundle() {
  return useMutation({
    mutationFn: ({ passphrase, destPath }: { passphrase: string; destPath: string }) =>
      ipc.exportSyncBundle(passphrase, destPath),
  });
}

/**
 * Import (decrypt + merge) a sync bundle. On success the reports and knowledge
 * base caches are invalidated so the UI reflects the merged data immediately.
 */
export function useImportSyncBundle() {
  const qc = useQueryClient();
  return useMutation<SyncSummary, unknown, { passphrase: string; srcPath: string }>({
    mutationFn: ({ passphrase, srcPath }) => ipc.importSyncBundle(passphrase, srcPath),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.reports });
      void qc.invalidateQueries({ queryKey: queryKeys.kb });
    },
  });
}
