import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import { queryKeys } from "./query-keys";

export function useVaultStatus() {
  return useQuery({
    queryKey: queryKeys.vault,
    queryFn: ipc.vaultStatus,
    staleTime: Infinity,
  });
}

export function useCreateVault() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ passphrase, remember }: { passphrase: string; remember: boolean }) =>
      ipc.createVault(passphrase, remember),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.vault }),
  });
}

export function useUnlockVault() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ passphrase, remember }: { passphrase: string; remember: boolean }) =>
      ipc.unlockVault(passphrase, remember),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.vault }),
  });
}

export function useUnlockWithKeychain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ipc.unlockWithKeychain,
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.vault }),
  });
}

export function useLockVault() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ipc.lockVault,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.vault });
      qc.removeQueries({ queryKey: queryKeys.reports });
    },
  });
}

export function useForgetKeychain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ipc.forgetKeychain,
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.vault }),
  });
}
