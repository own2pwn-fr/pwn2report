import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/lib/ipc";
import type { AiConfig } from "@/lib/types";

const aiConfigKey = ["ai", "config"] as const;

/** Read the persisted AI configuration (without the secret key). */
export function useAiConfig() {
  return useQuery({
    queryKey: aiConfigKey,
    queryFn: ipc.aiGetConfig,
  });
}

/**
 * Convenience selector that resolves to whether AI assistance is enabled.
 * Defaults to `false` while loading so AI affordances stay hidden until proven on.
 */
export function useAiEnabled(): boolean {
  const { data } = useAiConfig();
  return data?.enabled ?? false;
}

export function useSaveAiConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ config, apiKey }: { config: AiConfig; apiKey?: string | null }) =>
      ipc.aiSetConfig(config, apiKey),
    onSuccess: () => void qc.invalidateQueries({ queryKey: aiConfigKey }),
  });
}

export function useTestAiConnection() {
  return useMutation({
    mutationFn: ipc.aiTestConnection,
  });
}
