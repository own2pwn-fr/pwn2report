import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Loader2, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { aiComplete, asIpcError } from "@/lib/ipc";
import { useAiEnabled } from "@/lib/queries/use-ai";

/** The set of rewrite tasks the assist button offers. */
export type AiTask = "improve" | "generate" | "summarize" | "toFrench" | "toEnglish";

const SYSTEM_PROMPT =
  "You are a senior penetration tester writing a professional client report. " +
  "Return only the rewritten text, with no preamble, no explanation and no surrounding quotes or markdown fences.";

/**
 * Build the user prompt for a given task. `label` is the human-readable name of
 * the field (already localized) so the model knows what it is writing.
 */
function buildPrompt(task: AiTask, label: string, text: string): string {
  const trimmed = text.trim();
  switch (task) {
    case "improve":
      return `Rewrite and improve the following "${label}" section of a penetration test report. Keep the same language, meaning and any technical details, but make it clearer, more precise and more professional.\n\n${trimmed}`;
    case "generate":
      return `Write a concise, professional "${label}" section for a penetration test finding based on the following notes. Expand them into well-formed prose.\n\n${trimmed || "(no notes provided)"}`;
    case "summarize":
      return `Summarize the following "${label}" section of a penetration test report into a concise paragraph, preserving the key technical points.\n\n${trimmed}`;
    case "toFrench":
      return `Translate the following "${label}" section of a penetration test report into professional French. Preserve technical terms and meaning.\n\n${trimmed}`;
    case "toEnglish":
      return `Translate the following "${label}" section of a penetration test report into professional English. Preserve technical terms and meaning.\n\n${trimmed}`;
  }
}

const ALL_TASKS: AiTask[] = ["improve", "generate", "summarize", "toFrench", "toEnglish"];

/**
 * A small ✨ button that runs an AI rewrite task against the current field text
 * and replaces it with the result. Renders nothing when AI assistance is off.
 */
export function AiAssistButton({
  value,
  fieldLabel,
  onResult,
  tasks = ALL_TASKS,
  className,
}: {
  /** Current text of the target field. */
  value: string;
  /** Localized name of the field, used to compose the prompt. */
  fieldLabel: string;
  /** Called with the AI output to fill/replace the field. */
  onResult: (text: string) => void;
  /** Restrict which tasks are offered (defaults to all). */
  tasks?: AiTask[];
  className?: string;
}) {
  const { t } = useTranslation();
  const enabled = useAiEnabled();
  const [busy, setBusy] = useState(false);

  // Gate the whole affordance on the AI being enabled.
  if (!enabled) return null;

  const run = async (task: AiTask) => {
    // "generate" can work from empty notes; the others need existing text.
    if (task !== "generate" && !value.trim()) {
      toast.message(t("ai.empty"));
      return;
    }
    setBusy(true);
    try {
      const out = await aiComplete(buildPrompt(task, fieldLabel, value), SYSTEM_PROMPT);
      onResult(out.trim());
      toast.success(t("ai.done"));
    } catch (err) {
      toast.error(asIpcError(err).message || t("ai.error"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className={className}
              disabled={busy}
              aria-label={t("ai.assist")}
            >
              {busy ? (
                <Loader2 className="animate-spin" />
              ) : (
                <Sparkles className="text-[hsl(var(--accent-brand))]" />
              )}
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>{busy ? t("ai.working") : t("ai.assist")}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end">
        {tasks.map((task) => (
          <DropdownMenuItem key={task} onSelect={() => void run(task)}>
            <Sparkles />
            {t(`ai.tasks.${task}`)}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
