import type { FindingFormState } from "@/components/findings/finding-form-state";

/**
 * In-progress draft persistence for the finding editor.
 *
 * Drafts are keyed by the finding id when editing an existing finding, or by
 * `new:<reportId>` when creating one — so an interrupted create on report A
 * doesn't clobber an interrupted create on report B. Drafts survive a crash,
 * accidental dialog dismiss, or app restart, and are cleared on a successful
 * save (or an explicit discard).
 */
const PREFIX = "pwn2report.finding-draft.";

/** Stable storage key for a draft. */
export function draftKey(findingId: string | undefined, reportId: string): string {
  return findingId ? `${PREFIX}${findingId}` : `${PREFIX}new:${reportId}`;
}

function storage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    // localStorage can throw (privacy mode, disabled). Degrade gracefully.
    return null;
  }
}

export function saveDraft(key: string, state: FindingFormState): void {
  const s = storage();
  if (!s) return;
  try {
    s.setItem(key, JSON.stringify(state));
  } catch {
    // Quota / serialization errors are non-fatal — never block typing.
  }
}

export function loadDraft(key: string): FindingFormState | null {
  const s = storage();
  if (!s) return null;
  try {
    const raw = s.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && typeof parsed.title === "string") {
      return parsed as FindingFormState;
    }
    return null;
  } catch {
    return null;
  }
}

export function clearDraft(key: string): void {
  const s = storage();
  if (!s) return;
  try {
    s.removeItem(key);
  } catch {
    // ignore
  }
}
