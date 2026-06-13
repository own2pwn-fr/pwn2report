import { useEffect } from "react";

/** True when the event target is a text input / textarea / contentEditable. */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return (
    tag === "INPUT" ||
    tag === "TEXTAREA" ||
    tag === "SELECT" ||
    target.isContentEditable
  );
}

/**
 * Fire `handler` when the user presses Cmd/Ctrl+Enter while `enabled`. Intended
 * for dialogs whose primary action should be reachable from the keyboard even
 * when the content is not a single `<form>` (Radix dialogs trap focus, so a
 * document-level listener still only sees keys typed inside the open dialog).
 *
 * When dialogs are stacked (e.g. the annotator opens on top of the finding
 * form), only the TOP-MOST dialog reacts: we check the event target lives inside
 * the last open Radix dialog in DOM order, so the outer form doesn't also submit.
 */
export function useSubmitShortcut(
  enabled: boolean,
  handler: () => void,
): void {
  useEffect(() => {
    if (!enabled) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.key !== "Enter") return;
      // If dialogs are stacked, only the top-most one (last in DOM) should fire.
      const dialogs = document.querySelectorAll('[role="dialog"][data-state="open"]');
      if (dialogs.length > 0) {
        const top = dialogs[dialogs.length - 1];
        if (!(e.target instanceof Node) || !top.contains(e.target)) return;
      }
      e.preventDefault();
      handler();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [enabled, handler]);
}

interface HotkeyOptions {
  /** When false the hotkey is inert. Defaults to true. */
  enabled?: boolean;
  /** Also fire while focus is inside a text field. Defaults to false. */
  allowInInput?: boolean;
}

/**
 * Register a single-key global shortcut (e.g. "n", "/"). Ignored while the user
 * is typing in a field unless `allowInInput` is set, and never fires with a
 * modifier held so it won't clash with browser/OS chords.
 */
export function useHotkey(
  key: string,
  handler: (e: KeyboardEvent) => void,
  { enabled = true, allowInInput = false }: HotkeyOptions = {},
): void {
  useEffect(() => {
    if (!enabled) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key !== key) return;
      if (!allowInInput && isTypingTarget(e.target)) return;
      handler(e);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [key, handler, enabled, allowInInput]);
}
