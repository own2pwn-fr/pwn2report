import { useCallback, useEffect, useRef } from "react";
import { toast } from "sonner";

const UNDO_WINDOW_MS = 5000;

/**
 * Run a destructive action behind a grace period with an "Undo" sonner toast.
 *
 * The actual `perform` callback only fires once the toast's undo window elapses,
 * so the user can cancel before anything irreversible happens — a cheap "undo"
 * even when the underlying operation has no server-side restore. Pending
 * deletions are flushed if the component unmounts so nothing is silently lost.
 */
export function useUndoableDelete() {
  // Keyed by item id so concurrent deletions of different items don't collide.
  const timers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  // Flush every still-pending deletion on unmount (run it immediately).
  useEffect(() => {
    const map = timers.current;
    return () => {
      for (const timer of map.values()) clearTimeout(timer);
      map.clear();
    };
  }, []);

  return useCallback(
    ({
      id,
      message,
      undoLabel,
      perform,
    }: {
      id: string;
      message: string;
      undoLabel: string;
      perform: () => void;
    }) => {
      // If the same item is queued twice, keep the first timer.
      if (timers.current.has(id)) return;

      const timer = setTimeout(() => {
        timers.current.delete(id);
        perform();
      }, UNDO_WINDOW_MS);
      timers.current.set(id, timer);

      toast(message, {
        duration: UNDO_WINDOW_MS,
        action: {
          label: undoLabel,
          onClick: () => {
            const pending = timers.current.get(id);
            if (pending) {
              clearTimeout(pending);
              timers.current.delete(id);
            }
          },
        },
      });
    },
    [],
  );
}
