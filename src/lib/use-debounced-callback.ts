import { useEffect, useMemo, useRef } from "react";

/** A debounced function with an extra `flush()` to run any pending call now. */
export type DebouncedCallback<A extends unknown[]> = ((...args: A) => void) & {
  /** Immediately invoke the pending call (if any) and clear the timer. */
  flush: () => void;
  /** Drop any pending call without invoking it. */
  cancel: () => void;
};

/**
 * Returns a stable debounced version of `fn`. The latest `fn` is always
 * invoked (kept in a ref) so callers don't need to memoize it.
 *
 * On unmount any pending call is FLUSHED (not dropped) so the last keystrokes
 * before a route change / dialog close are not lost. The returned function also
 * exposes `flush()` and `cancel()` for explicit control.
 */
export function useDebouncedCallback<A extends unknown[]>(
  fn: (...args: A) => void,
  delay: number,
): DebouncedCallback<A> {
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // The args of the call currently waiting to fire, so flush() can replay it.
  const pendingArgs = useRef<A | null>(null);

  const debounced = useMemo(() => {
    const cancel = () => {
      if (timer.current) {
        clearTimeout(timer.current);
        timer.current = null;
      }
      pendingArgs.current = null;
    };

    const flush = () => {
      if (timer.current) {
        clearTimeout(timer.current);
        timer.current = null;
      }
      if (pendingArgs.current) {
        const args = pendingArgs.current;
        pendingArgs.current = null;
        fnRef.current(...args);
      }
    };

    const run = (...args: A) => {
      pendingArgs.current = args;
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        timer.current = null;
        pendingArgs.current = null;
        fnRef.current(...args);
      }, delay);
    };

    return Object.assign(run, { flush, cancel }) as DebouncedCallback<A>;
  }, [delay]);

  // Flush any pending call on unmount so trailing edits are not lost.
  useEffect(() => () => debounced.flush(), [debounced]);

  return debounced;
}
