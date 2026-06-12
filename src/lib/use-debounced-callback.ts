import { useEffect, useMemo, useRef } from "react";

/**
 * Returns a stable debounced version of `fn`. The latest `fn` is always
 * invoked (kept in a ref) so callers don't need to memoize it. Any pending
 * call is flushed/cancelled on unmount.
 */
export function useDebouncedCallback<A extends unknown[]>(
  fn: (...args: A) => void,
  delay: number,
) {
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  return useMemo(() => {
    return (...args: A) => {
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => fnRef.current(...args), delay);
    };
  }, [delay]);
}
