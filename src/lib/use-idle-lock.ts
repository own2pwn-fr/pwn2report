import { useCallback, useEffect, useRef, useState } from "react";

const STORAGE_KEY = "pwn2report.idleLockMinutes";

/** Default idle timeout in minutes when the setting has never been changed. */
export const DEFAULT_IDLE_LOCK_MINUTES = 15;

/** Read the persisted idle-lock timeout (minutes). 0 means "off". */
export function getIdleLockMinutes(): number {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw == null) return DEFAULT_IDLE_LOCK_MINUTES;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? n : DEFAULT_IDLE_LOCK_MINUTES;
  } catch {
    return DEFAULT_IDLE_LOCK_MINUTES;
  }
}

/** Persist the idle-lock timeout (minutes); 0 disables auto-lock. */
export function setIdleLockMinutes(minutes: number): void {
  try {
    localStorage.setItem(STORAGE_KEY, String(Math.max(0, Math.round(minutes))));
  } catch {
    // Best-effort persistence; the in-memory value still applies this session.
  }
  // Notify same-tab listeners (the storage event only fires cross-tab).
  window.dispatchEvent(new Event("pwn2report:idle-lock-changed"));
}

/**
 * React state wrapper around the persisted idle-lock setting, for the Settings
 * UI. Keeps in sync with changes made elsewhere in the app.
 */
export function useIdleLockSetting(): [number, (minutes: number) => void] {
  const [minutes, setMinutesState] = useState(getIdleLockMinutes);

  useEffect(() => {
    const sync = () => setMinutesState(getIdleLockMinutes());
    window.addEventListener("pwn2report:idle-lock-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("pwn2report:idle-lock-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const set = useCallback((next: number) => {
    setIdleLockMinutes(next);
    setMinutesState(getIdleLockMinutes());
  }, []);

  return [minutes, set];
}

const ACTIVITY_EVENTS = [
  "mousemove",
  "mousedown",
  "keydown",
  "wheel",
  "touchstart",
] as const;

/**
 * Lock the vault after `minutesProvider()` minutes of user inactivity. A value
 * of 0 disables the timer. The countdown resets on any user activity. `enabled`
 * should be false while the vault is already locked so the timer is inert.
 */
export function useIdleLock(enabled: boolean, onLock: () => void): void {
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;
  // Re-read the setting reactively so changing it in Settings takes effect now.
  const [minutes, setMinutes] = useState(getIdleLockMinutes);

  useEffect(() => {
    const sync = () => setMinutes(getIdleLockMinutes());
    window.addEventListener("pwn2report:idle-lock-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("pwn2report:idle-lock-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  useEffect(() => {
    if (!enabled || minutes <= 0) return;
    const timeoutMs = minutes * 60_000;
    let timer: ReturnType<typeof setTimeout>;

    const arm = () => {
      clearTimeout(timer);
      timer = setTimeout(() => onLockRef.current(), timeoutMs);
    };

    arm();
    for (const ev of ACTIVITY_EVENTS) {
      window.addEventListener(ev, arm, { passive: true });
    }
    return () => {
      clearTimeout(timer);
      for (const ev of ACTIVITY_EVENTS) window.removeEventListener(ev, arm);
    };
  }, [enabled, minutes]);
}
