import { useCallback, useEffect, useState } from "react";

const ONBOARDED_KEY = "pwn2report.onboarded";
// Custom event so multiple useOnboarding() instances stay in sync within the
// same window (the native "storage" event only fires across tabs/windows).
const ONBOARDING_EVENT = "pwn2report:onboarding-changed";

function readOnboarded(): boolean {
  try {
    return localStorage.getItem(ONBOARDED_KEY) === "1";
  } catch {
    // If storage is unavailable, treat the user as already onboarded so the
    // tour never blocks the app.
    return true;
  }
}

function writeOnboarded(value: boolean): void {
  try {
    if (value) localStorage.setItem(ONBOARDED_KEY, "1");
    else localStorage.removeItem(ONBOARDED_KEY);
  } catch {
    // best-effort persistence
  }
  window.dispatchEvent(new Event(ONBOARDING_EVENT));
}

/**
 * First-run onboarding state, backed by localStorage. Returns whether the
 * welcome tour should show plus actions to finish or replay it. All instances
 * in the window stay in sync via a custom event, so replaying from Settings
 * immediately re-opens the tour rendered by App.
 */
export function useOnboarding() {
  const [onboarded, setOnboarded] = useState<boolean>(readOnboarded);

  useEffect(() => {
    const sync = () => setOnboarded(readOnboarded());
    window.addEventListener(ONBOARDING_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(ONBOARDING_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const finish = useCallback(() => writeOnboarded(true), []);
  const replay = useCallback(() => writeOnboarded(false), []);

  return { showOnboarding: !onboarded, finish, replay };
}
