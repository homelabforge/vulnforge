/**
 * useAutoSave - Debounced auto-save hook for settings tabs.
 *
 * Handles initialization guard, payload diffing, and debounced save.
 */

import { useEffect, useRef } from "react";

export function useAutoSave(
  buildPayload: () => Record<string, string>,
  onSave: (payload: Record<string, string>) => void,
  deps: unknown[],
  enabled: boolean = true,
): void {
  const hasInitializedRef = useRef(false);
  const lastPayloadRef = useRef<string | null>(null);
  // Keep onSave current to avoid stale closure inside the debounce timer.
  const onSaveRef = useRef(onSave);
  useEffect(() => {
    onSaveRef.current = onSave;
  });

  useEffect(() => {
    if (!enabled) return;

    if (!hasInitializedRef.current) {
      // First run: capture initial snapshot synchronously — no save, no timer.
      // Synchronous init avoids the race where a user interaction fires before
      // a delayed init completes, silently dropping the save.
      lastPayloadRef.current = JSON.stringify(buildPayload());
      hasInitializedRef.current = true;
      return;
    }

    const timer = window.setTimeout(() => {
      const payload = buildPayload();
      const serialized = JSON.stringify(payload);
      if (lastPayloadRef.current === serialized) return;
      lastPayloadRef.current = serialized;
      onSaveRef.current(payload);
    }, 800);

    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
