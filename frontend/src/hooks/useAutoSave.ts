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

  // Mark as initialized after first render with enabled=true
  useEffect(() => {
    if (!enabled) return;

    // Use a small delay to let all state settle after initial hydration
    const timer = window.setTimeout(() => {
      const initialPayload = buildPayload();
      lastPayloadRef.current = JSON.stringify(initialPayload);
      hasInitializedRef.current = true;
    }, 100);

    return () => window.clearTimeout(timer);
    // Only run on mount/enable change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  // Auto-save on changes (debounced)
  useEffect(() => {
    if (!enabled || !hasInitializedRef.current) return;

    const timer = window.setTimeout(() => {
      const payload = buildPayload();
      const serialized = JSON.stringify(payload);

      if (lastPayloadRef.current === serialized) return;

      lastPayloadRef.current = serialized;
      onSave(payload);
    }, 800);

    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
