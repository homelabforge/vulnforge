/**
 * Tests for useScanStatus SSE/EventSource hook
 *
 * Covers: EventSource connection, scan-status events, error retry,
 * unmount cleanup, status transition cache invalidation
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useScanStatus } from "../useVulnForge";

// --- EventSource mock infrastructure ---

type ESListener = (event: MessageEvent) => void;

interface MockEventSource {
  url: string;
  listeners: Record<string, ESListener[]>;
  onerror: (() => void) | null;
  addEventListener: ReturnType<typeof vi.fn>;
  removeEventListener: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
}

let latestEventSource: MockEventSource | null = null;
const eventSourceInstances: MockEventSource[] = [];

function createMockEventSourceClass() {
  // Must be a real function (not arrow) so it can be called with `new`
  function MockES(this: MockEventSource, url: string) {
    this.url = url;
    this.listeners = {};
    this.onerror = null;
    this.addEventListener = vi.fn((event: string, cb: ESListener) => {
      if (!this.listeners[event]) this.listeners[event] = [];
      this.listeners[event].push(cb);
    });
    this.removeEventListener = vi.fn((event: string, cb: ESListener) => {
      if (this.listeners[event]) {
        this.listeners[event] = this.listeners[event].filter((l) => l !== cb);
      }
    });
    this.close = vi.fn();
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    latestEventSource = this;
    eventSourceInstances.push(this);
  }
  return MockES as unknown as typeof EventSource;
}

// Mock scansApi.getCurrent for the initial query
const mockGetCurrent = vi.fn();

vi.mock("@/lib/api", () => ({
  scansApi: {
    getCurrent: (...args: unknown[]) => mockGetCurrent(...args),
    trigger: vi.fn(),
    getHistory: vi.fn(),
    getTrends: vi.fn(),
  },
  containersApi: {},
  vulnerabilitiesApi: {},
  secretsApi: {},
  widgetApi: {},
  settingsApi: {},
  systemApi: {},
  activityApi: {},
  maintenanceApi: {},
  apiKeysApi: {},
}));

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
  }

  return { Wrapper, queryClient };
}

describe("useScanStatus", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    latestEventSource = null;
    eventSourceInstances.length = 0;
    vi.clearAllMocks();

    // Default: scan is idle
    mockGetCurrent.mockResolvedValue({ status: "idle", progress: 0 });

    // Install the mock EventSource on globalThis
    (globalThis as Record<string, unknown>).EventSource = createMockEventSourceClass();
  });

  afterEach(() => {
    vi.useRealTimers();
    delete (globalThis as Record<string, unknown>).EventSource;
  });

  it("opens an EventSource connection to /api/v1/scans/stream", () => {
    const { Wrapper } = createWrapper();
    renderHook(() => useScanStatus(), { wrapper: Wrapper });

    expect(latestEventSource).not.toBeNull();
    expect(latestEventSource!.url).toBe("/api/v1/scans/stream");
  });

  it("listens for scan-status events and updates query data", async () => {
    const { Wrapper, queryClient } = createWrapper();
    renderHook(() => useScanStatus(), { wrapper: Wrapper });

    const es = latestEventSource!;
    expect(es.addEventListener).toHaveBeenCalledWith(
      "scan-status",
      expect.any(Function),
    );

    // Simulate a scan-status event
    const payload = { status: "scanning", progress: 42 };
    const listeners = es.listeners["scan-status"] || [];
    act(() => {
      for (const listener of listeners) {
        listener(new MessageEvent("scan-status", { data: JSON.stringify(payload) }));
      }
    });

    const data = queryClient.getQueryData(["scanStatus"]);
    expect(data).toEqual(payload);
  });

  it("retries after 3000ms on EventSource error", () => {
    const { Wrapper } = createWrapper();
    renderHook(() => useScanStatus(), { wrapper: Wrapper });

    const firstEs = latestEventSource!;

    // Trigger error
    act(() => {
      firstEs.onerror?.();
    });

    expect(firstEs.close).toHaveBeenCalled();

    // Before 3000ms, no new connection
    act(() => {
      vi.advanceTimersByTime(2999);
    });
    expect(eventSourceInstances).toHaveLength(1);

    // At 3000ms, reconnects
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(eventSourceInstances).toHaveLength(2);
    expect(latestEventSource!.url).toBe("/api/v1/scans/stream");
  });

  it("closes EventSource on unmount", () => {
    const { Wrapper } = createWrapper();
    const { unmount } = renderHook(() => useScanStatus(), { wrapper: Wrapper });

    const es = latestEventSource!;
    expect(es.close).not.toHaveBeenCalled();

    unmount();

    expect(es.close).toHaveBeenCalled();
  });

  it("does not reconnect after unmount", () => {
    const { Wrapper } = createWrapper();
    const { unmount } = renderHook(() => useScanStatus(), { wrapper: Wrapper });

    const firstEs = latestEventSource!;

    // Trigger error, then immediately unmount
    act(() => {
      firstEs.onerror?.();
    });
    unmount();

    // Advance past retry delay
    act(() => {
      vi.advanceTimersByTime(5000);
    });

    // Should still only have the original instance (closed) — no reconnection
    expect(eventSourceInstances).toHaveLength(1);
  });

  it("invalidates data queries on scanning → idle transition", async () => {
    vi.useRealTimers();
    const { Wrapper, queryClient } = createWrapper();

    // Seed caches so we can observe invalidation
    queryClient.setQueryData(["widgetSummary"], { total: 5 });
    queryClient.setQueryData(["containers"], { containers: [] });
    queryClient.setQueryData(["vulnerabilities", undefined], { vulns: [] });

    const { result } = renderHook(() => useScanStatus(), { wrapper: Wrapper });

    // Wait for the initial query to settle so previousStatusRef gets set
    await waitFor(() => {
      expect(result.current.data).toBeDefined();
    });

    const es = latestEventSource!;
    const listeners = es.listeners["scan-status"] || [];

    // Transition to scanning via SSE
    act(() => {
      for (const listener of listeners) {
        listener(
          new MessageEvent("scan-status", {
            data: JSON.stringify({ status: "scanning", progress: 50 }),
          }),
        );
      }
    });

    // Let React flush the effect that updates previousStatusRef to "scanning"
    await waitFor(() => {
      expect(queryClient.getQueryData(["scanStatus"])).toEqual({ status: "scanning", progress: 50 });
    });

    // Transition to idle (scan complete) via SSE
    act(() => {
      for (const listener of listeners) {
        listener(
          new MessageEvent("scan-status", {
            data: JSON.stringify({ status: "idle", progress: 100 }),
          }),
        );
      }
    });

    // Cache keys should be invalidated after scanning → idle
    await waitFor(() => {
      expect(queryClient.getQueryState(["widgetSummary"])?.isInvalidated).toBe(true);
    });
    expect(queryClient.getQueryState(["containers"])?.isInvalidated).toBe(true);

    vi.useFakeTimers();
  });

  it("does NOT invalidate caches on idle → idle (no transition)", () => {
    const { Wrapper, queryClient } = createWrapper();

    // Seed scanStatus as idle
    queryClient.setQueryData(["scanStatus"], { status: "idle", progress: 0 });
    queryClient.setQueryData(["widgetSummary"], { total: 5 });

    renderHook(() => useScanStatus(), { wrapper: Wrapper });

    const es = latestEventSource!;
    const listeners = es.listeners["scan-status"] || [];

    // Send idle again (no transition from scanning)
    act(() => {
      for (const listener of listeners) {
        listener(
          new MessageEvent("scan-status", {
            data: JSON.stringify({ status: "idle", progress: 0 }),
          }),
        );
      }
    });

    expect(queryClient.getQueryState(["widgetSummary"])?.isInvalidated).toBe(false);
  });
});
