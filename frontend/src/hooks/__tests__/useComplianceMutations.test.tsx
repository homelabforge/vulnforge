/**
 * Tests for compliance mutation hooks
 *
 * These mutations are used inline in components (ImageCompliance.tsx, etc.)
 * but follow the same useMutation + cache invalidation pattern. We test
 * them by wrapping the API calls in lightweight hooks mirroring the component usage.
 *
 * Covers: triggerScan, ignoreFinding, unignoreFinding, 409 conflict on scan
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider, useMutation, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";

const mockTriggerScan = vi.fn();
const mockIgnoreFinding = vi.fn();
const mockUnignoreFinding = vi.fn();
const mockImageIgnoreFinding = vi.fn();
const mockImageUnignoreFinding = vi.fn();

vi.mock("@/lib/api", () => ({
  complianceApi: {
    triggerScan: (...args: unknown[]) => mockTriggerScan(...args),
    ignoreFinding: (...args: unknown[]) => mockIgnoreFinding(...args),
    unignoreFinding: (...args: unknown[]) => mockUnignoreFinding(...args),
    getSummary: vi.fn(),
    getCurrentScan: vi.fn(),
    getFindings: vi.fn(),
    getTrend: vi.fn(),
  },
  imageComplianceApi: {
    ignoreFinding: (...args: unknown[]) => mockImageIgnoreFinding(...args),
    unignoreFinding: (...args: unknown[]) => mockImageUnignoreFinding(...args),
    getSummary: vi.fn(),
    getImages: vi.fn(),
    getFindings: vi.fn(),
    getCurrentScan: vi.fn(),
    scanImage: vi.fn(),
    scanAll: vi.fn(),
  },
  containersApi: {},
  scansApi: {},
  vulnerabilitiesApi: {},
  secretsApi: {},
  widgetApi: {},
  settingsApi: {},
  systemApi: {},
  activityApi: {},
  maintenanceApi: {},
  apiKeysApi: {},
}));

// --- Inline hook wrappers matching component mutation patterns ---

function useTriggerComplianceScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => mockTriggerScan(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-current"] });
    },
  });
}

function useIgnoreComplianceFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ findingId, reason }: { findingId: number; reason: string }) =>
      mockIgnoreFinding(findingId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
    },
  });
}

function useUnignoreComplianceFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (findingId: number) => mockUnignoreFinding(findingId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
    },
  });
}

function useIgnoreImageFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ findingId, reason }: { findingId: number; reason: string }) =>
      mockImageIgnoreFinding(findingId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["image-compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["image-compliance-images"] });
    },
  });
}

function useUnignoreImageFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (findingId: number) => mockImageUnignoreFinding(findingId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["image-compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["image-compliance-images"] });
    },
  });
}

// --- Test infrastructure ---

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

// --- Tests ---

describe("useTriggerComplianceScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("triggers compliance scan successfully", async () => {
    mockTriggerScan.mockResolvedValue({ message: "Scan started" });

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useTriggerComplianceScan(), { wrapper: Wrapper });

    result.current.mutate();

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockTriggerScan).toHaveBeenCalledOnce();
    expect(result.current.data).toEqual({ message: "Scan started" });
  });

  it("invalidates compliance queries on success", async () => {
    mockTriggerScan.mockResolvedValue({ message: "Scan started" });

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["compliance-summary"], { score: 85 });
    queryClient.setQueryData(["compliance-current"], { status: "idle" });

    const { result } = renderHook(() => useTriggerComplianceScan(), { wrapper: Wrapper });

    result.current.mutate();

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(queryClient.getQueryState(["compliance-summary"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(["compliance-current"])?.isInvalidated).toBe(true);
  });

  it("handles 409 conflict when scan is already running", async () => {
    const conflictError = new Error("Scan already in progress");
    (conflictError as unknown as Record<string, unknown>).status = 409;
    mockTriggerScan.mockRejectedValue(conflictError);

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["compliance-summary"], { score: 85 });

    const { result } = renderHook(() => useTriggerComplianceScan(), { wrapper: Wrapper });

    result.current.mutate();

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error?.message).toBe("Scan already in progress");

    // Caches should NOT be invalidated on error
    expect(queryClient.getQueryState(["compliance-summary"])?.isInvalidated).toBe(false);
  });
});

describe("useIgnoreComplianceFinding", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls complianceApi.ignoreFinding with findingId and reason", async () => {
    mockIgnoreFinding.mockResolvedValue(undefined);

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useIgnoreComplianceFinding(), { wrapper: Wrapper });

    result.current.mutate({ findingId: 7, reason: "Not applicable to our setup" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockIgnoreFinding).toHaveBeenCalledWith(7, "Not applicable to our setup");
  });

  it("invalidates compliance queries on success", async () => {
    mockIgnoreFinding.mockResolvedValue(undefined);

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["compliance-findings"], []);
    queryClient.setQueryData(["compliance-summary"], { score: 90 });

    const { result } = renderHook(() => useIgnoreComplianceFinding(), { wrapper: Wrapper });

    result.current.mutate({ findingId: 1, reason: "False positive" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(queryClient.getQueryState(["compliance-findings"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(["compliance-summary"])?.isInvalidated).toBe(true);
  });

  it("does not invalidate caches on error", async () => {
    mockIgnoreFinding.mockRejectedValue(new Error("Finding not found"));

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["compliance-findings"], []);
    queryClient.setQueryData(["compliance-summary"], { score: 90 });

    const { result } = renderHook(() => useIgnoreComplianceFinding(), { wrapper: Wrapper });

    result.current.mutate({ findingId: 999, reason: "test" });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(queryClient.getQueryState(["compliance-findings"])?.isInvalidated).toBe(false);
    expect(queryClient.getQueryState(["compliance-summary"])?.isInvalidated).toBe(false);
  });
});

describe("useUnignoreComplianceFinding", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls complianceApi.unignoreFinding with findingId", async () => {
    mockUnignoreFinding.mockResolvedValue(undefined);

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useUnignoreComplianceFinding(), { wrapper: Wrapper });

    result.current.mutate(12);

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockUnignoreFinding).toHaveBeenCalledWith(12);
  });

  it("invalidates compliance queries on success", async () => {
    mockUnignoreFinding.mockResolvedValue(undefined);

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["compliance-findings"], []);
    queryClient.setQueryData(["compliance-summary"], { score: 88 });

    const { result } = renderHook(() => useUnignoreComplianceFinding(), { wrapper: Wrapper });

    result.current.mutate(3);

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(queryClient.getQueryState(["compliance-findings"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(["compliance-summary"])?.isInvalidated).toBe(true);
  });
});

describe("useIgnoreImageFinding (image compliance)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls imageComplianceApi.ignoreFinding with findingId and reason", async () => {
    mockImageIgnoreFinding.mockResolvedValue(undefined);

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useIgnoreImageFinding(), { wrapper: Wrapper });

    result.current.mutate({ findingId: 42, reason: "Base image limitation" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockImageIgnoreFinding).toHaveBeenCalledWith(42, "Base image limitation");
  });

  it("invalidates image-compliance queries on success", async () => {
    mockImageIgnoreFinding.mockResolvedValue(undefined);

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["image-compliance-findings"], []);
    queryClient.setQueryData(["image-compliance-images"], []);

    const { result } = renderHook(() => useIgnoreImageFinding(), { wrapper: Wrapper });

    result.current.mutate({ findingId: 10, reason: "Accepted risk" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(queryClient.getQueryState(["image-compliance-findings"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(["image-compliance-images"])?.isInvalidated).toBe(true);
  });
});

describe("useUnignoreImageFinding (image compliance)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls imageComplianceApi.unignoreFinding with findingId", async () => {
    mockImageUnignoreFinding.mockResolvedValue(undefined);

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useUnignoreImageFinding(), { wrapper: Wrapper });

    result.current.mutate(55);

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockImageUnignoreFinding).toHaveBeenCalledWith(55);
  });

  it("invalidates image-compliance queries on success", async () => {
    mockImageUnignoreFinding.mockResolvedValue(undefined);

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["image-compliance-findings"], []);
    queryClient.setQueryData(["image-compliance-images"], []);

    const { result } = renderHook(() => useUnignoreImageFinding(), { wrapper: Wrapper });

    result.current.mutate(55);

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(queryClient.getQueryState(["image-compliance-findings"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(["image-compliance-images"])?.isInvalidated).toBe(true);
  });
});
