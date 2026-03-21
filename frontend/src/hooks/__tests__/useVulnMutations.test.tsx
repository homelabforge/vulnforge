/**
 * Tests for vulnerability mutation hooks
 *
 * Covers: useUpdateVulnerability, useBulkUpdateVulnerabilities
 * Focuses on: API call arguments, cache invalidation on success, error propagation
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import {
  useUpdateVulnerability,
  useBulkUpdateVulnerabilities,
} from "../useVulnForge";

const mockUpdateStatus = vi.fn();
const mockBulkUpdate = vi.fn();

vi.mock("@/lib/api", () => ({
  vulnerabilitiesApi: {
    updateStatus: (...args: unknown[]) => mockUpdateStatus(...args),
    bulkUpdate: (...args: unknown[]) => mockBulkUpdate(...args),
    getAll: vi.fn(),
    getById: vi.fn(),
    getRemediationGroups: vi.fn(),
  },
  containersApi: {},
  scansApi: {},
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

describe("useUpdateVulnerability", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls vulnerabilitiesApi.updateStatus with correct arguments", async () => {
    const updatedVuln = { id: 42, status: "accepted", notes: "Risk accepted" };
    mockUpdateStatus.mockResolvedValue(updatedVuln);

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useUpdateVulnerability(), { wrapper: Wrapper });

    result.current.mutate({ id: 42, status: "accepted", notes: "Risk accepted" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockUpdateStatus).toHaveBeenCalledWith(42, "accepted", "Risk accepted");
  });

  it('invalidates ["vulnerabilities"] and ["widgetSummary"] on success', async () => {
    mockUpdateStatus.mockResolvedValue({ id: 1, status: "resolved" });

    const { Wrapper, queryClient } = createWrapper();

    // Seed caches
    queryClient.setQueryData(["vulnerabilities"], { vulnerabilities: [], total: 0 });
    queryClient.setQueryData(["widgetSummary"], { total: 10 });

    const { result } = renderHook(() => useUpdateVulnerability(), { wrapper: Wrapper });

    result.current.mutate({ id: 1, status: "resolved" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(queryClient.getQueryState(["vulnerabilities"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(["widgetSummary"])?.isInvalidated).toBe(true);
  });

  it("propagates API error without invalidating caches", async () => {
    mockUpdateStatus.mockRejectedValue(new Error("Bad Request"));

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["vulnerabilities"], { vulnerabilities: [], total: 0 });
    queryClient.setQueryData(["widgetSummary"], { total: 10 });

    const { result } = renderHook(() => useUpdateVulnerability(), { wrapper: Wrapper });

    result.current.mutate({ id: 99, status: "invalid" });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error?.message).toBe("Bad Request");

    // Caches should NOT be invalidated on error
    expect(queryClient.getQueryState(["vulnerabilities"])?.isInvalidated).toBe(false);
    expect(queryClient.getQueryState(["widgetSummary"])?.isInvalidated).toBe(false);
  });

  it("works without optional notes parameter", async () => {
    mockUpdateStatus.mockResolvedValue({ id: 5, status: "resolved" });

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useUpdateVulnerability(), { wrapper: Wrapper });

    result.current.mutate({ id: 5, status: "resolved" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockUpdateStatus).toHaveBeenCalledWith(5, "resolved", undefined);
  });
});

describe("useBulkUpdateVulnerabilities", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls vulnerabilitiesApi.bulkUpdate with correct arguments", async () => {
    mockBulkUpdate.mockResolvedValue({ updated: 3 });

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useBulkUpdateVulnerabilities(), { wrapper: Wrapper });

    result.current.mutate({ ids: [1, 2, 3], status: "accepted", notes: "Batch accept" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockBulkUpdate).toHaveBeenCalledWith([1, 2, 3], "accepted", "Batch accept");
  });

  it('invalidates ["vulnerabilities"] and ["widgetSummary"] on success', async () => {
    mockBulkUpdate.mockResolvedValue({ updated: 2 });

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["vulnerabilities"], { vulnerabilities: [], total: 0 });
    queryClient.setQueryData(["widgetSummary"], { total: 5 });

    const { result } = renderHook(() => useBulkUpdateVulnerabilities(), { wrapper: Wrapper });

    result.current.mutate({ ids: [10, 20], status: "resolved" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(queryClient.getQueryState(["vulnerabilities"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(["widgetSummary"])?.isInvalidated).toBe(true);
  });

  it("handles empty array — still calls API", async () => {
    mockBulkUpdate.mockResolvedValue({ updated: 0 });

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useBulkUpdateVulnerabilities(), { wrapper: Wrapper });

    result.current.mutate({ ids: [], status: "resolved" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockBulkUpdate).toHaveBeenCalledWith([], "resolved", undefined);
    expect(result.current.data).toEqual({ updated: 0 });
  });

  it("propagates API error without invalidating caches", async () => {
    mockBulkUpdate.mockRejectedValue(new Error("Server Error"));

    const { Wrapper, queryClient } = createWrapper();

    queryClient.setQueryData(["vulnerabilities"], { vulnerabilities: [], total: 0 });
    queryClient.setQueryData(["widgetSummary"], { total: 5 });

    const { result } = renderHook(() => useBulkUpdateVulnerabilities(), { wrapper: Wrapper });

    result.current.mutate({ ids: [1], status: "resolved" });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error?.message).toBe("Server Error");
    expect(queryClient.getQueryState(["vulnerabilities"])?.isInvalidated).toBe(false);
    expect(queryClient.getQueryState(["widgetSummary"])?.isInvalidated).toBe(false);
  });
});
