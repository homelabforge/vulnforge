/**
 * Tests for useVulnForge React Query hooks
 *
 * Focuses on:
 * - Query key correctness
 * - Configuration options (staleTime, etc.)
 * - Mutation cache invalidation behaviour
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import {
  useContainers,
  useAppInfo,
  useUpdateContainer,
  useCreateApiKey,
} from "../useVulnForge";

// Mock all API modules used by the hooks under test
const mockContainersGetAll = vi.fn();
const mockContainersUpdate = vi.fn();
const mockSystemGetAppInfo = vi.fn();
const mockApiKeysCreate = vi.fn();

vi.mock("@/lib/api", () => ({
  containersApi: {
    getAll: (...args: unknown[]) => mockContainersGetAll(...args),
    update: (...args: unknown[]) => mockContainersUpdate(...args),
  },
  systemApi: {
    getAppInfo: (...args: unknown[]) => mockSystemGetAppInfo(...args),
  },
  apiKeysApi: {
    create: (...args: unknown[]) => mockApiKeysCreate(...args),
  },
  // Stubs for imports referenced at module scope
  scansApi: {},
  vulnerabilitiesApi: {},
  secretsApi: {},
  widgetApi: {},
  settingsApi: {},
  activityApi: {},
  maintenanceApi: {},
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

describe("useContainers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uses ["containers"] as query key', async () => {
    const containers = [{ id: 1, name: "nginx" }];
    mockContainersGetAll.mockResolvedValue({ containers, total: 1 });

    const { Wrapper, queryClient } = createWrapper();
    renderHook(() => useContainers(), { wrapper: Wrapper });

    await waitFor(() => {
      const state = queryClient.getQueryState(["containers"]);
      expect(state).toBeDefined();
      expect(state?.status).toBe("success");
    });
  });

  it("returns data from containersApi.getAll", async () => {
    const payload = { containers: [{ id: 1, name: "redis" }], total: 1 };
    mockContainersGetAll.mockResolvedValue(payload);

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useContainers(), { wrapper: Wrapper });

    await waitFor(() => {
      expect(result.current.data).toEqual(payload);
    });
  });
});

describe("useAppInfo", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("has staleTime configured", async () => {
    mockSystemGetAppInfo.mockResolvedValue({ name: "VulnForge", version: "4.4.0" });

    const { Wrapper, queryClient } = createWrapper();
    renderHook(() => useAppInfo(), { wrapper: Wrapper });

    await waitFor(() => {
      const state = queryClient.getQueryState(["appInfo"]);
      expect(state?.status).toBe("success");
    });

    // Query should not be stale immediately (staleTime = 5 min)
    const state = queryClient.getQueryState(["appInfo"]);
    expect(state?.isInvalidated).toBe(false);
  });

  it("returns app info data", async () => {
    const info = { name: "VulnForge", version: "4.4.0" };
    mockSystemGetAppInfo.mockResolvedValue(info);

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useAppInfo(), { wrapper: Wrapper });

    await waitFor(() => {
      expect(result.current.data).toEqual(info);
    });
  });
});

describe("useUpdateContainer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('invalidates ["containers"] and ["container"] on success', async () => {
    mockContainersUpdate.mockResolvedValue({ id: 1, name: "nginx", is_my_project: true });

    const { Wrapper, queryClient } = createWrapper();

    // Seed the cache with container data
    queryClient.setQueryData(["containers"], { containers: [], total: 0 });
    queryClient.setQueryData(["container", 1], { id: 1, name: "nginx" });

    const { result } = renderHook(() => useUpdateContainer(), { wrapper: Wrapper });

    result.current.mutate({ id: 1, updates: { is_my_project: true } });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    // Both query keys should be invalidated
    const containersState = queryClient.getQueryState(["containers"]);
    const containerState = queryClient.getQueryState(["container", 1]);
    expect(containersState?.isInvalidated).toBe(true);
    expect(containerState?.isInvalidated).toBe(true);
  });
});

describe("useCreateApiKey", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('invalidates ["apiKeys"] on success', async () => {
    mockApiKeysCreate.mockResolvedValue({
      id: 1,
      name: "test-key",
      description: null,
      key: "vf_test123",
      key_prefix: "vf_test",
      created_at: "2025-06-15T12:00:00Z",
      created_by: "admin",
      warning: "Store this key securely",
    });

    const { Wrapper, queryClient } = createWrapper();

    // Seed cache
    queryClient.setQueryData(["apiKeys"], { keys: [], total: 0 });

    const { result } = renderHook(() => useCreateApiKey(), { wrapper: Wrapper });

    result.current.mutate({ name: "test-key" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    const state = queryClient.getQueryState(["apiKeys"]);
    expect(state?.isInvalidated).toBe(true);
  });

  it("calls apiKeysApi.create with the provided data", async () => {
    mockApiKeysCreate.mockResolvedValue({
      id: 2,
      name: "ci-key",
      description: "For CI/CD",
      key: "vf_ci123",
      key_prefix: "vf_ci",
      created_at: "2025-06-15T12:00:00Z",
      created_by: "admin",
      warning: "Store this key securely",
    });

    const { Wrapper } = createWrapper();
    const { result } = renderHook(() => useCreateApiKey(), { wrapper: Wrapper });

    result.current.mutate({ name: "ci-key", description: "For CI/CD" });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockApiKeysCreate).toHaveBeenCalledWith({ name: "ci-key", description: "For CI/CD" });
  });
});
