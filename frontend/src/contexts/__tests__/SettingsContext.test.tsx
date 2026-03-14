/**
 * Tests for SettingsContext provider and hooks
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { SettingsProvider, useTimezone, useGlobalSettings } from "../SettingsContext";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

// Mock the settings API
const mockGetAll = vi.fn();
const mockGetByKey = vi.fn();

vi.mock("@/lib/api", () => ({
  settingsApi: {
    getAll: (...args: unknown[]) => mockGetAll(...args),
    getByKey: (...args: unknown[]) => mockGetByKey(...args),
    update: vi.fn(),
  },
}));

// ThemeProvider also calls settingsApi — mock it out
vi.mock("@/contexts/ThemeContext", () => ({
  ThemeProvider: ({ children }: { children: ReactNode }) => children,
  useTheme: () => ({ theme: "dark", setTheme: vi.fn(), isLoading: false }),
}));

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <SettingsProvider>{children}</SettingsProvider>
        </MemoryRouter>
      </QueryClientProvider>
    );
  };
}

describe("SettingsContext", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("provides default timezone of UTC before settings are fetched", () => {
    // Make getAll hang forever so we can observe the default
    mockGetAll.mockReturnValue(new Promise(() => {}));

    const { result } = renderHook(() => useTimezone(), {
      wrapper: createWrapper(),
    });

    expect(result.current).toBe("UTC");
  });

  it("fetches settings on mount", async () => {
    mockGetAll.mockResolvedValue([
      { key: "timezone", value: "America/New_York", description: null, updated_at: "2025-01-01T00:00:00Z" },
    ]);

    renderHook(() => useGlobalSettings(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(mockGetAll).toHaveBeenCalledTimes(1);
    });
  });

  it("useTimezone returns timezone value from settings", async () => {
    mockGetAll.mockResolvedValue([
      { key: "timezone", value: "Europe/London", description: null, updated_at: "2025-01-01T00:00:00Z" },
    ]);

    const { result } = renderHook(() => useTimezone(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(result.current).toBe("Europe/London");
    });
  });

  it("falls back to UTC when settings fetch fails", async () => {
    mockGetAll.mockRejectedValue(new Error("Network error"));

    const { result } = renderHook(() => useTimezone(), {
      wrapper: createWrapper(),
    });

    // Wait for the effect to settle
    await waitFor(() => {
      expect(mockGetAll).toHaveBeenCalled();
    });

    expect(result.current).toBe("UTC");
  });

  it("useGlobalSettings returns isLoading=false after settings load", async () => {
    mockGetAll.mockResolvedValue([]);

    const { result } = renderHook(() => useGlobalSettings(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });
  });

  it("useGlobalSettings exposes all settings as a record", async () => {
    mockGetAll.mockResolvedValue([
      { key: "timezone", value: "Asia/Tokyo", description: null, updated_at: "2025-01-01T00:00:00Z" },
      { key: "theme", value: "dark", description: null, updated_at: "2025-01-01T00:00:00Z" },
    ]);

    const { result } = renderHook(() => useGlobalSettings(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(result.current.settings).toEqual({
        timezone: "Asia/Tokyo",
        theme: "dark",
      });
    });
  });

  it("throws when useTimezone is used outside SettingsProvider", () => {
    // Suppress React error boundary console output
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(() => {
      renderHook(() => useTimezone());
    }).toThrow("useTimezone must be used within a SettingsProvider");

    spy.mockRestore();
  });
});
