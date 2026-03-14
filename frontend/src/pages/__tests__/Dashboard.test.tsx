/**
 * Tests for Dashboard page
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "@/test-utils";
import { Dashboard } from "../Dashboard";

// Mock all hooks used by Dashboard
const mockUseWidgetSummary = vi.fn();
const mockUseScanStatus = vi.fn();
const mockUseSecretsSummary = vi.fn();
const mockUseDiscoverContainers = vi.fn();
const mockUseTriggerScan = vi.fn();

vi.mock("@/hooks/useVulnForge", () => ({
  useWidgetSummary: () => mockUseWidgetSummary(),
  useScanStatus: () => mockUseScanStatus(),
  useSecretsSummary: () => mockUseSecretsSummary(),
  useDiscoverContainers: () => mockUseDiscoverContainers(),
  useTriggerScan: () => mockUseTriggerScan(),
}));

// Mock child components that have their own data needs
vi.mock("@/components/VulnerabilityCharts", () => ({
  VulnerabilityCharts: () => <div data-testid="vuln-charts">VulnerabilityCharts</div>,
}));

vi.mock("@/components/ScanTrendsPanel", () => ({
  ScanTrendsPanel: () => <div data-testid="scan-trends">ScanTrendsPanel</div>,
}));

// Mock settingsApi for ThemeProvider/SettingsProvider
vi.mock("@/lib/api", () => ({
  settingsApi: {
    getAll: vi.fn().mockResolvedValue([]),
    getByKey: vi.fn().mockRejectedValue(new Error("not found")),
    update: vi.fn(),
  },
}));

// Mock sonner toast
vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

function setupDefaultMocks() {
  mockUseWidgetSummary.mockReturnValue({
    data: {
      total_containers: 12,
      scanned_containers: 10,
      last_scan: "2025-06-15T12:00:00Z",
      total_vulnerabilities: 42,
      fixable_vulnerabilities: 15,
      critical_count: 3,
      high_count: 8,
      medium_count: 20,
      low_count: 11,
      total_secrets: 5,
    },
    isLoading: false,
  });

  mockUseScanStatus.mockReturnValue({
    data: { status: "idle" },
    isLoading: false,
  });

  mockUseSecretsSummary.mockReturnValue({
    data: {
      total_secrets: 5,
      critical_count: 1,
      high_count: 2,
      medium_count: 1,
      low_count: 1,
      affected_containers: 3,
      top_categories: { "generic-api-key": 3, "aws-access-key": 2 },
    },
    isLoading: false,
  });

  mockUseDiscoverContainers.mockReturnValue({
    mutate: vi.fn(),
    isPending: false,
  });

  mockUseTriggerScan.mockReturnValue({
    mutate: vi.fn(),
    isPending: false,
  });
}

describe("Dashboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupDefaultMocks();
  });

  it("renders the dashboard heading", () => {
    renderWithProviders(<Dashboard />);
    expect(screen.getByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("renders summary stat cards with correct values", () => {
    renderWithProviders(<Dashboard />);

    // Total Vulnerabilities
    expect(screen.getByText("Total Vulnerabilities")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();

    // Fixable
    expect(screen.getByText("Fixable")).toBeInTheDocument();
    expect(screen.getByText("15")).toBeInTheDocument();

    // Critical count — appears in both stat card and secrets section,
    // so use getAllByText to verify at least one exists
    expect(screen.getAllByText("Critical").length).toBeGreaterThanOrEqual(1);

    // Container ratio — "Containers" label appears in stat card and secrets section
    expect(screen.getAllByText("Containers").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("10 / 12")).toBeInTheDocument();
  });

  it("renders secrets count from widget summary", () => {
    renderWithProviders(<Dashboard />);

    expect(screen.getByText("Secrets")).toBeInTheDocument();
    // The secrets stat card uses secretsSummary.total_secrets
    // There is both a stat card showing 5 and the secrets detail section showing 5
    const fives = screen.getAllByText("5");
    expect(fives.length).toBeGreaterThanOrEqual(1);
  });

  it("renders VulnerabilityCharts and ScanTrendsPanel", () => {
    renderWithProviders(<Dashboard />);

    expect(screen.getByTestId("vuln-charts")).toBeInTheDocument();
    expect(screen.getByTestId("scan-trends")).toBeInTheDocument();
  });

  it("shows Discover Containers and Scan All buttons", () => {
    renderWithProviders(<Dashboard />);

    expect(screen.getByRole("button", { name: /discover/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /scan all/i })).toBeInTheDocument();
  });

  it("renders zero values when summary data is undefined", () => {
    mockUseWidgetSummary.mockReturnValue({ data: undefined, isLoading: false });
    mockUseSecretsSummary.mockReturnValue({ data: undefined, isLoading: false });

    renderWithProviders(<Dashboard />);

    // Should show 0 for all stat cards
    const zeros = screen.getAllByText("0");
    expect(zeros.length).toBeGreaterThanOrEqual(4);

    // Container ratio should be "0 / 0"
    expect(screen.getByText("0 / 0")).toBeInTheDocument();
  });

  it("shows scan progress bar when scanning", () => {
    mockUseScanStatus.mockReturnValue({
      data: {
        status: "scanning",
        current_container: "redis",
        progress_current: 3,
        progress_total: 10,
      },
      isLoading: false,
    });

    renderWithProviders(<Dashboard />);

    expect(screen.getByText("Scanning containers...")).toBeInTheDocument();
    // The progress text is "redis (3 / 10)" inside a single <span> with JSX interpolation
    expect(screen.getByText(/redis/)).toBeInTheDocument();
    expect(screen.getByText(/3 \/ 10/)).toBeInTheDocument();
  });

  it("disables Scan All button when scanning", () => {
    mockUseScanStatus.mockReturnValue({
      data: { status: "scanning", current_container: "nginx", progress_current: 1, progress_total: 5 },
      isLoading: false,
    });

    renderWithProviders(<Dashboard />);

    // The scan button should be disabled when scanning
    const scanButtons = screen.getAllByRole("button");
    const scanAllBtn = scanButtons.find(
      (btn) => btn.textContent?.includes("Scanning"),
    );
    expect(scanAllBtn).toBeDefined();
    expect(scanAllBtn).toBeDisabled();
  });

  it("renders secret detection section when secrets exist", () => {
    renderWithProviders(<Dashboard />);

    expect(screen.getByText("Secret Detection")).toBeInTheDocument();
    expect(screen.getByText("Exposed credentials detected in container images")).toBeInTheDocument();
    expect(screen.getByText("generic-api-key: 3")).toBeInTheDocument();
    expect(screen.getByText("aws-access-key: 2")).toBeInTheDocument();
  });

  it("does not render secret detection section when no secrets", () => {
    mockUseSecretsSummary.mockReturnValue({
      data: {
        total_secrets: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        affected_containers: 0,
        top_categories: {},
      },
      isLoading: false,
    });

    renderWithProviders(<Dashboard />);

    expect(screen.queryByText("Secret Detection")).not.toBeInTheDocument();
  });
});
