/**
 * Tests for ContainerCard component
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ContainerCard } from "../ContainerCard";
import type { Container } from "@/lib/api";

function makeContainer(overrides: Partial<Container> = {}): Container {
  return {
    id: 1,
    name: "test-container",
    image: "nginx",
    image_tag: "latest",
    image_id: "sha256:abc123",
    is_running: true,
    is_my_project: false,
    total_vulns: 5,
    fixable_vulns: 2,
    critical_count: 1,
    high_count: 1,
    medium_count: 2,
    low_count: 1,
    last_scan_date: "2025-06-15T12:00:00Z",
    scanner_coverage: 100,
    dive_efficiency_score: 0.95,
    dive_inefficient_bytes: 1024,
    dive_image_size_bytes: 1024 * 1024,
    dive_layer_count: 5,
    dive_analyzed_at: "2025-06-15T12:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-06-15T12:00:00Z",
    ...overrides,
  };
}

function renderCard(props: Partial<Parameters<typeof ContainerCard>[0]> = {}) {
  const defaultProps = {
    container: makeContainer(),
    timezone: "UTC",
    onScan: vi.fn(),
    scanPending: false,
    scanning: false,
    ...props,
  };

  return render(
    <MemoryRouter>
      <ContainerCard {...defaultProps} />
    </MemoryRouter>
  );
}

describe("ContainerCard", () => {
  it("renders the container name", () => {
    renderCard();
    expect(screen.getByText("test-container")).toBeInTheDocument();
  });

  it("shows 'Running' badge for running containers", () => {
    renderCard({ container: makeContainer({ is_running: true }) });
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("shows 'Stopped' badge for stopped containers", () => {
    renderCard({ container: makeContainer({ is_running: false }) });
    expect(screen.getByText("Stopped")).toBeInTheDocument();
  });

  it("shows image name and tag", () => {
    renderCard({ container: makeContainer({ image: "redis", image_tag: "7.2" }) });
    expect(screen.getByText("redis:7.2")).toBeInTheDocument();
  });

  it("shows 'Clean' badge when no vulns after scan", () => {
    renderCard({
      container: makeContainer({
        total_vulns: 0,
        last_scan_date: "2025-06-15T12:00:00Z",
      }),
    });
    expect(screen.getByText("Clean")).toBeInTheDocument();
  });

  it("does not show 'Clean' badge when there are vulns", () => {
    renderCard({ container: makeContainer({ total_vulns: 3 }) });
    expect(screen.queryByText("Clean")).not.toBeInTheDocument();
  });

  it("shows 'Never scanned' when no last_scan_date", () => {
    renderCard({
      container: makeContainer({ last_scan_date: null }),
    });
    expect(screen.getByText("Never scanned")).toBeInTheDocument();
  });

  it("shows vulnerability counts when scanned", () => {
    renderCard({
      container: makeContainer({
        total_vulns: 10,
        fixable_vulns: 3,
        critical_count: 2,
        high_count: 3,
        medium_count: 4,
        low_count: 1,
      }),
    });
    // Check that Total and Critical labels with counts are displayed
    expect(screen.getByText("10")).toBeInTheDocument(); // total
    expect(screen.getByText("4")).toBeInTheDocument(); // medium (unique value)
    expect(screen.getByText("2")).toBeInTheDocument(); // critical (unique value)
  });

  it("shows dive efficiency score", () => {
    renderCard({
      container: makeContainer({ dive_efficiency_score: 0.92 }),
    });
    expect(screen.getByText("92% efficient")).toBeInTheDocument();
  });

  it("does not show efficiency when score is null", () => {
    renderCard({
      container: makeContainer({ dive_efficiency_score: null }),
    });
    expect(screen.queryByText(/efficient/)).not.toBeInTheDocument();
  });

  it("links to container detail page", () => {
    renderCard({ container: makeContainer({ id: 42 }) });
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "/containers/42");
  });

  it("calls onScan when scan button clicked", async () => {
    const user = userEvent.setup();
    const onScan = vi.fn();
    renderCard({ onScan, container: makeContainer({ id: 7, name: "my-app" }) });

    await user.click(screen.getByRole("button", { name: /scan/i }));
    expect(onScan).toHaveBeenCalledWith(7, "my-app");
  });

  it("shows 'Scanning...' when scanning is true", () => {
    renderCard({ scanning: true });
    expect(screen.getByText("Scanning...")).toBeInTheDocument();
  });

  it("disables scan button when scanning", () => {
    renderCard({ scanning: true });
    expect(screen.getByRole("button")).toBeDisabled();
  });

  it("disables scan button when scanPending", () => {
    renderCard({ scanPending: true });
    expect(screen.getByRole("button")).toBeDisabled();
  });

  it("shows green efficiency badge for high scores", () => {
    renderCard({ container: makeContainer({ dive_efficiency_score: 0.95 }) });
    const badge = screen.getByText("95% efficient");
    expect(badge.className).toContain("green");
  });

  it("shows yellow efficiency badge for medium scores", () => {
    renderCard({ container: makeContainer({ dive_efficiency_score: 0.75 }) });
    const badge = screen.getByText("75% efficient");
    expect(badge.className).toContain("yellow");
  });

  it("shows red efficiency badge for low scores", () => {
    renderCard({ container: makeContainer({ dive_efficiency_score: 0.5 }) });
    const badge = screen.getByText("50% efficient");
    expect(badge.className).toContain("red");
  });
});
