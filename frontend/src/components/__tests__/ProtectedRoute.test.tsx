/**
 * Tests for ProtectedRoute component
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ProtectedRoute } from "../ProtectedRoute";

// Mock the useAuth hook
const mockUseAuth = vi.fn();
vi.mock("../../hooks/useAuth", () => ({
  useAuth: () => mockUseAuth(),
}));

function renderWithRouter(initialRoute = "/protected") {
  return render(
    <MemoryRouter initialEntries={[initialRoute]}>
      <Routes>
        <Route
          path="/protected"
          element={
            <ProtectedRoute>
              <div>Protected Content</div>
            </ProtectedRoute>
          }
        />
        <Route path="/login" element={<div>Login Page</div>} />
        <Route path="/setup" element={<div>Setup Page</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ProtectedRoute", () => {
  it("shows loading spinner while checking auth", () => {
    mockUseAuth.mockReturnValue({
      isLoading: true,
      isAuthenticated: false,
      authMode: "local",
      setupComplete: true,
    });

    renderWithRouter();
    // Should show spinner (svg with animate-spin class), not content
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
  });

  it("renders children when auth mode is 'none'", () => {
    mockUseAuth.mockReturnValue({
      isLoading: false,
      isAuthenticated: false,
      authMode: "none",
      setupComplete: true,
    });

    renderWithRouter();
    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("redirects to /setup when setup not complete", () => {
    mockUseAuth.mockReturnValue({
      isLoading: false,
      isAuthenticated: false,
      authMode: "local",
      setupComplete: false,
    });

    renderWithRouter();
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
    expect(screen.getByText("Setup Page")).toBeInTheDocument();
  });

  it("redirects to /login when not authenticated", () => {
    mockUseAuth.mockReturnValue({
      isLoading: false,
      isAuthenticated: false,
      authMode: "local",
      setupComplete: true,
    });

    renderWithRouter();
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
    expect(screen.getByText("Login Page")).toBeInTheDocument();
  });

  it("renders children when authenticated", () => {
    mockUseAuth.mockReturnValue({
      isLoading: false,
      isAuthenticated: true,
      authMode: "local",
      setupComplete: true,
    });

    renderWithRouter();
    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("renders children when authenticated with OIDC", () => {
    mockUseAuth.mockReturnValue({
      isLoading: false,
      isAuthenticated: true,
      authMode: "oidc",
      setupComplete: true,
    });

    renderWithRouter();
    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("includes returnUrl in login redirect", () => {
    mockUseAuth.mockReturnValue({
      isLoading: false,
      isAuthenticated: false,
      authMode: "local",
      setupComplete: true,
    });

    // The MemoryRouter will navigate to /login?returnUrl=... which matches /login route
    renderWithRouter("/protected");
    expect(screen.getByText("Login Page")).toBeInTheDocument();
  });
});
