/**
 * Tests for ErrorBoundary component
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ErrorBoundary } from "../ErrorBoundary";

// Mock errorHandler
vi.mock("@/lib/errorHandler", () => ({
  formatErrorDetails: (error: unknown) => {
    if (error instanceof Error) {
      return {
        title: "Test Error",
        message: error.message,
        suggestions: [],
        isRetryable: false,
      };
    }
    return { title: "Unknown", message: String(error) };
  },
}));

// Mock api module for ApiError check
vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    detail: string;
    constructor(status: number, detail: string) {
      super(detail);
      this.status = status;
      this.detail = detail;
    }
  },
}));

// Component that throws on demand
function ThrowingComponent({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) {
    throw new Error("Test component error");
  }
  return <div>Working content</div>;
}

// Suppress console.error for expected errors
const originalError = console.error;
beforeEach(() => {
  console.error = vi.fn();
});
afterEach(() => {
  console.error = originalError;
});

describe("ErrorBoundary", () => {
  it("renders children when no error", () => {
    render(
      <ErrorBoundary>
        <div>Hello</div>
      </ErrorBoundary>
    );
    expect(screen.getByText("Hello")).toBeInTheDocument();
  });

  it("shows error UI when a child throws", () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.queryByText("Working content")).not.toBeInTheDocument();
    expect(screen.getByText("Test Error")).toBeInTheDocument();
  });

  it("shows the error message", () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText("Test component error")).toBeInTheDocument();
  });

  it("has a 'Return to Dashboard' button", () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText("Return to Dashboard")).toBeInTheDocument();
  });

  it("has a 'Reload Page' button", () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText("Reload Page")).toBeInTheDocument();
  });

  it("has a 'Copy Error' button", () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText("Copy Error")).toBeInTheDocument();
  });

  it("shows helpful tip about clearing cache", () => {
    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText(/clearing your browser cache/)).toBeInTheDocument();
  });

  it("copies error to clipboard", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      writable: true,
      configurable: true,
    });

    render(
      <ErrorBoundary>
        <ThrowingComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    await user.click(screen.getByText("Copy Error"));
    expect(writeText).toHaveBeenCalled();
    const copied = writeText.mock.calls[0][0] as string;
    expect(copied).toContain("VulnForge Error Report");
    expect(copied).toContain("Test component error");
  });
});
