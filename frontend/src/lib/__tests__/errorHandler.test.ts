/**
 * Tests for error handling utilities
 */
import { describe, it, expect, vi } from "vitest";
import { ApiError } from "../api";
import type { ApiErrorResponse } from "../api";
import { handleApiError, getStatusMessage, formatErrorDetails, isRetryableError } from "../errorHandler";

// Mock sonner's toast
vi.mock("sonner", () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
  },
}));

function makeApiError(status: number, detail: string, extra?: Partial<ApiErrorResponse>): ApiError {
  const res = { status, statusText: "Error", ok: false } as Response;
  return new ApiError(res, { detail, ...extra });
}

describe("getStatusMessage", () => {
  it("returns correct message for 400", () => {
    expect(getStatusMessage(400)).toBe("Invalid request");
  });

  it("returns correct message for 401", () => {
    expect(getStatusMessage(401)).toBe("Authentication required");
  });

  it("returns correct message for 403", () => {
    expect(getStatusMessage(403)).toBe("Permission denied");
  });

  it("returns correct message for 404", () => {
    expect(getStatusMessage(404)).toBe("Not found");
  });

  it("returns correct message for 409", () => {
    expect(getStatusMessage(409)).toBe("Conflict");
  });

  it("returns correct message for 429", () => {
    expect(getStatusMessage(429)).toBe("Too many requests - please wait");
  });

  it("returns correct message for 500", () => {
    expect(getStatusMessage(500)).toBe("Server error");
  });

  it("returns correct message for 503", () => {
    expect(getStatusMessage(503)).toBe("Service temporarily unavailable");
  });

  it("returns correct message for 504", () => {
    expect(getStatusMessage(504)).toBe("Request timed out");
  });

  it("returns generic message for unknown status", () => {
    expect(getStatusMessage(418)).toBe("An error occurred");
  });
});

describe("formatErrorDetails", () => {
  it("formats ApiError with status message title", () => {
    const err = makeApiError(404, "Container not found");
    const result = formatErrorDetails(err);

    expect(result.title).toBe("Not found");
    expect(result.message).toBe("Container not found");
  });

  it("includes suggestions from ApiError", () => {
    const err = makeApiError(400, "Bad input", {
      suggestions: ["Try a different value"],
    });
    const result = formatErrorDetails(err);

    expect(result.suggestions).toEqual(["Try a different value"]);
  });

  it("includes isRetryable from ApiError", () => {
    const err = makeApiError(503, "Unavailable", { is_retryable: true });
    const result = formatErrorDetails(err);

    expect(result.isRetryable).toBe(true);
  });

  it("formats standard Error", () => {
    const err = new Error("Something broke");
    const result = formatErrorDetails(err);

    expect(result.title).toBe("Error");
    expect(result.message).toBe("Something broke");
    expect(result.suggestions).toBeUndefined();
  });

  it("formats unknown error types", () => {
    const result = formatErrorDetails("string error");

    expect(result.title).toBe("Unknown Error");
    expect(result.message).toBe("string error");
  });

  it("formats number error", () => {
    const result = formatErrorDetails(42);
    expect(result.message).toBe("42");
  });
});

describe("isRetryableError", () => {
  it("respects explicit isRetryable=true", () => {
    const err = makeApiError(400, "Bad request", { is_retryable: true });
    expect(isRetryableError(err)).toBe(true);
  });

  it("respects explicit isRetryable=false", () => {
    const err = makeApiError(500, "Server error", { is_retryable: false });
    expect(isRetryableError(err)).toBe(false);
  });

  it("treats 5xx as retryable when no explicit flag", () => {
    expect(isRetryableError(makeApiError(500, "error"))).toBe(true);
    expect(isRetryableError(makeApiError(502, "error"))).toBe(true);
    expect(isRetryableError(makeApiError(503, "error"))).toBe(true);
  });

  it("treats 504 as retryable", () => {
    expect(isRetryableError(makeApiError(504, "timeout"))).toBe(true);
  });

  it("treats 4xx as not retryable when no explicit flag", () => {
    expect(isRetryableError(makeApiError(400, "error"))).toBe(false);
    expect(isRetryableError(makeApiError(404, "error"))).toBe(false);
    expect(isRetryableError(makeApiError(422, "error"))).toBe(false);
  });

  it("treats network TypeError as retryable", () => {
    const err = new TypeError("Failed to fetch");
    expect(isRetryableError(err)).toBe(true);
  });

  it("treats non-fetch TypeError as not retryable", () => {
    const err = new TypeError("Cannot read property 'foo'");
    expect(isRetryableError(err)).toBe(false);
  });

  it("treats unknown errors as not retryable", () => {
    expect(isRetryableError("string")).toBe(false);
    expect(isRetryableError(null)).toBe(false);
    expect(isRetryableError(42)).toBe(false);
  });
});

describe("handleApiError", () => {
  it("calls toast.error for ApiError", async () => {
    const { toast } = await import("sonner");
    vi.mocked(toast.error).mockClear();

    const err = makeApiError(500, "Server error");
    handleApiError(err, "Fallback message");

    expect(toast.error).toHaveBeenCalledWith("Server error");
  });

  it("includes suggestion in toast description for ApiError with suggestions", async () => {
    const { toast } = await import("sonner");
    vi.mocked(toast.error).mockClear();

    const err = makeApiError(400, "Bad input", {
      suggestions: ["Check field X"],
    });
    handleApiError(err, "Fallback");

    expect(toast.error).toHaveBeenCalledWith("Bad input", {
      description: "Check field X",
      duration: 6000,
    });
  });

  it("uses fallback message with Error description for standard errors", async () => {
    const { toast } = await import("sonner");
    vi.mocked(toast.error).mockClear();

    handleApiError(new Error("network down"), "Operation failed");

    expect(toast.error).toHaveBeenCalledWith("Operation failed", {
      description: "network down",
    });
  });

  it("uses fallback message for unknown errors", async () => {
    const { toast } = await import("sonner");
    vi.mocked(toast.error).mockClear();

    handleApiError("unknown", "Something went wrong");

    expect(toast.error).toHaveBeenCalledWith("Something went wrong");
  });
});
