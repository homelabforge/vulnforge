/**
 * Tests for API client core: ApiError class and error handling
 */
import { describe, it, expect } from "vitest";
import { ApiError } from "../api";
import type { ApiErrorResponse } from "../api";

function makeResponse(status: number, statusText = "Error"): Response {
  return {
    status,
    statusText,
    ok: status >= 200 && status < 300,
    headers: new Headers(),
    redirected: false,
    type: "basic",
    url: "http://localhost/api/v1/test",
  } as Response;
}

describe("ApiError", () => {
  it("sets status from response", () => {
    const res = makeResponse(404, "Not Found");
    const data: ApiErrorResponse = { detail: "Item not found" };
    const err = new ApiError(res, data);

    expect(err.status).toBe(404);
    expect(err.detail).toBe("Item not found");
    expect(err.message).toBe("Item not found");
    expect(err.name).toBe("ApiError");
  });

  it("captures suggestions from response data", () => {
    const res = makeResponse(400);
    const data: ApiErrorResponse = {
      detail: "Invalid input",
      suggestions: ["Check the field format", "Review the docs"],
    };
    const err = new ApiError(res, data);

    expect(err.suggestions).toEqual(["Check the field format", "Review the docs"]);
  });

  it("captures error_type from response data", () => {
    const res = makeResponse(409);
    const data: ApiErrorResponse = {
      detail: "Already exists",
      error_type: "CONFLICT",
    };
    const err = new ApiError(res, data);

    expect(err.errorType).toBe("CONFLICT");
  });

  it("captures is_retryable from response data", () => {
    const res = makeResponse(503);
    const data: ApiErrorResponse = {
      detail: "Service unavailable",
      is_retryable: true,
    };
    const err = new ApiError(res, data);

    expect(err.isRetryable).toBe(true);
  });

  it("leaves optional fields undefined when not present", () => {
    const res = makeResponse(500);
    const data: ApiErrorResponse = { detail: "Internal error" };
    const err = new ApiError(res, data);

    expect(err.errorType).toBeUndefined();
    expect(err.suggestions).toBeUndefined();
    expect(err.isRetryable).toBeUndefined();
  });

  it("is an instance of Error", () => {
    const res = makeResponse(400);
    const data: ApiErrorResponse = { detail: "Bad request" };
    const err = new ApiError(res, data);

    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ApiError);
  });

  it("has a stack trace", () => {
    const res = makeResponse(500);
    const data: ApiErrorResponse = { detail: "Server error" };
    const err = new ApiError(res, data);

    expect(err.stack).toBeDefined();
  });

  it("works correctly with different status codes", () => {
    const cases = [
      { status: 400, text: "Bad Request" },
      { status: 401, text: "Unauthorized" },
      { status: 403, text: "Forbidden" },
      { status: 404, text: "Not Found" },
      { status: 422, text: "Unprocessable Entity" },
      { status: 500, text: "Internal Server Error" },
      { status: 503, text: "Service Unavailable" },
    ];

    for (const { status, text } of cases) {
      const err = new ApiError(makeResponse(status, text), { detail: text });
      expect(err.status).toBe(status);
      expect(err.detail).toBe(text);
    }
  });
});
