/**
 * Error handling utilities for VulnForge frontend
 */

import { toast } from "sonner";
import { ApiError } from "./api";

/**
 * Handle API errors with user-friendly toast notifications.
 *
 * Displays detailed error information from the backend, including
 * actionable suggestions when available.
 */
export function handleApiError(error: unknown, fallbackMessage: string) {
  if (error instanceof ApiError) {
    // Show detailed error with suggestions if available
    if (error.suggestions?.length) {
      toast.error(error.detail, {
        description: error.suggestions[0],
        duration: 6000,
      });
    } else {
      toast.error(error.detail);
    }
  } else if (error instanceof Error) {
    toast.error(fallbackMessage, { description: error.message });
  } else {
    toast.error(fallbackMessage);
  }
}

/**
 * Map HTTP status codes to user-friendly messages.
 */
export function getStatusMessage(status: number): string {
  switch (status) {
    case 400:
      return "Invalid request";
    case 401:
      return "Authentication required";
    case 403:
      return "Permission denied";
    case 404:
      return "Not found";
    case 409:
      return "Conflict";
    case 429:
      return "Too many requests - please wait";
    case 500:
      return "Server error";
    case 503:
      return "Service temporarily unavailable";
    case 504:
      return "Request timed out";
    default:
      return "An error occurred";
  }
}

/**
 * Format error for display in error boundaries or modals.
 */
export function formatErrorDetails(error: unknown): {
  title: string;
  message: string;
  suggestions?: string[];
  isRetryable?: boolean;
} {
  if (error instanceof ApiError) {
    return {
      title: getStatusMessage(error.status),
      message: error.detail,
      suggestions: error.suggestions,
      isRetryable: error.isRetryable,
    };
  }

  if (error instanceof Error) {
    return {
      title: "Error",
      message: error.message,
    };
  }

  return {
    title: "Unknown Error",
    message: String(error),
  };
}

/**
 * Check if an error is retryable.
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof ApiError) {
    // Explicit retryable flag from backend
    if (error.isRetryable !== undefined) {
      return error.isRetryable;
    }
    // Default: 5xx errors and timeouts are typically retryable
    return error.status >= 500 || error.status === 504;
  }
  // Network errors are typically retryable
  if (error instanceof TypeError && error.message.includes("fetch")) {
    return true;
  }
  return false;
}
