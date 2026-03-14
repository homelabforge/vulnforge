/**
 * API client core: error types, response handlers, and base URL
 */

export const API_BASE = "/api/v1";

// Error response types matching backend
export interface ApiErrorResponse {
  detail: string;
  status_code?: number;
  error_type?: string;
  suggestions?: string[];
  is_retryable?: boolean;
}

export class ApiError extends Error {
  status: number;
  detail: string;
  errorType?: string;
  suggestions?: string[];
  isRetryable?: boolean;

  constructor(response: Response, data: ApiErrorResponse) {
    super(data.detail);
    this.name = "ApiError";
    this.status = response.status;
    this.detail = data.detail;
    this.errorType = data.error_type;
    this.suggestions = data.suggestions;
    this.isRetryable = data.is_retryable;
  }
}

// Helper function to handle API responses
export async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorData: ApiErrorResponse;
    try {
      errorData = await res.json();
    } catch {
      errorData = { detail: `HTTP ${res.status}: ${res.statusText}` };
    }
    throw new ApiError(res, errorData);
  }
  return res.json();
}

// Helper function to handle blob responses (file downloads)
export async function handleBlobResponse(res: Response): Promise<Blob> {
  if (!res.ok) {
    let errorData: ApiErrorResponse;
    try {
      errorData = await res.json();
    } catch {
      errorData = { detail: `HTTP ${res.status}: ${res.statusText}` };
    }
    throw new ApiError(res, errorData);
  }
  return res.blob();
}
