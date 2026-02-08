/**
 * API client for VulnForge backend
 */

const API_BASE = "/api/v1";

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
async function handleResponse<T>(res: Response): Promise<T> {
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

// Types
export interface Container {
  id: number;
  name: string;
  image: string;
  image_tag: string;
  image_id: string;
  is_running: boolean;
  is_my_project: boolean;
  total_vulns: number;
  fixable_vulns: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  last_scan_date: string | null;
  scanner_coverage: number | null;
  dive_efficiency_score: number | null;
  dive_inefficient_bytes: number | null;
  dive_image_size_bytes: number | null;
  dive_layer_count: number | null;
  dive_analyzed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: number;
  cve_id: string;
  container_name: string;
  container_id: number;
  package_name: string;
  severity: string;
  cvss_score: number | null;
  installed_version: string;
  fixed_version: string | null;
  is_fixable: boolean;
  status: string;
  title: string | null;
  description?: string | null;
  notes?: string | null;
  is_kev: boolean;
  kev_added_date: string | null;
  kev_due_date: string | null;
}

export interface RemediationGroup {
  package_name: string;
  installed_version: string;
  fixed_version: string;
  cve_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface Secret {
  id: number;
  scan_id: number;
  rule_id: string;
  category: string;
  title: string;
  severity: string;
  match: string;
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  code_snippet: string | null;
  layer_digest: string | null;
  status: string;
  notes: string | null;
  redacted?: boolean;
  created_at: string;
  updated_at: string | null;
}

export interface SecretSummary {
  total_secrets: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  affected_containers: number;
  top_categories: Record<string, number>;
}

export interface ScanStatus {
  status: "idle" | "scanning";
  current_container?: string;
  progress_current?: number;
  progress_total?: number;
  scan_id?: number;
  started_at?: string;
  queue?: {
    queue_size: number;
    active_scans: number;
    current_scan: string | null;
    workers_active: number;
    batch_total: number;
    batch_completed: number;
  };
}

export interface ScanHistoryEntry {
  id: number;
  container_id: number;
  image_scanned: string;
  scan_date: string;
  scan_status: string;
  scan_duration_seconds: number | null;
  error_message: string | null;
  total_vulns: number;
  fixable_vulns: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface WidgetSummary {
  total_containers: number;
  scanned_containers: number;
  last_scan: string | null;
  total_vulnerabilities: number;
  fixable_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_secrets: number;
}

export interface ScanTrendPoint {
  date: string;
  total_scans: number;
  completed_scans: number;
  failed_scans: number;
  total_vulns: number;
  fixable_vulns: number;
  critical_vulns: number;
  high_vulns: number;
  avg_duration_seconds: number | null;
}

export interface TrendVelocityMetric {
  current: number | null;
  previous: number | null;
  delta: number | null;
  percent_change: number | null;
}

export interface ScanTrendsResponse {
  window_days: number;
  series: ScanTrendPoint[];
  summary: {
    total_scans: number;
    completed_scans: number;
    failed_scans: number;
    total_vulns: number;
    fixable_vulns: number;
    critical_vulns: number;
    high_vulns: number;
    avg_duration_seconds: number | null;
  };
  velocity: {
    completed_scans: TrendVelocityMetric;
    fixable_vulns: TrendVelocityMetric;
    avg_duration_seconds: TrendVelocityMetric;
  };
}

// API Functions

// Containers
export const containersApi = {
  getAll: async (): Promise<{ containers: Container[]; total: number }> => {
    const res = await fetch(`${API_BASE}/containers/`);
    return handleResponse(res);
  },

  getById: async (id: number): Promise<Container> => {
    const res = await fetch(`${API_BASE}/containers/${id}`);
    return handleResponse(res);
  },

  discover: async (): Promise<{ total: number; discovered: string[] }> => {
    const res = await fetch(`${API_BASE}/containers/discover`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  update: async (id: number, updates: { is_my_project?: boolean; is_running?: boolean }): Promise<Container> => {
    const res = await fetch(`${API_BASE}/containers/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updates),
    });
    return handleResponse(res);
  },
};

// Scans
export const scansApi = {
  trigger: async (containerIds?: number[]): Promise<{ message: string; queued: number; skipped: number; total_requested: number }> => {
    const res = await fetch(`${API_BASE}/scans/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ container_ids: containerIds || null }),
    });
    return handleResponse(res);
  },

  getCurrent: async (): Promise<ScanStatus> => {
    const res = await fetch(`${API_BASE}/scans/current`);
    return handleResponse(res);
  },

  getTrends: async (windowDays = 30): Promise<ScanTrendsResponse> => {
    const res = await fetch(`${API_BASE}/scans/trends?window_days=${windowDays}`);
    return handleResponse(res);
  },

  getHistory: async (containerId: number): Promise<ScanHistoryEntry[]> => {
    const res = await fetch(`${API_BASE}/scans/history/${containerId}`);
    return handleResponse(res);
  },
};

// Vulnerabilities
export interface PaginatedVulnerabilities {
  vulnerabilities: Vulnerability[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export const vulnerabilitiesApi = {
  getAll: async (params?: {
    severity?: string;
    fixable_only?: boolean;
    kev_only?: boolean;
    status?: string;
    container_id?: number;
    limit?: number;
    offset?: number;
  }): Promise<PaginatedVulnerabilities> => {
    const query = new URLSearchParams();
    if (params?.severity) query.append("severity", params.severity);
    if (params?.fixable_only) query.append("fixable_only", "true");
    if (params?.kev_only) query.append("kev_only", "true");
    if (params?.status) query.append("status", params.status);
    if (params?.container_id) query.append("container_id", params.container_id.toString());
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());

    const res = await fetch(`${API_BASE}/vulnerabilities/?${query}`);
    return handleResponse(res);
  },

  getById: async (id: number): Promise<Vulnerability> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/${id}`);
    return handleResponse(res);
  },

  updateStatus: async (id: number, status: string, notes?: string): Promise<Vulnerability> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    });
    return handleResponse(res);
  },

  bulkUpdate: async (ids: number[], status: string, notes?: string): Promise<{ updated: number }> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/bulk-update`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vuln_ids: ids, update: { status, notes } }),
    });
    return handleResponse(res);
  },

  getRemediationGroups: async (containerId?: number): Promise<RemediationGroup[]> => {
    const query = containerId ? `?container_id=${containerId}` : "";
    const res = await fetch(`${API_BASE}/vulnerabilities/remediation-groups${query}`);
    return handleResponse(res);
  },

  export: async (format: "csv" | "json", filters?: {
    severity?: string;
    fixable_only?: boolean;
    kev_only?: boolean;
    status?: string;
  }): Promise<Blob> => {
    const query = new URLSearchParams({ format });
    if (filters?.severity) query.append("severity", filters.severity);
    if (filters?.fixable_only) query.append("fixable_only", "true");
    if (filters?.kev_only) query.append("kev_only", "true");
    if (filters?.status) query.append("status", filters.status);

    const res = await fetch(`${API_BASE}/vulnerabilities/export?${query}`);
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
  },
};

// Secrets
export const secretsApi = {
  getContainerSecrets: async (containerId: number): Promise<Secret[]> => {
    const res = await fetch(`${API_BASE}/containers/${containerId}/secrets`);
    return handleResponse(res);
  },

  getScanSecrets: async (scanId: number): Promise<Secret[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/secrets`);
    return handleResponse(res);
  },

  getSummary: async (): Promise<SecretSummary> => {
    const res = await fetch(`${API_BASE}/secrets/summary`);
    return handleResponse(res);
  },

  getAll: async (filters?: {
    severity?: string;
    category?: string;
    limit?: number;
    offset?: number;
  }): Promise<Secret[]> => {
    const query = new URLSearchParams();
    if (filters?.severity) query.append("severity", filters.severity);
    if (filters?.category) query.append("category", filters.category);
    if (filters?.limit) query.append("limit", filters.limit.toString());
    if (filters?.offset) query.append("offset", filters.offset.toString());

    const res = await fetch(`${API_BASE}/secrets/?${query}`);
    return handleResponse(res);
  },

  updateStatus: async (id: number, status: string, notes?: string): Promise<Secret> => {
    const res = await fetch(`${API_BASE}/secrets/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    });
    return handleResponse(res);
  },

  bulkUpdate: async (ids: number[], status: string, notes?: string): Promise<{ updated: number }> => {
    const res = await fetch(`${API_BASE}/secrets/bulk-update`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret_ids: ids, update: { status, notes } }),
    });
    return handleResponse(res);
  },

  export: async (format: "csv" | "json", filters?: {
    severity?: string;
    category?: string;
  }): Promise<Blob> => {
    const params = new URLSearchParams();
    if (filters?.severity) params.append("severity", filters.severity);
    if (filters?.category) params.append("category", filters.category);
    params.append("format", format);
    const res = await fetch(`${API_BASE}/secrets/export?${params}`);
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
  },
};

// Widget
export const widgetApi = {
  getSummary: async (): Promise<WidgetSummary> => {
    const res = await fetch(`${API_BASE}/widget/summary`);
    return handleResponse(res);
  },
};

// System
export interface TrivyDbInfo {
  db_version: number | null;
  updated_at: string | null;
  next_update: string | null;
  downloaded_at: string | null;
}

export interface ScannerInfo {
  name: string;
  enabled: boolean;
  available: boolean;
  version: string | null;
  latest_version: string | null;
  update_available: boolean;
  db_version: string | null;
  db_latest_version: string | null;
  db_update_available: boolean;
  db_updated_at: string | null;
  db_age_hours: number | null;
}

export interface ScannersInfoResponse {
  scanners: ScannerInfo[];
}

export interface AppInfo {
  name: string;
  version: string;
}

export const systemApi = {
  getAppInfo: async (): Promise<AppInfo> => {
    const res = await fetch(`${API_BASE}/system/info`);
    return handleResponse(res);
  },

  getTrivyDbInfo: async (): Promise<TrivyDbInfo> => {
    const res = await fetch(`${API_BASE}/system/trivy-db-info`);
    return handleResponse(res);
  },

  getScannersInfo: async (): Promise<ScannersInfoResponse> => {
    const res = await fetch(`${API_BASE}/system/scanners`);
    return handleResponse(res);
  },
};

// Settings
export interface Setting {
  key: string;
  value: string;
  description: string | null;
  updated_at: string;
}

// API Keys
export interface APIKey {
  id: number;
  name: string;
  description: string | null;
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  is_active: boolean;
  created_by: string;
}

export interface APIKeyCreate {
  name: string;
  description?: string;
}

export interface APIKeyCreated {
  id: number;
  name: string;
  description: string | null;
  key: string;
  key_prefix: string;
  created_at: string;
  created_by: string;
  warning: string;
}

export interface APIKeyList {
  keys: APIKey[];
  total: number;
}

export interface ActivityEventMetadata {
  total_vulns?: number;
  fixable_vulns?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  duration_seconds?: number;
  total_secrets?: number;
  containers_count?: number;
  categories?: string[];
  error_message?: string;
  [key: string]: unknown;
}

export interface TestConnectionResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export const settingsApi = {
  getAll: async (): Promise<Setting[]> => {
    const res = await fetch(`${API_BASE}/settings/`);
    return handleResponse(res);
  },

  getByKey: async (key: string): Promise<Setting> => {
    const res = await fetch(`${API_BASE}/settings/${key}`);
    return handleResponse(res);
  },

  update: async (key: string, value: string): Promise<Setting> => {
    const res = await fetch(`${API_BASE}/settings/${key}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value }),
    });
    return handleResponse(res);
  },

  bulkUpdate: async (settings: Record<string, string>): Promise<Setting[]> => {
    const res = await fetch(`${API_BASE}/settings/bulk`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ settings }),
    });
    return handleResponse(res);
  },

  testDocker: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/settings/test/docker`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  // Multi-service notification test endpoints
  testNtfy: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/ntfy`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testGotify: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/gotify`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testPushover: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/pushover`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testSlack: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/slack`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testDiscord: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/discord`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testTelegram: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/telegram`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  testEmail: async (): Promise<TestConnectionResult> => {
    const res = await fetch(`${API_BASE}/notifications/test/email`, {
      method: "POST",
    });
    return handleResponse(res);
  },
};

// Activity
export interface ActivityLog {
  id: number;
  event_type: string;
  severity: string;
  container_id: number | null;
  container_name: string | null;
  title: string;
  description: string | null;
  event_metadata: ActivityEventMetadata | null;
  timestamp: string;
  created_at: string;
}

export interface ActivityList {
  activities: ActivityLog[];
  total: number;
  event_type_counts: Record<string, number>;
}

export interface ActivityTypeCount {
  type: string;
  count: number;
  label: string;
}

export const activityApi = {
  getRecent: async (params?: {
    limit?: number;
    offset?: number;
    event_type?: string;
    severity?: string;
    container_id?: number;
  }): Promise<ActivityList> => {
    const query = new URLSearchParams();
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());
    if (params?.event_type) query.append("event_type", params.event_type);
    if (params?.severity) query.append("severity", params.severity);
    if (params?.container_id) query.append("container_id", params.container_id.toString());

    const res = await fetch(`${API_BASE}/activity/?${query}`);
    return handleResponse(res);
  },

  getTypes: async (): Promise<{ types: ActivityTypeCount[] }> => {
    const res = await fetch(`${API_BASE}/activity/types`);
    return handleResponse(res);
  },

  getByContainer: async (containerId: number, limit?: number): Promise<ActivityLog[]> => {
    const query = limit ? `?limit=${limit}` : "";
    const res = await fetch(`${API_BASE}/activity/container/${containerId}${query}`);
    return handleResponse(res);
  },
};

// Auth
export interface UserInfo {
  username: string;
  email: string | null;
  groups: string[];
  is_admin: boolean;
  provider: string;
  is_authenticated: boolean;
}

export interface AuthStatus {
  enabled: boolean;
  configured: boolean;
}

export const authApi = {
  getCurrentUser: async (): Promise<UserInfo> => {
    const res = await fetch(`${API_BASE}/auth/me`);
    return handleResponse(res);
  },

  getAuthStatus: async (): Promise<AuthStatus> => {
    const res = await fetch(`${API_BASE}/auth/status`);
    return handleResponse(res);
  },
};

// User Authentication API (single-user JWT auth)
import type {
  UserProfile,
  LoginRequest,
  TokenResponse,
  SetupRequest,
  SetupResponse,
  UpdateProfileRequest,
  ChangePasswordRequest,
  UserAuthStatusResponse,
  MessageResponse,
} from "../types/auth";

export const userAuthApi = {
  // Public endpoints (no auth required)
  getStatus: async (): Promise<UserAuthStatusResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/status`);
    return handleResponse(res);
  },

  login: async (data: LoginRequest): Promise<TokenResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  setup: async (data: SetupRequest): Promise<SetupResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  cancelSetup: async (): Promise<MessageResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/cancel-setup`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  // Protected endpoints (auth required)
  logout: async (): Promise<MessageResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/logout`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  getMe: async (): Promise<UserProfile> => {
    const res = await fetch(`${API_BASE}/user-auth/me`);
    return handleResponse(res);
  },

  updateProfile: async (data: UpdateProfileRequest): Promise<UserProfile> => {
    const res = await fetch(`${API_BASE}/user-auth/me`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  changePassword: async (data: ChangePasswordRequest): Promise<MessageResponse> => {
    const res = await fetch(`${API_BASE}/user-auth/password`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  // OIDC test connection
  testOidcConnection: async (issuerUrl: string, clientId: string, clientSecret: string): Promise<{
    success: boolean;
    provider_reachable: boolean;
    metadata_valid: boolean;
    endpoints_found: boolean;
    errors: string[];
  }> => {
    const res = await fetch(`${API_BASE}/user-auth/oidc/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        issuer_url: issuerUrl,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    return handleResponse(res);
  },
};

// API Keys
export const apiKeysApi = {
  list: async (includeRevoked: boolean = false): Promise<APIKeyList> => {
    const res = await fetch(`${API_BASE}/api-keys?include_revoked=${includeRevoked}`);
    return handleResponse(res);
  },

  create: async (data: APIKeyCreate): Promise<APIKeyCreated> => {
    const res = await fetch(`${API_BASE}/api-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  get: async (id: number): Promise<APIKey> => {
    const res = await fetch(`${API_BASE}/api-keys/${id}`);
    return handleResponse(res);
  },

  revoke: async (id: number): Promise<APIKey> => {
    const res = await fetch(`${API_BASE}/api-keys/${id}`, {
      method: "DELETE",
    });
    return handleResponse(res);
  },
};

// Host Compliance
export interface ComplianceSummary {
  last_scan_date: string | null;
  last_scan_status: string | null;
  compliance_score: number | null;
  total_checks: number;
  passed_checks: number;
  warned_checks: number;
  failed_checks: number;
  info_checks: number;
  note_checks: number;
  high_severity_failures: number;
  medium_severity_failures: number;
  low_severity_failures: number;
  ignored_findings_count: number;
  category_breakdown: { [key: string]: number } | null;
}

export interface ComplianceFinding {
  id: number;
  check_id: string;
  check_number: string | null;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  category: string;
  target: string | null;
  remediation: string | null;
  actual_value: string | null;
  expected_value: string | null;
  is_ignored: boolean;
  ignored_reason: string | null;
  ignored_by: string | null;
  ignored_at: string | null;
  first_seen: string;
  last_seen: string;
  scan_date: string;
}

export interface ComplianceCurrentScan {
  status: string;
  scan_id: number | null;
  started_at: string | null;
  progress: string | null;
  current_check: string | null;
  current_check_id: string | null;
  progress_current: number | null;
  progress_total: number | null;
}

export interface ComplianceTrendPoint {
  date: string;
  compliance_score: number;
  passed_checks: number;
  warned_checks: number;
  failed_checks: number;
  total_checks: number;
  category_scores: { [key: string]: number };
}

export const complianceApi = {
  getSummary: async (): Promise<ComplianceSummary> => {
    const res = await fetch(`${API_BASE}/compliance/summary`);
    return handleResponse(res);
  },

  getCurrentScan: async (): Promise<ComplianceCurrentScan> => {
    const res = await fetch(`${API_BASE}/compliance/current`);
    return handleResponse(res);
  },

  getFindings: async (params?: {
    status_filter?: string;
    category_filter?: string;
    include_ignored?: boolean;
  }): Promise<ComplianceFinding[]> => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.append("status_filter", params.status_filter);
    if (params?.category_filter) query.append("category_filter", params.category_filter);
    if (params?.include_ignored !== undefined) query.append("include_ignored", String(params.include_ignored));
    const res = await fetch(`${API_BASE}/compliance/findings?${query}`);
    return handleResponse(res);
  },

  getTrend: async (days = 30): Promise<ComplianceTrendPoint[]> => {
    const res = await fetch(`${API_BASE}/compliance/scans/trend?days=${days}`);
    return handleResponse(res);
  },

  triggerScan: async (): Promise<{ message: string }> => {
    const res = await fetch(`${API_BASE}/compliance/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trigger_type: "manual" }),
    });
    return handleResponse(res);
  },

  ignoreFinding: async (findingId: number, reason: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/compliance/findings/ignore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId, reason, ignored_by: "user" }),
    });
    return handleResponse(res);
  },

  unignoreFinding: async (findingId: number): Promise<void> => {
    const res = await fetch(`${API_BASE}/compliance/findings/unignore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId }),
    });
    return handleResponse(res);
  },

  getExportUrl: (params?: {
    status_filter?: string;
    category_filter?: string;
    include_ignored?: boolean;
  }): string => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.append("status_filter", params.status_filter);
    if (params?.category_filter) query.append("category_filter", params.category_filter);
    if (params?.include_ignored !== undefined) query.append("include_ignored", String(params.include_ignored));
    return `${API_BASE}/compliance/export/csv?${query}`;
  },
};

// Image Compliance
export interface ImageComplianceSummary {
  last_scan_date: string | null;
  last_scan_status: string | null;
  image_name: string | null;
  compliance_score: number | null;
  total_images_scanned: number;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  fatal_count: number;
  warn_count: number;
  category_breakdown: { [key: string]: number } | null;
}

export interface ImageComplianceImageSummary {
  image_name: string;
  compliance_score: number;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  active_failures: number;
  fatal_count: number;
  warn_count: number;
  last_scan_date: string;
  affected_containers: string[];
}

export interface ImageComplianceFinding {
  id: number;
  check_id: string;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  category: string;
  remediation: string | null;
  alerts: Array<{ code: string; line: number }>;
  is_ignored: boolean;
  ignored_reason: string | null;
  ignored_by: string | null;
  first_seen: string;
  last_seen: string;
}

export interface ImageScanStatus {
  status: "idle" | "scanning";
  mode?: "single" | "batch";
  current_image?: string | null;
  progress_current?: number | null;
  progress_total?: number | null;
  started_at?: string | null;
  targets?: string[];
  last_result?: {
    image_name: string;
    success: boolean;
    error?: string | null;
    finished_at?: string;
  } | null;
}

export const imageComplianceApi = {
  getSummary: async (): Promise<ImageComplianceSummary> => {
    const res = await fetch(`${API_BASE}/image-compliance/summary`);
    return handleResponse(res);
  },

  getImages: async (): Promise<ImageComplianceImageSummary[]> => {
    const res = await fetch(`${API_BASE}/image-compliance/images`);
    return handleResponse(res);
  },

  getFindings: async (imageName: string, params?: {
    status_filter?: string;
    include_ignored?: boolean;
  }): Promise<ImageComplianceFinding[]> => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.append("status_filter", params.status_filter);
    if (params?.include_ignored !== undefined) query.append("include_ignored", String(params.include_ignored));
    const res = await fetch(`${API_BASE}/image-compliance/findings/${encodeURIComponent(imageName)}?${query}`);
    return handleResponse(res);
  },

  getCurrentScan: async (): Promise<ImageScanStatus> => {
    const res = await fetch(`${API_BASE}/image-compliance/current`);
    return handleResponse(res);
  },

  scanImage: async (imageName: string): Promise<{ image_name: string }> => {
    const res = await fetch(`${API_BASE}/image-compliance/scan?image_name=${encodeURIComponent(imageName)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    return handleResponse(res);
  },

  scanAll: async (): Promise<{ image_count: number }> => {
    const res = await fetch(`${API_BASE}/image-compliance/scan-all`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    return handleResponse(res);
  },

  ignoreFinding: async (findingId: number, reason: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/image-compliance/findings/${findingId}/ignore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    return handleResponse(res);
  },

  unignoreFinding: async (findingId: number): Promise<void> => {
    const res = await fetch(`${API_BASE}/image-compliance/findings/${findingId}/unignore`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  getExportUrl: (imageName?: string): string => {
    if (imageName) {
      return `${API_BASE}/image-compliance/export/csv?image_name=${encodeURIComponent(imageName)}`;
    }
    return `${API_BASE}/image-compliance/export/csv`;
  },
};

// Maintenance / Backup
export interface BackupEntry {
  filename: string;
  path: string;
  size_bytes: number;
  size_mb: number;
  created_at: string;
}

export const maintenanceApi = {
  listBackups: async (): Promise<{ backups: BackupEntry[] }> => {
    const res = await fetch(`${API_BASE}/maintenance/backup/list`);
    return handleResponse(res);
  },

  createBackup: async (): Promise<{ filename: string; size_mb: number }> => {
    const res = await fetch(`${API_BASE}/maintenance/backup`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  downloadBackup: async (filename: string): Promise<Blob> => {
    const res = await fetch(`${API_BASE}/maintenance/backup/download/${filename}`);
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
  },

  deleteBackup: async (filename: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/maintenance/backup/${filename}`, {
      method: "DELETE",
    });
    return handleResponse(res);
  },

  restoreBackup: async (filename: string): Promise<{ safety_backup: string }> => {
    const res = await fetch(`${API_BASE}/maintenance/backup/restore/${filename}`, {
      method: "POST",
    });
    return handleResponse(res);
  },
};
