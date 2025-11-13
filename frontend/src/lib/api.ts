/**
 * API client for VulnForge backend
 */

const API_BASE = "/api/v1";

// Types
export interface Container {
  id: number;
  name: string;
  image: string;
  image_tag: string;
  image_id: string;
  is_running: boolean;
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

export interface ScannerComparison {
  total_trivy: number;
  trivy_by_severity: Record<string, number>;
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
    if (!res.ok) throw new Error("Failed to fetch containers");
    return res.json();
  },

  getById: async (id: number): Promise<Container> => {
    const res = await fetch(`${API_BASE}/containers/${id}`);
    if (!res.ok) throw new Error("Failed to fetch container");
    return res.json();
  },

  discover: async (): Promise<{ total: number; discovered: string[] }> => {
    const res = await fetch(`${API_BASE}/containers/discover`, {
      method: "POST",
    });
    if (!res.ok) throw new Error("Failed to discover containers");
    return res.json();
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
    if (!res.ok) throw new Error("Failed to trigger scan");
    return res.json();
  },

  getCurrent: async (): Promise<ScanStatus> => {
    const res = await fetch(`${API_BASE}/scans/current`);
    if (!res.ok) throw new Error("Failed to get current scan");
    return res.json();
  },

  getTrends: async (windowDays = 30): Promise<ScanTrendsResponse> => {
    const res = await fetch(`${API_BASE}/scans/trends?window_days=${windowDays}`);
    if (!res.ok) throw new Error("Failed to get scan trends");
    return res.json();
  },

  getHistory: async (containerId: number): Promise<ScanHistoryEntry[]> => {
    const res = await fetch(`${API_BASE}/scans/history/${containerId}`);
    if (!res.ok) throw new Error("Failed to get scan history");
    return res.json();
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
    limit?: number;
    offset?: number;
  }): Promise<PaginatedVulnerabilities> => {
    const query = new URLSearchParams();
    if (params?.severity) query.append("severity", params.severity);
    if (params?.fixable_only) query.append("fixable_only", "true");
    if (params?.kev_only) query.append("kev_only", "true");
    if (params?.status) query.append("status", params.status);
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());

    const res = await fetch(`${API_BASE}/vulnerabilities/?${query}`);
    if (!res.ok) throw new Error("Failed to fetch vulnerabilities");
    return res.json();
  },

  getById: async (id: number): Promise<Vulnerability> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/${id}`);
    if (!res.ok) throw new Error("Failed to fetch vulnerability");
    return res.json();
  },

  updateStatus: async (id: number, status: string, notes?: string): Promise<Vulnerability> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    });
    if (!res.ok) throw new Error("Failed to update vulnerability");
    return res.json();
  },

  bulkUpdate: async (ids: number[], status: string, notes?: string): Promise<{ updated: number }> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/bulk-update`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vuln_ids: ids, update: { status, notes } }),
    });
    if (!res.ok) throw new Error("Failed to bulk update vulnerabilities");
    return res.json();
  },

  getRemediationGroups: async (containerId?: number): Promise<RemediationGroup[]> => {
    const query = containerId ? `?container_id=${containerId}` : "";
    const res = await fetch(`${API_BASE}/vulnerabilities/remediation-groups${query}`);
    if (!res.ok) throw new Error("Failed to get remediation groups");
    return res.json();
  },

  getScannerComparison: async (): Promise<ScannerComparison> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/scanner/comparison`);
    if (!res.ok) throw new Error("Failed to get scanner comparison");
    return res.json();
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
    if (!res.ok) throw new Error("Failed to export vulnerabilities");
    return res.blob();
  },
};

// Secrets
export const secretsApi = {
  getContainerSecrets: async (containerId: number): Promise<Secret[]> => {
    const res = await fetch(`${API_BASE}/containers/${containerId}/secrets`);
    if (!res.ok) throw new Error("Failed to fetch container secrets");
    return res.json();
  },

  getScanSecrets: async (scanId: number): Promise<Secret[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/secrets`);
    if (!res.ok) throw new Error("Failed to fetch scan secrets");
    return res.json();
  },

  getSummary: async (): Promise<SecretSummary> => {
    const res = await fetch(`${API_BASE}/secrets/summary`);
    if (!res.ok) throw new Error("Failed to fetch secrets summary");
    return res.json();
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
    if (!res.ok) throw new Error("Failed to fetch secrets");
    return res.json();
  },

  updateStatus: async (id: number, status: string, notes?: string): Promise<Secret> => {
    const res = await fetch(`${API_BASE}/secrets/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    });
    if (!res.ok) throw new Error("Failed to update secret");
    return res.json();
  },

  bulkUpdate: async (ids: number[], status: string, notes?: string): Promise<{ updated: number }> => {
    const res = await fetch(`${API_BASE}/secrets/bulk-update`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret_ids: ids, update: { status, notes } }),
    });
    if (!res.ok) throw new Error("Failed to bulk update secrets");
    return res.json();
  },
};

// Widget
export const widgetApi = {
  getSummary: async (): Promise<WidgetSummary> => {
    const res = await fetch(`${API_BASE}/widget/summary`);
    if (!res.ok) throw new Error("Failed to fetch widget summary");
    return res.json();
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

export const systemApi = {
  getTrivyDbInfo: async (): Promise<TrivyDbInfo> => {
    const res = await fetch(`${API_BASE}/system/trivy-db-info`);
    if (!res.ok) throw new Error("Failed to fetch Trivy DB info");
    return res.json();
  },

  getScannersInfo: async (): Promise<ScannersInfoResponse> => {
    const res = await fetch(`${API_BASE}/system/scanners`);
    if (!res.ok) throw new Error("Failed to fetch scanners info");
    return res.json();
  },
};

// Settings
export interface Setting {
  key: string;
  value: string;
  description: string | null;
  updated_at: string;
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

export const settingsApi = {
  getAll: async (): Promise<Setting[]> => {
    const res = await fetch(`${API_BASE}/settings/`);
    if (!res.ok) throw new Error("Failed to fetch settings");
    return res.json();
  },

  getByKey: async (key: string): Promise<Setting> => {
    const res = await fetch(`${API_BASE}/settings/${key}`);
    if (!res.ok) throw new Error("Failed to fetch setting");
    return res.json();
  },

  update: async (key: string, value: string): Promise<Setting> => {
    const res = await fetch(`${API_BASE}/settings/${key}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value }),
    });
    if (!res.ok) throw new Error("Failed to update setting");
    return res.json();
  },

  bulkUpdate: async (settings: Record<string, string>): Promise<Setting[]> => {
    const res = await fetch(`${API_BASE}/settings/bulk`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ settings }),
    });
    if (!res.ok) throw new Error("Failed to bulk update settings");
    return res.json();
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
    if (!res.ok) throw new Error("Failed to fetch activities");
    return res.json();
  },

  getTypes: async (): Promise<{ types: ActivityTypeCount[] }> => {
    const res = await fetch(`${API_BASE}/activity/types`);
    if (!res.ok) throw new Error("Failed to fetch activity types");
    return res.json();
  },

  getByContainer: async (containerId: number, limit?: number): Promise<ActivityLog[]> => {
    const query = limit ? `?limit=${limit}` : "";
    const res = await fetch(`${API_BASE}/activity/container/${containerId}${query}`);
    if (!res.ok) throw new Error("Failed to fetch container activities");
    return res.json();
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
    if (!res.ok) throw new Error("Failed to fetch current user");
    return res.json();
  },

  getAuthStatus: async (): Promise<AuthStatus> => {
    const res = await fetch(`${API_BASE}/auth/status`);
    if (!res.ok) throw new Error("Failed to fetch auth status");
    return res.json();
  },
};
