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

export interface Setting {
  key: string;
  value: string;
  description: string | null;
  updated_at: string;
}

export interface TestConnectionResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

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
