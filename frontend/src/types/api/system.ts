/**
 * System type definitions.
 * Generated types aliased from OpenAPI; hand-maintained types below.
 */

import type { components } from '../api.generated';

// Generated aliases
export type ScannerInfo = components['schemas']['ScannerInfo'];
export type ScannersInfoResponse = components['schemas']['ScannersInfoResponse'];
export type Setting = components['schemas']['Setting'];
export type SettingUpdateResponse = components['schemas']['SettingUpdateResponse'];
export type TestConnectionResult = components['schemas']['TestConnectionResult'];
export type APIKeyCreate = components['schemas']['APIKeyCreate'];
export type APIKeyCreated = components['schemas']['APIKeyCreated'];
export type APIKeyList = components['schemas']['APIKeyList'];

// Generated with name mapping
export type AppInfo = components['schemas']['AppInfoResponse'];
export type APIKey = components['schemas']['APIKeyResponse'];

// Hand-maintained: frontend-only types not in OpenAPI spec

export interface TrivyDbInfo {
  db_version: number | null;
  updated_at: string | null;
  next_update: string | null;
  downloaded_at: string | null;
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
