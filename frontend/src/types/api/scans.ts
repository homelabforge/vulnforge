/**
 * Scan type definitions.
 * Generated types aliased from OpenAPI; hand-maintained types below.
 */

import type { components } from '../api.generated';

// Generated alias
export type WidgetSummary = components['schemas']['WidgetSummary'];
export type WidgetTopContainers = components['schemas']['WidgetTopContainers'];
export type ContainerVulnCount = components['schemas']['ContainerVulnCount'];

// Hand-maintained: frontend-only types not in OpenAPI spec

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
