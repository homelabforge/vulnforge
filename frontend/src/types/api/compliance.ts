/**
 * Compliance type definitions.
 * Generated types aliased from OpenAPI; hand-maintained types below.
 */

import type { components } from '../api.generated';

// Generated aliases (native compliance)
export type ComplianceSummary = components['schemas']['ComplianceSummary'];
export type ComplianceFinding = components['schemas']['ComplianceFinding'];
export type ComplianceCurrentScan = components['schemas']['ComplianceCurrentScan'];

// Hand-maintained: frontend-only or untyped-endpoint types

export interface ComplianceTrendPoint {
  date: string;
  compliance_score: number;
  passed_checks: number;
  warned_checks: number;
  failed_checks: number;
  total_checks: number;
  category_scores: { [key: string]: number };
}

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
