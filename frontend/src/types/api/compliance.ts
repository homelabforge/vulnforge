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
