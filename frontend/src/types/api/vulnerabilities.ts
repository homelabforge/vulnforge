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

export interface PaginatedVulnerabilities {
  vulnerabilities: Vulnerability[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
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
