/**
 * Shared test data factories
 *
 * Each factory returns a full object with sensible defaults.
 * Pass an overrides object to customise individual fields.
 */

import type {
  Vulnerability,
  ScanHistoryEntry,
  Secret,
  ActivityLog,
} from "@/lib/api";

export function makeVulnerability(
  overrides?: Partial<Vulnerability>,
): Vulnerability {
  return {
    id: 1,
    cve_id: "CVE-2024-12345",
    container_name: "nginx",
    container_id: 1,
    package_name: "libssl3",
    severity: "HIGH",
    cvss_score: 7.5,
    installed_version: "3.0.12-r0",
    fixed_version: "3.0.14-r0",
    is_fixable: true,
    scanner: "trivy",
    confidence: null,
    status: "open",
    title: "OpenSSL buffer overflow vulnerability",
    description: "A buffer overflow exists in libssl allowing remote code execution.",
    notes: null,
    is_kev: false,
    kev_added_date: null,
    kev_due_date: null,
    ...overrides,
  };
}

export function makeScan(
  overrides?: Partial<ScanHistoryEntry>,
): ScanHistoryEntry {
  return {
    id: 1,
    container_id: 1,
    image_scanned: "nginx:latest",
    scan_date: "2025-06-15T12:00:00Z",
    scan_status: "completed",
    scan_duration_seconds: 42,
    error_message: null,
    total_vulns: 5,
    fixable_vulns: 2,
    critical_count: 1,
    high_count: 1,
    medium_count: 2,
    low_count: 1,
    ...overrides,
  };
}

export function makeSecret(overrides?: Partial<Secret>): Secret {
  return {
    id: 1,
    scan_id: 1,
    rule_id: "generic-api-key",
    category: "generic",
    title: "Generic API Key",
    severity: "HIGH",
    match: "AKIAIOSFODNN7EXAMPLE",
    file_path: "/app/config.yml",
    start_line: 12,
    end_line: 12,
    code_snippet: 'api_key: "AKIAIOSFODNN7EXAMPLE"',
    layer_digest: "sha256:abc123",
    status: "open",
    notes: null,
    created_at: "2025-06-15T12:00:00Z",
    updated_at: null,
    ...overrides,
  };
}

export function makeActivityLog(
  overrides?: Partial<ActivityLog>,
): ActivityLog {
  return {
    id: 1,
    event_type: "scan_completed",
    severity: "info",
    container_id: 1,
    container_name: "nginx",
    title: "Scan completed",
    description: "Vulnerability scan completed successfully for nginx",
    event_metadata: {
      total_vulns: 5,
      fixable_vulns: 2,
      critical_count: 1,
      duration_seconds: 42,
    },
    timestamp: "2025-06-15T12:00:00Z",
    created_at: "2025-06-15T12:00:00Z",
    ...overrides,
  };
}
