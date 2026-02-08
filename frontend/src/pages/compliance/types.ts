/**
 * Compliance page shared types.
 *
 * API response types are defined in @/lib/api.ts and re-exported here
 * so existing sub-component imports stay unchanged.
 */

import type { ComplianceFinding } from "@/lib/api";

export type {
  ComplianceSummary,
  ComplianceFinding,
  ComplianceTrendPoint as TrendDataPoint,
} from "@/lib/api";
export type { ComplianceCurrentScan as CurrentScan } from "@/lib/api";

export interface GroupedFinding {
  check_id: string;
  title: string;
  description: string | null;
  category: string;
  severity: string;
  remediation: string | null;
  findings: ComplianceFinding[];
  passCount: number;
  warnCount: number;
  failCount: number;
  infoCount: number;
  worstStatus: string;
  hasTargets: boolean;
}
