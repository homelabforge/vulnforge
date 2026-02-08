/**
 * Compliance badge renderers and shared utilities.
 */

import type { ReactNode } from "react";
import { CheckCircle, AlertCircle, XCircle, Info } from "lucide-react";
import type { ComplianceFinding, GroupedFinding } from "./types";

export function getStatusBadge(status: string): ReactNode {
  const badges: Record<string, ReactNode> = {
    PASS: (
      <span className="px-2 py-1 rounded-full text-xs font-medium bg-green-500/20 text-green-400 flex items-center gap-1">
        <CheckCircle className="w-3 h-3" />
        PASS
      </span>
    ),
    WARN: (
      <span className="px-2 py-1 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400 flex items-center gap-1">
        <AlertCircle className="w-3 h-3" />
        WARN
      </span>
    ),
    FAIL: (
      <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400 flex items-center gap-1">
        <XCircle className="w-3 h-3" />
        FAIL
      </span>
    ),
    INFO: (
      <span className="px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400 flex items-center gap-1">
        <Info className="w-3 h-3" />
        INFO
      </span>
    ),
    NOTE: (
      <span className="px-2 py-1 rounded-full text-xs font-medium bg-vuln-text-disabled/20 text-vuln-text-muted flex items-center gap-1">
        <Info className="w-3 h-3" />
        NOTE
      </span>
    ),
  };
  return badges[status] || status;
}

export function getSeverityBadge(severity: string): ReactNode {
  const badges: Record<string, ReactNode> = {
    HIGH: <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400">HIGH</span>,
    MEDIUM: <span className="px-2 py-1 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400">MEDIUM</span>,
    LOW: <span className="px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400">LOW</span>,
    INFO: <span className="px-2 py-1 rounded-full text-xs font-medium bg-vuln-text-disabled/20 text-vuln-text-muted">INFO</span>,
  };
  return badges[severity] || severity;
}

export function getScoreColor(score: number | null): string {
  if (!score) return "text-vuln-text-muted";
  if (score >= 90) return "text-green-400";
  if (score >= 70) return "text-yellow-400";
  return "text-red-400";
}

/** Group findings by check_id for the aggregated table view. */
export function groupFindings(findings: ComplianceFinding[]): GroupedFinding[] {
  const groups = new Map<string, GroupedFinding>();

  for (const finding of findings) {
    const existing = groups.get(finding.check_id);
    if (existing) {
      existing.findings.push(finding);
      if (finding.status === "PASS") existing.passCount++;
      else if (finding.status === "WARN") existing.warnCount++;
      else if (finding.status === "FAIL") existing.failCount++;
      else existing.infoCount++;

      // Update worst status (FAIL > WARN > INFO > PASS)
      if (finding.status === "FAIL") existing.worstStatus = "FAIL";
      else if (finding.status === "WARN" && existing.worstStatus !== "FAIL") existing.worstStatus = "WARN";

      if (finding.target) existing.hasTargets = true;
    } else {
      groups.set(finding.check_id, {
        check_id: finding.check_id,
        title: finding.title,
        description: finding.description,
        category: finding.category,
        severity: finding.severity,
        remediation: finding.remediation,
        findings: [finding],
        passCount: finding.status === "PASS" ? 1 : 0,
        warnCount: finding.status === "WARN" ? 1 : 0,
        failCount: finding.status === "FAIL" ? 1 : 0,
        infoCount: finding.status !== "PASS" && finding.status !== "WARN" && finding.status !== "FAIL" ? 1 : 0,
        worstStatus: finding.status,
        hasTargets: !!finding.target,
      });
    }
  }

  return Array.from(groups.values()).sort((a, b) => a.check_id.localeCompare(b.check_id));
}
