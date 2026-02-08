/**
 * ScoreCard - Compliance score summary with check stats.
 */

import { getScoreColor } from "./complianceUtils";
import type { ComplianceSummary } from "./types";

interface ScoreCardProps {
  summary: ComplianceSummary;
}

export function ScoreCard({ summary }: ScoreCardProps): React.ReactElement {
  return (
    <div className="mb-6 p-6 bg-vuln-surface rounded-lg border border-vuln-border">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Overall Score */}
        <div className="md:col-span-1 text-center border-r border-vuln-border">
          <div className={`text-5xl font-bold ${getScoreColor(summary.compliance_score)}`}>
            {summary.compliance_score?.toFixed(1)}%
          </div>
          <div className="text-vuln-text-muted mt-2">Compliance Score</div>
          <div className="text-xs text-vuln-text-disabled mt-1">
            Last scan: {new Date(summary.last_scan_date!).toLocaleString()}
          </div>
        </div>

        {/* Check Stats */}
        <div className="md:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-green-400">{summary.passed_checks}</div>
            <div className="text-sm text-vuln-text-muted">Passed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-400">{summary.warned_checks}</div>
            <div className="text-sm text-vuln-text-muted">Warnings</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">{summary.failed_checks}</div>
            <div className="text-sm text-vuln-text-muted">Failed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-vuln-text-muted">{summary.ignored_findings_count}</div>
            <div className="text-sm text-vuln-text-muted">Ignored</div>
          </div>
        </div>
      </div>
    </div>
  );
}
