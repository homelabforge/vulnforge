/**
 * Scan History Timeline - Visual timeline of container scans
 */

import { Clock, CheckCircle, XCircle, Bug, Key, TrendingDown, TrendingUp } from "lucide-react";
import { formatRelativeDate, formatDate } from "@/lib/utils";
import { useTimezone } from "@/contexts/SettingsContext";

interface ScanHistoryItem {
  id: number;
  scan_date: string;
  scan_status: string;
  scan_duration_seconds: number | null;
  total_vulns: number;
  fixable_vulns: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

interface ScanHistoryTimelineProps {
  history: ScanHistoryItem[];
  isLoading?: boolean;
}

export function ScanHistoryTimeline({ history, isLoading }: ScanHistoryTimelineProps) {
  const timezone = useTimezone();

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map((i) => (
          <div key={i} className="bg-vuln-surface border border-vuln-border rounded-lg p-6 animate-pulse">
            <div className="h-4 bg-vuln-surface-light rounded w-1/4 mb-2"></div>
            <div className="h-3 bg-vuln-surface-light rounded w-1/2"></div>
          </div>
        ))}
      </div>
    );
  }

  if (!history || history.length === 0) {
    return (
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-8 text-center">
        <Clock className="w-12 h-12 text-vuln-text-disabled mx-auto mb-3" />
        <p className="text-vuln-text-muted">No scan history available</p>
        <p className="text-sm text-vuln-text-disabled mt-1">Run a scan to see history</p>
      </div>
    );
  }

  // Calculate trends
  const getTrend = (current: number, previous: number | undefined) => {
    if (previous === undefined) return null;
    if (current > previous) return "up";
    if (current < previous) return "down";
    return "same";
  };

  return (
    <div className="space-y-4">
      {history.map((scan, index) => {
        const previousScan = history[index + 1];
        const vulnTrend = getTrend(scan.total_vulns, previousScan?.total_vulns);

        return (
          <div
            key={scan.id}
            className="bg-vuln-surface border border-vuln-border rounded-lg p-6 hover:border-vuln-border transition-colors relative"
          >
            {/* Timeline Line */}
            {index < history.length - 1 && (
              <div className="absolute left-8 top-full h-4 w-0.5 bg-vuln-surface" />
            )}

            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                {scan.scan_status === "completed" ? (
                  <CheckCircle className="w-6 h-6 text-green-500" />
                ) : scan.scan_status === "failed" ? (
                  <XCircle className="w-6 h-6 text-red-500" />
                ) : (
                  <Clock className="w-6 h-6 text-yellow-500" />
                )}
                <div>
                  <p className="text-vuln-text font-medium">
                    {formatRelativeDate(scan.scan_date, timezone)}
                  </p>
                  <p className="text-sm text-vuln-text-muted">
                    {formatDate(scan.scan_date, timezone)} · Duration:{" "}
                    {scan.scan_duration_seconds != null ? `${scan.scan_duration_seconds}s` : "N/A"}
                  </p>
                </div>
              </div>

              {/* Trend Indicator */}
              {vulnTrend && vulnTrend !== "same" && (
                <div
                  className={`flex items-center gap-1 px-2 py-1 rounded text-xs ${
                    vulnTrend === "up"
                      ? "bg-red-500/10 text-red-500"
                      : "bg-green-500/10 text-green-500"
                  }`}
                >
                  {vulnTrend === "up" ? (
                    <>
                      <TrendingUp className="w-3 h-3" />
                      +{scan.total_vulns - (previousScan?.total_vulns || 0)}
                    </>
                  ) : (
                    <>
                      <TrendingDown className="w-3 h-3" />
                      -{(previousScan?.total_vulns || 0) - scan.total_vulns}
                    </>
                  )}
                </div>
              )}
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
              {/* Total Vulns */}
              <div className="bg-vuln-surface-light rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Bug className="w-3 h-3 text-vuln-text-muted" />
                  <p className="text-xs text-vuln-text-muted">Total</p>
                </div>
                <p className="text-lg font-bold text-vuln-text">{scan.total_vulns}</p>
              </div>

              {/* Fixable */}
              <div className="bg-vuln-surface-light rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Key className="w-3 h-3 text-vuln-text-muted" />
                  <p className="text-xs text-vuln-text-muted">Fixable</p>
                </div>
                <p className="text-lg font-bold text-green-500">{scan.fixable_vulns}</p>
              </div>

              {/* Critical */}
              <div className="bg-vuln-surface-light rounded-lg p-3">
                <p className="text-xs text-vuln-text-muted mb-1">Critical</p>
                <p className="text-lg font-bold text-red-500">{scan.critical_count}</p>
              </div>

              {/* High */}
              <div className="bg-vuln-surface-light rounded-lg p-3">
                <p className="text-xs text-vuln-text-muted mb-1">High</p>
                <p className="text-lg font-bold text-orange-500">{scan.high_count}</p>
              </div>

              {/* Medium */}
              <div className="bg-vuln-surface-light rounded-lg p-3">
                <p className="text-xs text-vuln-text-muted mb-1">Medium</p>
                <p className="text-lg font-bold text-yellow-500">{scan.medium_count}</p>
              </div>

              {/* Low */}
              <div className="bg-vuln-surface-light rounded-lg p-3">
                <p className="text-xs text-vuln-text-muted mb-1">Low</p>
                <p className="text-lg font-bold text-blue-400">{scan.low_count}</p>
              </div>
            </div>

            {/* Status Badge */}
            <div className="mt-3 pt-3 border-t border-vuln-border">
              <span
                className={`text-xs px-2 py-1 rounded ${
                  scan.scan_status === "completed"
                    ? "bg-green-500/10 text-green-500"
                    : scan.scan_status === "failed"
                      ? "bg-red-500/10 text-red-500"
                      : "bg-yellow-500/10 text-yellow-500"
                }`}
              >
                {scan.scan_status.toUpperCase()}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
