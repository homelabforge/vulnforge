/**
 * ContainerCard - Reusable container summary card for the Containers page.
 */

import { Link } from "react-router-dom";
import { Container as ContainerIcon, Play, Circle, Loader2 } from "lucide-react";
import { formatRelativeDate } from "@/lib/utils";
import type { Container } from "@/lib/api";

interface ContainerCardProps {
  container: Container;
  timezone: string;
  onScan: (containerId: number, containerName: string) => void;
  scanPending: boolean;
  scanning: boolean;
}

export function ContainerCard({ container, timezone, onScan, scanPending, scanning }: ContainerCardProps): React.ReactElement {
  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6 hover:border-vuln-border transition-colors">
      <div className="flex items-start justify-between gap-4">
        <Link
          to={`/containers/${container.id}`}
          className="flex-1 hover:opacity-80 transition-opacity"
        >
          <div className="flex items-center gap-3 mb-2">
            <ContainerIcon className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-semibold text-vuln-text">{container.name}</h3>
            {container.is_running ? (
              <span className="flex items-center gap-1 text-xs px-2 py-1 bg-green-500/10 text-green-500 rounded">
                <Circle className="w-2 h-2 fill-green-500" />
                Running
              </span>
            ) : (
              <span className="flex items-center gap-1 text-xs px-2 py-1 bg-vuln-text-disabled/10 text-vuln-text-disabled rounded">
                <Circle className="w-2 h-2" />
                Stopped
              </span>
            )}
            {container.last_scan_date && container.total_vulns === 0 && (
              <span className="text-xs px-2 py-1 rounded bg-green-500/10 text-green-400 flex items-center gap-1">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                Clean
              </span>
            )}
          </div>

          <div className="space-y-1 text-sm">
            <p className="text-vuln-text-muted">
              <span className="text-vuln-text-disabled">Image:</span>{" "}
              <span className="text-vuln-text">{container.image}:{container.image_tag}</span>
            </p>
            {container.last_scan_date ? (
              <>
                <p className="text-vuln-text-muted">
                  <span className="text-vuln-text-disabled">Last Scan:</span>{" "}
                  <span className="text-vuln-text">{formatRelativeDate(container.last_scan_date, timezone)}</span>
                </p>
                <div className="flex items-end gap-2 flex-wrap">
                  <span className="text-vuln-text-muted">
                    Total: <span className="text-vuln-text font-medium">{container.total_vulns || 0}</span>
                  </span>
                  <span className="text-vuln-text-muted">
                    Fixable: <span className="text-green-500 font-medium">{container.fixable_vulns || 0}</span>
                  </span>
                  <span className="text-vuln-text-muted">
                    Critical: <span className="text-red-500 font-medium">{container.critical_count || 0}</span>
                  </span>
                  <span className="text-vuln-text-muted">
                    High: <span className="text-orange-500 font-medium">{container.high_count || 0}</span>
                  </span>
                  <span className="text-vuln-text-muted">
                    Medium: <span className="text-yellow-500 font-medium">{container.medium_count || 0}</span>
                  </span>
                  <span className="text-vuln-text-muted">
                    Low: <span className="text-lime-500 font-medium">{container.low_count || 0}</span>
                  </span>
                </div>

                <div className="flex items-center gap-4 mt-2 flex-wrap">
                  {container.dive_efficiency_score !== null && (
                    <span className={`text-xs px-2 py-1 rounded ${
                      container.dive_efficiency_score >= 0.9
                        ? 'bg-green-500/10 text-green-500' :
                      container.dive_efficiency_score >= 0.7
                        ? 'bg-yellow-500/10 text-yellow-500' :
                      'bg-red-500/10 text-red-500'
                    }`}>
                      {(container.dive_efficiency_score * 100).toFixed(0)}% efficient
                    </span>
                  )}
                </div>
              </>
            ) : (
              <p className="text-yellow-500 text-sm">Never scanned</p>
            )}
          </div>
        </Link>

        <button
          onClick={() => onScan(container.id, container.name)}
          disabled={scanPending || scanning}
          className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50 flex-shrink-0"
        >
          {scanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Scan
            </>
          )}
        </button>
      </div>
    </div>
  );
}
