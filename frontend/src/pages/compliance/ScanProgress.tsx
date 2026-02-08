/**
 * ScanProgress - Real-time compliance scan progress bar.
 */

import { Loader2 } from "lucide-react";
import type { CurrentScan } from "./types";

interface ScanProgressProps {
  currentScan: CurrentScan;
}

export function ScanProgress({ currentScan }: ScanProgressProps): React.ReactElement {
  return (
    <div className="mb-6 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />
          <div>
            <p className="text-blue-400 font-medium">Compliance scan in progress...</p>
            {currentScan.current_check && (
              <p className="text-sm text-vuln-text-muted mt-0.5">
                {currentScan.current_check_id && (
                  <span className="font-mono text-blue-300">[{currentScan.current_check_id}]</span>
                )}{" "}
                {currentScan.current_check}
              </p>
            )}
          </div>
        </div>
        {currentScan.progress_current !== null && currentScan.progress_total !== null && (
          <span className="text-sm text-vuln-text-muted font-medium">
            {currentScan.progress_current} / {currentScan.progress_total} checks
          </span>
        )}
      </div>

      {/* Progress Bar */}
      {currentScan.progress_current !== null && currentScan.progress_total !== null && (
        <div className="w-full bg-vuln-surface rounded-full h-2">
          <div
            className="bg-blue-500 h-full rounded-full transition-all duration-300"
            style={{
              width: `${(currentScan.progress_current / currentScan.progress_total) * 100}%`,
            }}
          />
        </div>
      )}
    </div>
  );
}
