/**
 * DataTab - Database backup and data retention settings.
 */

import { useState } from "react";
import { Clock, Database } from "lucide-react";
import { HelpTooltip } from "@/components/HelpTooltip";
import { DatabaseBackupSection } from "@/components/DatabaseBackupSection";
import { parseSettingInt } from "@/schemas/settings";
import { useAutoSave } from "@/hooks/useAutoSave";

interface DataTabProps {
  settingsMap: Record<string, string>;
  onSave: (payload: Record<string, string>) => void;
}

export function DataTab({ settingsMap, onSave }: DataTabProps): React.ReactElement {
  const [keepScanHistoryDays, setKeepScanHistoryDays] = useState(
    parseSettingInt(settingsMap.keep_scan_history_days, 90),
  );

  useAutoSave(
    () => ({
      keep_scan_history_days: keepScanHistoryDays.toString(),
    }),
    onSave,
    [keepScanHistoryDays],
    true,
  );

  return (
    <div className="columns-1 md:columns-2 gap-4 space-y-4">
      {/* Database Backup */}
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <Database className="w-6 h-6 text-purple-500" />
            <div>
              <h2 className="text-xl font-semibold text-vuln-text">Database Backup</h2>
              <p className="text-sm text-vuln-text-muted mt-0.5">
                Backup and restore your VulnForge database.
              </p>
            </div>
          </div>
          <HelpTooltip content="Create and restore database backups. Backups include all containers, scan history, vulnerabilities, and settings. Download backups for disaster recovery or migrate to another instance." />
        </div>

        <div className="space-y-4">
          <DatabaseBackupSection />
        </div>
      </div>

      {/* Data Retention */}
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <Clock className="w-6 h-6 text-blue-500" />
            <div>
              <h2 className="text-xl font-semibold text-vuln-text">Data Retention</h2>
              <p className="text-sm text-vuln-text-muted mt-0.5">
                Configure how long scan history is kept in the database.
              </p>
            </div>
          </div>
          <HelpTooltip content="Control how long historical scan data is retained. Older scans are automatically purged to save disk space. The most recent scan for each container is always kept. Data Retention Policy: Old scan history is cleaned up automatically. Current container states and the latest scan results are always retained regardless of this setting." />
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-vuln-text mb-2">
              Keep Scan History (Days)
            </label>
            <input
              type="number"
              value={keepScanHistoryDays}
              onChange={(e) => setKeepScanHistoryDays(parseSettingInt(e.target.value, 90))}
              min="1"
              max="365"
              className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-vuln-text-disabled mt-1">
              Scan results older than this will be automatically deleted
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
