/**
 * ScanningTab - Scan schedule, offline resilience, UI preferences, scanner management.
 */

import { useState } from "react";
import { Settings as SettingsIcon, RefreshCw, Shield, Database } from "lucide-react";
import { HelpTooltip } from "@/components/HelpTooltip";
import { Toggle } from "@/components/Toggle";
import { ScannerManagementCard } from "@/components/ScannerManagementCard";
import { parseSettingInt } from "@/schemas/settings";
import { useScanStatus } from "@/hooks/useVulnForge";
import { useAutoSave } from "@/hooks/useAutoSave";

interface ScanningTabProps {
  settingsMap: Record<string, string>;
  onSave: (payload: Record<string, string>) => void;
}

export function ScanningTab({ settingsMap, onSave }: ScanningTabProps): React.ReactElement {
  const { data: scanStatus } = useScanStatus();

  // Scan settings
  const [scanSchedule, setScanSchedule] = useState(settingsMap.scan_schedule || "0 2 * * *");
  const [scanTimeout, setScanTimeout] = useState(parseSettingInt(settingsMap.scan_timeout, 300));
  const [parallelScans, setParallelScans] = useState(parseSettingInt(settingsMap.parallel_scans, 3));
  const [enableSecretScanning, setEnableSecretScanning] = useState(settingsMap.enable_secret_scanning !== "false");

  // Compliance settings (no UI in this tab — forwarded to keep backend values intact)
  const complianceScanEnabled = settingsMap.compliance_scan_enabled !== "false";
  const complianceScanSchedule = settingsMap.compliance_scan_schedule || "0 3 * * 0";
  const complianceNotifyOnScan = settingsMap.compliance_notify_on_scan !== "false";
  const complianceNotifyOnFailures = settingsMap.compliance_notify_on_failures !== "false";

  // Scanner offline resilience
  const [scannerDbMaxAgeHours, setScannerDbMaxAgeHours] = useState(parseSettingInt(settingsMap.scanner_db_max_age_hours, 24));
  const [scannerSkipDbUpdateWhenFresh, setScannerSkipDbUpdateWhenFresh] = useState(settingsMap.scanner_skip_db_update_when_fresh !== "false");
  const [scannerAllowStaleDb, setScannerAllowStaleDb] = useState(settingsMap.scanner_allow_stale_db !== "false");
  const [scannerStaleDbWarningHours, setScannerStaleDbWarningHours] = useState(parseSettingInt(settingsMap.scanner_stale_db_warning_hours, 72));

  // UI preferences
  const [defaultSeverityFilter, setDefaultSeverityFilter] = useState(settingsMap.default_severity_filter || "all");
  const [defaultShowFixableOnly, setDefaultShowFixableOnly] = useState(settingsMap.default_show_fixable_only === "true");

  useAutoSave(
    () => ({
      scan_schedule: scanSchedule,
      scan_timeout: scanTimeout.toString(),
      parallel_scans: parallelScans.toString(),
      enable_secret_scanning: enableSecretScanning.toString(),
      compliance_scan_enabled: complianceScanEnabled.toString(),
      compliance_scan_schedule: complianceScanSchedule,
      compliance_notify_on_scan: complianceNotifyOnScan.toString(),
      compliance_notify_on_failures: complianceNotifyOnFailures.toString(),
      scanner_db_max_age_hours: scannerDbMaxAgeHours.toString(),
      scanner_skip_db_update_when_fresh: scannerSkipDbUpdateWhenFresh.toString(),
      scanner_allow_stale_db: scannerAllowStaleDb.toString(),
      scanner_stale_db_warning_hours: scannerStaleDbWarningHours.toString(),
      default_severity_filter: defaultSeverityFilter,
      default_show_fixable_only: defaultShowFixableOnly.toString(),
    }),
    onSave,
    [
      scanSchedule, scanTimeout, parallelScans, enableSecretScanning,
      complianceScanEnabled, complianceScanSchedule, complianceNotifyOnScan, complianceNotifyOnFailures,
      scannerDbMaxAgeHours, scannerSkipDbUpdateWhenFresh, scannerAllowStaleDb, scannerStaleDbWarningHours,
      defaultSeverityFilter, defaultShowFixableOnly,
    ],
    true,
  );

  return (
    <>
      {/* Scanner Management */}
      <div className="mb-6">
        <ScannerManagementCard />
      </div>

      {/* Masonry layout */}
      <div className="columns-1 md:columns-2 gap-4 space-y-4">
        {/* Scan Settings */}
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <Shield className="w-6 h-6 text-blue-500" />
              <div>
                <h2 className="text-xl font-semibold text-vuln-text">Scan Settings</h2>
                <p className="text-sm text-vuln-text-muted mt-0.5">
                  Configure scan schedule and performance.
                </p>
              </div>
            </div>
            <HelpTooltip content="Configure vulnerability scan behavior: schedule, timeout limits, parallel workers, and secret detection. Performance Note: Values above 35 parallel workers may cause timeout errors and database lock issues. Recommended: 30-35 workers for optimal performance. Restart Required: Changes to parallel workers require a container restart to take effect." />
          </div>

          {scanStatus?.status === "scanning" && (
            <div className="flex items-center gap-2 text-sm mb-4 px-2 py-1.5 bg-blue-500/10 border border-blue-500/20 rounded-lg">
              <RefreshCw className="w-4 h-4 text-blue-500 animate-spin" />
              <span className="text-blue-400">
                Scanning {scanStatus.current_container} ({scanStatus.progress_current}/{scanStatus.progress_total})
              </span>
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">Scan Schedule (Cron)</label>
              <input
                type="text"
                value={scanSchedule}
                onChange={(e) => setScanSchedule(e.target.value)}
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="0 2 * * *"
              />
              <p className="text-xs text-vuln-text-disabled mt-1">Current: Daily at 2:00 AM</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">Scan Timeout (seconds)</label>
              <input
                type="number"
                value={scanTimeout}
                onChange={(e) => setScanTimeout(Number(e.target.value))}
                min={60}
                max={600}
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-vuln-text-disabled mt-1">Maximum time per container scan</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">Parallel Scans</label>
              <input
                type="number"
                value={parallelScans}
                onChange={(e) => setParallelScans(Number(e.target.value))}
                min={1}
                max={50}
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-vuln-text-disabled mt-1">Number of containers to scan simultaneously</p>
            </div>

            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                    Enable Secret Detection
                  </span>
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Scan for exposed credentials (API keys, tokens, passwords). Disabling speeds up scans but skips security checks.
                  </p>
                </div>
                <Toggle checked={enableSecretScanning} onChange={setEnableSecretScanning} />
              </label>
            </div>
          </div>
        </div>

        {/* Scanner Offline Resilience */}
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <Database className="w-6 h-6 text-blue-500" />
              <div>
                <h2 className="text-xl font-semibold text-vuln-text">Scanner Offline Resilience</h2>
                <p className="text-sm text-vuln-text-muted mt-0.5">
                  Configure database update behavior.
                </p>
              </div>
            </div>
            <HelpTooltip content="Configure how VulnForge handles vulnerability database updates. These settings help VulnForge work better in environments with limited or unreliable internet connectivity. Enable 'Skip Database Updates When Fresh' to reduce network dependency by ~80%." />
          </div>

          <div className="space-y-4">
            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                    Skip Database Updates When Fresh
                  </span>
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Skip updating scanner databases if they're fresh (saves network bandwidth and scan time)
                  </p>
                </div>
                <Toggle checked={scannerSkipDbUpdateWhenFresh} onChange={setScannerSkipDbUpdateWhenFresh} />
              </label>
            </div>

            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">Maximum Database Age (Hours)</label>
              <input
                type="number"
                value={scannerDbMaxAgeHours}
                onChange={(e) => setScannerDbMaxAgeHours(parseSettingInt(e.target.value, 24))}
                min="1"
                max="168"
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-vuln-text-disabled mt-1">
                Maximum age for scanner databases to be considered "fresh" (default: 24 hours)
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">Stale Database Warning (Hours)</label>
              <input
                type="number"
                value={scannerStaleDbWarningHours}
                onChange={(e) => setScannerStaleDbWarningHours(parseSettingInt(e.target.value, 72))}
                min="1"
                max="720"
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-vuln-text-disabled mt-1">
                Show warnings when scanner databases exceed this age (default: 72 hours)
              </p>
            </div>

            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                    Allow Scans with Stale Databases
                  </span>
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Allow scanning even when databases are older than the maximum age (useful for offline environments)
                  </p>
                </div>
                <Toggle checked={scannerAllowStaleDb} onChange={setScannerAllowStaleDb} />
              </label>
            </div>
          </div>
        </div>

        {/* UI Preferences */}
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <SettingsIcon className="w-6 h-6 text-orange-500" />
              <div>
                <h2 className="text-xl font-semibold text-vuln-text">UI Preferences</h2>
                <p className="text-sm text-vuln-text-muted mt-0.5">
                  Customize default view settings.
                </p>
              </div>
            </div>
            <HelpTooltip content="Customize how vulnerability data is displayed. Set default filters to focus on the severity levels most relevant to your security priorities." />
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">Default Severity Filter</label>
              <select
                value={defaultSeverityFilter}
                onChange={(e) => setDefaultSeverityFilter(e.target.value)}
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical Only</option>
                <option value="high">High & Above</option>
                <option value="medium">Medium & Above</option>
                <option value="low">Low & Above</option>
              </select>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Default filter when viewing vulnerabilities
              </p>
            </div>

            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                    Show Fixable Only by Default
                  </span>
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Only show vulnerabilities with available fixes
                  </p>
                </div>
                <Toggle checked={defaultShowFixableOnly} onChange={setDefaultShowFixableOnly} />
              </label>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
