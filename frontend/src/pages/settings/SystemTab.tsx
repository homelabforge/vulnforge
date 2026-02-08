/**
 * SystemTab - Theme, timezone, and log level settings.
 */

import { useState } from "react";
import { Settings as SettingsIcon, Clock, Sun, Moon } from "lucide-react";
import { useTheme } from "@/contexts/ThemeContext";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useAutoSave } from "@/hooks/useAutoSave";

const TIMEZONE_PRESETS = ["UTC", "America/New_York", "Europe/London", "Asia/Tokyo"];

interface SystemTabProps {
  settingsMap: Record<string, string>;
  onSave: (payload: Record<string, string>) => void;
}

export function SystemTab({ settingsMap, onSave }: SystemTabProps): React.ReactElement {
  const { theme, setTheme } = useTheme();

  // Timezone
  const initialTz = settingsMap.timezone || "UTC";
  const isPreset = TIMEZONE_PRESETS.includes(initialTz);
  const [timezoneMode, setTimezoneMode] = useState<"preset" | "custom">(isPreset ? "preset" : "custom");
  const [timezonePreset, setTimezonePreset] = useState(isPreset ? initialTz : "UTC");
  const [timezoneCustom, setTimezoneCustom] = useState(isPreset ? "" : initialTz);

  // Log level
  const [logLevel, setLogLevel] = useState(settingsMap.log_level || "INFO");

  useAutoSave(
    () => ({
      timezone: timezoneMode === "preset" ? timezonePreset : timezoneCustom.trim() || "UTC",
      log_level: logLevel,
    }),
    onSave,
    [timezoneMode, timezonePreset, timezoneCustom, logLevel],
    !!settingsMap.timezone || !!settingsMap.log_level,
  );

  return (
    <>
      <div className="columns-1 md:columns-2 gap-4 space-y-4">
        {/* Theme Toggle */}
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              {theme === "light" ? (
                <Sun className="w-6 h-6 text-yellow-500" />
              ) : (
                <Moon className="w-6 h-6 text-blue-400" />
              )}
              <div>
                <h2 className="text-xl font-semibold text-vuln-text">Appearance</h2>
                <p className="text-sm text-vuln-text-muted mt-0.5">
                  Choose your preferred color theme.
                </p>
              </div>
            </div>
            <HelpTooltip content="Switch between light and dark color themes. Your preference is saved locally and synced across devices." />
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => setTheme("light")}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-colors ${
                theme === "light"
                  ? "bg-blue-600 border-blue-600 text-white"
                  : "bg-vuln-surface-light border-vuln-border text-vuln-text hover:border-blue-500"
              }`}
            >
              <Sun className="w-5 h-5" />
              Light
            </button>
            <button
              onClick={() => setTheme("dark")}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-colors ${
                theme === "dark"
                  ? "bg-blue-600 border-blue-600 text-white"
                  : "bg-vuln-surface-light border-vuln-border text-vuln-text hover:border-blue-500"
              }`}
            >
              <Moon className="w-5 h-5" />
              Dark
            </button>
          </div>
        </div>

        {/* Timezone */}
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <Clock className="w-6 h-6 text-blue-500" />
              <div>
                <h2 className="text-xl font-semibold text-vuln-text">System Timezone</h2>
                <p className="text-sm text-vuln-text-muted mt-0.5">
                  Controls how schedules and timestamps are interpreted.
                </p>
              </div>
            </div>
            <HelpTooltip content="Set the timezone for all timestamps and scheduled scans. Uses IANA timezone format (e.g., America/Chicago). All dates in the UI will display in this timezone." />
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">
                Timezone
              </label>
              <select
                value={timezoneMode === "preset" ? timezonePreset : "custom"}
                onChange={(e) => {
                  const value = e.target.value;
                  if (value === "custom") {
                    setTimezoneMode("custom");
                  } else {
                    setTimezoneMode("preset");
                    setTimezonePreset(value);
                  }
                }}
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="UTC">UTC (default)</option>
                <option value="America/New_York">America/New_York</option>
                <option value="America/Chicago">America/Chicago</option>
                <option value="America/Denver">America/Denver</option>
                <option value="America/Los_Angeles">America/Los_Angeles</option>
                <option value="Europe/London">Europe/London</option>
                <option value="Europe/Paris">Europe/Paris</option>
                <option value="Asia/Tokyo">Asia/Tokyo</option>
                <option value="Asia/Shanghai">Asia/Shanghai</option>
                <option value="Australia/Sydney">Australia/Sydney</option>
                <option value="custom">Custom…</option>
              </select>
              <p className="text-xs text-vuln-text-disabled mt-1">
                Uses IANA timezone names (e.g., UTC, America/Los_Angeles).
              </p>
            </div>

            {timezoneMode === "custom" && (
              <div>
                <label className="block text-sm font-medium text-vuln-text mb-2">
                  Custom IANA Timezone
                </label>
                <input
                  type="text"
                  value={timezoneCustom}
                  onChange={(e) => setTimezoneCustom(e.target.value)}
                  placeholder="e.g., America/Phoenix"
                  className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            )}
          </div>
        </div>

        {/* Log Level */}
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 break-inside-avoid">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <SettingsIcon className="w-6 h-6 text-orange-500" />
              <div>
                <h2 className="text-xl font-semibold text-vuln-text">Log Level</h2>
                <p className="text-sm text-vuln-text-muted mt-0.5">
                  Configure application logging verbosity.
                </p>
              </div>
            </div>
            <HelpTooltip content="Control how much detail is written to logs. DEBUG shows everything, ERROR shows only critical issues. Use DEBUG for troubleshooting, INFO for normal operation." />
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">
                Log Level
              </label>
              <select
                value={logLevel}
                onChange={(e) => setLogLevel(e.target.value)}
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="DEBUG">DEBUG</option>
                <option value="INFO">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ERROR">ERROR</option>
              </select>
              <p className="text-xs text-vuln-text-disabled mt-1">Application logging verbosity</p>
            </div>
          </div>
        </div>
      </div>

      {/* Info Box */}
      <div className="mt-4 bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Clock className="w-5 h-5 text-blue-500 mt-0.5" />
          <div>
            <h3 className="text-sm font-medium text-blue-500 mb-1">Persistent Settings</h3>
            <p className="text-sm text-vuln-text-muted">
              All settings are stored in the database and persist across container restarts. Changes are saved
              automatically as you edit them.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
