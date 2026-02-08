/**
 * SecurityTab - API keys, KEV settings, user authentication.
 */

import { useState } from "react";
import { Shield } from "lucide-react";
import { HelpTooltip } from "@/components/HelpTooltip";
import { Toggle } from "@/components/Toggle";
import { ApiKeysCard } from "@/components/ApiKeysCard";
import { UserAuthenticationCard } from "@/components/UserAuthenticationCard";
import { parseSettingInt } from "@/schemas/settings";
import { useAutoSave } from "@/hooks/useAutoSave";

interface SecurityTabProps {
  settingsMap: Record<string, string>;
  onSave: (payload: Record<string, string>) => void;
}

export function SecurityTab({ settingsMap, onSave }: SecurityTabProps): React.ReactElement {
  // KEV settings
  const [kevCheckingEnabled, setKevCheckingEnabled] = useState(settingsMap.kev_checking_enabled !== "false");
  const [kevCacheHours, setKevCacheHours] = useState(parseSettingInt(settingsMap.kev_cache_hours, 12));
  const kevLastRefresh = settingsMap.kev_last_refresh || "";

  useAutoSave(
    () => ({
      kev_checking_enabled: kevCheckingEnabled.toString(),
      kev_cache_hours: kevCacheHours.toString(),
    }),
    onSave,
    [kevCheckingEnabled, kevCacheHours],
    true,
  );

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Left Column */}
      <div className="space-y-4">
        <ApiKeysCard />

        {/* KEV Settings */}
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <Shield className="w-6 h-6 text-red-500" />
              <div>
                <h2 className="text-xl font-semibold text-vuln-text">KEV (Known Exploited Vulnerabilities)</h2>
                <p className="text-sm text-vuln-text-muted mt-0.5">
                  Track actively exploited vulnerabilities from CISA's KEV catalog.
                </p>
              </div>
            </div>
            <HelpTooltip content="CISA's Known Exploited Vulnerabilities catalog tracks CVEs actively being exploited in the wild. KEV vulnerabilities are confirmed by CISA to be used in real-world attacks and should be prioritized for immediate remediation. Visit cisa.gov/known-exploited-vulnerabilities-catalog for the full catalog." />
          </div>

          <div className="space-y-4">
            <div>
              <label className="flex items-center justify-between cursor-pointer group">
                <div>
                  <span className="text-sm font-medium text-vuln-text group-hover:text-vuln-text transition-colors">
                    Enable KEV Checking
                  </span>
                  <p className="text-xs text-vuln-text-disabled mt-1">
                    Check CVEs against CISA's Known Exploited Vulnerabilities catalog
                  </p>
                </div>
                <Toggle checked={kevCheckingEnabled} onChange={setKevCheckingEnabled} />
              </label>
            </div>

            <div>
              <label className="block text-sm font-medium text-vuln-text mb-2">Cache Duration (Hours)</label>
              <input
                type="number"
                value={kevCacheHours}
                onChange={(e) => setKevCacheHours(parseSettingInt(e.target.value, 12))}
                disabled={!kevCheckingEnabled}
                min="1"
                max="72"
                className="w-full px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
              />
              <p className="text-xs text-vuln-text-disabled mt-1">
                How long to cache the KEV catalog before refreshing
              </p>
            </div>

            {kevLastRefresh && (
              <div className="bg-vuln-surface-light/20 border border-vuln-border rounded-lg p-3">
                <p className="text-sm text-vuln-text">
                  <strong>Last KEV Refresh:</strong>{" "}
                  <span className="text-vuln-text-muted">
                    {new Date(kevLastRefresh).toLocaleString()}
                  </span>
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Right Column */}
      <div className="space-y-4">
        <UserAuthenticationCard />
      </div>
    </div>
  );
}
