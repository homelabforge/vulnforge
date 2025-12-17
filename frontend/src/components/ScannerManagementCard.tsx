/**
 * Scanner Management Card - Display scanner versions, database age, and health status
 */

import { useQuery } from "@tanstack/react-query";
import { systemApi, type ScannerInfo } from "@/lib/api";
import { Shield, CheckCircle, XCircle, AlertTriangle, Clock, Database, Package, ArrowUpCircle } from "lucide-react";
import { HelpTooltip } from "@/components/HelpTooltip";

export function ScannerManagementCard() {
  const { data: scannersInfo, isLoading } = useQuery({
    queryKey: ["scanners-info"],
    queryFn: () => systemApi.getScannersInfo(),
    refetchInterval: 60000, // Refresh every minute
  });

  const getScannerStatusIcon = (scanner: ScannerInfo) => {
    if (!scanner.available) {
      return <XCircle className="w-5 h-5 text-red-500" />;
    }
    if (!scanner.enabled) {
      return <XCircle className="w-5 h-5 text-vuln-text-disabled" />;
    }
    if (scanner.db_age_hours !== null && scanner.db_age_hours > 72) {
      return <AlertTriangle className="w-5 h-5 text-orange-500" />;
    }
    return <CheckCircle className="w-5 h-5 text-green-500" />;
  };

  const getScannerStatusText = (scanner: ScannerInfo) => {
    if (!scanner.available) {
      return <span className="text-red-400">Unavailable</span>;
    }
    if (!scanner.enabled) {
      return <span className="text-vuln-text-muted">Disabled</span>;
    }
    if (scanner.db_age_hours !== null && scanner.db_age_hours > 72) {
      return <span className="text-orange-400">Database Stale</span>;
    }
    return <span className="text-green-400">Healthy</span>;
  };

  const getDbAgeColor = (hours: number | null) => {
    if (hours === null) return "text-vuln-text-muted";
    if (hours < 24) return "text-green-400";
    if (hours < 72) return "text-yellow-400";
    return "text-orange-400";
  };

  return (
    <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-blue-400" />
          <div>
            <h2 className="text-xl font-semibold text-vuln-text">Scanner Management</h2>
            <p className="text-sm text-vuln-text-muted mt-0.5">Monitor vulnerability scanner health and versions</p>
          </div>
        </div>
        <HelpTooltip content="View scanner versions, database freshness, and health status. Database Age: Fresh (<24h) = Green, Stale (24-72h) = Yellow, Very Stale (>72h) = Orange. Scanners automatically update their vulnerability databases - a stale database may contain outdated CVE information." />
      </div>

      {isLoading ? (
        <div className="text-center py-8">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          <p className="text-vuln-text-muted mt-2">Loading scanner information...</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {scannersInfo?.scanners.sort((a, b) => a.name.localeCompare(b.name)).map((scanner) => (
            <div
              key={scanner.name}
              className="bg-vuln-surface-light border border-vuln-border rounded-lg p-5"
            >
              {/* Grid Layout with Responsive Column Widths */}
              <div className="grid grid-cols-[140px_130px_130px_110px] gap-3">
                {/* Column 1: Scanner Name & Status */}
                <div className="flex items-start gap-2">
                  <Shield className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                  <div className="flex flex-col gap-1">
                    <span className="font-semibold text-vuln-text">{scanner.name}</span>
                    <div className="flex items-center gap-1.5">
                      {getScannerStatusIcon(scanner)}
                      {getScannerStatusText(scanner)}
                    </div>
                    {!scanner.enabled && (
                      <span className="px-2 py-0.5 bg-vuln-surface-light text-vuln-text-muted text-xs rounded w-fit">
                        Disabled
                      </span>
                    )}
                  </div>
                </div>

                {/* Column 2: Scanner Version */}
                <div className="flex items-start gap-2">
                  <Package className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                  <div className="flex flex-col gap-1">
                    <span className="text-vuln-text-disabled text-sm">Scanner Version</span>
                    {scanner.available ? (
                      <>
                        <span className="font-mono text-vuln-text">{scanner.version || "N/A"}</span>
                        {scanner.update_available ? (
                          <span className="text-xs text-amber-400 flex items-center gap-1">
                            <ArrowUpCircle className="w-3 h-3" />
                            Update to {scanner.latest_version}
                          </span>
                        ) : scanner.latest_version ? (
                          <span className="text-xs text-green-400/70 flex items-center gap-1">
                            <CheckCircle className="w-3 h-3" />
                            Up to date
                          </span>
                        ) : null}
                      </>
                    ) : (
                      <span className="text-vuln-text-muted">—</span>
                    )}
                  </div>
                </div>

                {/* Column 3: Database Version */}
                <div className="flex items-start gap-2">
                  <Database className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
                  <div className="flex flex-col gap-1">
                    <span className="text-vuln-text-disabled text-sm">Database Version</span>
                    {scanner.available ? (
                      <>
                        <span className="font-mono text-vuln-text">{scanner.db_version || "N/A"}</span>
                        {scanner.db_update_available ? (
                          <span className="text-xs text-amber-400 flex items-center gap-1">
                            <ArrowUpCircle className="w-3 h-3" />
                            Update to {scanner.db_latest_version}
                          </span>
                        ) : scanner.db_latest_version ? (
                          <span className="text-xs text-green-400/70 flex items-center gap-1">
                            <CheckCircle className="w-3 h-3" />
                            Up to date
                          </span>
                        ) : null}
                      </>
                    ) : (
                      <span className="text-vuln-text-muted">—</span>
                    )}
                  </div>
                </div>

                {/* Column 4: Database Age */}
                <div className="flex items-start gap-2">
                  <Clock className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                  <div className="flex flex-col gap-1">
                    <span className="text-vuln-text-disabled text-sm">Database Age</span>
                    {scanner.available ? (
                      scanner.db_age_hours !== null ? (
                        <span className={`font-medium ${getDbAgeColor(scanner.db_age_hours)}`}>
                          {scanner.db_age_hours < 1
                            ? "< 1 hour"
                            : scanner.db_age_hours === 1
                            ? "1 hour"
                            : `${scanner.db_age_hours} hours`}
                        </span>
                      ) : (
                        <span className="text-vuln-text-muted">N/A</span>
                      )
                    ) : (
                      <span className="text-vuln-text-muted">—</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Unavailable Message */}
              {!scanner.available && scanner.enabled && (
                <div className="mt-4 p-3 bg-blue-900/20 border border-blue-500/30 rounded">
                  <p className="text-sm text-blue-300">
                    {scanner.name === "Grype" ? (
                      <>
                        <span className="font-medium">Grype automatically downloads on first scan.</span> The scanner image will be pulled when you run a vulnerability scan.
                      </>
                    ) : (
                      <>
                        Scanner container not found. Ensure the <span className="font-mono">{scanner.name.toLowerCase()}</span> container is running.
                      </>
                    )}
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

    </div>
  );
}
