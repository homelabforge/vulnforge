/**
 * Scanner Management Card - Display scanner versions, database age, and health status
 */

import { useQuery } from "@tanstack/react-query";
import { systemApi, type ScannerInfo } from "@/lib/api";
import { Shield, CheckCircle, XCircle, AlertTriangle, Clock, Database, Package, ArrowUpCircle } from "lucide-react";
import { formatRelativeDate } from "@/lib/utils";

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
      return <XCircle className="w-5 h-5 text-gray-500" />;
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
      return <span className="text-gray-400">Disabled</span>;
    }
    if (scanner.db_age_hours !== null && scanner.db_age_hours > 72) {
      return <span className="text-orange-400">Database Stale</span>;
    }
    return <span className="text-green-400">Healthy</span>;
  };

  const getDbAgeColor = (hours: number | null) => {
    if (hours === null) return "text-gray-400";
    if (hours < 24) return "text-green-400";
    if (hours < 72) return "text-yellow-400";
    return "text-orange-400";
  };

  return (
    <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
      <div className="flex items-center gap-3 mb-6">
        <Shield className="w-6 h-6 text-blue-400" />
        <div>
          <h2 className="text-xl font-semibold text-white">Scanner Management</h2>
          <p className="text-sm text-gray-400 mt-0.5">Monitor vulnerability scanner health and versions</p>
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-8">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          <p className="text-gray-400 mt-2">Loading scanner information...</p>
        </div>
      ) : (
        <div className="space-y-4">
          {scannersInfo?.scanners.map((scanner) => (
            <div
              key={scanner.name}
              className="bg-[#0f1419] border border-gray-700 rounded-lg p-5"
            >
              {/* Horizontal 3-Column Layout with Vertical Stacking */}
              <div className="flex items-start justify-between gap-8">
                {/* Column 1: Scanner Name & Status */}
                <div className="flex items-start gap-2">
                  <Shield className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                  <div className="flex flex-col gap-1">
                    <span className="font-semibold text-white">{scanner.name}</span>
                    <div className="flex items-center gap-1.5">
                      {getScannerStatusIcon(scanner)}
                      {getScannerStatusText(scanner)}
                    </div>
                    {!scanner.enabled && (
                      <span className="px-2 py-0.5 bg-gray-700/50 text-gray-400 text-xs rounded w-fit">
                        Disabled
                      </span>
                    )}
                  </div>
                </div>

                {/* Column 2: Scanner Version */}
                {scanner.available && (
                  <div className="flex items-start gap-2">
                    <Package className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                    <div className="flex flex-col gap-1">
                      <span className="text-gray-500 text-sm">Scanner Version</span>
                      <span className="font-mono text-gray-300">{scanner.version || "Unknown"}</span>
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
                    </div>
                  </div>
                )}

                {/* Column 3: Database Version */}
                {scanner.available && (
                  <div className="flex items-start gap-2">
                    <Database className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
                    <div className="flex flex-col gap-1">
                      <span className="text-gray-500 text-sm">Database Version</span>
                      <span className="font-mono text-gray-300">{scanner.db_version || "Unknown"}</span>
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
                    </div>
                  </div>
                )}

                {/* Column 4: Database Age */}
                {scanner.available && (
                  <div className="flex items-start gap-2">
                    <Clock className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                    <div className="flex flex-col gap-1">
                      <span className="text-gray-500 text-sm">Database Age</span>
                      {scanner.db_age_hours !== null ? (
                        <>
                          <span className={`font-medium ${getDbAgeColor(scanner.db_age_hours)}`}>
                            {scanner.db_age_hours < 1
                              ? "< 1 hour"
                              : scanner.db_age_hours === 1
                              ? "1 hour"
                              : `${scanner.db_age_hours} hours`}
                          </span>
                          {scanner.db_updated_at && (
                            <span className="text-xs text-gray-500">
                              Updated {formatRelativeDate(scanner.db_updated_at)}
                            </span>
                          )}
                        </>
                      ) : (
                        <span className="text-gray-400">Unknown</span>
                      )}
                    </div>
                  </div>
                )}
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

      {/* Help Text */}
      <div className="mt-6 p-4 bg-blue-900/10 border border-blue-500/20 rounded-lg">
        <p className="text-xs text-blue-300/70">
          <strong className="text-blue-400">Database Age:</strong> Fresh (&lt;24h) = Green, Stale (24-72h) = Yellow, Very Stale (&gt;72h) = Orange
        </p>
        <p className="text-xs text-blue-300/70 mt-1">
          Scanners automatically update their vulnerability databases. A stale database may contain outdated CVE information.
        </p>
      </div>
    </div>
  );
}
