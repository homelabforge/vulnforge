/**
 * Dashboard Page - Overview and quick stats
 */

import { Shield, Container, Bug, RefreshCw, Play, Key, AlertTriangle, Loader2 } from "lucide-react";
import {
  useDiscoverContainers,
  useTriggerScan,
  useScanStatus,
  useWidgetSummary,
  useSecretsSummary,
} from "@/hooks/useVulnForge";
import { toast } from "sonner";
import { VulnerabilityCharts } from "@/components/VulnerabilityCharts";
import { ScanTrendsPanel } from "@/components/ScanTrendsPanel";

export function Dashboard() {
  const { data: summary } = useWidgetSummary();
  const { data: scanStatus } = useScanStatus();
  const { data: secretsSummary } = useSecretsSummary();

  const discoverMutation = useDiscoverContainers();
  const scanMutation = useTriggerScan();

  const handleDiscoverContainers = () => {
    discoverMutation.mutate(undefined, {
      onSuccess: (data) => {
        toast.success(`Discovered ${data.discovered.length} new containers`);
      },
      onError: () => {
        toast.error("Failed to discover containers");
      },
    });
  };

  const handleScanAll = () => {
    scanMutation.mutate(undefined, {
      onSuccess: () => {
        toast.success("Scan started for all containers");
      },
      onError: () => {
        toast.error("Failed to start scan");
      },
    });
  };

  const isScanning = scanStatus?.status === "scanning";

  return (
    <div>
      {/* Header with Actions */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-400 mt-1">Container vulnerability overview</p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleDiscoverContainers}
            disabled={discoverMutation.isPending}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${discoverMutation.isPending ? "animate-spin" : ""}`} />
            Discover Containers
          </button>
          <button
            onClick={handleScanAll}
            disabled={isScanning || scanMutation.isPending}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            {scanMutation.isPending || isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Scan All
              </>
            )}
          </button>
        </div>
      </div>

      {/* Scan Progress */}
      {isScanning && scanStatus && (
        <div className="bg-[#1a1f2e] border border-blue-500/30 rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-2 text-sm">
            <span className="text-blue-400 font-medium">Scanning containers...</span>
            <span className="text-gray-400">
              {scanStatus.current_container} ({scanStatus.progress_current} / {scanStatus.progress_total})
            </span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div
              className="bg-blue-500 h-full rounded-full transition-all duration-300"
              style={{ width: `${(scanStatus.progress_current! / scanStatus.progress_total!) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-6">
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Vulnerabilities</p>
              <p className="text-3xl font-bold text-white mt-1">{summary?.total_vulnerabilities || 0}</p>
            </div>
            <Bug className="w-10 h-10 text-red-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Fixable</p>
              <p className="text-3xl font-bold text-green-500 mt-1">{summary?.fixable_vulnerabilities || 0}</p>
            </div>
            <Shield className="w-10 h-10 text-green-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Critical</p>
              <p className="text-3xl font-bold text-red-500 mt-1">{summary?.critical_count || 0}</p>
            </div>
            <Shield className="w-10 h-10 text-red-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Secrets</p>
              <p className="text-3xl font-bold text-orange-500 mt-1">{secretsSummary?.total_secrets || 0}</p>
            </div>
            <Key className="w-10 h-10 text-orange-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Containers</p>
              <p className="text-3xl font-bold text-white mt-1">
                {summary?.scanned_containers || 0} / {summary?.total_containers || 0}
              </p>
            </div>
            <Container className="w-10 h-10 text-blue-500" />
          </div>
        </div>
      </div>

      {/* Vulnerability Charts */}
      <VulnerabilityCharts />

      {/* Scan Trends */}
      <ScanTrendsPanel />

      {/* Secret Detection Summary */}
      {secretsSummary && secretsSummary.total_secrets > 0 && (
        <div className="mt-6 bg-[#1a1f2e] border border-orange-500/30 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <Key className="w-6 h-6 text-orange-500" />
            <div>
              <h2 className="text-xl font-semibold text-white">Secret Detection</h2>
              <p className="text-sm text-gray-400">Exposed credentials detected in container images</p>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            {/* Total Secrets */}
            <div className="bg-[#0f1419] rounded-lg p-4">
              <p className="text-gray-400 text-xs mb-1">Total Secrets</p>
              <p className="text-2xl font-bold text-orange-500">{secretsSummary.total_secrets}</p>
            </div>

            {/* Critical */}
            <div className="bg-[#0f1419] rounded-lg p-4">
              <p className="text-gray-400 text-xs mb-1">Critical</p>
              <p className="text-2xl font-bold text-red-500">{secretsSummary.critical_count}</p>
            </div>

            {/* High */}
            <div className="bg-[#0f1419] rounded-lg p-4">
              <p className="text-gray-400 text-xs mb-1">High</p>
              <p className="text-2xl font-bold text-orange-400">{secretsSummary.high_count}</p>
            </div>

            {/* Medium */}
            <div className="bg-[#0f1419] rounded-lg p-4">
              <p className="text-gray-400 text-xs mb-1">Medium</p>
              <p className="text-2xl font-bold text-yellow-500">{secretsSummary.medium_count}</p>
            </div>

            {/* Low */}
            <div className="bg-[#0f1419] rounded-lg p-4">
              <p className="text-gray-400 text-xs mb-1">Low</p>
              <p className="text-2xl font-bold text-blue-400">{secretsSummary.low_count}</p>
            </div>

            {/* Affected Containers */}
            <div className="bg-[#0f1419] rounded-lg p-4">
              <p className="text-gray-400 text-xs mb-1">Containers</p>
              <p className="text-2xl font-bold text-white">{secretsSummary.affected_containers}</p>
            </div>
          </div>

          {/* Top Categories */}
          {Object.keys(secretsSummary.top_categories).length > 0 && (
            <div className="mt-4 pt-4 border-t border-gray-800">
              <p className="text-sm font-medium text-gray-300 mb-2">Top Categories</p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(secretsSummary.top_categories).slice(0, 5).map(([category, count]) => (
                  <span
                    key={category}
                    className="px-3 py-1 bg-orange-500/10 border border-orange-500/20 rounded-full text-sm text-orange-400"
                  >
                    {category}: {count}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Warning Message */}
          <div className="mt-4 flex items-start gap-2 text-sm text-orange-400">
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <p>
              Exposed secrets detected. Review affected containers and rotate credentials immediately.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
