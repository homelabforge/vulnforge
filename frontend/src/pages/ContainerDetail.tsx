/**
 * Container Detail Page - View container details with tabs for vulnerabilities and secrets
 */

import { useParams, Link } from "react-router-dom";
import { useState } from "react";
import { Container, ArrowLeft, Shield, Key, Bug, Play, Loader2, Circle, History, Layers } from "lucide-react";
import { useContainer, useTriggerScan, useScanStatus, useContainerSecrets, useScanHistory } from "@/hooks/useVulnForge";
import { formatRelativeDate, getSeverityBadge, formatBytes } from "@/lib/utils";
import { toast } from "sonner";
import { ScanHistoryTimeline } from "@/components/ScanHistoryTimeline";

type TabType = "overview" | "vulnerabilities" | "secrets" | "history";

export function ContainerDetail() {
  const { id } = useParams<{ id: string }>();
  const containerId = parseInt(id || "0");
  const [activeTab, setActiveTab] = useState<TabType>("overview");

  const { data: container, isLoading } = useContainer(containerId);
  const { data: scanStatus } = useScanStatus();
  const { data: secrets, isLoading: secretsLoading } = useContainerSecrets(containerId);
  const { data: scanHistory, isLoading: historyLoading } = useScanHistory(containerId);
  const scanMutation = useTriggerScan();

  const handleScan = () => {
    if (!container) return;
    scanMutation.mutate([containerId], {
      onSuccess: () => {
        toast.success(`Started scan for ${container.name}`);
      },
      onError: () => {
        toast.error(`Failed to scan ${container.name}`);
      },
    });
  };

  const isScanning = scanStatus?.status === "scanning" && scanStatus?.current_container === container?.name;

  if (isLoading) {
    return (
      <div className="text-center py-12">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-2" />
        <p className="text-gray-400">Loading container details...</p>
      </div>
    );
  }

  if (!container) {
    return (
      <div className="text-center py-12">
        <Container className="w-12 h-12 text-gray-600 mx-auto mb-3" />
        <p className="text-gray-400 text-lg">Container not found</p>
        <Link to="/containers" className="text-blue-500 hover:text-blue-400 mt-2 inline-block">
          Back to Containers
        </Link>
      </div>
    );
  }

  const tabs = [
    { key: "overview", label: "Overview", icon: Container },
    { key: "vulnerabilities", label: "Vulnerabilities", icon: Bug, count: container.total_vulns },
    { key: "secrets", label: "Secrets", icon: Key, count: secrets?.length || 0 },
    { key: "history", label: "Scan History", icon: History, count: scanHistory?.length || 0 },
  ];

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <Link
          to="/containers"
          className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-4 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Containers
        </Link>

        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-blue-600/10 rounded-lg">
              <Container className="w-8 h-8 text-blue-500" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">{container.name}</h1>
              <div className="flex items-center gap-3 mt-2">
                <span className="text-gray-400 text-sm">
                  {container.image}:{container.image_tag}
                </span>
                {container.is_running ? (
                  <span className="flex items-center gap-1 text-xs px-2 py-1 bg-green-500/10 text-green-500 rounded">
                    <Circle className="w-2 h-2 fill-green-500" />
                    Running
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-xs px-2 py-1 bg-gray-500/10 text-gray-500 rounded">
                    <Circle className="w-2 h-2" />
                    Stopped
                  </span>
                )}
              </div>
            </div>
          </div>

          <button
            onClick={handleScan}
            disabled={isScanning || scanMutation.isPending}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Rescan
              </>
            )}
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {container.last_scan_date && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
            <p className="text-gray-400 text-sm">Total Vulnerabilities</p>
            <p className="text-2xl font-bold text-white mt-1">{container.total_vulns || 0}</p>
          </div>
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
            <p className="text-gray-400 text-sm">Fixable</p>
            <p className="text-2xl font-bold text-green-500 mt-1">{container.fixable_vulns || 0}</p>
          </div>
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
            <p className="text-gray-400 text-sm">Critical</p>
            <p className="text-2xl font-bold text-red-500 mt-1">{container.critical_count || 0}</p>
          </div>
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
            <p className="text-gray-400 text-sm">High</p>
            <p className="text-2xl font-bold text-orange-500 mt-1">{container.high_count || 0}</p>
          </div>
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
            <p className="text-gray-400 text-sm">Secrets</p>
            <p className="text-2xl font-bold text-orange-500 mt-1">{secrets?.length || 0}</p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-800 mb-6">
        <div className="flex gap-4">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as TabType)}
                className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.key
                    ? "border-blue-500 text-blue-500"
                    : "border-transparent text-gray-400 hover:text-white"
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded-full text-xs font-medium">
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Content */}
      <div>
        {activeTab === "overview" && (
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Container Information</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Container ID</span>
                <span className="text-gray-300 font-mono text-sm">{container.id}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Image</span>
                <span className="text-gray-300">{container.image}:{container.image_tag}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Image ID</span>
                <span className="text-gray-300 font-mono text-sm">{container.image_id}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Status</span>
                <span className={container.is_running ? "text-green-500" : "text-gray-500"}>
                  {container.is_running ? "Running" : "Stopped"}
                </span>
              </div>
              {container.last_scan_date && (
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Last Scanned</span>
                  <span className="text-gray-300">{formatRelativeDate(container.last_scan_date)}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Image Efficiency Section */}
        {activeTab === "overview" && container.dive_efficiency_score !== null && (
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 mt-6">
            <div className="flex items-center gap-3 mb-4">
              <Layers className="w-6 h-6 text-blue-400" />
              <div>
                <h3 className="text-lg font-semibold text-white">Image Efficiency</h3>
                <p className="text-sm text-gray-400">
                  Analyzed {formatRelativeDate(container.dive_analyzed_at!)}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* Efficiency Score */}
              <div className="bg-[#0f1419] rounded-lg p-4">
                <p className="text-gray-400 text-xs mb-1">Efficiency Score</p>
                <div className="flex items-center gap-2">
                  <p className={`text-2xl font-bold ${
                    container.dive_efficiency_score >= 0.9 ? 'text-green-500' :
                    container.dive_efficiency_score >= 0.7 ? 'text-yellow-500' :
                    'text-red-500'
                  }`}>
                    {(container.dive_efficiency_score * 100).toFixed(1)}%
                  </p>
                  <span className={`text-xs px-2 py-1 rounded ${
                    container.dive_efficiency_score >= 0.9
                      ? 'bg-green-500/10 text-green-500' :
                    container.dive_efficiency_score >= 0.7
                      ? 'bg-yellow-500/10 text-yellow-500' :
                    'bg-red-500/10 text-red-500'
                  }`}>
                    {container.dive_efficiency_score >= 0.9 ? 'Excellent' :
                     container.dive_efficiency_score >= 0.7 ? 'Good' : 'Poor'}
                  </span>
                </div>
              </div>

              {/* Wasted Space */}
              <div className="bg-[#0f1419] rounded-lg p-4">
                <p className="text-gray-400 text-xs mb-1">Wasted Space</p>
                <p className="text-2xl font-bold text-orange-500">
                  {formatBytes(container.dive_inefficient_bytes)}
                </p>
              </div>

              {/* Image Size */}
              <div className="bg-[#0f1419] rounded-lg p-4">
                <p className="text-gray-400 text-xs mb-1">Image Size</p>
                <p className="text-2xl font-bold text-white">
                  {formatBytes(container.dive_image_size_bytes)}
                </p>
              </div>

              {/* Layers */}
              <div className="bg-[#0f1419] rounded-lg p-4">
                <p className="text-gray-400 text-xs mb-1">Layers</p>
                <p className="text-2xl font-bold text-blue-400">
                  {container.dive_layer_count}
                </p>
              </div>
            </div>
          </div>
        )}

        {activeTab === "vulnerabilities" && (
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Vulnerabilities</h3>
            <p className="text-gray-400">
              This container has {container.total_vulns || 0} vulnerabilities.{" "}
              <Link to="/vulnerabilities" className="text-blue-500 hover:text-blue-400">
                View all vulnerabilities
              </Link>
            </p>
          </div>
        )}

        {activeTab === "secrets" && (
          <div className="space-y-4">
            {secretsLoading ? (
              <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 text-center">
                <Loader2 className="w-6 h-6 text-blue-500 animate-spin mx-auto mb-2" />
                <p className="text-gray-400">Loading secrets...</p>
              </div>
            ) : secrets && secrets.length > 0 ? (
              <>
                <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg p-4 mb-4">
                  <div className="flex items-start gap-3">
                    <Shield className="w-5 h-5 text-orange-500 mt-0.5" />
                    <div className="flex-1">
                      <p className="text-orange-400 font-medium">
                        {secrets.length} exposed secret{secrets.length !== 1 ? "s" : ""} detected
                      </p>
                      <p className="text-orange-300/70 text-sm mt-1">
                        Review and rotate these credentials immediately to prevent unauthorized access.
                      </p>
                    </div>
                  </div>
                </div>

                {secrets.map((secret) => (
                  <div key={secret.id} className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="text-lg font-semibold text-white">{secret.title}</h4>
                          <span className={getSeverityBadge(secret.severity)}>{secret.severity}</span>
                        </div>
                        <p className="text-gray-400 text-sm">{secret.category}</p>
                      </div>
                    </div>

                    {secret.redacted && (
                      <div className="bg-amber-900/20 border border-amber-500/30 rounded p-3 mb-4">
                        <div className="flex items-center gap-2 text-amber-400 text-sm">
                          <Shield className="w-4 h-4" />
                          <span className="font-medium">Secret content redacted for security.</span>
                        </div>
                        <p className="text-amber-300/70 text-xs mt-1 ml-6">
                          Only metadata is shown below. Actual secret values are never stored in the database.
                        </p>
                      </div>
                    )}

                    <div className="space-y-3 text-sm">
                      <div>
                        <span className="text-gray-500">Rule ID:</span>{" "}
                        <span className="text-gray-300 font-mono">{secret.rule_id}</span>
                      </div>

                      {secret.file_path && (
                        <div>
                          <span className="text-gray-500">File:</span>{" "}
                          <span className="text-gray-300 font-mono">{secret.file_path}</span>
                        </div>
                      )}

                      {secret.start_line && (
                        <div>
                          <span className="text-gray-500">Lines:</span>{" "}
                          <span className="text-gray-300">
                            {secret.start_line}
                            {secret.end_line && secret.end_line !== secret.start_line
                              ? `-${secret.end_line}`
                              : ""}
                          </span>
                        </div>
                      )}

                      <div>
                        <span className="text-gray-500">Match:</span>{" "}
                        <span className="text-orange-400 font-mono break-all">{secret.match}</span>
                      </div>

                      {secret.code_snippet && (
                        <div className="mt-4">
                          <p className="text-gray-500 mb-2">Code Context:</p>
                          <pre className="bg-[#0f1419] border border-gray-700 rounded p-3 text-xs text-gray-300 overflow-x-auto">
                            {secret.code_snippet}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-12 text-center">
                <Key className="w-12 h-12 text-green-600 mx-auto mb-3" />
                <p className="text-white text-lg font-medium">No secrets detected</p>
                <p className="text-gray-400 text-sm mt-1">
                  This container doesn't have any exposed credentials in its image layers.
                </p>
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === "history" && (
          <div>
            <div className="mb-6">
              <h3 className="text-xl font-semibold text-white mb-2">Scan History Timeline</h3>
              <p className="text-gray-400 text-sm">
                View historical scan results and track vulnerability trends over time
              </p>
            </div>
            <ScanHistoryTimeline history={scanHistory || []} isLoading={historyLoading} />
          </div>
        )}
      </div>
    </div>
  );
}
