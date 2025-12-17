/**
 * Container Detail Page - View container details with tabs for vulnerabilities and secrets
 */

import { useParams, Link } from "react-router-dom";
import { useState } from "react";
import { Container, ArrowLeft, Shield, Key, Bug, Play, Loader2, Circle, History, AlertCircle, Star } from "lucide-react";
import { useContainer, useTriggerScan, useScanStatus, useContainerSecrets, useScanHistory, useVulnerabilities } from "@/hooks/useVulnForge";
import { formatRelativeDate, getSeverityBadge, formatBytes } from "@/lib/utils";
import { useTimezone } from "@/contexts/SettingsContext";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { containersApi } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";
import { ScanHistoryTimeline } from "@/components/ScanHistoryTimeline";
import { VulnerabilityDetailModal } from "@/components/VulnerabilityDetailModal";

type TabType = "overview" | "vulnerabilities" | "secrets" | "history";

export function ContainerDetail() {
  const { id } = useParams<{ id: string }>();
  const containerId = parseInt(id || "0");
  const timezone = useTimezone();
  const [activeTab, setActiveTab] = useState<TabType>("overview");

  // Vulnerability filters
  const [selectedVulnId, setSelectedVulnId] = useState<number | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [fixableOnly, setFixableOnly] = useState(false);
  const [kevOnly, setKevOnly] = useState(false);

  const queryClient = useQueryClient();
  const { data: container, isLoading } = useContainer(containerId);
  const { data: scanStatus } = useScanStatus();
  const { data: secrets, isLoading: secretsLoading } = useContainerSecrets(containerId);
  const { data: scanHistory, isLoading: historyLoading } = useScanHistory(containerId);
  const scanMutation = useTriggerScan();
  const [isTogglingProject, setIsTogglingProject] = useState(false);

  // Fetch vulnerabilities for this container
  const { data: vulnerabilitiesData, isLoading: vulnerabilitiesLoading } = useVulnerabilities({
    container_id: containerId,
    severity: severityFilter || undefined,
    status: statusFilter || undefined,
    fixable_only: fixableOnly,
    kev_only: kevOnly,
  });

  const handleScan = () => {
    if (!container) return;
    scanMutation.mutate([containerId], {
      onSuccess: () => {
        toast.success(`Started scan for ${container.name}`);
      },
      onError: (error) => handleApiError(error, `Failed to scan ${container.name}`),
    });
  };

  const handleToggleMyProject = async () => {
    if (!container) return;
    setIsTogglingProject(true);
    try {
      await containersApi.update(containerId, { is_my_project: !container.is_my_project });
      toast.success(container.is_my_project ? "Removed from My Projects" : "Added to My Projects");
      // Invalidate queries to refresh the data
      queryClient.invalidateQueries({ queryKey: ["container", containerId] });
      queryClient.invalidateQueries({ queryKey: ["containers"] });
    } catch (error) {
      handleApiError(error, "Failed to update project status");
    } finally {
      setIsTogglingProject(false);
    }
  };

  const isScanning = scanStatus?.status === "scanning" && scanStatus?.current_container === container?.name;

  if (isLoading) {
    return (
      <div className="text-center py-12">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-2" />
        <p className="text-vuln-text-muted">Loading container details...</p>
      </div>
    );
  }

  if (!container) {
    return (
      <div className="text-center py-12">
        <Container className="w-12 h-12 text-vuln-text-disabled mx-auto mb-3" />
        <p className="text-vuln-text-muted text-lg">Container not found</p>
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
          className="inline-flex items-center gap-2 text-vuln-text-muted hover:text-vuln-text mb-4 transition-colors"
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
              <h1 className="text-2xl font-bold text-vuln-text">{container.name}</h1>
              <div className="flex items-center gap-3 mt-2">
                <span className="text-vuln-text-muted text-sm">
                  {container.image}:{container.image_tag}
                </span>
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
                <button
                  onClick={handleToggleMyProject}
                  disabled={isTogglingProject}
                  className={`flex items-center gap-1 text-xs px-2 py-1 rounded transition-all active:scale-95 ${
                    container.is_my_project
                      ? "bg-blue-600 text-white hover:bg-blue-700"
                      : "bg-vuln-surface-light text-vuln-text-muted hover:bg-blue-600 hover:text-vuln-text"
                  } ${isTogglingProject ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
                  title={container.is_my_project ? "Remove from My Projects" : "Add to My Projects"}
                >
                  <Star className={`w-3 h-3 ${container.is_my_project ? "fill-white" : ""}`} />
                  {container.is_my_project ? "My Project" : "Add to Projects"}
                </button>
              </div>
            </div>
          </div>

          <button
            onClick={handleScan}
            disabled={isScanning || scanMutation.isPending}
            className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
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
        <div className="grid grid-cols-2 md:grid-cols-7 gap-4 mb-4">
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
            <p className="text-vuln-text-muted text-sm">Total Vulnerabilities</p>
            <p className="text-2xl font-bold text-vuln-text mt-1">{container.total_vulns || 0}</p>
          </div>
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
            <p className="text-vuln-text-muted text-sm">Fixable</p>
            <p className="text-2xl font-bold text-green-500 mt-1">{container.fixable_vulns || 0}</p>
          </div>
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
            <p className="text-vuln-text-muted text-sm">Critical</p>
            <p className="text-2xl font-bold text-red-500 mt-1">{container.critical_count || 0}</p>
          </div>
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
            <p className="text-vuln-text-muted text-sm">High</p>
            <p className="text-2xl font-bold text-orange-500 mt-1">{container.high_count || 0}</p>
          </div>
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
            <p className="text-vuln-text-muted text-sm">Medium</p>
            <p className="text-2xl font-bold text-yellow-500 mt-1">{container.medium_count || 0}</p>
          </div>
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
            <p className="text-vuln-text-muted text-sm">Low</p>
            <p className="text-2xl font-bold text-lime-500 mt-1">{container.low_count || 0}</p>
          </div>
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4">
            <p className="text-vuln-text-muted text-sm">Secrets</p>
            <p className="text-2xl font-bold text-orange-500 mt-1">{secrets?.length || 0}</p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-vuln-border mb-6">
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
                    : "border-transparent text-vuln-text-muted hover:text-vuln-text"
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span className="px-2 py-0.5 bg-vuln-surface-light text-vuln-text rounded-full text-xs font-medium">
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
          <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
            <h3 className="text-lg font-semibold text-vuln-text mb-4">Container Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-3 mb-6">
              <div className="flex items-center justify-between">
                <span className="text-vuln-text-muted">Container ID</span>
                <span className="text-vuln-text font-mono text-sm">{container.id}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-vuln-text-muted">Image</span>
                <span className="text-vuln-text">{container.image}:{container.image_tag}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-vuln-text-muted">Status</span>
                <span className={container.is_running ? "text-green-500" : "text-vuln-text-disabled"}>
                  {container.is_running ? "Running" : "Stopped"}
                </span>
              </div>
              {container.last_scan_date && (
                <div className="flex items-center justify-between">
                  <span className="text-vuln-text-muted">Last Scanned</span>
                  <span className="text-vuln-text">{formatRelativeDate(container.last_scan_date, timezone)}</span>
                </div>
              )}
            </div>

            {/* Image Efficiency Metrics */}
            {container.dive_efficiency_score != null && (
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {/* Efficiency Score */}
                <div className="bg-vuln-surface-light rounded-lg p-4">
                  <p className="text-vuln-text-muted text-xs mb-1">Efficiency Score</p>
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
                <div className="bg-vuln-surface-light rounded-lg p-4">
                  <p className="text-vuln-text-muted text-xs mb-1">Wasted Space</p>
                  <p className="text-2xl font-bold text-orange-500">
                    {formatBytes(container.dive_inefficient_bytes)}
                  </p>
                </div>

                {/* Image Size */}
                <div className="bg-vuln-surface-light rounded-lg p-4">
                  <p className="text-vuln-text-muted text-xs mb-1">Image Size</p>
                  <p className="text-2xl font-bold text-vuln-text">
                    {formatBytes(container.dive_image_size_bytes)}
                  </p>
                </div>

                {/* Layers */}
                <div className="bg-vuln-surface-light rounded-lg p-4">
                  <p className="text-vuln-text-muted text-xs mb-1">Layers</p>
                  <p className="text-2xl font-bold text-blue-400">
                    {container.dive_layer_count}
                  </p>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === "vulnerabilities" && (
          <div>
            {/* Filters */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 mb-4">
              <div className="flex flex-wrap gap-4">
                <div>
                  <label className="block text-sm text-vuln-text-muted mb-1">Severity</label>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded text-vuln-text text-sm focus:outline-none focus:border-blue-500"
                  >
                    <option value="">All</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-vuln-text-muted mb-1">Status</label>
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded text-vuln-text text-sm focus:outline-none focus:border-blue-500"
                  >
                    <option value="">All</option>
                    <option value="to_fix">To Fix</option>
                    <option value="accepted">Accepted</option>
                    <option value="ignored">Ignored</option>
                  </select>
                </div>
                <div className="flex items-end gap-4">
                  <label className="flex items-center gap-2 text-sm text-vuln-text-muted cursor-pointer">
                    <input
                      type="checkbox"
                      checked={fixableOnly}
                      onChange={(e) => setFixableOnly(e.target.checked)}
                      className="rounded border-vuln-border bg-vuln-surface-light text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                    />
                    Fixable Only
                  </label>
                  <label className="flex items-center gap-2 text-sm text-vuln-text-muted cursor-pointer">
                    <input
                      type="checkbox"
                      checked={kevOnly}
                      onChange={(e) => setKevOnly(e.target.checked)}
                      className="rounded border-vuln-border bg-vuln-surface-light text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                    />
                    KEV Only
                  </label>
                </div>
              </div>
            </div>

            {/* Vulnerabilities Table */}
            <div className="bg-vuln-surface border border-vuln-border rounded-lg overflow-hidden">
              {vulnerabilitiesLoading ? (
                <div className="p-12 text-center">
                  <Loader2 className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-2" />
                  <p className="text-vuln-text-muted">Loading vulnerabilities...</p>
                </div>
              ) : vulnerabilitiesData && vulnerabilitiesData.vulnerabilities.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-vuln-surface-light border-b border-vuln-border">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                          CVE ID
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                          Package
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                          Severity
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                          Installed
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                          Fixed In
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                          Status
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {vulnerabilitiesData.vulnerabilities.map((vuln) => (
                        <tr
                          key={vuln.id}
                          onClick={() => setSelectedVulnId(vuln.id)}
                          className="hover:bg-vuln-surface-light cursor-pointer transition-colors"
                        >
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <span className="text-blue-400 font-mono text-sm">{vuln.cve_id}</span>
                              {vuln.is_kev && (
                                <span className="px-2 py-0.5 bg-red-500/10 text-red-400 text-xs rounded flex items-center gap-1">
                                  <AlertCircle className="w-3 h-3" />
                                  KEV
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3 text-vuln-text text-sm">{vuln.package_name}</td>
                          <td className="px-4 py-3">
                            <span className={getSeverityBadge(vuln.severity)}>{vuln.severity}</span>
                          </td>
                          <td className="px-4 py-3 text-vuln-text-muted text-sm font-mono">{vuln.installed_version}</td>
                          <td className="px-4 py-3">
                            {vuln.fixed_version ? (
                              <span className="text-green-400 text-sm font-mono">{vuln.fixed_version}</span>
                            ) : (
                              <span className="text-vuln-text-disabled text-sm">N/A</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`px-2 py-1 rounded text-xs ${
                                vuln.status === "to_fix"
                                  ? "bg-yellow-500/10 text-yellow-400"
                                  : vuln.status === "accepted"
                                  ? "bg-blue-500/10 text-blue-400"
                                  : "bg-vuln-text-disabled/10 text-vuln-text-muted"
                              }`}
                            >
                              {vuln.status === "to_fix" ? "To Fix" : vuln.status === "accepted" ? "Accepted" : "Ignored"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-12 text-center">
                  <Bug className="w-12 h-12 text-vuln-text-disabled mx-auto mb-3" />
                  <p className="text-vuln-text-muted text-lg">No vulnerabilities found</p>
                  <p className="text-vuln-text-disabled text-sm mt-1">
                    {container.last_scan_date
                      ? "This container has no vulnerabilities matching your filters."
                      : "Scan this container to discover vulnerabilities."}
                  </p>
                </div>
              )}
            </div>

            {/* Vulnerability Detail Modal */}
            {selectedVulnId && vulnerabilitiesData && (
              <VulnerabilityDetailModal
                vulnerability={vulnerabilitiesData.vulnerabilities.find(v => v.id === selectedVulnId)!}
                onClose={() => setSelectedVulnId(null)}
              />
            )}
          </div>
        )}

        {activeTab === "secrets" && (
          <div className="space-y-4">
            {secretsLoading ? (
              <div className="bg-vuln-surface border border-vuln-border rounded-lg p-6 text-center">
                <Loader2 className="w-6 h-6 text-blue-500 animate-spin mx-auto mb-2" />
                <p className="text-vuln-text-muted">Loading secrets...</p>
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
                  <div key={secret.id} className="bg-vuln-surface border border-vuln-border rounded-lg p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="text-lg font-semibold text-vuln-text">{secret.title}</h4>
                          <span className={getSeverityBadge(secret.severity)}>{secret.severity}</span>
                        </div>
                        <p className="text-vuln-text-muted text-sm">{secret.category}</p>
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
                        <span className="text-vuln-text-disabled">Rule ID:</span>{" "}
                        <span className="text-vuln-text font-mono">{secret.rule_id}</span>
                      </div>

                      {secret.file_path && (
                        <div>
                          <span className="text-vuln-text-disabled">File:</span>{" "}
                          <span className="text-vuln-text font-mono">{secret.file_path}</span>
                        </div>
                      )}

                      {secret.start_line && (
                        <div>
                          <span className="text-vuln-text-disabled">Lines:</span>{" "}
                          <span className="text-vuln-text">
                            {secret.start_line}
                            {secret.end_line && secret.end_line !== secret.start_line
                              ? `-${secret.end_line}`
                              : ""}
                          </span>
                        </div>
                      )}

                      <div>
                        <span className="text-vuln-text-disabled">Match:</span>{" "}
                        <span className="text-orange-400 font-mono break-all">{secret.match}</span>
                      </div>

                      {secret.code_snippet && (
                        <div className="mt-4">
                          <p className="text-vuln-text-disabled mb-2">Code Context:</p>
                          <pre className="bg-vuln-surface-light border border-vuln-border rounded p-3 text-xs text-vuln-text overflow-x-auto">
                            {secret.code_snippet}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <div className="bg-vuln-surface border border-vuln-border rounded-lg p-12 text-center">
                <Key className="w-12 h-12 text-green-600 mx-auto mb-3" />
                <p className="text-vuln-text text-lg font-medium">No secrets detected</p>
                <p className="text-vuln-text-muted text-sm mt-1">
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
              <h3 className="text-xl font-semibold text-vuln-text mb-2">Scan History Timeline</h3>
              <p className="text-vuln-text-muted text-sm">
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
