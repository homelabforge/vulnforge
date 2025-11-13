/**
 * Secrets Page - Full secrets list with filtering, export, and false positive management
 */

import { useState } from "react";
import { Download, Filter, Key, AlertTriangle, CheckCircle, FileCode } from "lucide-react";
import { useAllSecrets, useSecretsSummary, useBulkUpdateSecrets } from "@/hooks/useVulnForge";
import { getSeverityBadge } from "@/lib/utils";
import { toast } from "sonner";

export function Secrets() {
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [filters, setFilters] = useState({
    severity: "",
    category: "",
  });
  const [showStatus, setShowStatus] = useState<string>("active"); // "active", "false_positive", "all"

  const { data: secrets, isLoading } = useAllSecrets(filters);
  const { data: summary } = useSecretsSummary();
  const bulkUpdateMutation = useBulkUpdateSecrets();

  // Filter secrets by status
  const filteredSecrets = secrets?.filter((secret) => {
    if (showStatus === "active") {
      return secret.status !== "false_positive" && secret.status !== "accepted_risk";
    } else if (showStatus === "false_positive") {
      return secret.status === "false_positive";
    } else if (showStatus === "accepted_risk") {
      return secret.status === "accepted_risk";
    }
    return true; // "all" - show everything
  });

  const handleSelectAll = () => {
    if (selectedIds.length === filteredSecrets?.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredSecrets?.map((s) => s.id) || []);
    }
  };

  const handleToggleSelect = (id: number) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((sid) => sid !== id) : [...prev, id]
    );
  };

  const handleExport = async (format: "csv" | "json") => {
    const params = new URLSearchParams();
    if (filters.severity) params.append("severity", filters.severity);
    if (filters.category) params.append("category", filters.category);
    params.append("format", format);

    const url = `/api/v1/secrets/export?${params}`;

    try {
      const response = await fetch(url);
      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `secrets.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(downloadUrl);
      toast.success(`Exported ${format.toUpperCase()} file`);
    } catch (error) {
      console.error("Failed to export secrets", error);
      toast.error("Export failed");
    }
  };

  // Get unique categories from summary
  const categories = summary?.top_categories
    ? Object.keys(summary.top_categories)
    : [];

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Key className="w-8 h-8 text-orange-500" />
            Secret Detection
          </h1>
          <p className="text-gray-400 mt-1">
            {filteredSecrets?.length || 0} of {secrets?.length || 0} secrets shown • {summary?.affected_containers || 0} containers affected
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleExport("csv")}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
          <button
            onClick={() => handleExport("json")}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            JSON
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && summary.total_secrets > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-6">
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
            <p className="text-2xl font-bold text-white">{summary.total_secrets}</p>
            <p className="text-xs text-gray-400 mt-1">Total Secrets</p>
          </div>
          <div className="bg-[#1a1f2e] border border-red-500/30 rounded-lg p-4">
            <p className="text-2xl font-bold text-red-500">{summary.critical_count}</p>
            <p className="text-xs text-gray-400 mt-1">Critical</p>
          </div>
          <div className="bg-[#1a1f2e] border border-orange-500/30 rounded-lg p-4">
            <p className="text-2xl font-bold text-orange-500">{summary.high_count}</p>
            <p className="text-xs text-gray-400 mt-1">High</p>
          </div>
          <div className="bg-[#1a1f2e] border border-yellow-500/30 rounded-lg p-4">
            <p className="text-2xl font-bold text-yellow-500">{summary.medium_count}</p>
            <p className="text-xs text-gray-400 mt-1">Medium</p>
          </div>
          <div className="bg-[#1a1f2e] border border-blue-500/30 rounded-lg p-4">
            <p className="text-2xl font-bold text-blue-500">{summary.low_count}</p>
            <p className="text-xs text-gray-400 mt-1">Low</p>
          </div>
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
            <p className="text-2xl font-bold text-white">{summary.affected_containers}</p>
            <p className="text-xs text-gray-400 mt-1">Containers</p>
          </div>
        </div>
      )}

      {/* Warning Banner */}
      {summary && summary.critical_count > 0 && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-red-500 font-semibold">Critical Secrets Detected</p>
            <p className="text-gray-400 text-sm mt-1">
              {summary.critical_count} critical {summary.critical_count === 1 ? "secret has" : "secrets have"} been detected.
              Immediate action required to secure your infrastructure.
            </p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4 mb-6">
        <div className="flex items-center gap-4 flex-wrap">
          <Filter className="w-5 h-5 text-gray-400" />

          <select
            value={filters.severity}
            onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            className="px-3 py-2 bg-[#0f1419] border border-gray-700 rounded text-white"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={filters.category}
            onChange={(e) => setFilters({ ...filters, category: e.target.value })}
            className="px-3 py-2 bg-[#0f1419] border border-gray-700 rounded text-white"
          >
            <option value="">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>

          <select
            value={showStatus}
            onChange={(e) => setShowStatus(e.target.value)}
            className="px-3 py-2 bg-[#0f1419] border border-gray-700 rounded text-white"
          >
            <option value="active">Active Secrets</option>
            <option value="false_positive">False Positives</option>
            <option value="accepted_risk">Accepted Risks</option>
            <option value="all">All Secrets</option>
          </select>

          {selectedIds.length > 0 && (
            <div className="ml-auto flex gap-2">
              <span className="text-gray-400 py-2">{selectedIds.length} selected</span>
              <button
                onClick={async () => {
                  bulkUpdateMutation.mutate(
                    { ids: selectedIds, status: "false_positive" },
                    {
                      onSuccess: (data) => {
                        toast.success(`Marked ${data.updated} secrets as false positive`);
                        setSelectedIds([]);
                      },
                      onError: () => {
                        toast.error("Failed to update secrets");
                      },
                    }
                  );
                }}
                className="px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded"
                disabled={bulkUpdateMutation.isPending}
              >
                Mark as False Positive
              </button>
              <button
                onClick={async () => {
                  bulkUpdateMutation.mutate(
                    { ids: selectedIds, status: "accepted_risk" },
                    {
                      onSuccess: (data) => {
                        toast.success(`Marked ${data.updated} secrets as accepted risk`);
                        setSelectedIds([]);
                      },
                      onError: () => {
                        toast.error("Failed to update secrets");
                      },
                    }
                  );
                }}
                className="px-3 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded"
                disabled={bulkUpdateMutation.isPending}
              >
                Accept Risk
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Secrets List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-8 text-center">
            <p className="text-gray-400">Loading secrets...</p>
          </div>
        ) : filteredSecrets && filteredSecrets.length === 0 ? (
          <div className="bg-[#1a1f2e] border border-green-500/30 rounded-lg p-8 text-center">
            <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-3" />
            <p className="text-white font-semibold">
              {showStatus === "active" && secrets && secrets.length > 0
                ? "No Active Secrets"
                : "No Secrets Detected"}
            </p>
            <p className="text-gray-400 text-sm mt-2">
              {showStatus === "active" && secrets && secrets.length > 0
                ? "All secrets have been reviewed and marked as false positives or accepted risks."
                : "Your containers are secure!"}
            </p>
          </div>
        ) : (
          filteredSecrets?.map((secret) => (
            <div
              key={secret.id}
              className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 hover:border-orange-500/50 transition-colors"
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(secret.id)}
                      onChange={() => handleToggleSelect(secret.id)}
                      className="w-4 h-4"
                      onClick={(e) => e.stopPropagation()}
                    />
                    <h3 className="text-white font-semibold text-lg">{secret.title}</h3>
                    <span className={getSeverityBadge(secret.severity)}>{secret.severity}</span>
                    {secret.status === "false_positive" && (
                      <span className="px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded border border-green-500/30">
                        FALSE POSITIVE
                      </span>
                    )}
                    {secret.status === "accepted_risk" && (
                      <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 text-xs rounded border border-yellow-500/30">
                        ACCEPTED RISK
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-sm text-gray-400">
                    <span className="flex items-center gap-1">
                      <Key className="w-3 h-3" />
                      {secret.category}
                    </span>
                    <span className="text-gray-600">•</span>
                    <span>Rule: {secret.rule_id}</span>
                  </div>
                </div>
              </div>

              {/* File Location */}
              {secret.file_path && (
                <div className="bg-[#0f1419] border border-gray-700 rounded-lg p-3 mb-3">
                  <div className="flex items-center gap-2 text-sm">
                    <FileCode className="w-4 h-4 text-blue-400" />
                    <span className="text-gray-300 font-mono">{secret.file_path}</span>
                    {secret.start_line && (
                      <span className="text-gray-500">
                        (lines {secret.start_line}
                        {secret.end_line && secret.end_line !== secret.start_line
                          ? `-${secret.end_line}`
                          : ""}
                        )
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Match (Redacted) */}
              <div className="mb-3">
                <p className="text-xs text-gray-500 mb-1">Detected Match:</p>
                <div className="bg-red-500/10 border border-red-500/30 rounded px-3 py-2">
                  <code className="text-sm text-red-400 font-mono break-all">{secret.match}</code>
                </div>
              </div>

              {/* Code Snippet */}
              {secret.code_snippet && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Code Context:</p>
                  <div className="bg-[#0f1419] border border-gray-700 rounded-lg p-3 overflow-x-auto">
                    <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">
                      {secret.code_snippet}
                    </pre>
                  </div>
                </div>
              )}

              {/* Layer Info */}
              {secret.layer_digest && (
                <div className="mt-3 pt-3 border-t border-gray-700">
                  <p className="text-xs text-gray-500">
                    Layer: <span className="font-mono text-gray-400">{secret.layer_digest.substring(0, 16)}...</span>
                  </p>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Bulk Select All */}
      {filteredSecrets && filteredSecrets.length > 0 && (
        <div className="mt-6 flex justify-center">
          <button
            onClick={handleSelectAll}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm"
          >
            {selectedIds.length === filteredSecrets.length ? "Deselect All" : "Select All"}
          </button>
        </div>
      )}
    </div>
  );
}
