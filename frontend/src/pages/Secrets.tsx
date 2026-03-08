/**
 * Secrets Page - Full secrets list with filtering, export, and false positive management
 */

import { useState } from "react";
import { Download, Filter, Key, CheckCircle, FileCode, Box } from "lucide-react";
import { useAllSecrets, useSecretsSummary, useBulkUpdateSecrets } from "@/hooks/useVulnForge";
import { getSeverityBadge } from "@/lib/utils";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { secretsApi } from "@/lib/api";

export function Secrets() {
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [filters, setFilters] = useState({
    severity: "",
    category: "",
  });
  const [showStatus, setShowStatus] = useState<string>("active");

  const { data: secrets, isLoading } = useAllSecrets({
    severity: filters.severity || undefined,
    category: filters.category || undefined,
    status: showStatus,
  });
  const { data: summary } = useSecretsSummary();
  const bulkUpdateMutation = useBulkUpdateSecrets();

  const updateFilters = (newFilters: typeof filters) => {
    setFilters(newFilters);
    setSelectedIds([]);
  };

  const updateStatus = (newStatus: string) => {
    setShowStatus(newStatus);
    setSelectedIds([]);
  };

  const handleSelectAll = () => {
    if (selectedIds.length === secrets?.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(secrets?.map((s) => s.id) || []);
    }
  };

  const handleToggleSelect = (id: number) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((sid) => sid !== id) : [...prev, id]
    );
  };

  const handleExport = async (format: "csv" | "json") => {
    try {
      const blob = await secretsApi.export(format, {
        severity: filters.severity || undefined,
        category: filters.category || undefined,
      });
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
      handleApiError(error, "Export failed");
    }
  };

  // Get unique categories from summary
  const categories = summary?.top_categories
    ? Object.keys(summary.top_categories)
    : [];

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-vuln-text flex items-center gap-3">
            <Key className="w-8 h-8 text-orange-500" />
            Secret Detection
          </h1>
          <p className="text-sm text-vuln-text-muted mt-0.5">
            {secrets?.length || 0} secrets shown • {summary?.affected_containers || 0} containers affected
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleExport("csv")}
            className="px-3 py-2 bg-vuln-surface-light hover:bg-vuln-border text-vuln-text rounded-lg flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
          <button
            onClick={() => handleExport("json")}
            className="px-3 py-2 bg-vuln-surface-light hover:bg-vuln-border text-vuln-text rounded-lg flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-4 mb-6">
        <div className="flex items-center gap-4 flex-wrap">
          <Filter className="w-5 h-5 text-vuln-text-muted" />

          {secrets && secrets.length > 0 && (
            <button
              onClick={handleSelectAll}
              className="px-3 py-1.5 bg-vuln-surface-light hover:bg-vuln-border text-vuln-text rounded text-sm border border-vuln-border"
            >
              {selectedIds.length === secrets.length ? "Deselect All" : "Select All"}
            </button>
          )}

          <select
            value={filters.severity}
            onChange={(e) => updateFilters({ ...filters, severity: e.target.value })}
            className="px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded text-vuln-text"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={filters.category}
            onChange={(e) => updateFilters({ ...filters, category: e.target.value })}
            className="px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded text-vuln-text"
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
            onChange={(e) => updateStatus(e.target.value)}
            className="px-3 py-2 bg-vuln-surface-light border border-vuln-border rounded text-vuln-text"
          >
            <option value="active">Active Secrets</option>
            <option value="false_positive">False Positives</option>
            <option value="accepted_risk">Accepted Risks</option>
            <option value="all">All Secrets</option>
          </select>

          {selectedIds.length > 0 && (
            <div className="ml-auto flex gap-2">
              <span className="text-vuln-text-muted py-2">{selectedIds.length} selected</span>
              <button
                onClick={async () => {
                  bulkUpdateMutation.mutate(
                    { ids: selectedIds, status: "false_positive" },
                    {
                      onSuccess: (data) => {
                        toast.success(`Marked ${data.updated} secrets as false positive`);
                        setSelectedIds([]);
                      },
                      onError: (error) => handleApiError(error, "Failed to update secrets"),
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
                      onError: (error) => handleApiError(error, "Failed to update secrets"),
                    }
                  );
                }}
                className="px-3 py-2 bg-yellow-600 hover:bg-yellow-700 text-vuln-text rounded"
                disabled={bulkUpdateMutation.isPending}
              >
                Accept Risk
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Secrets Grid */}
      {isLoading ? (
        <div className="bg-vuln-surface border border-vuln-border rounded-lg p-8 text-center">
          <p className="text-vuln-text-muted">Loading secrets...</p>
        </div>
      ) : secrets && secrets.length === 0 ? (
        <div className="bg-vuln-surface border border-green-500/30 rounded-lg p-8 text-center">
          <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-3" />
          <p className="text-vuln-text font-semibold">
            {showStatus === "active" ? "No Active Secrets" : "No Secrets Found"}
          </p>
          <p className="text-vuln-text-muted text-sm mt-2">
            {showStatus === "active"
              ? "All secrets have been reviewed and marked as false positives or accepted risks."
              : "No secrets match the current filters."}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {secrets?.map((secret) => (
            <div
              key={secret.id}
              className="bg-vuln-surface border border-vuln-border rounded-lg p-4 hover:border-orange-500/50 transition-colors"
            >
              {/* Row 1: Checkbox + Title + Severity + Status */}
              <div className="flex items-center gap-2 mb-2">
                <input
                  type="checkbox"
                  checked={selectedIds.includes(secret.id)}
                  onChange={() => handleToggleSelect(secret.id)}
                  className="w-4 h-4 flex-shrink-0"
                  onClick={(e) => e.stopPropagation()}
                />
                <h3 className="text-vuln-text font-semibold text-sm truncate flex-1">
                  {secret.title}
                </h3>
                <span className={getSeverityBadge(secret.severity)}>{secret.severity}</span>
                {secret.status === "false_positive" && (
                  <span className="px-1.5 py-0.5 bg-green-500/20 text-green-400 text-xs rounded border border-green-500/30">
                    FP
                  </span>
                )}
                {secret.status === "accepted_risk" && (
                  <span className="px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded border border-yellow-500/30">
                    AR
                  </span>
                )}
              </div>

              {/* Row 2: Container + Category + Rule */}
              <div className="flex items-center gap-3 text-xs text-vuln-text-muted mb-2">
                {secret.container_name && (
                  <span className="flex items-center gap-1 px-1.5 py-0.5 bg-blue-500/10 text-blue-400 rounded border border-blue-500/20">
                    <Box className="w-3 h-3" />
                    {secret.container_name}
                  </span>
                )}
                <span className="flex items-center gap-1">
                  <Key className="w-3 h-3" />
                  {secret.category}
                </span>
                <span className="text-vuln-text-disabled">|</span>
                <span>{secret.rule_id}</span>
              </div>

              {/* Row 3: File path + Layer digest */}
              <div className="flex items-center gap-3 text-xs">
                {secret.file_path && (
                  <div className="flex items-center gap-1.5 min-w-0 flex-1">
                    <FileCode className="w-3 h-3 text-blue-400 flex-shrink-0" />
                    <span className="text-vuln-text-muted font-mono truncate">
                      {secret.file_path}
                    </span>
                    {secret.start_line && (
                      <span className="text-vuln-text-disabled flex-shrink-0">
                        :{secret.start_line}
                        {secret.end_line && secret.end_line !== secret.start_line
                          ? `-${secret.end_line}`
                          : ""}
                      </span>
                    )}
                  </div>
                )}
                {secret.layer_digest && (
                  <span className="text-vuln-text-disabled font-mono flex-shrink-0">
                    {secret.layer_digest.substring(0, 16)}...
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
