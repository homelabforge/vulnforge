/**
 * Vulnerabilities Page - Full vulnerability list with filtering and bulk actions
 */

import { useState } from "react";
import { Download, Filter, Copy, Check, Package } from "lucide-react";
import { useVulnerabilities, useBulkUpdateVulnerabilities, useRemediationGroups } from "@/hooks/useVulnForge";
import { getSeverityBadge } from "@/lib/utils";
import { VulnerabilityDetailModal } from "@/components/VulnerabilityDetailModal";
import { toast } from "sonner";
import type { Vulnerability } from "@/lib/api";

type ViewMode = "vulnerabilities" | "remediation";

export function Vulnerabilities() {
  const [viewMode, setViewMode] = useState<ViewMode>("vulnerabilities");
  const [copiedPackage, setCopiedPackage] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [filters, setFilters] = useState({
    severity: "",
    fixable_only: false,
    kev_only: false,
    status: "",
  });

  const { data: vulnData, isLoading } = useVulnerabilities(filters);
  const { data: remediationGroups } = useRemediationGroups();
  const bulkUpdateMutation = useBulkUpdateVulnerabilities();

  // Extract vulnerabilities array from paginated response
  const vulnerabilities = vulnData?.vulnerabilities || [];

  const handleSelectAll = () => {
    if (selectedIds.length === vulnerabilities.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(vulnerabilities.map((v) => v.id));
    }
  };

  const handleToggleSelect = (id: number) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((vid) => vid !== id) : [...prev, id]
    );
  };

  const handleBulkUpdate = (status: string) => {
    if (selectedIds.length === 0) {
      toast.error("No vulnerabilities selected");
      return;
    }

    bulkUpdateMutation.mutate(
      { ids: selectedIds, status },
      {
        onSuccess: () => {
          toast.success(`Updated ${selectedIds.length} vulnerabilities to ${status}`);
          setSelectedIds([]);
        },
        onError: () => {
          toast.error("Failed to update vulnerabilities");
        },
      }
    );
  };

  const handleExport = async (format: "csv" | "json") => {
    const params = new URLSearchParams();
    if (filters.severity) params.append("severity", filters.severity);
    if (filters.fixable_only) params.append("fixable_only", "true");
    if (filters.kev_only) params.append("kev_only", "true");
    if (filters.status) params.append("status", filters.status);
    params.append("format", format);

    const url = `/api/v1/vulnerabilities/export?${params}`;

    try {
      const response = await fetch(url);
      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `vulnerabilities.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(downloadUrl);
      toast.success(`Exported ${format.toUpperCase()} file`);
    } catch (error) {
      console.error("Failed to export vulnerabilities", error);
      toast.error("Export failed");
    }
  };

  const handleCopyPackage = (packageName: string, fixedVersion: string) => {
    const text = `${packageName}@${fixedVersion}`;
    navigator.clipboard.writeText(text);
    setCopiedPackage(packageName);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopiedPackage(null), 2000);
  };

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Vulnerabilities</h1>
          <p className="text-gray-400 mt-1">
            {viewMode === "vulnerabilities"
              ? `${vulnerabilities?.length || 0} vulnerabilities found`
              : `${remediationGroups?.length || 0} remediation groups`}
          </p>
        </div>
        {viewMode === "vulnerabilities" && (
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
        )}
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setViewMode("vulnerabilities")}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            viewMode === "vulnerabilities"
              ? "bg-blue-600 text-white"
              : "bg-[#1a1f2e] text-gray-400 hover:text-white border border-gray-800"
          }`}
        >
          All Vulnerabilities
        </button>
        <button
          onClick={() => setViewMode("remediation")}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
            viewMode === "remediation"
              ? "bg-blue-600 text-white"
              : "bg-[#1a1f2e] text-gray-400 hover:text-white border border-gray-800"
          }`}
        >
          <Package className="w-4 h-4" />
          Remediation Groups
        </button>
      </div>

      {/* Vulnerabilities View */}
      {viewMode === "vulnerabilities" && (
        <>
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
                value={filters.status}
                onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                className="px-3 py-2 bg-[#0f1419] border border-gray-700 rounded text-white"
              >
                <option value="">All Statuses</option>
                <option value="to_fix">To Fix</option>
                <option value="accepted">Accepted</option>
                <option value="ignored">Ignored</option>
              </select>

              <label className="flex items-center gap-2 text-white">
                <input
                  type="checkbox"
                  checked={filters.fixable_only}
                  onChange={(e) => setFilters({ ...filters, fixable_only: e.target.checked })}
                  className="w-4 h-4"
                />
                Fixable Only
              </label>

              <label className="flex items-center gap-2 text-white">
                <input
                  type="checkbox"
                  checked={filters.kev_only}
                  onChange={(e) => setFilters({ ...filters, kev_only: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="flex items-center gap-1">
                  KEV Only
                  <span className="text-xs text-red-400">(Actively Exploited)</span>
                </span>
              </label>

              {selectedIds.length > 0 && (
                <div className="ml-auto flex gap-2">
                  <span className="text-gray-400 py-2">{selectedIds.length} selected</span>
                  <button
                    onClick={() => handleBulkUpdate("accepted")}
                    className="px-3 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded"
                  >
                    Mark Accepted
                  </button>
                  <button
                    onClick={() => handleBulkUpdate("ignored")}
                    className="px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded"
                  >
                    Mark Ignored
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Vulnerabilities Table */}
          <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-[#0f1419] border-b border-gray-800">
                <tr>
                  <th className="px-4 py-3 text-left">
                    <input
                      type="checkbox"
                      checked={selectedIds.length === vulnerabilities?.length && vulnerabilities.length > 0}
                      onChange={handleSelectAll}
                      className="w-4 h-4"
                    />
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">CVE ID</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Container</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Package</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Severity</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Version</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Fixed</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {isLoading ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-gray-400">
                      Loading...
                    </td>
                  </tr>
                ) : vulnerabilities?.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-gray-400">
                      No vulnerabilities found
                    </td>
                  </tr>
                ) : (
                  vulnerabilities?.map((vuln) => (
                    <tr
                      key={vuln.id}
                      className="hover:bg-[#0f1419] cursor-pointer transition-colors"
                      onClick={() => setSelectedVuln(vuln)}
                    >
                      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(vuln.id)}
                          onChange={() => handleToggleSelect(vuln.id)}
                          className="w-4 h-4"
                        />
                      </td>
                      <td className="px-4 py-3 text-white font-medium">
                        <div className="flex items-center gap-2">
                          {vuln.cve_id}
                          {vuln.is_kev && (
                            <span className="px-2 py-0.5 bg-red-600 text-white text-xs rounded font-semibold flex items-center gap-1">
                              <span>⚠</span> KEV
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-400">{vuln.container_name}</td>
                      <td className="px-4 py-3 text-gray-400">{vuln.package_name}</td>
                      <td className="px-4 py-3">
                        <span className={getSeverityBadge(vuln.severity)}>{vuln.severity}</span>
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-sm">{vuln.installed_version}</td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {vuln.fixed_version || "N/A"}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-xs ${
                          vuln.status === "accepted" ? "bg-yellow-500/10 text-yellow-500" :
                          vuln.status === "ignored" ? "bg-gray-500/10 text-gray-500" :
                          "bg-red-500/10 text-red-500"
                        }`}>
                          {vuln.status}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Remediation Groups View */}
      {viewMode === "remediation" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {remediationGroups && remediationGroups.length > 0 ? (
            remediationGroups.map((group, idx) => (
              <div key={idx} className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 hover:border-blue-500/50 transition-colors">
                {/* Header with Package Info */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <Package className="w-5 h-5 text-blue-400" />
                      <h3 className="text-white font-medium">{group.package_name}</h3>
                    </div>
                    <p className="text-sm text-gray-400">
                      {group.installed_version} → <span className="text-green-500">{group.fixed_version}</span>
                    </p>
                  </div>
                  <button
                    onClick={() => handleCopyPackage(group.package_name, group.fixed_version)}
                    className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm flex items-center gap-2 transition-colors"
                  >
                    {copiedPackage === group.package_name ? (
                      <>
                        <Check className="w-3 h-3" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        Copy
                      </>
                    )}
                  </button>
                </div>

                {/* CVE Count */}
                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3 mb-3">
                  <p className="text-2xl font-bold text-blue-400">{group.cve_count}</p>
                  <p className="text-xs text-gray-400">CVEs Fixed</p>
                </div>

                {/* Severity Breakdown */}
                <div className="space-y-2">
                  {group.critical_count > 0 && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Critical</span>
                      <span className="px-2 py-0.5 bg-red-500/10 text-red-500 rounded font-medium">
                        {group.critical_count}
                      </span>
                    </div>
                  )}
                  {group.high_count > 0 && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">High</span>
                      <span className="px-2 py-0.5 bg-orange-500/10 text-orange-500 rounded font-medium">
                        {group.high_count}
                      </span>
                    </div>
                  )}
                  {group.medium_count > 0 && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Medium</span>
                      <span className="px-2 py-0.5 bg-yellow-500/10 text-yellow-500 rounded font-medium">
                        {group.medium_count}
                      </span>
                    </div>
                  )}
                  {group.low_count > 0 && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Low</span>
                      <span className="px-2 py-0.5 bg-green-500/10 text-green-500 rounded font-medium">
                        {group.low_count}
                      </span>
                    </div>
                  )}
                </div>

                {/* Update Command Hint */}
                <div className="mt-4 pt-4 border-t border-gray-700">
                  <p className="text-xs text-gray-500">
                    Update this package to fix {group.cve_count} {group.cve_count === 1 ? "vulnerability" : "vulnerabilities"}
                  </p>
                </div>
              </div>
            ))
          ) : (
            <div className="col-span-full text-center py-12">
              <p className="text-gray-400">No remediation data available</p>
              <p className="text-sm text-gray-500 mt-2">Run a scan to generate remediation groups</p>
            </div>
          )}
        </div>
      )}

      {/* Vulnerability Detail Modal */}
      {selectedVuln && (
        <VulnerabilityDetailModal
          vulnerability={selectedVuln}
          onClose={() => setSelectedVuln(null)}
        />
      )}
    </div>
  );
}
