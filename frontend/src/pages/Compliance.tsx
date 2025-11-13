/**
 * Compliance Page - Docker Bench + Dockle Image Security
 */

import { useState, useRef, useMemo, type ReactNode } from "react";
import { Shield, Play, Filter, AlertCircle, CheckCircle, XCircle, Info, TrendingUp, Download, Loader2 } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { ImageCompliance } from "../components/ImageCompliance";

interface ComplianceSummary {
  last_scan_date: string | null;
  last_scan_status: string | null;
  compliance_score: number | null;
  total_checks: number;
  passed_checks: number;
  warned_checks: number;
  failed_checks: number;
  info_checks: number;
  note_checks: number;
  high_severity_failures: number;
  medium_severity_failures: number;
  low_severity_failures: number;
  ignored_findings_count: number;
  category_breakdown: { [key: string]: number } | null;
}

interface ComplianceFinding {
  id: number;
  check_id: string;
  check_number: string | null;
  title: string;
  description: string | null;
  status: string; // PASS, WARN, FAIL, INFO, NOTE
  severity: string; // HIGH, MEDIUM, LOW, INFO
  category: string;
  remediation: string | null;
  actual_value: string | null;
  expected_value: string | null;
  is_ignored: boolean;
  ignored_reason: string | null;
  ignored_by: string | null;
  ignored_at: string | null;
  first_seen: string;
  last_seen: string;
  scan_date: string;
}

interface CurrentScan {
  status: string;
  scan_id: number | null;
  started_at: string | null;
  progress: string | null;
  current_check: string | null;
  current_check_id: string | null;
  progress_current: number | null;
  progress_total: number | null;
}

interface TrendDataPoint {
  date: string;
  compliance_score: number;
  passed_checks: number;
  warned_checks: number;
  failed_checks: number;
  total_checks: number;
  category_scores: { [key: string]: number };
}

export function Compliance() {
  const [activeTab, setActiveTab] = useState<"host" | "image">("host");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [showIgnored, setShowIgnored] = useState(false);
  const [ignoreModalOpen, setIgnoreModalOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<ComplianceFinding | null>(null);
  const [ignoreReason, setIgnoreReason] = useState("");
  const [imageActions, setImageActions] = useState<ReactNode | null>(null);

  const queryClient = useQueryClient();

  // Track highest progress to prevent backwards movement due to out-of-order responses
  const highestProgressRef = useRef<number>(0);

  // Fetch compliance summary
  const { data: summary } = useQuery<ComplianceSummary>({
    queryKey: ["compliance-summary"],
    queryFn: async () => {
      const res = await fetch("/api/v1/compliance/summary");
      return res.json();
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  // Fetch current scan status with aggressive polling configuration
  const currentScanQuery = useQuery<CurrentScan>({
    queryKey: ["compliance-current"],
    queryFn: async () => {
      const res = await fetch("/api/v1/compliance/current");
      return res.json();
    },
    refetchInterval: 1000,           // Poll every 1s for real-time progress
    refetchIntervalInBackground: true, // Continue polling even when tab is inactive
    staleTime: 0,                     // Always consider data stale to force refetch
    enabled: true,                    // Always enabled
    retry: 1,                         // Retry failed requests once
  });

  // Apply client-side monotonic filtering to prevent progress bouncing on high-latency networks
  const currentScan = useMemo(() => {
    const rawData = currentScanQuery.data;

    if (!rawData) return rawData;

    // Reset highest progress when scan completes or is idle
    if (rawData.status === "idle") {
      highestProgressRef.current = 0;
      return rawData;
    }

    // For scanning state, enforce monotonic progress
    if (rawData.status === "scanning" && rawData.progress_current !== null) {
      // Only update if progress is higher than what we've seen
      if (rawData.progress_current > highestProgressRef.current) {
        highestProgressRef.current = rawData.progress_current;
        return rawData;
      } else {
        // Stale response detected - return data with highest known progress
        // This prevents backwards movement when responses arrive out of order
        return {
          ...rawData,
          progress_current: highestProgressRef.current,
        };
      }
    }

    return rawData;
  }, [currentScanQuery.data]);

  // Fetch findings
  const { data: findings, isLoading } = useQuery<ComplianceFinding[]>({
    queryKey: ["compliance-findings", statusFilter, categoryFilter, showIgnored],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (statusFilter) params.append("status_filter", statusFilter);
      if (categoryFilter) params.append("category_filter", categoryFilter);
      params.append("include_ignored", showIgnored.toString());

      const res = await fetch(`/api/v1/compliance/findings?${params}`);
      return res.json();
    },
  });

  // Fetch trend data
  const { data: trendData } = useQuery<TrendDataPoint[]>({
    queryKey: ["compliance-trend"],
    queryFn: async () => {
      const res = await fetch("/api/v1/compliance/scans/trend?days=30");
      return res.json();
    },
    refetchInterval: 60000, // Refresh every minute
  });

  // Trigger scan mutation
  const triggerScanMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/v1/compliance/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ trigger_type: "manual" }),
      });
      return res.json();
    },
    onSuccess: () => {
      toast.success("Compliance scan started");
      // Force immediate refetch to ensure polling continues
      queryClient.invalidateQueries({ queryKey: ["compliance-current"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
    },
    onError: () => {
      toast.error("Failed to start compliance scan");
    },
  });

  // Ignore finding mutation
  const ignoreFindingMutation = useMutation({
    mutationFn: async ({ findingId, reason }: { findingId: number; reason: string }) => {
      const res = await fetch("/api/v1/compliance/findings/ignore", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: findingId,
          reason,
          ignored_by: "user",
        }),
      });
      return res.json();
    },
    onSuccess: () => {
      toast.success("Finding marked as false positive");
      queryClient.invalidateQueries({ queryKey: ["compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
      setIgnoreModalOpen(false);
      setIgnoreReason("");
    },
    onError: () => {
      toast.error("Failed to mark finding as false positive");
    },
  });

  // Unignore finding mutation
  const unignoreFindingMutation = useMutation({
    mutationFn: async (findingId: number) => {
      const res = await fetch("/api/v1/compliance/findings/unignore", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: findingId }),
      });
      return res.json();
    },
    onSuccess: () => {
      toast.success("Finding unmarked as false positive");
      queryClient.invalidateQueries({ queryKey: ["compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
    },
    onError: () => {
      toast.error("Failed to unmark finding");
    },
  });

  const handleIgnore = (finding: ComplianceFinding) => {
    setSelectedFinding(finding);
    setIgnoreModalOpen(true);
  };

  const handleIgnoreSubmit = () => {
    if (!selectedFinding || !ignoreReason.trim()) {
      toast.error("Please provide a reason");
      return;
    }
    ignoreFindingMutation.mutate({
      findingId: selectedFinding.id,
      reason: ignoreReason.trim(),
    });
  };

  const getStatusBadge = (status: string) => {
    const badges: Record<string, ReactNode> = {
      PASS: (
        <span className="px-2 py-1 rounded-full text-xs font-medium bg-green-500/20 text-green-400 flex items-center gap-1">
          <CheckCircle className="w-3 h-3" />
          PASS
        </span>
      ),
      WARN: (
        <span className="px-2 py-1 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400 flex items-center gap-1">
          <AlertCircle className="w-3 h-3" />
          WARN
        </span>
      ),
      FAIL: (
        <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400 flex items-center gap-1">
          <XCircle className="w-3 h-3" />
          FAIL
        </span>
      ),
      INFO: (
        <span className="px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400 flex items-center gap-1">
          <Info className="w-3 h-3" />
          INFO
        </span>
      ),
      NOTE: (
        <span className="px-2 py-1 rounded-full text-xs font-medium bg-gray-500/20 text-gray-400 flex items-center gap-1">
          <Info className="w-3 h-3" />
          NOTE
        </span>
      ),
    };
    return badges[status] || status;
  };

  const getSeverityBadge = (severity: string) => {
    const badges: Record<string, ReactNode> = {
      HIGH: <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400">HIGH</span>,
      MEDIUM: <span className="px-2 py-1 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400">MEDIUM</span>,
      LOW: <span className="px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400">LOW</span>,
      INFO: <span className="px-2 py-1 rounded-full text-xs font-medium bg-gray-500/20 text-gray-400">INFO</span>,
    };
    return badges[severity] || severity;
  };

  const getScoreColor = (score: number | null) => {
    if (!score) return "text-gray-400";
    if (score >= 90) return "text-green-400";
    if (score >= 70) return "text-yellow-400";
    return "text-red-400";
  };

  const isScanning = currentScan?.status === "scanning";

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-500" />
            Security Compliance
          </h1>
          <p className="text-gray-400 mt-1">
            Host Configuration & Image Security Analysis
          </p>
        </div>
        <div className="flex gap-2">
          {activeTab === "host"
            ? (
              <>
                <button
                  onClick={() => {
                    // Build export URL with current filters
                    const params = new URLSearchParams();
                    if (statusFilter) params.append("status_filter", statusFilter);
                    if (categoryFilter) params.append("category_filter", categoryFilter);
                    params.append("include_ignored", showIgnored.toString());

                    // Trigger download
                    window.location.href = `/api/v1/compliance/export/csv?${params}`;
                    toast.success("Exporting compliance report...");
                  }}
                  disabled={!findings || findings.length === 0}
                  className="px-4 py-2 bg-green-600 hover:bg-green-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg flex items-center gap-2 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  Export CSV
                </button>
                <button
                  onClick={() => triggerScanMutation.mutate()}
                  disabled={isScanning || triggerScanMutation.isPending}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg flex items-center gap-2 transition-colors"
                >
                  {triggerScanMutation.isPending || isScanning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Scan Now
                    </>
                  )}
                </button>
              </>
            )
            : imageActions ?? null}
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6 border-b border-gray-700">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab("host")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "host"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-gray-400 hover:text-gray-300"
            }`}
          >
            Host Configuration
            <span className="text-xs ml-2 text-gray-500">Docker Bench</span>
          </button>
          <button
            onClick={() => setActiveTab("image")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "image"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-gray-400 hover:text-gray-300"
            }`}
          >
            Image Security
            <span className="text-xs ml-2 text-gray-500">Dockle</span>
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === "image" ? (
        <ImageCompliance onActionsChange={setImageActions} />
      ) : (
        <>
          {/* Scan Progress with Real-Time Details */}
          {isScanning && currentScan && (
        <div className="mb-6 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />
              <div>
                <p className="text-blue-400 font-medium">Compliance scan in progress...</p>
                {currentScan.current_check && (
                  <p className="text-sm text-gray-400 mt-1">
                    {currentScan.current_check_id && (
                      <span className="font-mono text-blue-300">[{currentScan.current_check_id}]</span>
                    )}{" "}
                    {currentScan.current_check}
                  </p>
                )}
              </div>
            </div>
            {currentScan.progress_current !== null && currentScan.progress_total !== null && (
              <span className="text-sm text-gray-400 font-medium">
                {currentScan.progress_current} / {currentScan.progress_total} checks
              </span>
            )}
          </div>

          {/* Progress Bar */}
          {currentScan.progress_current !== null && currentScan.progress_total !== null && (
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div
                className="bg-blue-500 h-full rounded-full transition-all duration-300"
                style={{
                  width: `${(currentScan.progress_current / currentScan.progress_total) * 100}%`,
                }}
              />
            </div>
          )}
        </div>
      )}

      {/* Compliance Score Card */}
      {summary && summary.last_scan_date && (
        <div className="mb-6 p-6 bg-gray-800 rounded-lg border border-gray-700">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {/* Overall Score */}
            <div className="md:col-span-1 text-center border-r border-gray-700">
              <div className={`text-5xl font-bold ${getScoreColor(summary.compliance_score)}`}>
                {summary.compliance_score?.toFixed(1)}%
              </div>
              <div className="text-gray-400 mt-2">Compliance Score</div>
              <div className="text-xs text-gray-500 mt-1">
                Last scan: {new Date(summary.last_scan_date).toLocaleString()}
              </div>
            </div>

            {/* Check Stats */}
            <div className="md:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400">{summary.passed_checks}</div>
                <div className="text-sm text-gray-400">Passed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-400">{summary.warned_checks}</div>
                <div className="text-sm text-gray-400">Warnings</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-400">{summary.failed_checks}</div>
                <div className="text-sm text-gray-400">Failed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-gray-400">{summary.ignored_findings_count}</div>
                <div className="text-sm text-gray-400">Ignored</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Category Breakdown */}
      {summary?.category_breakdown && (
        <div className="mb-6">
          <h2 className="text-xl font-semibold text-white mb-4">Category Breakdown</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {Object.entries(summary.category_breakdown).map(([category, score]) => (
              <div
                key={category}
                className="p-4 bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors cursor-pointer"
                onClick={() => setCategoryFilter(categoryFilter === category ? "" : category)}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-300 font-medium">{category}</span>
                  <span className={`text-lg font-bold ${getScoreColor(score)}`}>
                    {score.toFixed(0)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      score >= 90 ? "bg-green-500" : score >= 70 ? "bg-yellow-500" : "bg-red-500"
                    }`}
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Compliance Trend Chart */}
      {trendData && trendData.length > 1 && (
        <div className="mb-6 p-6 bg-gray-800 rounded-lg border border-gray-700">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-5 h-5 text-cyan-500" />
            <h2 className="text-xl font-semibold text-white">Compliance Trend (30 Days)</h2>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis
                dataKey="date"
                stroke="#9CA3AF"
                tickFormatter={(value) => new Date(value).toLocaleDateString()}
              />
              <YAxis stroke="#9CA3AF" domain={[0, 100]} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1F2937",
                  border: "1px solid #374151",
                  borderRadius: "0.5rem",
                }}
                labelFormatter={(value) => new Date(value).toLocaleString()}
              />
              <Legend />
              <Line
                type="monotone"
                dataKey="compliance_score"
                name="Compliance Score"
                stroke="#06B6D4"
                strokeWidth={2}
                dot={{ fill: "#06B6D4" }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400" />
          <span className="text-sm text-gray-400">Filters:</span>
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white"
        >
          <option value="">All Statuses</option>
          <option value="PASS">Pass</option>
          <option value="WARN">Warn</option>
          <option value="FAIL">Fail</option>
          <option value="INFO">Info</option>
          <option value="NOTE">Note</option>
        </select>

        {summary?.category_breakdown && (
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white"
          >
            <option value="">All Categories</option>
            {Object.keys(summary.category_breakdown).map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        )}

        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={showIgnored}
            onChange={(e) => setShowIgnored(e.target.checked)}
            className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-blue-600 focus:ring-blue-500"
          />
          <span className="text-sm text-gray-300">Show Ignored</span>
        </label>

        {(statusFilter || categoryFilter || showIgnored) && (
          <button
            onClick={() => {
              setStatusFilter("");
              setCategoryFilter("");
              setShowIgnored(false);
            }}
            className="text-sm text-blue-400 hover:text-blue-300"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Findings Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-900/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Check ID
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Title
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Severity
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Category
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-400">
                    Loading findings...
                  </td>
                </tr>
              ) : findings && findings.length > 0 ? (
                findings.map((finding) => (
                  <tr
                    key={finding.id}
                    className={`hover:bg-gray-700/50 transition-colors ${
                      finding.is_ignored ? "opacity-50" : ""
                    }`}
                  >
                    <td className="px-4 py-3 whitespace-nowrap">
                      {getStatusBadge(finding.status)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="text-sm text-gray-300 font-mono">{finding.check_id}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-sm ${finding.is_ignored ? "line-through" : "text-gray-200"}`}>
                        {finding.title}
                      </span>
                      {finding.is_ignored && (
                        <div className="text-xs text-gray-500 mt-1">
                          Ignored: {finding.ignored_reason}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {getSeverityBadge(finding.severity)}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-400">{finding.category}</span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {finding.is_ignored ? (
                        <button
                          onClick={() => unignoreFindingMutation.mutate(finding.id)}
                          disabled={unignoreFindingMutation.isPending}
                          className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50"
                        >
                          Unignore
                        </button>
                      ) : (
                        <button
                          onClick={() => handleIgnore(finding)}
                          className="text-xs text-gray-400 hover:text-gray-300"
                        >
                          Mark as False Positive
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-400">
                    No findings found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Ignore Modal */}
      {ignoreModalOpen && selectedFinding && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-lg w-full mx-4 border border-gray-700">
            <h3 className="text-xl font-semibold text-white mb-4">Mark as False Positive</h3>
            <p className="text-gray-300 mb-4">
              Check: <span className="font-mono text-blue-400">{selectedFinding.check_id}</span> -{" "}
              {selectedFinding.title}
            </p>
            <div className="mb-4">
              <label className="block text-sm text-gray-400 mb-2">
                Reason (required)
              </label>
              <textarea
                value={ignoreReason}
                onChange={(e) => setIgnoreReason(e.target.value)}
                placeholder="Explain why this finding is not applicable..."
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                rows={4}
              />
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setIgnoreModalOpen(false);
                  setIgnoreReason("");
                }}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleIgnoreSubmit}
                disabled={!ignoreReason.trim() || ignoreFindingMutation.isPending}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
              >
                {ignoreFindingMutation.isPending ? "Saving..." : "Mark as False Positive"}
              </button>
            </div>
          </div>
        </div>
      )}
        </>
      )}
    </div>
  );
}
