/**
 * Compliance Page - VulnForge Native Checker (Host) + Trivy (Image Misconfiguration)
 */

import { useState, useMemo, useEffect, type ReactNode } from "react";
import { Shield, Play, Filter, AlertCircle, CheckCircle, XCircle, Info, TrendingUp, Download, Loader2, ChevronDown, ChevronRight, Copy, Check, Container, Server } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { ImageCompliance } from "../components/ImageCompliance";
import { validateIgnoreReason } from "@/schemas/modals";

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
  target: string | null; // Container/image name for per-target checks
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
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const queryClient = useQueryClient();

  // Track highest progress to prevent backwards movement due to out-of-order responses
  const [highestProgress, setHighestProgress] = useState(0);

  // Fetch compliance summary
  const summaryQuery = useQuery<ComplianceSummary>({
    queryKey: ["compliance-summary"],
    queryFn: async () => {
      const res = await fetch("/api/v1/compliance/summary");
      return res.json();
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });
  const summary = summaryQuery.data;

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

  // Fetch findings
  const findingsQuery = useQuery<ComplianceFinding[]>({
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
  const findings = findingsQuery.data;
  const isLoading = findingsQuery.isLoading;

  // Track progress updates and handle side effects
  const rawScanData = currentScanQuery.data;

  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect -- Progress tracking requires setState in effect */
    if (!rawScanData) return;

    // Reset highest progress when scan completes or is idle
    if (rawScanData.status === "idle" || rawScanData.status === "completed") {
      setHighestProgress(0);

      // If completed, trigger data refresh
      if (rawScanData.status === "completed") {
        const timer = setTimeout(() => {
          summaryQuery.refetch();
          findingsQuery.refetch();
        }, 500);
        return () => clearTimeout(timer);
      }
    }

    // For scanning state, track highest progress
    if (rawScanData.status === "scanning" && rawScanData.progress_current !== null) {
      if (rawScanData.progress_current > highestProgress) {
        setHighestProgress(rawScanData.progress_current);
      }
    }
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [rawScanData, highestProgress, summaryQuery, findingsQuery]);

  // Derive current scan data with monotonic progress
  const currentScan = useMemo(() => {
    if (!rawScanData) return rawScanData;

    // For scanning state, use highest known progress to prevent backwards movement
    if (rawScanData.status === "scanning" && rawScanData.progress_current !== null) {
      const effectiveProgress = Math.max(rawScanData.progress_current, highestProgress);
      if (effectiveProgress !== rawScanData.progress_current) {
        return {
          ...rawScanData,
          progress_current: effectiveProgress,
        };
      }
    }

    return rawScanData;
  }, [rawScanData, highestProgress]);

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
    onError: (error) => handleApiError(error, "Failed to start compliance scan"),
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
    onError: (error) => handleApiError(error, "Failed to mark finding as false positive"),
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
    onError: (error) => handleApiError(error, "Failed to unmark finding"),
  });

  const handleIgnore = (finding: ComplianceFinding) => {
    setSelectedFinding(finding);
    setIgnoreModalOpen(true);
  };

  const toggleGroupExpanded = (checkId: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(checkId)) {
        next.delete(checkId);
      } else {
        next.add(checkId);
      }
      return next;
    });
  };

  const copyToClipboard = async (text: string, field: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Group findings by check_id for aggregated view
  interface GroupedFinding {
    check_id: string;
    title: string;
    description: string | null;
    category: string;
    severity: string;
    remediation: string | null;
    findings: ComplianceFinding[];
    passCount: number;
    warnCount: number;
    failCount: number;
    infoCount: number;
    worstStatus: string;
    hasTargets: boolean;
  }

  const groupedFindings = useMemo<GroupedFinding[]>(() => {
    if (!findings) return [];

    const groups = new Map<string, GroupedFinding>();

    for (const finding of findings) {
      const existing = groups.get(finding.check_id);
      if (existing) {
        existing.findings.push(finding);
        if (finding.status === "PASS") existing.passCount++;
        else if (finding.status === "WARN") existing.warnCount++;
        else if (finding.status === "FAIL") existing.failCount++;
        else existing.infoCount++;

        // Update worst status (FAIL > WARN > INFO > PASS)
        if (finding.status === "FAIL") existing.worstStatus = "FAIL";
        else if (finding.status === "WARN" && existing.worstStatus !== "FAIL") existing.worstStatus = "WARN";

        if (finding.target) existing.hasTargets = true;
      } else {
        groups.set(finding.check_id, {
          check_id: finding.check_id,
          title: finding.title,
          description: finding.description,
          category: finding.category,
          severity: finding.severity,
          remediation: finding.remediation,
          findings: [finding],
          passCount: finding.status === "PASS" ? 1 : 0,
          warnCount: finding.status === "WARN" ? 1 : 0,
          failCount: finding.status === "FAIL" ? 1 : 0,
          infoCount: finding.status !== "PASS" && finding.status !== "WARN" && finding.status !== "FAIL" ? 1 : 0,
          worstStatus: finding.status,
          hasTargets: !!finding.target,
        });
      }
    }

    // Sort by check_id
    return Array.from(groups.values()).sort((a, b) => a.check_id.localeCompare(b.check_id));
  }, [findings]);

  const handleIgnoreSubmit = () => {
    if (!selectedFinding) return;

    const validation = validateIgnoreReason(ignoreReason);
    if (!validation.success) {
      toast.error(validation.error);
      return;
    }

    ignoreFindingMutation.mutate({
      findingId: selectedFinding.id,
      reason: validation.data,
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
        <span className="px-2 py-1 rounded-full text-xs font-medium bg-vuln-text-disabled/20 text-vuln-text-muted flex items-center gap-1">
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
      INFO: <span className="px-2 py-1 rounded-full text-xs font-medium bg-vuln-text-disabled/20 text-vuln-text-muted">INFO</span>,
    };
    return badges[severity] || severity;
  };

  const getScoreColor = (score: number | null) => {
    if (!score) return "text-vuln-text-muted";
    if (score >= 90) return "text-green-400";
    if (score >= 70) return "text-yellow-400";
    return "text-red-400";
  };

  const isScanning = currentScan?.status === "scanning";

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-vuln-text flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-500" />
            Security Compliance
          </h1>
          <p className="text-sm text-vuln-text-muted mt-0.5">
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
                  className="px-3 py-2 bg-green-600 hover:bg-green-500 disabled:bg-vuln-surface disabled:cursor-not-allowed text-white rounded-lg flex items-center gap-2 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  Export CSV
                </button>
                <button
                  onClick={() => triggerScanMutation.mutate()}
                  disabled={isScanning || triggerScanMutation.isPending}
                  className="px-3 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-vuln-surface disabled:cursor-not-allowed text-white rounded-lg flex items-center gap-2 transition-colors"
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
      <div className="mb-6 border-b border-vuln-border">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab("host")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "host"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-vuln-text-muted hover:text-vuln-text"
            }`}
          >
            Host Configuration
            <span className="text-xs ml-2 text-vuln-text-disabled">VulnForge Checker</span>
          </button>
          <button
            onClick={() => setActiveTab("image")}
            className={`px-4 py-2 font-medium transition-colors relative ${
              activeTab === "image"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-vuln-text-muted hover:text-vuln-text"
            }`}
          >
            Image Security
            <span className="text-xs ml-2 text-vuln-text-disabled">Trivy</span>
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
                  <p className="text-sm text-sm text-vuln-text-muted mt-0.5">
                    {currentScan.current_check_id && (
                      <span className="font-mono text-blue-300">[{currentScan.current_check_id}]</span>
                    )}{" "}
                    {currentScan.current_check}
                  </p>
                )}
              </div>
            </div>
            {currentScan.progress_current !== null && currentScan.progress_total !== null && (
              <span className="text-sm text-vuln-text-muted font-medium">
                {currentScan.progress_current} / {currentScan.progress_total} checks
              </span>
            )}
          </div>

          {/* Progress Bar */}
          {currentScan.progress_current !== null && currentScan.progress_total !== null && (
            <div className="w-full bg-vuln-surface rounded-full h-2">
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
        <div className="mb-6 p-6 bg-vuln-surface rounded-lg border border-vuln-border">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {/* Overall Score */}
            <div className="md:col-span-1 text-center border-r border-vuln-border">
              <div className={`text-5xl font-bold ${getScoreColor(summary.compliance_score)}`}>
                {summary.compliance_score?.toFixed(1)}%
              </div>
              <div className="text-vuln-text-muted mt-2">Compliance Score</div>
              <div className="text-xs text-vuln-text-disabled mt-1">
                Last scan: {new Date(summary.last_scan_date).toLocaleString()}
              </div>
            </div>

            {/* Check Stats */}
            <div className="md:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400">{summary.passed_checks}</div>
                <div className="text-sm text-vuln-text-muted">Passed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-400">{summary.warned_checks}</div>
                <div className="text-sm text-vuln-text-muted">Warnings</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-400">{summary.failed_checks}</div>
                <div className="text-sm text-vuln-text-muted">Failed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-vuln-text-muted">{summary.ignored_findings_count}</div>
                <div className="text-sm text-vuln-text-muted">Ignored</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Category Breakdown */}
      {summary?.category_breakdown && (
        <div className="mb-6">
          <h2 className="text-xl font-semibold text-vuln-text mb-4">Category Breakdown</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {Object.entries(summary.category_breakdown).map(([category, score]) => (
              <div
                key={category}
                className="p-4 bg-vuln-surface rounded-lg border border-vuln-border hover:border-vuln-border-light transition-colors cursor-pointer"
                onClick={() => setCategoryFilter(categoryFilter === category ? "" : category)}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-vuln-text font-medium">{category}</span>
                  <span className={`text-lg font-bold ${getScoreColor(score)}`}>
                    {score.toFixed(0)}%
                  </span>
                </div>
                <div className="w-full bg-vuln-surface-light rounded-full h-2">
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
        <div className="mb-6 p-6 bg-vuln-surface rounded-lg border border-vuln-border">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-5 h-5 text-cyan-500" />
            <h2 className="text-xl font-semibold text-vuln-text">Compliance Trend (30 Days)</h2>
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
                content={({ active, payload, label }) => {
                  if (active && payload && payload.length) {
                    return (
                      <div className="bg-vuln-surface border border-vuln-border rounded-lg p-3 shadow-lg">
                        <p className="font-semibold text-vuln-text mb-2">
                          {label ? new Date(label).toLocaleString() : "Unknown"}
                        </p>
                        {payload.map((entry, index) => (
                          <p key={index} className="text-sm" style={{ color: entry.color }}>
                            {entry.name}: {entry.value}%
                          </p>
                        ))}
                      </div>
                    );
                  }
                  return null;
                }}
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
          <Filter className="w-4 h-4 text-vuln-text-muted" />
          <span className="text-sm text-vuln-text-muted">Filters:</span>
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 bg-vuln-surface border border-vuln-border rounded-lg text-sm text-vuln-text"
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
            className="px-3 py-1.5 bg-vuln-surface border border-vuln-border rounded-lg text-sm text-vuln-text"
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
            className="w-4 h-4 rounded border-vuln-border bg-vuln-surface text-blue-600 focus:ring-blue-500"
          />
          <span className="text-sm text-vuln-text">Show Ignored</span>
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

      {/* Findings Table - Grouped by Check ID */}
      <div className="bg-vuln-surface rounded-lg border border-vuln-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-vuln-surface-light">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider w-8">
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                  Check ID
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                  Title
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                  Results
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                  Severity
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-vuln-text-muted uppercase tracking-wider">
                  Category
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-vuln-text-muted">
                    Loading findings...
                  </td>
                </tr>
              ) : groupedFindings.length > 0 ? (
                groupedFindings.map((group) => {
                  const isExpanded = expandedGroups.has(group.check_id);
                  const hasDetails = group.remediation || group.description || group.hasTargets;
                  const totalFindings = group.passCount + group.warnCount + group.failCount + group.infoCount;

                  return (
                    <>
                      {/* Group Header Row */}
                      <tr
                        key={group.check_id}
                        className={`hover:bg-vuln-surface-light transition-colors ${hasDetails ? "cursor-pointer" : ""}`}
                        onClick={() => hasDetails && toggleGroupExpanded(group.check_id)}
                      >
                        <td className="px-4 py-3 whitespace-nowrap">
                          {hasDetails && (
                            <button className="text-vuln-text-muted hover:text-vuln-text">
                              {isExpanded ? (
                                <ChevronDown className="w-4 h-4" />
                              ) : (
                                <ChevronRight className="w-4 h-4" />
                              )}
                            </button>
                          )}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span className="text-sm text-vuln-text font-mono">{group.check_id}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-vuln-text">{group.title}</span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            {group.passCount > 0 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/20 text-green-400">
                                <CheckCircle className="w-3 h-3" />
                                {group.passCount}
                              </span>
                            )}
                            {group.warnCount > 0 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400">
                                <AlertCircle className="w-3 h-3" />
                                {group.warnCount}
                              </span>
                            )}
                            {group.failCount > 0 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-400">
                                <XCircle className="w-3 h-3" />
                                {group.failCount}
                              </span>
                            )}
                            {group.infoCount > 0 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400">
                                <Info className="w-3 h-3" />
                                {group.infoCount}
                              </span>
                            )}
                            {!group.hasTargets && totalFindings === 1 && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-vuln-text-disabled/20 text-vuln-text-muted">
                                <Server className="w-3 h-3" />
                                System
                              </span>
                            )}
                            {group.hasTargets && (
                              <span className="text-xs text-vuln-text-muted">
                                ({totalFindings} {totalFindings === 1 ? "container" : "containers"})
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          {getSeverityBadge(group.severity)}
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-vuln-text-muted">{group.category}</span>
                        </td>
                      </tr>

                      {/* Expanded Details */}
                      {isExpanded && (
                        <tr key={`${group.check_id}-details`} className="bg-vuln-bg">
                          <td colSpan={6} className="px-4 py-4">
                            <div className="space-y-4">
                              {/* Description */}
                              {group.description && (
                                <div>
                                  <h4 className="text-sm font-medium text-vuln-text mb-2">Description</h4>
                                  <p className="text-sm text-vuln-text-muted">{group.description}</p>
                                </div>
                              )}

                              {/* Remediation */}
                              {group.remediation && (
                                <div>
                                  <h4 className="text-sm font-medium text-vuln-text mb-2 flex items-center gap-2">
                                    Remediation
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        copyToClipboard(group.remediation || "", `remediation-${group.check_id}`);
                                      }}
                                      className="text-vuln-text-muted hover:text-blue-400 transition-colors"
                                      title="Copy remediation"
                                    >
                                      {copiedField === `remediation-${group.check_id}` ? (
                                        <Check className="w-4 h-4 text-green-400" />
                                      ) : (
                                        <Copy className="w-4 h-4" />
                                      )}
                                    </button>
                                  </h4>
                                  <pre className="text-xs bg-vuln-surface p-3 rounded overflow-x-auto text-vuln-text-muted whitespace-pre-wrap">
                                    {group.remediation}
                                  </pre>
                                </div>
                              )}

                              {/* Individual Container Results */}
                              {group.hasTargets && (
                                <div>
                                  <h4 className="text-sm font-medium text-vuln-text mb-2">Container Results</h4>
                                  <div className="bg-vuln-surface rounded-lg border border-vuln-border overflow-hidden">
                                    <table className="w-full">
                                      <thead className="bg-vuln-surface-light">
                                        <tr>
                                          <th className="px-3 py-2 text-left text-xs font-medium text-vuln-text-muted uppercase">Status</th>
                                          <th className="px-3 py-2 text-left text-xs font-medium text-vuln-text-muted uppercase">Container</th>
                                          <th className="px-3 py-2 text-left text-xs font-medium text-vuln-text-muted uppercase">Current Value</th>
                                          <th className="px-3 py-2 text-left text-xs font-medium text-vuln-text-muted uppercase">Actions</th>
                                        </tr>
                                      </thead>
                                      <tbody className="divide-y divide-gray-700">
                                        {group.findings
                                          .sort((a, b) => {
                                            // Sort: FAIL first, then WARN, then PASS
                                            const order: Record<string, number> = { FAIL: 0, WARN: 1, INFO: 2, NOTE: 3, PASS: 4 };
                                            return (order[a.status] ?? 5) - (order[b.status] ?? 5);
                                          })
                                          .map((finding) => (
                                            <tr
                                              key={finding.id}
                                              className={`hover:bg-vuln-surface-light ${finding.is_ignored ? "opacity-50" : ""}`}
                                            >
                                              <td className="px-3 py-2 whitespace-nowrap">
                                                {getStatusBadge(finding.status)}
                                              </td>
                                              <td className="px-3 py-2 whitespace-nowrap">
                                                {finding.target ? (
                                                  <span className="inline-flex items-center gap-1 text-sm text-vuln-text">
                                                    <Container className="w-3 h-3 text-purple-400" />
                                                    {finding.target}
                                                  </span>
                                                ) : (
                                                  <span className="inline-flex items-center gap-1 text-sm text-vuln-text-muted">
                                                    <Server className="w-3 h-3" />
                                                    System
                                                  </span>
                                                )}
                                              </td>
                                              <td className="px-3 py-2">
                                                {finding.actual_value && (
                                                  <code className="text-xs bg-vuln-bg px-2 py-1 rounded text-vuln-text-muted">
                                                    {finding.actual_value}
                                                  </code>
                                                )}
                                              </td>
                                              <td className="px-3 py-2 whitespace-nowrap">
                                                {finding.is_ignored ? (
                                                  <button
                                                    onClick={(e) => {
                                                      e.stopPropagation();
                                                      unignoreFindingMutation.mutate(finding.id);
                                                    }}
                                                    disabled={unignoreFindingMutation.isPending}
                                                    className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50"
                                                  >
                                                    Unignore
                                                  </button>
                                                ) : finding.status !== "PASS" ? (
                                                  <button
                                                    onClick={(e) => {
                                                      e.stopPropagation();
                                                      handleIgnore(finding);
                                                    }}
                                                    className="text-xs text-vuln-text-muted hover:text-vuln-text"
                                                  >
                                                    Mark as False Positive
                                                  </button>
                                                ) : null}
                                              </td>
                                            </tr>
                                          ))}
                                      </tbody>
                                    </table>
                                  </div>
                                </div>
                              )}

                              {/* System check (non-container) details */}
                              {!group.hasTargets && group.findings.length === 1 && (
                                <div className="flex items-center justify-between">
                                  <div>
                                    {group.findings[0].actual_value && (
                                      <div className="flex items-start gap-2">
                                        <span className="text-xs text-vuln-text-disabled min-w-16">Current:</span>
                                        <code className="text-xs bg-vuln-surface px-2 py-1 rounded text-vuln-text-muted">
                                          {group.findings[0].actual_value}
                                        </code>
                                      </div>
                                    )}
                                    {group.findings[0].expected_value && (
                                      <div className="flex items-start gap-2 mt-1">
                                        <span className="text-xs text-vuln-text-disabled min-w-16">Expected:</span>
                                        <code className="text-xs bg-vuln-surface px-2 py-1 rounded text-green-400">
                                          {group.findings[0].expected_value}
                                        </code>
                                      </div>
                                    )}
                                  </div>
                                  {group.findings[0].status !== "PASS" && !group.findings[0].is_ignored && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleIgnore(group.findings[0]);
                                      }}
                                      className="text-xs text-vuln-text-muted hover:text-vuln-text"
                                    >
                                      Mark as False Positive
                                    </button>
                                  )}
                                  {group.findings[0].is_ignored && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        unignoreFindingMutation.mutate(group.findings[0].id);
                                      }}
                                      disabled={unignoreFindingMutation.isPending}
                                      className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50"
                                    >
                                      Unignore
                                    </button>
                                  )}
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-vuln-text-muted">
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
          <div className="bg-vuln-surface rounded-lg p-6 max-w-lg w-full mx-4 border border-vuln-border">
            <h3 className="text-xl font-semibold text-vuln-text mb-4">Mark as False Positive</h3>
            <p className="text-vuln-text mb-4">
              Check: <span className="font-mono text-blue-400">{selectedFinding.check_id}</span> -{" "}
              {selectedFinding.title}
            </p>
            <div className="mb-4">
              <label className="block text-sm text-vuln-text-muted mb-2">
                Reason (required)
              </label>
              <textarea
                value={ignoreReason}
                onChange={(e) => setIgnoreReason(e.target.value)}
                placeholder="Explain why this finding is not applicable..."
                className="w-full px-3 py-2 bg-vuln-bg border border-vuln-border rounded-lg text-vuln-text focus:outline-none focus:border-blue-500"
                rows={4}
              />
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setIgnoreModalOpen(false);
                  setIgnoreReason("");
                }}
                className="px-4 py-2 text-vuln-text-muted hover:text-vuln-text transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleIgnoreSubmit}
                disabled={!ignoreReason.trim() || ignoreFindingMutation.isPending}
                className="px-3 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-vuln-surface disabled:cursor-not-allowed text-white rounded-lg transition-colors"
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
