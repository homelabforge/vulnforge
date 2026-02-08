/**
 * Compliance Page - VulnForge Native Checker (Host) + Trivy (Image Misconfiguration)
 *
 * Thin shell: data fetching, mutations, and layout. Visual sections are
 * delegated to sub-components under ./compliance/.
 */

import { useState, useMemo, useEffect, type ReactNode } from "react";
import { Shield, Play, Download, Loader2 } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { handleApiError } from "@/lib/errorHandler";
import { complianceApi } from "@/lib/api";
import { ImageCompliance } from "../components/ImageCompliance";

import type { ComplianceSummary, ComplianceFinding, CurrentScan, TrendDataPoint } from "./compliance/types";
import { ScanProgress } from "./compliance/ScanProgress";
import { ScoreCard } from "./compliance/ScoreCard";
import { CategoryBreakdown } from "./compliance/CategoryBreakdown";
import { TrendChart } from "./compliance/TrendChart";
import { FindingsFilters } from "./compliance/FindingsFilters";
import { FindingsTable } from "./compliance/FindingsTable";
import { IgnoreModal } from "./compliance/IgnoreModal";

export function Compliance() {
  const [activeTab, setActiveTab] = useState<"host" | "image">("host");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [showIgnored, setShowIgnored] = useState(false);
  const [ignoreModalFinding, setIgnoreModalFinding] = useState<ComplianceFinding | null>(null);
  const [imageActions, setImageActions] = useState<ReactNode | null>(null);

  const queryClient = useQueryClient();

  // Track highest progress to prevent backwards movement due to out-of-order responses
  const [highestProgress, setHighestProgress] = useState(0);

  // --- Queries ---

  const summaryQuery = useQuery<ComplianceSummary>({
    queryKey: ["compliance-summary"],
    queryFn: complianceApi.getSummary,
    refetchInterval: 10000,
  });

  const currentScanQuery = useQuery<CurrentScan>({
    queryKey: ["compliance-current"],
    queryFn: complianceApi.getCurrentScan,
    refetchInterval: 1000,
    refetchIntervalInBackground: true,
    staleTime: 0,
    enabled: true,
    retry: 1,
  });

  const findingsQuery = useQuery<ComplianceFinding[]>({
    queryKey: ["compliance-findings", statusFilter, categoryFilter, showIgnored],
    queryFn: () =>
      complianceApi.getFindings({
        status_filter: statusFilter || undefined,
        category_filter: categoryFilter || undefined,
        include_ignored: showIgnored,
      }),
  });

  const { data: trendData } = useQuery<TrendDataPoint[]>({
    queryKey: ["compliance-trend"],
    queryFn: () => complianceApi.getTrend(30),
    refetchInterval: 60000,
  });

  // --- Progress tracking ---

  const rawScanData = currentScanQuery.data;

  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect -- Progress tracking requires setState in effect */
    if (!rawScanData) return;

    if (rawScanData.status === "idle" || rawScanData.status === "completed") {
      setHighestProgress(0);
      if (rawScanData.status === "completed") {
        const timer = setTimeout(() => {
          summaryQuery.refetch();
          findingsQuery.refetch();
        }, 500);
        return () => clearTimeout(timer);
      }
    }

    if (rawScanData.status === "scanning" && rawScanData.progress_current !== null) {
      if (rawScanData.progress_current > highestProgress) {
        setHighestProgress(rawScanData.progress_current);
      }
    }
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [rawScanData, highestProgress, summaryQuery, findingsQuery]);

  const currentScan = useMemo(() => {
    if (!rawScanData) return rawScanData;
    if (rawScanData.status === "scanning" && rawScanData.progress_current !== null) {
      const effectiveProgress = Math.max(rawScanData.progress_current, highestProgress);
      if (effectiveProgress !== rawScanData.progress_current) {
        return { ...rawScanData, progress_current: effectiveProgress };
      }
    }
    return rawScanData;
  }, [rawScanData, highestProgress]);

  // --- Mutations ---

  const triggerScanMutation = useMutation({
    mutationFn: complianceApi.triggerScan,
    onSuccess: () => {
      toast.success("Compliance scan started");
      queryClient.invalidateQueries({ queryKey: ["compliance-current"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
    },
    onError: (error) => handleApiError(error, "Failed to start compliance scan"),
  });

  const ignoreFindingMutation = useMutation({
    mutationFn: ({ findingId, reason }: { findingId: number; reason: string }) =>
      complianceApi.ignoreFinding(findingId, reason),
    onSuccess: () => {
      toast.success("Finding marked as false positive");
      queryClient.invalidateQueries({ queryKey: ["compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
      setIgnoreModalFinding(null);
    },
    onError: (error) => handleApiError(error, "Failed to mark finding as false positive"),
  });

  const unignoreFindingMutation = useMutation({
    mutationFn: complianceApi.unignoreFinding,
    onSuccess: () => {
      toast.success("Finding unmarked as false positive");
      queryClient.invalidateQueries({ queryKey: ["compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-summary"] });
    },
    onError: (error) => handleApiError(error, "Failed to unmark finding"),
  });

  // --- Derived state ---

  const summary = summaryQuery.data;
  const isScanning = currentScan?.status === "scanning";
  const categories = summary?.category_breakdown ? Object.keys(summary.category_breakdown) : null;

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
          {activeTab === "host" ? (
            <>
              <button
                onClick={() => {
                  window.location.href = complianceApi.getExportUrl({
                    status_filter: statusFilter || undefined,
                    category_filter: categoryFilter || undefined,
                    include_ignored: showIgnored,
                  });
                  toast.success("Exporting compliance report...");
                }}
                disabled={!findingsQuery.data || findingsQuery.data.length === 0}
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
          ) : (
            imageActions ?? null
          )}
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
          {isScanning && currentScan && <ScanProgress currentScan={currentScan} />}

          {summary && summary.last_scan_date && <ScoreCard summary={summary} />}

          {summary?.category_breakdown && (
            <CategoryBreakdown
              categoryBreakdown={summary.category_breakdown}
              categoryFilter={categoryFilter}
              onCategoryFilter={setCategoryFilter}
            />
          )}

          {trendData && trendData.length > 1 && <TrendChart trendData={trendData} />}

          <FindingsFilters
            statusFilter={statusFilter}
            categoryFilter={categoryFilter}
            showIgnored={showIgnored}
            categories={categories}
            onStatusFilter={setStatusFilter}
            onCategoryFilter={setCategoryFilter}
            onShowIgnored={setShowIgnored}
            onClearFilters={() => {
              setStatusFilter("");
              setCategoryFilter("");
              setShowIgnored(false);
            }}
          />

          <FindingsTable
            findings={findingsQuery.data}
            isLoading={findingsQuery.isLoading}
            onIgnore={setIgnoreModalFinding}
            onUnignore={(id) => unignoreFindingMutation.mutate(id)}
            unignorePending={unignoreFindingMutation.isPending}
          />

          {ignoreModalFinding && (
            <IgnoreModal
              finding={ignoreModalFinding}
              onClose={() => setIgnoreModalFinding(null)}
              onSubmit={(findingId, reason) => ignoreFindingMutation.mutate({ findingId, reason })}
              isPending={ignoreFindingMutation.isPending}
            />
          )}
        </>
      )}
    </div>
  );
}
