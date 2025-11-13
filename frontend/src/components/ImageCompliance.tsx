/**
 * Image Compliance Component - Dockle image security scanning
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  Package,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Shield,
  Download,
  Play,
  Loader2,
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

interface ImageSummary {
  image_name: string;
  compliance_score: number;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  active_failures: number;
  fatal_count: number;
  warn_count: number;
  last_scan_date: string;
  affected_containers: string[];
}

interface ImageFinding {
  id: number;
  check_id: string;
  title: string;
  description: string | null;
  status: string; // PASS, FAIL, INFO, SKIP
  severity: string; // CRITICAL, HIGH, MEDIUM, LOW, INFO
  category: string;
  remediation: string | null;
  alerts: string[];
  is_ignored: boolean;
  ignored_reason: string | null;
  ignored_by: string | null;
  first_seen: string;
  last_seen: string;
}

interface ImageComplianceSummary {
  last_scan_date: string | null;
  last_scan_status: string | null;
  image_name: string | null;
  compliance_score: number | null;
  total_images_scanned: number;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  fatal_count: number;
  warn_count: number;
  category_breakdown: { [key: string]: number } | null;
}

interface ImageScanStatus {
  status: "idle" | "scanning";
  mode?: "single" | "batch";
  current_image?: string | null;
  progress_current?: number | null;
  progress_total?: number | null;
  started_at?: string | null;
  targets?: string[];
  last_result?: {
    image_name: string;
    success: boolean;
    error?: string | null;
    finished_at?: string;
  } | null;
}

interface ImageComplianceProps {
  onActionsChange?: (actions: ReactNode | null) => void;
}

export function ImageCompliance({ onActionsChange }: ImageComplianceProps) {
  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [showIgnored, setShowIgnored] = useState(false);
  const [ignoreModalOpen, setIgnoreModalOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<ImageFinding | null>(null);
  const [ignoreReason, setIgnoreReason] = useState("");
  const [scanModalOpen, setScanModalOpen] = useState(false);
  const [imageInput, setImageInput] = useState("");

  const queryClient = useQueryClient();

  // Fetch overall summary
  const { data: summary } = useQuery<ImageComplianceSummary>({
    queryKey: ["image-compliance-summary"],
    queryFn: async () => {
      const res = await fetch("/api/v1/image-compliance/summary");
      return res.json();
    },
    refetchInterval: 10000,
  });

  // Fetch scanned images
  const { data: images = [] } = useQuery<ImageSummary[]>({
    queryKey: ["image-compliance-images"],
    queryFn: async () => {
      const res = await fetch("/api/v1/image-compliance/images");
      return res.json();
    },
    refetchInterval: 10000,
  });

  // Fetch findings for selected image
  const { data: findings = [], isFetching: isFindingFetching } = useQuery<ImageFinding[]>({
    queryKey: ["image-compliance-findings", selectedImage, statusFilter, showIgnored],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (statusFilter) params.append("status_filter", statusFilter);
      params.append("include_ignored", showIgnored.toString());

      const res = await fetch(
        `/api/v1/image-compliance/findings/${encodeURIComponent(selectedImage!)}?${params}`
      );
      return res.json();
    },
    enabled: !!selectedImage,
  });

  // Mutation to ignore a finding
  const ignoreMutation = useMutation({
    mutationFn: async ({ findingId, reason }: { findingId: number; reason: string }) => {
      const res = await fetch(`/api/v1/image-compliance/findings/${findingId}/ignore`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
      });
      if (!res.ok) throw new Error("Failed to ignore finding");
      return res.json();
    },
    onSuccess: () => {
      toast.success("Finding marked as ignored");
      queryClient.invalidateQueries({ queryKey: ["image-compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["image-compliance-images"] });
      setIgnoreModalOpen(false);
      setIgnoreReason("");
      setSelectedFinding(null);
    },
    onError: (error: Error) => {
      toast.error(`Failed to ignore finding: ${error.message}`);
    },
  });

  // Mutation to unignore a finding
  const unignoreMutation = useMutation({
    mutationFn: async (findingId: number) => {
      const res = await fetch(`/api/v1/image-compliance/findings/${findingId}/unignore`, {
        method: "POST",
      });
      if (!res.ok) throw new Error("Failed to unignore finding");
      return res.json();
    },
    onSuccess: () => {
      toast.success("Finding unmarked as ignored");
      queryClient.invalidateQueries({ queryKey: ["image-compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["image-compliance-images"] });
    },
    onError: (error: Error) => {
      toast.error(`Failed to unignore finding: ${error.message}`);
    },
  });

  const handleIgnoreFinding = (finding: ImageFinding) => {
    setSelectedFinding(finding);
    setIgnoreModalOpen(true);
  };

  const handleConfirmIgnore = () => {
    if (!selectedFinding || !ignoreReason.trim()) {
      toast.error("Please provide a reason for ignoring this finding");
      return;
    }

    ignoreMutation.mutate({
      findingId: selectedFinding.id,
      reason: ignoreReason,
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-red-500/20 text-red-400";
      case "HIGH":
        return "bg-orange-500/20 text-orange-400";
      case "MEDIUM":
        return "bg-yellow-500/20 text-yellow-400";
      case "LOW":
        return "bg-blue-500/20 text-blue-400";
      default:
        return "bg-gray-500/20 text-gray-400";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "PASS":
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case "FAIL":
        return <XCircle className="h-5 w-5 text-red-500" />;
      case "INFO":
        return <Info className="h-5 w-5 text-blue-500" />;
      case "SKIP":
        return <AlertTriangle className="h-5 w-5 text-gray-400" />;
      default:
        return <Info className="h-5 w-5 text-gray-400" />;
    }
  };

  const { data: currentScan } = useQuery<ImageScanStatus>({
    queryKey: ["image-compliance-current"],
    queryFn: async () => {
      const res = await fetch("/api/v1/image-compliance/current");
      if (!res.ok) {
        throw new Error("Failed to load image scan status");
      }
      return res.json();
    },
    refetchInterval: 1000,
    refetchIntervalInBackground: true,
  });

  const scanImageMutation = useMutation({
    mutationFn: async (imageName: string) => {
      const res = await fetch(
        `/api/v1/image-compliance/scan?image_name=${encodeURIComponent(imageName)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        }
      );
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail.detail || "Failed to start image scan");
      }
      return res.json();
    },
    onSuccess: (data) => {
      toast.success(`Started scan for ${data.image_name}`);
      setScanModalOpen(false);
      setImageInput("");
      queryClient.invalidateQueries({ queryKey: ["image-compliance-summary"] });
      queryClient.invalidateQueries({ queryKey: ["image-compliance-images"] });
      if (selectedImage) {
        queryClient.invalidateQueries({ queryKey: ["image-compliance-findings"] });
      }
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  const scanAllMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/v1/image-compliance/scan-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail.detail || "Failed to start batch scan");
      }
      return res.json();
    },
    onSuccess: (data) => {
      toast.success(`Started batch scan for ${data.image_count} images`);
      queryClient.invalidateQueries({ queryKey: ["image-compliance-summary"] });
      queryClient.invalidateQueries({ queryKey: ["image-compliance-images"] });
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  const isScanning = currentScan?.status === "scanning";

  const previousStatusRef = useRef<string>(currentScan?.status ?? "idle");
  useEffect(() => {
    const previous = previousStatusRef.current;
    const nextStatus = currentScan?.status ?? "idle";
    if (previous === "scanning" && nextStatus !== "scanning") {
      queryClient.invalidateQueries({ queryKey: ["image-compliance-summary"] });
      queryClient.invalidateQueries({ queryKey: ["image-compliance-images"] });
      if (selectedImage) {
        queryClient.invalidateQueries({ queryKey: ["image-compliance-findings"] });
      }
    }
    previousStatusRef.current = nextStatus;
  }, [currentScan?.status, queryClient, selectedImage]);

  const handleExportAll = useCallback(() => {
    window.location.href = "/api/v1/image-compliance/export/csv";
    toast.success("Exporting image compliance report...");
  }, []);

  const { isPending: isScanImagePending } = scanImageMutation;
  const { mutate: runScanAll, isPending: isScanAllPending } = scanAllMutation;

  const actionButtons = useMemo(() => {
    const scanImageDisabled = isScanning || isScanImagePending;
    const scanAllDisabled = isScanning || isScanAllPending;

    return (
      <div className="flex gap-2">
        <button
          onClick={() => setScanModalOpen(true)}
          disabled={scanImageDisabled}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg flex items-center gap-2 transition-colors"
        >
          {isScanImagePending ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Starting…
            </>
          ) : isScanning ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Scanning…
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Scan Image
            </>
          )}
        </button>
        <button
          onClick={() => runScanAll()}
          disabled={scanAllDisabled}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg flex items-center gap-2 transition-colors"
        >
          {isScanAllPending ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Starting…
            </>
          ) : isScanning ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Scanning…
            </>
          ) : (
            <>
              <Shield className="h-4 w-4" />
              Scan All
            </>
          )}
        </button>
        <button
          onClick={handleExportAll}
          className="px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg flex items-center gap-2 transition-colors"
        >
          <Download className="h-4 w-4" />
          Export CSV
        </button>
      </div>
    );
  }, [handleExportAll, isScanning, isScanAllPending, isScanImagePending, runScanAll]);

  useEffect(() => {
    onActionsChange?.(actionButtons);
    return () => {
      onActionsChange?.(null);
    };
  }, [actionButtons, onActionsChange]);

  const visibleFindings = useMemo(
    () => findings.filter((f) => !f.is_ignored || showIgnored),
    [findings, showIgnored]
  );

  return (
    <div className="space-y-6">
      {isScanning && currentScan && (
        <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-400 font-semibold flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin" />
                Image security scan in progress…
              </p>
              {currentScan.current_image && (
                <p className="text-sm text-gray-300 mt-1">
                  Processing <span className="font-mono text-blue-300">{currentScan.current_image}</span>
                </p>
              )}
            </div>
            {typeof currentScan.progress_current === "number" &&
              typeof currentScan.progress_total === "number" &&
              currentScan.progress_total > 0 && (
                <span className="text-sm text-gray-300">
                  {currentScan.progress_current}/{currentScan.progress_total} images
                </span>
              )}
          </div>
          {typeof currentScan.progress_current === "number" &&
            typeof currentScan.progress_total === "number" &&
            currentScan.progress_total > 0 && (
              <div className="mt-3 h-2 bg-blue-500/20 rounded">
                <div
                  className="h-full bg-blue-500 rounded"
                  style={{
                    width: `${Math.min(
                      100,
                      Math.round(
                        (currentScan.progress_current / currentScan.progress_total) * 100
                      )
                    )}%`,
                  }}
                />
              </div>
            )}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#1a1f2e] border border-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Images Scanned</p>
              <p className="text-3xl font-bold text-white">{summary?.total_images_scanned || 0}</p>
            </div>
            <Package className="h-10 w-10 text-blue-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Avg Compliance</p>
              <p className="text-3xl font-bold text-white">
                {images.length > 0
                  ? Math.round(
                      images.reduce((sum, img) => sum + img.compliance_score, 0) /
                        images.length
                    )
                  : 0}
                %
              </p>
            </div>
            <Shield className="h-10 w-10 text-green-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Critical Findings</p>
              <p className="text-3xl font-bold text-red-400">
                {images.reduce((sum, img) => sum + img.fatal_count, 0)}
              </p>
            </div>
            <AlertTriangle className="h-10 w-10 text-red-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Active Failures</p>
              <p className="text-3xl font-bold text-orange-400">
                {images.reduce((sum, img) => sum + img.active_failures, 0)}
              </p>
            </div>
            <XCircle className="h-10 w-10 text-orange-500" />
          </div>
        </div>
      </div>

      {/* Images Table */}
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg">
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold text-white">Scanned Images</h2>
          </div>

          {images.length === 0 ? (
            <div className="text-center py-12 text-gray-400">
              <Package className="h-16 w-16 mx-auto mb-4 text-gray-600" />
              <p className="text-lg font-semibold mb-2 text-white">No images scanned yet</p>
              <p className="text-sm">Click "Scan Image" to analyze a Docker image for security compliance</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-900/50">
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-2 text-xs font-medium text-gray-400 uppercase tracking-wider">Image</th>
                    <th className="text-center py-3 px-2 text-xs font-medium text-gray-400 uppercase tracking-wider">Score</th>
                    <th className="text-center py-3 px-2 text-xs font-medium text-gray-400 uppercase tracking-wider">Checks</th>
                    <th className="text-center py-3 px-2 text-xs font-medium text-gray-400 uppercase tracking-wider">Failures</th>
                    <th className="text-center py-3 px-2 text-xs font-medium text-gray-400 uppercase tracking-wider">Critical</th>
                    <th className="text-left py-3 px-2 text-xs font-medium text-gray-400 uppercase tracking-wider">Containers</th>
                    <th className="text-right py-3 px-2 text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {images.map((image) => (
                    <tr key={image.image_name} className="hover:bg-gray-700/50 transition-colors">
                      <td className="py-3 px-2">
                        <div className="font-mono text-sm text-gray-300 truncate max-w-md" title={image.image_name}>
                          {image.image_name}
                        </div>
                      </td>
                      <td className="text-center px-2">
                        <span
                          className={`inline-block px-3 py-1 rounded-full text-sm font-semibold ${
                            image.compliance_score >= 80
                              ? "bg-green-500/20 text-green-400"
                              : image.compliance_score >= 60
                              ? "bg-yellow-500/20 text-yellow-400"
                              : "bg-red-500/20 text-red-400"
                          }`}
                        >
                          {Math.round(image.compliance_score)}%
                        </span>
                      </td>
                      <td className="text-center px-2">
                        <span className="text-green-400 font-semibold">{image.passed_checks}</span>
                        <span className="text-gray-500 mx-1">/</span>
                        <span className="text-gray-400">{image.total_checks}</span>
                      </td>
                      <td className="text-center px-2">
                        {image.active_failures > 0 ? (
                          <span className="text-red-400 font-semibold">{image.active_failures}</span>
                        ) : (
                          <span className="text-gray-500">0</span>
                        )}
                      </td>
                      <td className="text-center px-2">
                        {image.fatal_count > 0 ? (
                          <span className="text-red-400 font-semibold flex items-center justify-center gap-1">
                            <AlertTriangle className="h-4 w-4" />
                            {image.fatal_count}
                          </span>
                        ) : (
                          <span className="text-gray-500">0</span>
                        )}
                      </td>
                      <td className="py-3 px-2">
                        <div className="flex flex-wrap gap-1">
                          {image.affected_containers.slice(0, 2).map((container) => (
                            <span
                              key={container}
                              className="px-2 py-1 bg-blue-500/10 border border-blue-500/30 rounded text-xs text-blue-400"
                              title={container}
                            >
                              {container.length > 15 ? container.substring(0, 15) + "..." : container}
                            </span>
                          ))}
                          {image.affected_containers.length > 2 && (
                            <span
                              className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300"
                              title={image.affected_containers.slice(2).join(", ")}
                            >
                              +{image.affected_containers.length - 2}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="text-right px-2">
                        <button
                          onClick={() => setSelectedImage(image.image_name)}
                          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors text-sm"
                        >
                          View Findings
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Findings Panel */}
      {selectedImage && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 py-8">
          <div className="bg-[#161b25] border border-gray-700 rounded-xl shadow-xl w-full max-w-5xl max-h-[85vh] flex flex-col">
            <div className="flex items-start justify-between gap-4 border-b border-gray-700 p-6">
              <div>
                <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                  <Package className="h-6 w-6 text-blue-400" />
                  Image Findings
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  {selectedImage} • {visibleFindings.length} finding{visibleFindings.length === 1 ? "" : "s"}
                </p>
              </div>
              <button
                onClick={() => setSelectedImage(null)}
                className="text-gray-400 hover:text-white transition-colors"
                aria-label="Close findings"
              >
                ✕
              </button>
            </div>

            <div className="px-6 pt-4 pb-6 flex flex-col gap-4 flex-1 overflow-hidden">
              <div className="flex flex-wrap items-center gap-3">
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-4 py-2 bg-[#0f1419] border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">All Statuses</option>
                  <option value="FAIL">Failures Only</option>
                  <option value="PASS">Passed Only</option>
                  <option value="INFO">Info Only</option>
                </select>
                <label className="flex items-center gap-2 px-4 py-2 border border-gray-700 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors">
                  <input
                    type="checkbox"
                    checked={showIgnored}
                    onChange={(e) => setShowIgnored(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-300">Show Ignored</span>
                </label>
                <button
                  onClick={() => {
                    window.location.href = `/api/v1/image-compliance/export/csv?image_name=${encodeURIComponent(selectedImage)}`;
                    toast.success("Exporting image findings...");
                  }}
                  className="px-3 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg text-sm flex items-center gap-2"
                >
                  <Download className="h-4 w-4" />
                  Export CSV
                </button>
              </div>

              <div className="flex-1 overflow-y-auto rounded-lg border border-gray-800">
                {isFindingFetching && visibleFindings.length === 0 ? (
                  <div className="flex items-center justify-center py-12 text-gray-400 gap-3">
                    <Loader2 className="h-5 w-5 animate-spin text-blue-400" />
                    Loading findings…
                  </div>
                ) : visibleFindings.length === 0 ? (
                  <div className="py-12 text-center text-gray-400">
                    <XCircle className="mx-auto h-10 w-10 text-gray-600 mb-3" />
                    <p className="text-lg font-semibold text-white">No findings to display</p>
                    <p className="text-sm text-gray-400">Dockle did not report any checks matching the selected filters.</p>
                  </div>
                ) : (
                  <table className="w-full">
                    <thead className="bg-gray-900/50">
                      <tr className="border-b border-gray-700">
                        <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                        <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Check ID</th>
                        <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Title</th>
                        <th className="text-center py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Severity</th>
                        <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Category</th>
                        <th className="text-right py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {visibleFindings.map((finding) => (
                        <tr
                          key={finding.id}
                          className={`hover:bg-gray-800/60 transition-colors ${finding.is_ignored ? "opacity-50" : ""}`}
                        >
                          <td className="py-3 px-3 align-top">{getStatusIcon(finding.status)}</td>
                          <td className="py-3 px-3 align-top">
                            <span className="font-mono text-sm text-gray-300">{finding.check_id}</span>
                          </td>
                          <td className="py-3 px-3">
                            <div className={`font-semibold ${finding.is_ignored ? "line-through text-gray-400" : "text-gray-200"}`}>
                              {finding.title}
                            </div>
                            {finding.description && (
                              <div className="text-sm text-gray-400 mt-1 whitespace-pre-wrap">{finding.description}</div>
                            )}
                            {finding.alerts.length > 0 && (
                              <div className="mt-2 space-y-1">
                                {finding.alerts.map((alert, idx) => (
                                  <div key={idx} className="text-xs bg-yellow-500/10 border border-yellow-500/30 rounded px-2 py-1 text-yellow-400">
                                    • {alert}
                                  </div>
                                ))}
                              </div>
                            )}
                            {finding.remediation && (
                              <details className="mt-3">
                                <summary className="text-xs text-blue-400 cursor-pointer hover:underline">
                                  Show remediation guidance
                                </summary>
                                <div className="text-xs bg-blue-500/10 border border-blue-500/30 rounded px-3 py-2 mt-2 text-gray-300 whitespace-pre-wrap">
                                  {finding.remediation}
                                </div>
                              </details>
                            )}
                            {finding.is_ignored && finding.ignored_reason && (
                              <div className="mt-2 text-xs text-gray-500">
                                Ignored: {finding.ignored_reason}
                              </div>
                            )}
                          </td>
                          <td className="text-center px-3 align-top">
                            <span className={`px-2 py-1 rounded text-xs font-semibold ${getSeverityColor(finding.severity)}`}>
                              {finding.severity}
                            </span>
                          </td>
                          <td className="py-3 px-3 align-top">
                            <span className="text-sm text-gray-400">{finding.category}</span>
                          </td>
                          <td className="text-right px-3 align-top">
                            {finding.is_ignored ? (
                              <button
                                onClick={() => unignoreMutation.mutate(finding.id)}
                                className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded transition-colors text-sm"
                              >
                                Unignore
                              </button>
                            ) : finding.status === "FAIL" ? (
                              <button
                                onClick={() => handleIgnoreFinding(finding)}
                                className="px-3 py-1 bg-yellow-600 hover:bg-yellow-700 text-white rounded transition-colors text-sm"
                              >
                                Ignore
                              </button>
                            ) : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scan Modal */}
      {scanModalOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-lg w-full mx-4 border border-gray-700">
            <h3 className="text-xl font-semibold text-white mb-4">Scan Image</h3>
            <p className="text-sm text-gray-300 mb-4">
              Enter the image reference (e.g. <span className="font-mono text-blue-300">alpine:3.19</span>).
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const trimmed = imageInput.trim();
                if (!trimmed) {
                  toast.error("Please provide an image reference");
                  return;
                }
                scanImageMutation.mutate(trimmed);
              }}
            >
              <input
                value={imageInput}
                onChange={(e) => setImageInput(e.target.value)}
                placeholder="repository:tag"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                autoFocus
              />
              <div className="flex justify-end gap-3 mt-6">
                <button
                  type="button"
                  onClick={() => {
                    setScanModalOpen(false);
                    setImageInput("");
                  }}
                  className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={scanImageMutation.isPending || !imageInput.trim()}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
                >
                  {scanImageMutation.isPending ? (
                    <span className="flex items-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Starting…
                    </span>
                  ) : (
                    "Start Scan"
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Ignore Modal */}
      {ignoreModalOpen && selectedFinding && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-lg w-full mx-4 border border-gray-700">
            <h3 className="text-xl font-semibold text-white mb-4">Mark as False Positive</h3>
            <p className="text-sm text-gray-300 mb-4">
              Check: <span className="font-mono text-blue-400">{selectedFinding.check_id}</span> - {selectedFinding.title}
            </p>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Reason (required)
              </label>
              <textarea
                value={ignoreReason}
                onChange={(e) => setIgnoreReason(e.target.value)}
                placeholder="Explain why this finding is not applicable..."
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500 h-24"
              />
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => {
                  setIgnoreModalOpen(false);
                  setIgnoreReason("");
                  setSelectedFinding(null);
                }}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmIgnore}
                disabled={!ignoreReason.trim() || ignoreMutation.isPending}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
              >
                {ignoreMutation.isPending ? "Saving..." : "Mark as False Positive"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
