/**
 * Containers Page - List and manage all containers
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { Container, Play, RefreshCw, Shield, Circle, Loader2, ChevronRight, Search, X } from "lucide-react";
import { useContainers, useTriggerScan, useDiscoverContainers, useScanStatus } from "@/hooks/useVulnForge";
import { formatRelativeDate } from "@/lib/utils";
import { toast } from "sonner";

type FilterType = "all" | "running" | "stopped" | "never_scanned" | "clean";

export function Containers() {
  const { data: containersData, isLoading } = useContainers();
  const { data: scanStatus } = useScanStatus();
  const [filter, setFilter] = useState<FilterType>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const discoverMutation = useDiscoverContainers();
  const scanMutation = useTriggerScan();

  const containers = containersData?.containers || [];

  const handleDiscover = () => {
    discoverMutation.mutate(undefined, {
      onSuccess: (data) => {
        toast.success(`Discovered ${data.discovered.length} new containers`);
      },
      onError: () => {
        toast.error("Failed to discover containers");
      },
    });
  };

  const handleScanContainer = (containerId: number, containerName: string) => {
    scanMutation.mutate([containerId], {
      onSuccess: () => {
        toast.success(`Started scan for ${containerName}`);
      },
      onError: () => {
        toast.error(`Failed to scan ${containerName}`);
      },
    });
  };

  // Check if a specific container is currently being scanned
  const isContainerScanning = (containerName: string) => {
    return scanStatus?.status === "scanning" && scanStatus?.current_container === containerName;
  };

  // Filter and sort containers
  const filteredContainers = containers
    .filter((container) => {
      // Apply filter tabs
      if (filter === "running" && !container.is_running) return false;
      if (filter === "stopped" && container.is_running) return false;
      if (filter === "never_scanned" && container.last_scan_date) return false;
      if (filter === "clean" && (container.total_vulns !== 0 || !container.last_scan_date)) return false;

      // Apply search query (case-insensitive)
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          container.name.toLowerCase().includes(query) ||
          container.image.toLowerCase().includes(query) ||
          container.image_tag.toLowerCase().includes(query)
        );
      }

      return true;
    })
    .sort((a, b) => a.name.localeCompare(b.name)); // Alphabetical sort (A-Z)

  const stats = {
    total: containers.length,
    running: containers.filter((c) => c.is_running).length,
    stopped: containers.filter((c) => !c.is_running).length,
    neverScanned: containers.filter((c) => !c.last_scan_date).length,
    clean: containers.filter((c) => c.total_vulns === 0 && c.last_scan_date).length,
  };

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Containers</h1>
          <p className="text-gray-400 mt-1">Manage and scan Docker containers</p>
        </div>
        <button
          onClick={handleDiscover}
          disabled={discoverMutation.isPending}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${discoverMutation.isPending ? "animate-spin" : ""}`} />
          Discover Containers
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total</p>
              <p className="text-2xl font-bold text-white mt-1">{stats.total}</p>
            </div>
            <Container className="w-8 h-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Running</p>
              <p className="text-2xl font-bold text-green-500 mt-1">{stats.running}</p>
            </div>
            <Circle className="w-8 h-8 text-green-500 fill-green-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Stopped</p>
              <p className="text-2xl font-bold text-gray-500 mt-1">{stats.stopped}</p>
            </div>
            <Circle className="w-8 h-8 text-gray-500" />
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Clean</p>
              <p className="text-2xl font-bold text-green-400 mt-1">{stats.clean}</p>
            </div>
            <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        </div>

        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Never Scanned</p>
              <p className="text-2xl font-bold text-yellow-500 mt-1">{stats.neverScanned}</p>
            </div>
            <Shield className="w-8 h-8 text-yellow-500" />
          </div>
        </div>
      </div>

      {/* Search Bar */}
      <div className="mb-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            type="text"
            placeholder="Search containers by name, image, or tag..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#1a1f2e] border border-gray-800 rounded-lg pl-10 pr-10 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {[
          { key: "all", label: "All Containers" },
          { key: "running", label: "Running" },
          { key: "stopped", label: "Stopped" },
          { key: "clean", label: "Clean" },
          { key: "never_scanned", label: "Never Scanned" },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setFilter(tab.key as FilterType)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              filter === tab.key
                ? "bg-blue-600 text-white"
                : "bg-[#1a1f2e] text-gray-400 hover:text-white border border-gray-800"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Containers List */}
      {isLoading ? (
        <div className="text-center py-12">
          <RefreshCw className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-2" />
          <p className="text-gray-400">Loading containers...</p>
        </div>
      ) : filteredContainers.length > 0 ? (
        <div className="grid grid-cols-1 gap-4">
          {filteredContainers.map((container) => (
            <div
              key={container.id}
              className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 hover:border-gray-700 transition-colors"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <Container className="w-5 h-5 text-blue-400" />
                    <h3 className="text-lg font-semibold text-white">{container.name}</h3>
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
                    {container.last_scan_date && container.total_vulns === 0 && (
                      <span className="text-xs px-2 py-1 rounded bg-green-500/10 text-green-400 flex items-center gap-1">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                        Clean
                      </span>
                    )}
                    {container.last_scan_date && container.scanner_coverage && container.total_vulns > 0 && (
                      <span className={`text-xs px-2 py-1 rounded ${
                        container.scanner_coverage === 2
                          ? 'bg-purple-500/10 text-purple-400'
                          : 'bg-blue-500/10 text-blue-400'
                      }`}>
                        {container.scanner_coverage === 2 ? 'Both Scanners' : 'Trivy Only'}
                      </span>
                    )}
                  </div>

                  <div className="space-y-1 text-sm">
                    <p className="text-gray-400">
                      <span className="text-gray-500">Image:</span>{" "}
                      <span className="text-gray-300">{container.image}:{container.image_tag}</span>
                    </p>
                    {container.last_scan_date ? (
                      <>
                        <p className="text-gray-400">
                          <span className="text-gray-500">Last Scan:</span>{" "}
                          <span className="text-gray-300">{formatRelativeDate(container.last_scan_date)}</span>
                        </p>
                        <div className="flex items-center gap-4 mt-2 flex-wrap">
                          <span className="text-gray-400">
                            Total: <span className="text-white font-medium">{container.total_vulns || 0}</span>
                          </span>
                          <span className="text-gray-400">
                            Fixable: <span className="text-green-500 font-medium">{container.fixable_vulns || 0}</span>
                          </span>
                          <span className="text-gray-400">
                            Critical: <span className="text-red-500 font-medium">{container.critical_count || 0}</span>
                          </span>
                          <span className="text-gray-400">
                            High: <span className="text-orange-500 font-medium">{container.high_count || 0}</span>
                          </span>
                          {container.dive_efficiency_score !== null && (
                            <span className={`text-xs px-2 py-1 rounded ${
                              container.dive_efficiency_score >= 0.9
                                ? 'bg-green-500/10 text-green-500' :
                              container.dive_efficiency_score >= 0.7
                                ? 'bg-yellow-500/10 text-yellow-500' :
                              'bg-red-500/10 text-red-500'
                            }`}>
                              {(container.dive_efficiency_score * 100).toFixed(0)}% efficient
                            </span>
                          )}
                        </div>
                      </>
                    ) : (
                      <p className="text-yellow-500 text-sm">Never scanned</p>
                    )}
                  </div>
                </div>

                <div className="flex gap-2">
                  <Link
                    to={`/containers/${container.id}`}
                    className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg flex items-center gap-2 transition-colors"
                  >
                    View Details
                    <ChevronRight className="w-4 h-4" />
                  </Link>
                  <button
                    onClick={() => handleScanContainer(container.id, container.name)}
                    disabled={scanMutation.isPending || isContainerScanning(container.name)}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
                  >
                    {isContainerScanning(container.name) ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" />
                        Scan
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-12 bg-[#1a1f2e] border border-gray-800 rounded-lg">
          <Container className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          {searchQuery || filter !== "all" ? (
            <>
              <p className="text-gray-400 text-lg">No containers match your {searchQuery ? "search" : "filter"}</p>
              <p className="text-gray-500 text-sm mt-1">
                {searchQuery ? "Try a different search term" : "Try a different filter"}
              </p>
            </>
          ) : (
            <>
              <p className="text-gray-400 text-lg">No containers found</p>
              <p className="text-gray-500 text-sm mt-1">Click "Discover Containers" to find containers</p>
            </>
          )}
        </div>
      )}
    </div>
  );
}
