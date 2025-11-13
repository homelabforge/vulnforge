/**
 * Activity Filter Bar - Event type filter chips
 */

interface FilterOption {
  value: string | null;
  label: string;
  count?: number;
}

interface ActivityFilterBarProps {
  activeFilter: string | null;
  onFilterChange: (filter: string | null) => void;
  eventTypeCounts: Record<string, number>;
}

export function ActivityFilterBar({
  activeFilter,
  onFilterChange,
  eventTypeCounts,
}: ActivityFilterBarProps) {
  // Calculate total count
  const totalCount = Object.values(eventTypeCounts).reduce((sum, count) => sum + count, 0);

  const filters: FilterOption[] = [
    { value: null, label: "All", count: totalCount },
    { value: "scan_completed", label: "Scans", count: eventTypeCounts.scan_completed || 0 },
    { value: "scan_failed", label: "Failures", count: eventTypeCounts.scan_failed || 0 },
    { value: "secret_detected", label: "Secrets", count: eventTypeCounts.secret_detected || 0 },
    {
      value: "high_severity_found",
      label: "High Severity",
      count: eventTypeCounts.high_severity_found || 0,
    },
    {
      value: "container_discovered",
      label: "Discoveries",
      count: eventTypeCounts.container_discovered || 0,
    },
    {
      value: "container_status_changed",
      label: "Status Changes",
      count: eventTypeCounts.container_status_changed || 0,
    },
  ];

  return (
    <div className="flex flex-wrap gap-2">
      {filters.map((filter) => {
        const isActive = activeFilter === filter.value;
        const showCount = filter.count !== undefined && filter.count > 0;

        return (
          <button
            key={filter.value || "all"}
            onClick={() => onFilterChange(filter.value)}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              isActive
                ? "bg-blue-600 text-white shadow-lg shadow-blue-600/30"
                : "bg-[#1a1f2e] text-gray-400 border border-gray-800 hover:border-gray-700 hover:text-white"
            }`}
          >
            <span className="flex items-center gap-2">
              {filter.label}
              {showCount && (
                <span
                  className={`text-xs px-2 py-0.5 rounded-full ${
                    isActive
                      ? "bg-blue-700 text-white"
                      : "bg-gray-800 text-gray-400"
                  }`}
                >
                  {filter.count}
                </span>
              )}
            </span>
          </button>
        );
      })}
    </div>
  );
}
