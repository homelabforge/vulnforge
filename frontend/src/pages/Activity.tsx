/**
 * Activity Page - Timeline view of system events
 */

import { useState } from "react";
import { Activity as ActivityIcon, RefreshCw } from "lucide-react";
import { useActivities } from "@/hooks/useVulnForge";
import { ActivityTimeline } from "@/components/ActivityTimeline";
import { ActivityFilterBar } from "@/components/ActivityFilterBar";

export function Activity() {
  const [eventTypeFilter, setEventTypeFilter] = useState<string | null>(null);
  const [limit] = useState(50);

  // Fetch activities with auto-refresh (15s polling)
  const { data: activityData, isLoading, error } = useActivities({
    limit,
    event_type: eventTypeFilter || undefined,
  });

  const activities = activityData?.activities || [];
  const eventTypeCounts = activityData?.event_type_counts || {};
  const total = activityData?.total || 0;

  // Handle filter change
  const handleFilterChange = (filter: string | null) => {
    setEventTypeFilter(filter);
  };

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <ActivityIcon className="w-8 h-8 text-blue-500" />
            Activity
          </h1>
          <p className="text-gray-400 mt-1">System event timeline</p>
        </div>

        {/* Auto-refresh indicator */}
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <RefreshCw className="w-4 h-4 animate-spin" />
          <span>Auto-refreshing every 15s</span>
        </div>
      </div>

      {/* Stats Summary */}
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-gray-400 mb-1">Total Events</p>
            <p className="text-3xl font-bold text-white">{total}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400 mb-1">
              {eventTypeFilter ? "Filtered" : "All Events"}
            </p>
            <p className="text-xl font-semibold text-blue-400">{activities.length} displayed</p>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="mb-6">
        <ActivityFilterBar
          activeFilter={eventTypeFilter}
          onFilterChange={handleFilterChange}
          eventTypeCounts={eventTypeCounts}
        />
      </div>

      {/* Error State */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-6 mb-6">
          <p className="text-red-500 font-medium mb-2">Failed to load activities</p>
          <p className="text-sm text-gray-400">{error.message}</p>
        </div>
      )}

      {/* Timeline */}
      <ActivityTimeline activities={activities} isLoading={isLoading} />

      {/* Empty State (when filter returns no results) */}
      {!isLoading && activities.length === 0 && !error && eventTypeFilter && (
        <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-8 text-center">
          <p className="text-gray-400">No events found for this filter</p>
          <button
            onClick={() => setEventTypeFilter(null)}
            className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            Clear Filter
          </button>
        </div>
      )}
    </div>
  );
}
