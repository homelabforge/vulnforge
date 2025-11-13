/**
 * Activity Timeline - Visual timeline of system events
 */

import { Link } from "react-router-dom";
import {
  CheckCircle,
  XCircle,
  Shield,
  Key,
  Container as ContainerIcon,
  AlertTriangle,
  Circle,
  Clock,
  Bug,
} from "lucide-react";
import { formatRelativeDate } from "@/lib/utils";
import type { ActivityEventMetadata, ActivityLog } from "@/lib/api";

interface ActivityTimelineProps {
  activities: ActivityLog[];
  isLoading?: boolean;
}

const renderMetadata = (metadata: ActivityEventMetadata | null | undefined) => {
  if (!metadata || Object.keys(metadata).length === 0) {
    return null;
  }

  return (
    <div className="bg-[#0f1419] rounded-lg p-4 space-y-2">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {metadata.total_vulns !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Total Vulns</p>
            <p className="text-lg font-bold text-white">{metadata.total_vulns}</p>
          </div>
        )}
        {metadata.fixable_vulns !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Fixable</p>
            <p className="text-lg font-bold text-green-500">{metadata.fixable_vulns}</p>
          </div>
        )}
        {metadata.critical_count !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Critical</p>
            <p className="text-lg font-bold text-red-500">{metadata.critical_count}</p>
          </div>
        )}
        {metadata.high_count !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">High</p>
            <p className="text-lg font-bold text-orange-500">{metadata.high_count}</p>
          </div>
        )}
        {metadata.medium_count !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Medium</p>
            <p className="text-lg font-bold text-yellow-500">{metadata.medium_count}</p>
          </div>
        )}
        {metadata.low_count !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Low</p>
            <p className="text-lg font-bold text-blue-400">{metadata.low_count}</p>
          </div>
        )}
        {metadata.duration_seconds !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Duration</p>
            <p className="text-lg font-bold text-white">{metadata.duration_seconds}s</p>
          </div>
        )}
        {metadata.total_secrets !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Secrets</p>
            <p className="text-lg font-bold text-yellow-500">{metadata.total_secrets}</p>
          </div>
        )}
        {metadata.containers_count !== undefined && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Containers</p>
            <p className="text-lg font-bold text-white">{metadata.containers_count}</p>
          </div>
        )}
      </div>

      {Array.isArray(metadata.categories) && metadata.categories.length > 0 && (
        <div className="pt-2 border-t border-gray-800">
          <p className="text-xs text-gray-400 mb-2">Categories:</p>
          <div className="flex flex-wrap gap-2">
            {metadata.categories.map((category) => (
              <span key={category} className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs">
                {category}
              </span>
            ))}
          </div>
        </div>
      )}

      {metadata.error_message && (
        <div className="pt-2 border-t border-gray-800">
          <p className="text-xs text-gray-400 mb-1">Error:</p>
          <p className="text-sm text-red-400 font-mono">{metadata.error_message}</p>
        </div>
      )}
    </div>
  );
};

export function ActivityTimeline({ activities, isLoading }: ActivityTimelineProps) {
  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 animate-pulse">
            <div className="flex items-start gap-4">
              <div className="w-10 h-10 bg-gray-700 rounded-full"></div>
              <div className="flex-1">
                <div className="h-4 bg-gray-700 rounded w-1/3 mb-2"></div>
                <div className="h-3 bg-gray-700 rounded w-1/2"></div>
              </div>
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (!activities || activities.length === 0) {
    return (
      <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-12 text-center">
        <Clock className="w-16 h-16 text-gray-600 mx-auto mb-4" />
        <p className="text-gray-400 text-lg mb-2">No activity yet</p>
        <p className="text-sm text-gray-500">Run a scan to start tracking activity</p>
      </div>
    );
  }

  const getEventIcon = (eventType: string) => {
    const baseClasses = "w-10 h-10 p-2 rounded-full";

    switch (eventType) {
      case "scan_completed":
        return (
          <div className={`${baseClasses} bg-green-500/10 border border-green-500/30`}>
            <CheckCircle className="w-full h-full text-green-500" />
          </div>
        );
      case "scan_failed":
        return (
          <div className={`${baseClasses} bg-red-500/10 border border-red-500/30`}>
            <XCircle className="w-full h-full text-red-500" />
          </div>
        );
      case "secret_detected":
        return (
          <div className={`${baseClasses} bg-yellow-500/10 border border-yellow-500/30`}>
            <Key className="w-full h-full text-yellow-500" />
          </div>
        );
      case "high_severity_found":
        return (
          <div className={`${baseClasses} bg-orange-500/10 border border-orange-500/30`}>
            <AlertTriangle className="w-full h-full text-orange-500" />
          </div>
        );
      case "container_discovered":
        return (
          <div className={`${baseClasses} bg-blue-500/10 border border-blue-500/30`}>
            <ContainerIcon className="w-full h-full text-blue-500" />
          </div>
        );
      case "container_status_changed":
        return (
          <div className={`${baseClasses} bg-gray-500/10 border border-gray-500/30`}>
            <Circle className="w-full h-full text-gray-500" />
          </div>
        );
      case "batch_scan_completed":
        return (
          <div className={`${baseClasses} bg-purple-500/10 border border-purple-500/30`}>
            <Shield className="w-full h-full text-purple-500" />
          </div>
        );
      default:
        return (
          <div className={`${baseClasses} bg-gray-500/10 border border-gray-500/30`}>
            <Bug className="w-full h-full text-gray-500" />
          </div>
        );
    }
  };

  const getSeverityBadge = (severity: string) => {
    const baseClasses = "px-2 py-1 rounded text-xs font-semibold uppercase";
    switch (severity) {
      case "critical":
        return `${baseClasses} bg-red-500/10 text-red-500 border border-red-500/20`;
      case "warning":
        return `${baseClasses} bg-yellow-500/10 text-yellow-500 border border-yellow-500/20`;
      case "info":
      default:
        return `${baseClasses} bg-blue-500/10 text-blue-500 border border-blue-500/20`;
    }
  };

  return (
    <div className="space-y-4">
      {activities.map((activity, index) => (
        <div
          key={activity.id}
          className="bg-[#1a1f2e] border border-gray-800 rounded-lg p-6 hover:border-gray-700 transition-colors relative"
        >
          {/* Timeline connector line */}
          {index < activities.length - 1 && (
            <div className="absolute left-11 top-[4.5rem] h-4 w-0.5 bg-gray-800" />
          )}

          <div className="flex items-start gap-4">
            {/* Event Icon */}
            {getEventIcon(activity.event_type)}

            {/* Event Content */}
            <div className="flex-1 min-w-0">
              {/* Header */}
              <div className="flex items-start justify-between gap-4 mb-2">
                <div className="flex-1 min-w-0">
                  <h3 className="text-white font-medium text-lg mb-1">{activity.title}</h3>
                  <div className="flex items-center gap-2 text-sm text-gray-400">
                    <span>{formatRelativeDate(activity.timestamp)}</span>
                    <span>•</span>
                    <span>{new Date(activity.timestamp).toLocaleString()}</span>
                    {activity.container_name && (
                      <>
                        <span>•</span>
                        {activity.container_id ? (
                          <Link
                            to={`/containers/${activity.container_id}`}
                            className="text-blue-400 hover:text-blue-300 transition-colors"
                          >
                            {activity.container_name}
                          </Link>
                        ) : (
                          <span>{activity.container_name}</span>
                        )}
                      </>
                    )}
                  </div>
                </div>
                <span className={getSeverityBadge(activity.severity)}>{activity.severity}</span>
              </div>

              {/* Description */}
              {activity.description && (
                <p className="text-gray-300 mb-3 leading-relaxed">{activity.description}</p>
              )}

              {/* Metadata Display */}
              {renderMetadata(activity.event_metadata)}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
