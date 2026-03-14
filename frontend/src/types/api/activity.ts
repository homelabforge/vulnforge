import type { ActivityEventMetadata } from './system';

export interface ActivityLog {
  id: number;
  event_type: string;
  severity: string;
  container_id: number | null;
  container_name: string | null;
  title: string;
  description: string | null;
  event_metadata: ActivityEventMetadata | null;
  timestamp: string;
  created_at: string;
}

export interface ActivityList {
  activities: ActivityLog[];
  total: number;
  event_type_counts: Record<string, number>;
}

export interface ActivityTypeCount {
  type: string;
  count: number;
  label: string;
}
