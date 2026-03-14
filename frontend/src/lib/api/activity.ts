import type { ActivityLog, ActivityList, ActivityTypeCount } from '../../types/api/activity';
import { API_BASE, handleResponse } from './client';

export const activityApi = {
  getRecent: async (params?: {
    limit?: number;
    offset?: number;
    event_type?: string;
    severity?: string;
    container_id?: number;
  }): Promise<ActivityList> => {
    const query = new URLSearchParams();
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());
    if (params?.event_type) query.append("event_type", params.event_type);
    if (params?.severity) query.append("severity", params.severity);
    if (params?.container_id) query.append("container_id", params.container_id.toString());

    const res = await fetch(`${API_BASE}/activity/?${query}`);
    return handleResponse(res);
  },

  getTypes: async (): Promise<{ types: ActivityTypeCount[] }> => {
    const res = await fetch(`${API_BASE}/activity/types`);
    return handleResponse(res);
  },

  getByContainer: async (containerId: number, limit?: number): Promise<ActivityLog[]> => {
    const query = limit ? `?limit=${limit}` : "";
    const res = await fetch(`${API_BASE}/activity/container/${containerId}${query}`);
    return handleResponse(res);
  },
};
