import type { ScanStatus, ScanTrendsResponse, ScanHistoryEntry } from '../../types/api/scans';
import { API_BASE, handleResponse } from './client';

export const scansApi = {
  trigger: async (containerIds?: number[]): Promise<{ message: string; queued: number; skipped: number; total_requested: number }> => {
    const res = await fetch(`${API_BASE}/scans/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ container_ids: containerIds || null }),
    });
    return handleResponse(res);
  },

  getCurrent: async (): Promise<ScanStatus> => {
    const res = await fetch(`${API_BASE}/scans/current`);
    return handleResponse(res);
  },

  getTrends: async (windowDays = 30): Promise<ScanTrendsResponse> => {
    const res = await fetch(`${API_BASE}/scans/trends?window_days=${windowDays}`);
    return handleResponse(res);
  },

  getHistory: async (containerId: number): Promise<ScanHistoryEntry[]> => {
    const res = await fetch(`${API_BASE}/scans/history/${containerId}`);
    return handleResponse(res);
  },
};
