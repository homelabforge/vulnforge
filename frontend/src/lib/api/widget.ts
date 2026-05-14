import type { WidgetSummary, WidgetTopContainers } from '../../types/api/scans';
import { API_BASE, handleResponse } from './client';

export const widgetApi = {
  getSummary: async (): Promise<WidgetSummary> => {
    const res = await fetch(`${API_BASE}/widget/summary`);
    return handleResponse(res);
  },
  getTopContainers: async (limit = 10): Promise<WidgetTopContainers> => {
    const res = await fetch(`${API_BASE}/widget/top-containers?limit=${limit}`);
    return handleResponse(res);
  },
};
