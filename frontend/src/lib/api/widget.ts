import type { WidgetSummary } from '../../types/api/scans';
import { API_BASE, handleResponse } from './client';

export const widgetApi = {
  getSummary: async (): Promise<WidgetSummary> => {
    const res = await fetch(`${API_BASE}/widget/summary`);
    return handleResponse(res);
  },
};
