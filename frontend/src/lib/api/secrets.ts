import type { Secret, SecretListItem, SecretSummary } from '../../types/api/secrets';
import { API_BASE, handleResponse, handleBlobResponse } from './client';

export const secretsApi = {
  getContainerSecrets: async (containerId: number): Promise<Secret[]> => {
    const res = await fetch(`${API_BASE}/containers/${containerId}/secrets`);
    return handleResponse(res);
  },

  getScanSecrets: async (scanId: number): Promise<Secret[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/secrets`);
    return handleResponse(res);
  },

  getSummary: async (): Promise<SecretSummary> => {
    const res = await fetch(`${API_BASE}/secrets/summary`);
    return handleResponse(res);
  },

  getAll: async (filters?: {
    severity?: string;
    category?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<SecretListItem[]> => {
    const query = new URLSearchParams();
    if (filters?.severity) query.append("severity", filters.severity);
    if (filters?.category) query.append("category", filters.category);
    if (filters?.status) query.append("status", filters.status);
    if (filters?.limit) query.append("limit", filters.limit.toString());
    if (filters?.offset) query.append("offset", filters.offset.toString());

    const res = await fetch(`${API_BASE}/secrets/?${query}`);
    return handleResponse(res);
  },

  updateStatus: async (id: number, status: string, notes?: string): Promise<Secret> => {
    const res = await fetch(`${API_BASE}/secrets/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    });
    return handleResponse(res);
  },

  bulkUpdate: async (ids: number[], status: string, notes?: string): Promise<{ updated: number }> => {
    const res = await fetch(`${API_BASE}/secrets/bulk-update`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret_ids: ids, update: { status, notes } }),
    });
    return handleResponse(res);
  },

  export: async (format: "csv" | "json", filters?: {
    severity?: string;
    category?: string;
  }): Promise<Blob> => {
    const params = new URLSearchParams();
    if (filters?.severity) params.append("severity", filters.severity);
    if (filters?.category) params.append("category", filters.category);
    params.append("format", format);
    const res = await fetch(`${API_BASE}/secrets/export?${params}`);
    return handleBlobResponse(res);
  },
};
