import type { PaginatedVulnerabilities, Vulnerability, RemediationGroup } from '../../types/api/vulnerabilities';
import { API_BASE, handleResponse, handleBlobResponse } from './client';

export const vulnerabilitiesApi = {
  getAll: async (params?: {
    severity?: string;
    fixable_only?: boolean;
    kev_only?: boolean;
    status?: string;
    container_id?: number;
    limit?: number;
    offset?: number;
  }): Promise<PaginatedVulnerabilities> => {
    const query = new URLSearchParams();
    if (params?.severity) query.append("severity", params.severity);
    if (params?.fixable_only) query.append("fixable_only", "true");
    if (params?.kev_only) query.append("kev_only", "true");
    if (params?.status) query.append("status", params.status);
    if (params?.container_id) query.append("container_id", params.container_id.toString());
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());

    const res = await fetch(`${API_BASE}/vulnerabilities/?${query}`);
    return handleResponse(res);
  },

  getById: async (id: number): Promise<Vulnerability> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/${id}`);
    return handleResponse(res);
  },

  updateStatus: async (id: number, status: string, notes?: string): Promise<Vulnerability> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    });
    return handleResponse(res);
  },

  bulkUpdate: async (ids: number[], status: string, notes?: string): Promise<{ updated: number }> => {
    const res = await fetch(`${API_BASE}/vulnerabilities/bulk-update`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vuln_ids: ids, update: { status, notes } }),
    });
    return handleResponse(res);
  },

  getRemediationGroups: async (containerId?: number): Promise<RemediationGroup[]> => {
    const query = containerId ? `?container_id=${containerId}` : "";
    const res = await fetch(`${API_BASE}/vulnerabilities/remediation-groups${query}`);
    return handleResponse(res);
  },

  export: async (format: "csv" | "json", filters?: {
    severity?: string;
    fixable_only?: boolean;
    kev_only?: boolean;
    status?: string;
  }): Promise<Blob> => {
    const query = new URLSearchParams({ format });
    if (filters?.severity) query.append("severity", filters.severity);
    if (filters?.fixable_only) query.append("fixable_only", "true");
    if (filters?.kev_only) query.append("kev_only", "true");
    if (filters?.status) query.append("status", filters.status);

    const res = await fetch(`${API_BASE}/vulnerabilities/export?${query}`);
    return handleBlobResponse(res);
  },
};
