import type {
  ComplianceSummary,
  ComplianceCurrentScan,
  ComplianceFinding,
  ComplianceTrendPoint,
  ImageComplianceSummary,
  ImageComplianceImageSummary,
  ImageComplianceFinding,
  ImageScanStatus,
} from '../../types/api/compliance';
import { API_BASE, handleResponse } from './client';

export const complianceApi = {
  getSummary: async (): Promise<ComplianceSummary> => {
    const res = await fetch(`${API_BASE}/compliance/summary`);
    return handleResponse(res);
  },

  getCurrentScan: async (): Promise<ComplianceCurrentScan> => {
    const res = await fetch(`${API_BASE}/compliance/current`);
    return handleResponse(res);
  },

  getFindings: async (params?: {
    status_filter?: string;
    category_filter?: string;
    include_ignored?: boolean;
  }): Promise<ComplianceFinding[]> => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.append("status_filter", params.status_filter);
    if (params?.category_filter) query.append("category_filter", params.category_filter);
    if (params?.include_ignored !== undefined) query.append("include_ignored", String(params.include_ignored));
    const res = await fetch(`${API_BASE}/compliance/findings?${query}`);
    return handleResponse(res);
  },

  getTrend: async (days = 30): Promise<ComplianceTrendPoint[]> => {
    const res = await fetch(`${API_BASE}/compliance/scans/trend?days=${days}`);
    return handleResponse(res);
  },

  triggerScan: async (): Promise<{ message: string }> => {
    const res = await fetch(`${API_BASE}/compliance/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trigger_type: "manual" }),
    });
    return handleResponse(res);
  },

  ignoreFinding: async (findingId: number, reason: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/compliance/findings/ignore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId, reason, ignored_by: "user" }),
    });
    return handleResponse(res);
  },

  unignoreFinding: async (findingId: number): Promise<void> => {
    const res = await fetch(`${API_BASE}/compliance/findings/unignore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId }),
    });
    return handleResponse(res);
  },

  getExportUrl: (params?: {
    status_filter?: string;
    category_filter?: string;
    include_ignored?: boolean;
  }): string => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.append("status_filter", params.status_filter);
    if (params?.category_filter) query.append("category_filter", params.category_filter);
    if (params?.include_ignored !== undefined) query.append("include_ignored", String(params.include_ignored));
    return `${API_BASE}/compliance/export/csv?${query}`;
  },
};

export const imageComplianceApi = {
  getSummary: async (): Promise<ImageComplianceSummary> => {
    const res = await fetch(`${API_BASE}/image-compliance/summary`);
    return handleResponse(res);
  },

  getImages: async (): Promise<ImageComplianceImageSummary[]> => {
    const res = await fetch(`${API_BASE}/image-compliance/images`);
    return handleResponse(res);
  },

  getFindings: async (imageName: string, params?: {
    status_filter?: string;
    include_ignored?: boolean;
  }): Promise<ImageComplianceFinding[]> => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.append("status_filter", params.status_filter);
    if (params?.include_ignored !== undefined) query.append("include_ignored", String(params.include_ignored));
    const res = await fetch(`${API_BASE}/image-compliance/findings/${encodeURIComponent(imageName)}?${query}`);
    return handleResponse(res);
  },

  getCurrentScan: async (): Promise<ImageScanStatus> => {
    const res = await fetch(`${API_BASE}/image-compliance/current`);
    return handleResponse(res);
  },

  scanImage: async (imageName: string): Promise<{ image_name: string }> => {
    const res = await fetch(`${API_BASE}/image-compliance/scan?image_name=${encodeURIComponent(imageName)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    return handleResponse(res);
  },

  scanAll: async (): Promise<{ image_count: number }> => {
    const res = await fetch(`${API_BASE}/image-compliance/scan-all`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    return handleResponse(res);
  },

  ignoreFinding: async (findingId: number, reason: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/image-compliance/findings/${findingId}/ignore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    return handleResponse(res);
  },

  unignoreFinding: async (findingId: number): Promise<void> => {
    const res = await fetch(`${API_BASE}/image-compliance/findings/${findingId}/unignore`, {
      method: "POST",
    });
    return handleResponse(res);
  },

  getExportUrl: (imageName?: string): string => {
    if (imageName) {
      return `${API_BASE}/image-compliance/export/csv?image_name=${encodeURIComponent(imageName)}`;
    }
    return `${API_BASE}/image-compliance/export/csv`;
  },
};
